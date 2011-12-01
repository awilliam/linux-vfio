/*
 * VFIO framework
 *
 * Copyright (C) 2011 Red Hat, Inc.  All rights reserved.
 *     Author: Alex Williamson <alex.williamson@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Derived from original vfio:
 * Copyright 2010 Cisco Systems, Inc.  All rights reserved.
 * Author: Tom Lyon, pugs@cisco.com
 */

#include <linux/cdev.h>
#include <linux/compat.h>
#include <linux/device.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/iommu.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/vfio.h>
#include <linux/wait.h>

#include "vfio_private.h"

#define DRIVER_VERSION	"0.2"
#define DRIVER_AUTHOR	"Alex Williamson <alex.williamson@redhat.com>"
#define DRIVER_DESC	"VFIO - User Level meta-driver"

static struct vfio {
	dev_t			devt;
	struct cdev		cdev;
	struct list_head	group_list;
	struct mutex		lock;
	struct kref		kref;
	struct class		*class;
	struct idr		idr;
	wait_queue_head_t	release_q;
} vfio;

static const struct file_operations vfio_group_fops;
extern const struct file_operations vfio_iommu_fops;

struct vfio_group {
	dev_t			devt;
	unsigned int		groupid;
	struct bus_type		*bus;
	struct vfio_iommu	*iommu;
	struct list_head	device_list;
	struct list_head	iommu_next;
	struct list_head	group_next;
	struct device		*dev;
	struct kobject		*devices_kobj;
	int			refcnt;
	bool			tainted;
};

struct vfio_device {
	struct device			*dev;
	const struct vfio_device_ops	*ops;
	struct vfio_group		*group;
	struct list_head		device_next;
	bool				attached;
	bool				deleteme;
	int				refcnt;
	void				*device_data;
};

/*
 * Helper functions called under vfio.lock
 */

/* Return true if any devices within a group are opened */
static bool __vfio_group_devs_inuse(struct vfio_group *group)
{
	struct list_head *pos;

	list_for_each(pos, &group->device_list) {
		struct vfio_device *device;

		device = list_entry(pos, struct vfio_device, device_next);
		if (device->refcnt)
			return true;
	}
	return false;
}

/* Return true if any of the groups attached to an iommu are opened.
 * We can only tear apart merged groups when nothing is left open. */
static bool __vfio_iommu_groups_inuse(struct vfio_iommu *iommu)
{
	struct list_head *pos;

	list_for_each(pos, &iommu->group_list) {
		struct vfio_group *group;

		group = list_entry(pos, struct vfio_group, iommu_next);
		if (group->refcnt)
			return true;
	}
	return false;
}

/* An iommu is "in use" if it has a file descriptor open or if any of
 * the groups assigned to the iommu have devices open. */
static bool __vfio_iommu_inuse(struct vfio_iommu *iommu)
{
	struct list_head *pos;

	if (iommu->refcnt)
		return true;

	list_for_each(pos, &iommu->group_list) {
		struct vfio_group *group;

		group = list_entry(pos, struct vfio_group, iommu_next);

		if (__vfio_group_devs_inuse(group))
			return true;
	}
	return false;
}

static void __vfio_group_set_iommu(struct vfio_group *group,
				   struct vfio_iommu *iommu)
{
	if (group->iommu)
		list_del(&group->iommu_next);
	if (iommu)
		list_add(&group->iommu_next, &iommu->group_list);

	group->iommu = iommu;
}

static void __vfio_iommu_detach_dev(struct vfio_iommu *iommu,
				    struct vfio_device *device)
{
	if (WARN_ON(!iommu->domain && device->attached))
		return;

	if (!device->attached)
		return;

	iommu_detach_device(iommu->domain, device->dev);
	device->attached = false;
}

static void __vfio_iommu_detach_group(struct vfio_iommu *iommu,
				      struct vfio_group *group)
{
	struct list_head *pos;

	list_for_each(pos, &group->device_list) {
		struct vfio_device *device;

		device = list_entry(pos, struct vfio_device, device_next);
		__vfio_iommu_detach_dev(iommu, device);
	}
}

static int __vfio_iommu_attach_dev(struct vfio_iommu *iommu,
				   struct vfio_device *device)
{
	int ret;

	if (WARN_ON(device->attached || !iommu || !iommu->domain))
		return -EINVAL;

	ret = iommu_attach_device(iommu->domain, device->dev);
	if (!ret)
		device->attached = true;

	return ret;
}

static int __vfio_iommu_attach_group(struct vfio_iommu *iommu,
				     struct vfio_group *group)
{
	struct list_head *pos;

	list_for_each(pos, &group->device_list) {
		struct vfio_device *device;
		int ret;

		device = list_entry(pos, struct vfio_device, device_next);
		ret = __vfio_iommu_attach_dev(iommu, device);
		if (ret) {
			__vfio_iommu_detach_group(iommu, group);
			return ret;
		}
	}
	return 0;
}

/* The iommu is viable, ie. ready to be configured, when all the devices
 * for all the groups attached to the iommu are bound to their vfio device
 * drivers (ex. vfio-pci).  This sets the device_data private data pointer. */
static bool __vfio_iommu_viable(struct vfio_iommu *iommu)
{
	struct list_head *gpos, *dpos;

	list_for_each(gpos, &iommu->group_list) {
		struct vfio_group *group;
		group = list_entry(gpos, struct vfio_group, iommu_next);

		if (group->tainted)
			return false;

		list_for_each(dpos, &group->device_list) {
			struct vfio_device *device;
			device = list_entry(dpos,
					    struct vfio_device, device_next);

			if (!device->device_data)
				return false;
		}
	}
	return true;
}

static void __vfio_iommu_close(struct vfio_iommu *iommu)
{
	struct list_head *pos;

	if (!iommu->domain)
		return;

	list_for_each(pos, &iommu->group_list) {
		struct vfio_group *group;
		group = list_entry(pos, struct vfio_group, iommu_next);

		__vfio_iommu_detach_group(iommu, group);
	}

	vfio_iommu_unmapall(iommu);

	iommu_domain_free(iommu->domain);
	iommu->domain = NULL;
	iommu->mm = NULL;
}

/* Open the IOMMU.  This gates all access to the iommu or device file
 * descriptors and sets current->mm as the exclusive user. */
static int __vfio_iommu_open(struct vfio_iommu *iommu)
{
	struct list_head *pos;
	int ret;

	if (!__vfio_iommu_viable(iommu))
		return -EBUSY;

	if (iommu->domain)
		return -EINVAL;

	iommu->domain = iommu_domain_alloc(iommu->bus);
	if (!iommu->domain)
		return -ENOMEM;

	list_for_each(pos, &iommu->group_list) {
		struct vfio_group *group;
		group = list_entry(pos, struct vfio_group, iommu_next);

		ret = __vfio_iommu_attach_group(iommu, group);
		if (ret) {
			__vfio_iommu_close(iommu);
			return ret;
		}
	}

	iommu->cache = (iommu_domain_has_cap(iommu->domain,
					     IOMMU_CAP_CACHE_COHERENCY) != 0);
	iommu->mm = current->mm;

	return 0;
}

/* Actively try to tear down the iommu and merged groups.  If there are no
 * open iommu or device fds, we close the iommu.  If we close the iommu and
 * there are also no open group fds, we can futher dissolve the group to
 * iommu association and free the iommu data structure. */
static int __vfio_try_dissolve_iommu(struct vfio_iommu *iommu)
{

	if (__vfio_iommu_inuse(iommu))
		return -EBUSY;

	__vfio_iommu_close(iommu);

	if (!__vfio_iommu_groups_inuse(iommu)) {
		struct list_head *pos, *ppos;

		list_for_each_safe(pos, ppos, &iommu->group_list) {
			struct vfio_group *group;

			group = list_entry(pos, struct vfio_group, iommu_next);
			__vfio_group_set_iommu(group, NULL);
		}

		kfree(iommu);
	}

	return 0;
}

static struct vfio_device *__vfio_lookup_dev(struct device *dev)
{
	struct list_head *gpos;
	unsigned int groupid;

	if (iommu_device_group(dev, &groupid))
		return NULL;

	list_for_each(gpos, &vfio.group_list) {
		struct vfio_group *group;
		struct list_head *dpos;

		group = list_entry(gpos, struct vfio_group, group_next);

		if (group->groupid != groupid || group->bus != dev->bus)
			continue;

		list_for_each(dpos, &group->device_list) {
			struct vfio_device *device;

			device = list_entry(dpos,
					    struct vfio_device, device_next);

			if (device->dev == dev)
				return device;
		}
	}
	return NULL;
}

static struct vfio_group *__vfio_dev_to_group(struct device *dev,
					      unsigned int groupid)
{
	struct list_head *pos;
	struct vfio_group *group;

	list_for_each(pos, &vfio.group_list) {
		group = list_entry(pos, struct vfio_group, group_next);
		if (group->groupid == groupid && group->bus == dev->bus)
			return group;
	}

	return NULL;
}

struct vfio_device *__vfio_group_find_device(struct vfio_group *group,
					     struct device *dev)
{
	struct list_head *pos;
	struct vfio_device *device;

	list_for_each(pos, &group->device_list) {
		device = list_entry(pos, struct vfio_device, device_next);
		if (device->dev == dev)
			return device;
	}

	return NULL;
}

static struct vfio_group *__vfio_create_group(struct device *dev,
					      unsigned int groupid)
{
	struct vfio_group *group;
	int ret, minor;

	group = kzalloc(sizeof(*group), GFP_KERNEL);

	/* We can't recover from this.  If we can't even get memory for
	 * the group, we can't track the device and we don't have a place
	 * to mark the groupid tainted.  Failures below should at least
	 * return a tainted group. */
	BUG_ON(!group);

	group->groupid = groupid;
	group->bus = dev->bus;
	INIT_LIST_HEAD(&group->device_list);

	group->tainted = true;
	list_add(&group->group_next, &vfio.group_list);

again:
	if (unlikely(idr_pre_get(&vfio.idr, GFP_KERNEL) == 0))
		goto out;

	ret = idr_get_new(&vfio.idr, group, &minor);
	if (ret == -EAGAIN)
		goto again;
	if (ret || minor > MINORMASK) {
		if (minor > MINORMASK)
			idr_remove(&vfio.idr, minor);
		goto out;
	}

	group->devt = MKDEV(MAJOR(vfio.devt), minor);
	group->dev = device_create(vfio.class, NULL, group->devt, group,
				   "%s:%u", dev->bus->name, groupid);
	if (IS_ERR(group->dev))
		goto out_device;

	/* Create a place to link individual devices in sysfs */
	group->devices_kobj = kobject_create_and_add("devices",
						     &group->dev->kobj);
	if (!group->devices_kobj)
		goto out_kobj;

	group->tainted = false;

	return group;

out_kobj:
	device_destroy(vfio.class, group->devt);
out_device:
	group->dev = NULL;
	group->devt = 0;
	idr_remove(&vfio.idr, minor);
out:
	printk(KERN_WARNING "vfio: Failed to complete setup on group %u, "
	       "marking as unusable\n", groupid);

	return group;
}

static struct vfio_iommu *vfio_create_iommu(struct vfio_group *group)
{
	struct vfio_iommu *iommu;

	iommu = kzalloc(sizeof(*iommu), GFP_KERNEL);
	if (!iommu)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&iommu->group_list);
	INIT_LIST_HEAD(&iommu->dma_list);
	mutex_init(&iommu->lock);
	iommu->bus = group->bus;

	return iommu;
}

/* All release paths simply decrement the refcnt, attempt to teardown
 * the iommu and merged groups, and wakeup anything that might be
 * waiting if we successfully dissolve anything. */
static int vfio_do_release(int *refcnt, struct vfio_iommu *iommu)
{
	bool wake;

	mutex_lock(&vfio.lock);

	(*refcnt)--;
	wake = (__vfio_try_dissolve_iommu(iommu) == 0);

	mutex_unlock(&vfio.lock);

	if (wake)
		wake_up(&vfio.release_q);

	return 0;
}

/*
 * Device fops - passthrough to vfio device driver w/ device_data
 */
static int vfio_device_release(struct inode *inode, struct file *filep)
{
	struct vfio_device *device = filep->private_data;

	vfio_do_release(&device->refcnt, device->group->iommu);

	device->ops->release(device->device_data);

	return 0;
}

static long vfio_device_unl_ioctl(struct file *filep,
				  unsigned int cmd, unsigned long arg)
{
	struct vfio_device *device = filep->private_data;

	return device->ops->ioctl(device->device_data, cmd, arg);
}

static ssize_t vfio_device_read(struct file *filep, char __user *buf,
				size_t count, loff_t *ppos)
{
	struct vfio_device *device = filep->private_data;

	return device->ops->read(device->device_data, buf, count, ppos);
}

static ssize_t vfio_device_write(struct file *filep, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	struct vfio_device *device = filep->private_data;

	return device->ops->write(device->device_data, buf, count, ppos);
}

static int vfio_device_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct vfio_device *device = filep->private_data;

	return device->ops->mmap(device->device_data, vma);
}
	
#ifdef CONFIG_COMPAT
static long vfio_device_compat_ioctl(struct file *filep,
				     unsigned int cmd, unsigned long arg)
{
	arg = (unsigned long)compat_ptr(arg);
	return vfio_device_unl_ioctl(filep, cmd, arg);
}
#endif	/* CONFIG_COMPAT */

const struct file_operations vfio_device_fops = {
	.owner		= THIS_MODULE,
	.release	= vfio_device_release,
	.read		= vfio_device_read,
	.write		= vfio_device_write,
	.unlocked_ioctl	= vfio_device_unl_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= vfio_device_compat_ioctl,
#endif
	.mmap		= vfio_device_mmap,
};

/*
 * Group fops
 */
static int vfio_group_open(struct inode *inode, struct file *filep)
{
	struct vfio_group *group;
	int ret = 0;

	mutex_lock(&vfio.lock);

	group = idr_find(&vfio.idr, iminor(inode));

	if (!group) {
		ret = -ENODEV;
		goto out;
	}

	filep->private_data = group;

	if (!group->iommu) {
		struct vfio_iommu *iommu;

		iommu = vfio_create_iommu(group);
		if (IS_ERR(iommu)) {
			ret = PTR_ERR(iommu);
			goto out;
		}
		__vfio_group_set_iommu(group, iommu);
	}
	group->refcnt++;

out:
	mutex_unlock(&vfio.lock);

	return ret;
}

static int vfio_group_release(struct inode *inode, struct file *filep)
{
	struct vfio_group *group = filep->private_data;

	return vfio_do_release(&group->refcnt, group->iommu);
}

/* Attempt to merge the group pointed to by fd into group.  The merge-ee
 * group must not have an iommu or any devices open because we cannot
 * maintain that context across the merge.  The merge-er group can be
 * in use. */
static int vfio_group_merge(struct vfio_group *group, int fd)
{
	struct vfio_group *new;
	struct vfio_iommu *old_iommu;
	struct file *file;
	int ret = 0;
	bool opened = false;

	mutex_lock(&vfio.lock);

	file = fget(fd);
	if (!file) {
		ret = -EBADF;
		goto out_noput;
	}

	/* Sanity check, is this really our fd? */
	if (file->f_op != &vfio_group_fops) {
		ret = -EINVAL;
		goto out;
	}

	new = file->private_data;

	if (!new || new == group || !new->iommu ||
	    new->iommu->domain || new->bus != group->bus) {
		ret = -EINVAL;
		goto out;
	}

	/* We need to attach all the devices to each domain separately
	 * in order to validate that the capabilities match for both.  */
	ret = __vfio_iommu_open(new->iommu);
	if (ret)
		goto out;

	if (!group->iommu->domain) {
		ret = __vfio_iommu_open(group->iommu);
		if (ret)
			goto out;
		opened = true;
	}

	/* If cache coherency doesn't match we'd potentialy need to
	 * remap existing iommu mappings in the merge-er domain.
	 * Poor return to bother trying to allow this currently. */
	if (iommu_domain_has_cap(group->iommu->domain,
				 IOMMU_CAP_CACHE_COHERENCY) !=
	    iommu_domain_has_cap(new->iommu->domain,
				 IOMMU_CAP_CACHE_COHERENCY)) {
		__vfio_iommu_close(new->iommu);
		if (opened)
			__vfio_iommu_close(group->iommu);
		ret = -EINVAL;
		goto out;
	}

	/* Close the iommu for the merge-ee and attach all its devices
	 * to the merge-er iommu. */
	__vfio_iommu_close(new->iommu);

	ret = __vfio_iommu_attach_group(group->iommu, new);
	if (ret)
		goto out;

	/* set_iommu unlinks new from the iommu, so save a pointer to it */
	old_iommu = new->iommu;
	__vfio_group_set_iommu(new, group->iommu);
	kfree(old_iommu);

out:
	fput(file);
out_noput:
	mutex_unlock(&vfio.lock);
	return ret;
}

/* Unmerge a group */
static int vfio_group_unmerge(struct vfio_group *group)
{
	struct vfio_iommu *iommu;
	int ret = 0;

	/* Since the merge-out group is already opened, it needs to
	 * have an iommu struct associated with it. */
	iommu = vfio_create_iommu(group);
	if (IS_ERR(iommu))
		return PTR_ERR(iommu);

	mutex_lock(&vfio.lock);

	if (list_is_singular(&group->iommu->group_list)) {
		ret = -EINVAL; /* Not merged group */
		goto out;
	}

	/* We can't merge-out a group with devices still in use. */
	if (__vfio_group_devs_inuse(group)) {
		ret = -EBUSY;
		goto out;
	}

	__vfio_iommu_detach_group(group->iommu, group);
	__vfio_group_set_iommu(group, iommu);

out:
	if (ret)
		kfree(iommu);
	mutex_unlock(&vfio.lock);
	return ret;
}

/* Get a new iommu file descriptor.  This will open the iommu, setting
 * the current->mm ownership if it's not already set. */
static int vfio_group_get_iommu_fd(struct vfio_group *group)
{
	int ret = 0;

	mutex_lock(&vfio.lock);

	if (!group->iommu->domain) {
		ret = __vfio_iommu_open(group->iommu);
		if (ret)
			goto out;
	}

	ret = anon_inode_getfd("[vfio-iommu]", &vfio_iommu_fops,
			       group->iommu, O_RDWR);
	if (ret < 0)
		goto out;

	group->iommu->refcnt++;
out:
	mutex_unlock(&vfio.lock);
	return ret;
}

/* Get a new device file descriptor.  This will open the iommu, setting
 * the current->mm ownership if it's not already set.  It's difficult to
 * specify the requirements for matching a user supplied buffer to a
 * device, so we use a vfio driver callback to test for a match.  For
 * PCI, dev_name(dev) is unique, but other drivers may require including
 * a parent device string. */
static int vfio_group_get_device_fd(struct vfio_group *group, char *buf)
{
	struct vfio_iommu *iommu = group->iommu;
	struct list_head *gpos;
	int ret = -ENODEV;

	mutex_lock(&vfio.lock);

	if (!iommu->domain) {
		ret = __vfio_iommu_open(iommu);
		if (ret)
			goto out;
	}

	list_for_each(gpos, &iommu->group_list) {
		struct list_head *dpos;

		group = list_entry(gpos, struct vfio_group, iommu_next);

		list_for_each(dpos, &group->device_list) {
			struct vfio_device *device;
			struct file *file;

			device = list_entry(dpos,
					    struct vfio_device, device_next);

			if (!device->ops->match(device->dev, buf))
				continue;

			ret = device->ops->open(device->device_data);
			if (ret)
				goto out;

			/* We can't use anon_inode_getfd(), like above
			 * because we need to modify the f_mode flags
			 * directly to allow more than just ioctls */
			ret = get_unused_fd();
			if (ret < 0) {
				device->ops->release(device->device_data);
				goto out;
			}

			file = anon_inode_getfile("[vfio-device]",
						  &vfio_device_fops,
						  device, O_RDWR);
			if (IS_ERR(file)) {
				put_unused_fd(ret);
				ret = PTR_ERR(file);
				device->ops->release(device->device_data);
				goto out;
			}

			/* Todo: add an anon_inode interface to do
			 * this.  Appears to be missing by lack of
			 * need rather than explicitly prevented.
			 * Now there's need. */
			file->f_mode |= (FMODE_LSEEK |
					 FMODE_PREAD |
					 FMODE_PWRITE);

			fd_install(ret, file);

			device->refcnt++;
			goto out;
		}
	}
out:
	mutex_unlock(&vfio.lock);
	return ret;
}

static long vfio_group_unl_ioctl(struct file *filep,
				 unsigned int cmd, unsigned long arg)
{
	struct vfio_group *group = filep->private_data;

	if (cmd == VFIO_GROUP_GET_INFO) {
		struct vfio_group_info info;
		unsigned long minsz;

		minsz = offsetofend(struct vfio_group_info, flags);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz)
			return -EINVAL;

		mutex_lock(&vfio.lock);
		if (__vfio_iommu_viable(group->iommu))
			info.flags |= VFIO_GROUP_FLAGS_VIABLE;
		mutex_unlock(&vfio.lock);

		if (group->iommu->mm)
			info.flags |= VFIO_GROUP_FLAGS_MM_LOCKED;

		return copy_to_user((void __user *)arg, &info, minsz);
	}
		
	/* Below commands are restricted once the mm is set */
	if (group->iommu->mm && group->iommu->mm != current->mm)
		return -EPERM;

	if (cmd == VFIO_GROUP_MERGE) {
		int fd;
		
		if (get_user(fd, (int __user *)arg))
			return -EFAULT;
		if (fd < 0)
			return -EINVAL;

		return vfio_group_merge(group, fd);

	} else if (cmd == VFIO_GROUP_UNMERGE) {

		return vfio_group_unmerge(group);

	} else if (cmd == VFIO_GROUP_GET_IOMMU_FD) {

		return vfio_group_get_iommu_fd(group);

	} else if (cmd == VFIO_GROUP_GET_DEVICE_FD) {
		char *buf;
		int ret;

		buf = strndup_user((const char __user *)arg, PAGE_SIZE);
		if (IS_ERR(buf))
			return PTR_ERR(buf);

		ret = vfio_group_get_device_fd(group, buf);
		kfree(buf);
		return ret;
	}

	return -ENOTTY;
}

#ifdef CONFIG_COMPAT
static long vfio_group_compat_ioctl(struct file *filep,
				    unsigned int cmd, unsigned long arg)
{
	arg = (unsigned long)compat_ptr(arg);
	return vfio_group_unl_ioctl(filep, cmd, arg);
}
#endif	/* CONFIG_COMPAT */

static const struct file_operations vfio_group_fops = {
	.owner		= THIS_MODULE,
	.open		= vfio_group_open,
	.release	= vfio_group_release,
	.unlocked_ioctl	= vfio_group_unl_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= vfio_group_compat_ioctl,
#endif
};

/* iommu fd release hook */
int vfio_release_iommu(struct vfio_iommu *iommu)
{
	return vfio_do_release(&iommu->refcnt, iommu);
}

/*
 * VFIO driver API
 */

/* Add a new device to the vfio framework with associated vfio driver
 * callbacks.  This is the entry point for vfio drivers to register devices. */
int vfio_group_add_dev(struct device *dev, const struct vfio_device_ops *ops)
{
	struct vfio_group *group;
	struct vfio_device *device;
	unsigned int groupid;
	int ret = 0;

	if (iommu_device_group(dev, &groupid))
		return -ENODEV;

	if (WARN_ON(!ops))
		return -EINVAL;

	mutex_lock(&vfio.lock);

	group = __vfio_dev_to_group(dev, groupid);
	if (!group)
		group = __vfio_create_group(dev, groupid); /* No fail */

	device = __vfio_group_find_device(group, dev);
	if (!device) {
		device = kzalloc(sizeof(*device), GFP_KERNEL);
		if (WARN_ON(!device)) {
			/* We created the group, but can't add this device,
			 * taint the group to prevent it being used.  If
			 * it's already in use, we have to BUG_ON.
			 * XXX - Kill the user process? */
			group->tainted = true;
			BUG_ON(group->iommu && group->iommu->domain);
			ret = -ENOMEM;
			goto out;
		}

		list_add(&device->device_next, &group->device_list);
		device->dev = dev;
		device->ops = ops;
		device->group = group;

		if (!group->devices_kobj ||
		    sysfs_create_link(group->devices_kobj,
				      &dev->kobj, dev_name(dev)))
			printk(KERN_WARNING
			       "vfio: Unable to create sysfs link to %s\n",
			       dev_name(dev));

		if (group->iommu && group->iommu->domain) {
			printk(KERN_WARNING "Adding device %s to group %s:%u "
			       "while group is already in use!!\n",
			       dev_name(dev), group->bus->name, group->groupid);

			mutex_unlock(&vfio.lock);

			ret = ops->claim(dev);

			BUG_ON(ret);

			goto out_unlocked;
		}

	}
out:
	mutex_unlock(&vfio.lock);
out_unlocked:
	return ret;
}
EXPORT_SYMBOL_GPL(vfio_group_add_dev);

/* Remove a device from the vfio framework */
void vfio_group_del_dev(struct device *dev)
{
	struct vfio_group *group;
	struct vfio_device *device;
	unsigned int groupid;

	if (iommu_device_group(dev, &groupid))
		return;

	mutex_lock(&vfio.lock);

	group = __vfio_dev_to_group(dev, groupid);

	if (WARN_ON(!group))
		goto out;

	device = __vfio_group_find_device(group, dev);

	if (WARN_ON(!device))
		goto out;

	/* If device is bound to a bus driver, we'll get a chance to
	 * unbind it first.  Just mark it to be removed after unbind. */
	if (device->device_data) {
		device->deleteme = true;
		goto out;
	}

	if (device->attached)
		__vfio_iommu_detach_dev(group->iommu, device);

	list_del(&device->device_next);

	if (group->devices_kobj)
		sysfs_remove_link(group->devices_kobj, dev_name(dev));

	kfree(device);

	/* If this was the only device in the group, remove the group.
	 * Note that we intentionally unmerge empty groups here if the
	 * group fd isn't opened. */
	if (list_empty(&group->device_list) && group->refcnt == 0) {
		struct vfio_iommu *iommu = group->iommu;

		if (iommu) {
			__vfio_group_set_iommu(group, NULL);
			__vfio_try_dissolve_iommu(iommu);
		}

		/* Groups can be mostly placeholders if setup isn't
		 * completed, remove them carefully. */
		if (group->devices_kobj)
			kobject_put(group->devices_kobj);
		if (group->dev) {
			device_destroy(vfio.class, group->devt);
			idr_remove(&vfio.idr, MINOR(group->devt));
		}
		list_del(&group->group_next);
		kfree(group);
	}

out:
	mutex_unlock(&vfio.lock);
}
EXPORT_SYMBOL_GPL(vfio_group_del_dev);

/* When a device is bound to a vfio device driver (ex. vfio-pci), this
 * entry point is used to mark the device usable (viable).  The vfio
 * device driver associates a private device_data struct with the device
 * here, which will later be return for vfio_device_fops callbacks. */
int vfio_bind_dev(struct device *dev, void *device_data)
{
	struct vfio_device *device;
	int ret;

	if (WARN_ON(!device_data))
		return -EINVAL;

	mutex_lock(&vfio.lock);

	device = __vfio_lookup_dev(dev);

	if (WARN_ON(!device)) {
		ret = -EINVAL;
		goto out;
	}

	ret = dev_set_drvdata(dev, device);
	if (!ret)
		device->device_data = device_data;

out:
	mutex_unlock(&vfio.lock);
	return ret;
}
EXPORT_SYMBOL_GPL(vfio_bind_dev);

/* A device is only removeable if the iommu for the group is not in use. */
static bool vfio_device_removeable(struct vfio_device *device)
{
	bool ret = true;

	mutex_lock(&vfio.lock);

	if (device->group->iommu && __vfio_iommu_inuse(device->group->iommu))
		ret = false;

	mutex_unlock(&vfio.lock);
	return ret;
}

/* Notify vfio that a device is being unbound from the vfio device driver
 * and return the device private device_data pointer.  If the group is
 * in use, we need to block or take other measures to make it safe for
 * the device to be removed from the iommu. */
void *vfio_unbind_dev(struct device *dev)
{
	struct vfio_device *device = dev_get_drvdata(dev);
	void *device_data;

	if (WARN_ON(!device))
		return NULL;
again:
	if (!vfio_device_removeable(device)) {
		/* XXX signal for all devices in group to be removed or
		 * resort to killing the process holding the device fds.
		 * For now just block waiting for releases to wake us. */
		wait_event(vfio.release_q, vfio_device_removeable(device));
	}

	mutex_lock(&vfio.lock);

	/* Need to re-check that the device is still removeable under lock. */
	if (device->group->iommu && __vfio_iommu_inuse(device->group->iommu)) {
		mutex_unlock(&vfio.lock);
		goto again;
	}

	device_data = device->device_data;

	device->device_data = NULL;
	dev_set_drvdata(dev, NULL);

	mutex_unlock(&vfio.lock);

	if (device->deleteme)
		vfio_group_del_dev(dev);

	return device_data;
}
EXPORT_SYMBOL_GPL(vfio_unbind_dev);

/*
 * Module/class support
 */
static void vfio_class_release(struct kref *kref)
{
	class_destroy(vfio.class);
	vfio.class = NULL;
}

static char *vfio_devnode(struct device *dev, mode_t *mode)
{
	return kasprintf(GFP_KERNEL, "vfio/%s", dev_name(dev));
}

static int __init vfio_init(void)
{
	int ret;

	idr_init(&vfio.idr);
	mutex_init(&vfio.lock);
	INIT_LIST_HEAD(&vfio.group_list);
	init_waitqueue_head(&vfio.release_q);

	kref_init(&vfio.kref);
	vfio.class = class_create(THIS_MODULE, "vfio");
	if (IS_ERR(vfio.class)) {
		ret = PTR_ERR(vfio.class);
		goto err_class;
	}

	vfio.class->devnode = vfio_devnode;

	/* FIXME - how many minors to allocate... all of them! */
	ret = alloc_chrdev_region(&vfio.devt, 0, MINORMASK, "vfio");
	if (ret)
		goto err_chrdev;

	cdev_init(&vfio.cdev, &vfio_group_fops);
	ret = cdev_add(&vfio.cdev, vfio.devt, MINORMASK);
	if (ret)
		goto err_cdev;

	pr_info(DRIVER_DESC " version: " DRIVER_VERSION "\n");

	return 0;

err_cdev:
	unregister_chrdev_region(vfio.devt, MINORMASK);
err_chrdev:
	kref_put(&vfio.kref, vfio_class_release);
err_class:
	return ret;
}

static void __exit vfio_cleanup(void)
{
	struct list_head *gpos, *gppos;

	list_for_each_safe(gpos, gppos, &vfio.group_list) {
		struct vfio_group *group;
		struct list_head *dpos, *dppos;

		group = list_entry(gpos, struct vfio_group, group_next);

		list_for_each_safe(dpos, dppos, &group->device_list) {
			struct vfio_device *device;

			device = list_entry(dpos,
					    struct vfio_device, device_next);
			vfio_group_del_dev(device->dev);
		}
	}

	idr_destroy(&vfio.idr);
	cdev_del(&vfio.cdev);
	unregister_chrdev_region(vfio.devt, MINORMASK);
	kref_put(&vfio.kref, vfio_class_release);
}

module_init(vfio_init);
module_exit(vfio_cleanup);

MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
