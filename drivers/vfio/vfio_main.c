/*
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

/*
 * VFIO main module: IOMMU group framework
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

#include "vfio_private.h"

#define DRIVER_VERSION	"0.2"
#define DRIVER_AUTHOR	"Alex Williamson <alex.williamson@redhat.com>"
#define DRIVER_DESC	"VFIO - User Level meta-driver"

static int allow_unsafe_intrs;
module_param(allow_unsafe_intrs, int, 0);
MODULE_PARM_DESC(allow_unsafe_intrs,
        "Allow use of IOMMUs which do not support interrupt remapping");

static struct vfio vfio;
static const struct file_operations vfio_group_fops;

static bool __vfio_group_devs_inuse(struct vfio_group *group)
{
	struct list_head *pos;

	list_for_each(pos, &group->device_list) {
		struct vfio_device *device;

		device = list_entry(pos, struct vfio_device, device_next);
		if (device->refcnt) {
printk("%s group %u dev %s in use\n", __FUNCTION__, group->groupid, dev_name(device->dev));
			return true;
		}
	}
printk("%s group %u unused\n", __FUNCTION__, group->groupid);
	return false;
}

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

static bool __vfio_iommu_inuse(struct vfio_iommu *iommu)
{
	struct list_head *pos;

	if (iommu->refcnt) {
printk("%s iommu %p in use refcnt %d\n", __FUNCTION__, iommu, iommu->refcnt);
		return true;
	}

	list_for_each(pos, &iommu->group_list) {
		struct vfio_group *group;

		group = list_entry(pos, struct vfio_group, iommu_next);

#if 0 // group refcnt doesn't hold the iommu together
		if (group->refcnt) {
printk("%s iommu %p group %u in use\n", __FUNCTION__, iommu, group->groupid);
			return true;
		}
#endif

		if (__vfio_group_devs_inuse(group)) {
printk("%s iommu %p group %u dev(s) in use\n", __FUNCTION__, iommu, group->groupid);
			return true;
		}
	}
printk("%s iommu %p unused\n", __FUNCTION__, iommu);
	return false;
}

static void __vfio_group_set_iommu(struct vfio_group *group,
				   struct vfio_iommu *iommu)
{
	struct list_head *pos;

printk("%s(group %u, iommu %p)\n", __FUNCTION__, group->groupid, iommu);
	if (group->iommu)
		list_del(&group->iommu_next);
	if (iommu)
		list_add(&group->iommu_next, &iommu->group_list);

	group->iommu = iommu;

	list_for_each(pos, &group->device_list) {
		struct vfio_device *device;

		device = list_entry(pos, struct vfio_device, device_next);
		device->iommu = iommu;
	}
}

static void __vfio_iommu_detach_dev(struct vfio_iommu *iommu,
				    struct vfio_device *device)
{
	BUG_ON(!iommu->domain && device->attached);

printk("%s(iommu %p, dev %s)\n", __FUNCTION__, iommu, dev_name(device->dev));
	if (!iommu->domain || !device->attached)
		return;

	iommu_detach_device(iommu->domain, device->dev);
	device->attached = false;
}

static void __vfio_iommu_detach_group(struct vfio_iommu *iommu,
				      struct vfio_group *group)
{
	struct list_head *pos;

printk("%s(iommu %p, group %u)\n", __FUNCTION__, iommu, group->groupid);
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

	BUG_ON(device->attached);

	if (!iommu || !iommu->domain)
		return -EINVAL;

	ret = iommu_attach_device(iommu->domain, device->dev);
	if (!ret)
		device->attached = true;

printk("%s(iommu %p, dev %s): %d\n", __FUNCTION__, iommu, dev_name(device->dev), ret);
	return ret;
}

static int __vfio_iommu_attach_group(struct vfio_iommu *iommu,
				     struct vfio_group *group)
{
	struct list_head *pos;

printk("%s(iommu %p, group %u)\n", __FUNCTION__, iommu, group->groupid);
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

static bool __vfio_group_viable(struct vfio_iommu *iommu)
{
	struct list_head *gpos, *dpos;

	list_for_each(gpos, &iommu->group_list) {
		struct vfio_group *group;
		group = list_entry(gpos, struct vfio_group, iommu_next);

		list_for_each(dpos, &group->device_list) {
			struct vfio_device *device;
			device = list_entry(dpos,
					    struct vfio_device, device_next);

			if (!device->dev->driver ||
			    device->dev->driver->owner != device->ops->owner) {
printk("%s(iommu %p) dev %s NOT viable\n", __FUNCTION__, iommu, dev_name(device->dev));
				return false;
			}
		}
	}
printk("%s(iommu %p) viable\n", __FUNCTION__, iommu);
	return true;
}

static void __vfio_close_iommu(struct vfio_iommu *iommu)
{
	struct list_head *pos;

	if (!iommu->domain)
		return;

printk("%s(iommu %p)\n", __FUNCTION__, iommu);
	list_for_each(pos, &iommu->group_list) {
		struct vfio_group *group;
		group = list_entry(pos, struct vfio_group, iommu_next);

		__vfio_iommu_detach_group(iommu, group);
	}
	iommu_domain_free(iommu->domain);
	iommu->domain = NULL;
	iommu->mm = NULL;
}

static int __vfio_open_iommu(struct vfio_iommu *iommu)
{
	struct list_head *pos;
	int ret;

printk("%s(iommu %p)\n", __FUNCTION__, iommu);
	if (!__vfio_group_viable(iommu))
		return -EBUSY;

	if (iommu->domain)
		return -EINVAL;

	iommu->domain = iommu_domain_alloc();
	if (!iommu->domain)
		return -EFAULT;

	list_for_each(pos, &iommu->group_list) {
		struct vfio_group *group;
		group = list_entry(pos, struct vfio_group, iommu_next);

		ret = __vfio_iommu_attach_group(iommu, group);
		if (ret) {
			__vfio_close_iommu(iommu);
			return ret;
		}
	}

	if (!allow_unsafe_intrs &&
	    !iommu_domain_has_cap(iommu->domain, IOMMU_CAP_INTR_REMAP)) {
		__vfio_close_iommu(iommu);
		return -EFAULT;
	}

	iommu->mm = current->mm;

printk("%s(iommu %p) OK\n", __FUNCTION__, iommu);
	return 0;
}

static int __vfio_try_dissolve_iommu(struct vfio_iommu *iommu)
{

printk("%s(iommu %p)\n", __FUNCTION__, iommu);
	if (__vfio_iommu_inuse(iommu))
		return -EBUSY;

	__vfio_close_iommu(iommu);

	if (!__vfio_iommu_groups_inuse(iommu)) {
		struct list_head *pos, *ppos;

printk("%s(iommu %p) removing iommu\n", __FUNCTION__, iommu);
		list_for_each_safe(pos, ppos, &iommu->group_list) {
			struct vfio_group *group;

			group = list_entry(pos, struct vfio_group, iommu_next);
			__vfio_group_set_iommu(group, NULL);
		}


		kfree(iommu);
	}

printk("%s(iommu %p) OK\n", __FUNCTION__, iommu);

	return 0;
}

int vfio_group_add_dev(struct device *dev, void *data)
{
	struct vfio_device_ops *ops = data;
	struct list_head *pos;
	struct vfio_group *group = NULL;
	struct vfio_device *device = NULL;
	unsigned int groupid;
	int ret = 0;
	bool new_group = false;

	if (!ops)
		return -EINVAL;

	if (iommu_device_group(dev, &groupid))
		return -ENODEV;

printk("Adding %s, group id %u\n", dev_name(dev), groupid);

	mutex_lock(&vfio.lock);

	list_for_each(pos, &vfio.group_list) {
		group = list_entry(pos, struct vfio_group, group_next);
		if (group->groupid == groupid)
			break;
		group = NULL;
	}


	if (!group) {
		int minor;

printk("New group!\n");
		if (unlikely(idr_pre_get(&vfio.idr, GFP_KERNEL) == 0)) {
			ret = -ENOMEM;
			goto out;
		}

		group = kzalloc(sizeof(*group), GFP_KERNEL);
		if (!group) {
			ret = -ENOMEM;
			goto out;
		}

		group->groupid = groupid;
		INIT_LIST_HEAD(&group->device_list);

		ret = idr_get_new(&vfio.idr, group, &minor);
		if (ret == 0 && minor > MINORMASK) {
			idr_remove(&vfio.idr, minor);
			kfree(group);
			ret = -ENOSPC;
			goto out;
		}

printk("Minor %d\n", minor);
		group->devt = MKDEV(MAJOR(vfio.devt), minor);
		device_create(vfio.class, NULL, group->devt,
			      group, "%u", groupid);

		list_add(&group->group_next, &vfio.group_list);
		new_group = true;
	} else {
		list_for_each(pos, &group->device_list) {
			device = list_entry(pos,
					    struct vfio_device, device_next);
			if (device->dev == dev)
				break;
			device = NULL;
		}
	}

	if (!device) {
		if (__vfio_group_devs_inuse(group) ||
		    (group->iommu && group->iommu->refcnt)) {
			printk(KERN_WARNING
			       "Adding device %s to group %u while group is already in use!!\n",
			       dev_name(dev), group->groupid);
		}

		device = ops->alloc(dev);
		if (IS_ERR(device)) {
			/* If we just created this group, tear it down */
			if (new_group) {
				list_del(&group->group_next);
				device_destroy(vfio.class, group->devt);
				idr_remove(&vfio.idr, MINOR(group->devt));
				kfree(group);
			}
			ret = PTR_ERR(device);
			goto out;
		}

		list_add(&device->device_next, &group->device_list);
		device->dev = dev;
		device->ops = ops;
		device->iommu = group->iommu;
		__vfio_iommu_attach_dev(group->iommu, device);
	}
out:
	mutex_unlock(&vfio.lock);
	return ret;
}
EXPORT_SYMBOL_GPL(vfio_group_add_dev);

void vfio_group_del_dev(struct device *dev)
{
	struct list_head *pos;
	struct vfio_group *group = NULL;
	struct vfio_device *device = NULL;
	unsigned int groupid;

	if (iommu_device_group(dev, &groupid))
		return;

printk("Removing %s, group id %u\n", dev_name(dev), groupid);

	mutex_lock(&vfio.lock);

	list_for_each(pos, &vfio.group_list) {
		group = list_entry(pos, struct vfio_group, group_next);
		if (group->groupid == groupid)
			break;
		group = NULL;
	}

	if (!group)
		goto out;

	list_for_each(pos, &group->device_list) {
		device = list_entry(pos, struct vfio_device, device_next);
		if (device->dev == dev)
			break;
		device = NULL;
	}

	if (!device)
		goto out;

	BUG_ON(device->refcnt);

	if (device->attached)
		__vfio_iommu_detach_dev(group->iommu, device);

	list_del(&device->device_next);
	device->ops->free(device);

	if (list_empty(&group->device_list) && group->refcnt == 0) {
		struct vfio_iommu *iommu = group->iommu;

		if (iommu) {
			__vfio_group_set_iommu(group, NULL);
			__vfio_try_dissolve_iommu(iommu);
		}

		device_destroy(vfio.class, group->devt);
		idr_remove(&vfio.idr, MINOR(group->devt));
		list_del(&group->group_next);
		kfree(group);
	}
out:
	mutex_unlock(&vfio.lock);
}
EXPORT_SYMBOL_GPL(vfio_group_del_dev);

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
	if (file->f_op != &vfio_group_fops) {
		ret = -EINVAL;
		goto out;
	}

	new = file->private_data;

	if (!new || new == group || !new->iommu || new->iommu->domain ||
            (group->iommu->mm && group->iommu->mm != current->mm)) {
		ret = -EINVAL;
		goto out;
	}

printk("merging group id %u & %u\n", group->groupid, new->groupid);
	/*
	 * We need to attach all the devices to each domain separately
	 * in order to validate that the capabilities match for both.
	 */
	ret = __vfio_open_iommu(new->iommu);
	if (ret)
		goto out;

	if (!group->iommu->domain) {
		ret = __vfio_open_iommu(group->iommu);
		if (ret)
			goto out;
		opened = true;
	}

	if (iommu_domain_has_cap(group->iommu->domain,
				 IOMMU_CAP_CACHE_COHERENCY) !=
	    iommu_domain_has_cap(new->iommu->domain,
				 IOMMU_CAP_CACHE_COHERENCY)) {
		__vfio_close_iommu(new->iommu);
		if (opened)
			__vfio_close_iommu(group->iommu);
		ret = -EINVAL;
		goto out;
	}

	__vfio_close_iommu(new->iommu);

	ret = __vfio_iommu_attach_group(group->iommu, new);
	if (ret)
		goto out;

	old_iommu = new->iommu;
	__vfio_group_set_iommu(new, group->iommu);
	BUG_ON(!list_empty(&old_iommu->group_list));
	kfree(old_iommu);

out:
	if (ret)
printk("Merged failed %d\n", ret);
	fput(file);
out_noput:
	mutex_unlock(&vfio.lock);
	return ret;
}

static int vfio_group_unmerge(struct vfio_group *group, int fd)
{
	struct vfio_group *new;
	struct vfio_iommu *new_iommu;
	struct file *file;
	int ret = 0;

	new_iommu = kzalloc(sizeof(*new_iommu), GFP_KERNEL);
	if (!new_iommu)
		return -ENOMEM;

	INIT_LIST_HEAD(&new_iommu->group_list);

	mutex_lock(&vfio.lock);

	file = fget(fd);
	if (!file) {
		ret = -EBADF;
		goto out_noput;
	}
	if (file->f_op != &vfio_group_fops) {
		ret = -EINVAL;
		goto out;
	}

	new = file->private_data;
	if (!new || new == group || new->iommu != group->iommu) {
		ret = -EINVAL;
		goto out;
	}

printk("unmerging group id %u & %u\n", group->groupid, new->groupid);
	if (__vfio_group_devs_inuse(new)) {
		ret = -EBUSY;
		goto out;
	}

	__vfio_iommu_detach_group(group->iommu, new);
	__vfio_group_set_iommu(new, new_iommu);

out:
	if (ret)
printk("Unmerged failed %d\n", ret);
	fput(file);
out_noput:
	if (ret)
		kfree(new_iommu);
	mutex_unlock(&vfio.lock);
	return ret;
}

static int vfio_group_get_iommu_fd(struct vfio_group *group)
{
	int ret = 0;

	mutex_lock(&vfio.lock);

printk("%s\n", __FUNCTION__);
	if (!group->iommu->domain) {
		ret = __vfio_open_iommu(group->iommu);
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

static int vfio_group_get_device_fd(struct vfio_group *group, char *buf)
{
	struct vfio_iommu *iommu = group->iommu;
	struct list_head *gpos;
	int ret = -ENODEV;

	mutex_lock(&vfio.lock);
printk("%s\n", __FUNCTION__);
	if (!iommu->domain) {
		ret = __vfio_open_iommu(iommu);
		if (ret)
			goto out;
	}

	list_for_each(gpos, &iommu->group_list) {
		struct list_head *dpos;

		group = list_entry(gpos, struct vfio_group, iommu_next);

		list_for_each(dpos, &group->device_list) {
			struct vfio_device *device;

			device = list_entry(dpos,
					  struct vfio_device, device_next);

			if (device->ops->match(device, buf)) {
				if (!device->ops->get(device)) {
					ret = -EFAULT;
					goto out;
				}

				ret = anon_inode_getfd("[vfio-device]",
						       &vfio_device_fops,
						       device, O_RDWR);
				if (ret < 0) {
					device->ops->put(device);
					goto out;
				}

				device->refcnt++;
				goto out;
			}
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

	if (group->iommu->mm && group->iommu->mm != current->mm)
		return -EPERM;

	switch (cmd) {
	case VFIO_GROUP_MERGE:
	case VFIO_GROUP_UNMERGE:
		{
			int fd;
		
			if (get_user(fd, (int __user *)arg))
				return -EFAULT;
			if (fd < 0)
				return -EINVAL;

			if (cmd == VFIO_GROUP_MERGE)
				return vfio_group_merge(group, fd);
			else
				return vfio_group_unmerge(group, fd);
		}
	case VFIO_GROUP_GET_IOMMU_FD:
		return vfio_group_get_iommu_fd(group);
	case VFIO_GROUP_GET_DEVICE_FD:
		{
			char *buf;
			int ret;

			buf = strndup_user((const char __user *)arg, PAGE_SIZE);
			if (IS_ERR(buf))
				return PTR_ERR(buf);

			ret = vfio_group_get_device_fd(group, buf);
			kfree(buf);
			return ret;
		}
	}
	return -ENOSYS;
}


#ifdef CONFIG_COMPAT
static long vfio_group_compat_ioctl(struct file *filep,
				    unsigned int cmd, unsigned long arg)
{
	arg = (unsigned long)compat_ptr(arg);
	return vfio_group_unl_ioctl(filep, cmd, arg);
}
#endif	/* CONFIG_COMPAT */

static int vfio_group_open(struct inode *inode, struct file *filep)
{
	struct vfio_group *group;
	int ret = 0;

	mutex_lock(&vfio.lock);

printk("%s\n", __FUNCTION__);
	group = idr_find(&vfio.idr, iminor(inode));

	if (!group) {
		ret = -ENODEV;
		goto out;
	}

	filep->private_data = group;

	if (!group->iommu) {
		struct vfio_iommu *iommu;

		iommu = kzalloc(sizeof(*iommu), GFP_KERNEL);
		if (!iommu) {
			ret = -ENOMEM;
			goto out;
		}
		INIT_LIST_HEAD(&iommu->group_list);
		__vfio_group_set_iommu(group, iommu);
	}
	group->refcnt++;

	mutex_unlock(&vfio.lock);

out:
	return ret;
}

static int vfio_group_release(struct inode *inode, struct file *filep)
{
	struct vfio_group *group = filep->private_data;

	mutex_lock(&vfio.lock);

printk("%s\n", __FUNCTION__);
	group->refcnt--;

	__vfio_try_dissolve_iommu(group->iommu);

	mutex_unlock(&vfio.lock);

	return 0;
}

int vfio_release_device(struct vfio_device *device)
{
	mutex_lock(&vfio.lock);

printk("%s\n", __FUNCTION__);
	device->refcnt--;
	__vfio_try_dissolve_iommu(device->iommu);

	// XXX put file?

	mutex_unlock(&vfio.lock);

	return 0;
}

int vfio_release_iommu(struct vfio_iommu *iommu)
{
	mutex_lock(&vfio.lock);

printk("%s\n", __FUNCTION__);
	iommu->refcnt--;
	__vfio_try_dissolve_iommu(iommu);

	// XXX put file?

	mutex_unlock(&vfio.lock);

	return 0;
}

static const struct file_operations vfio_group_fops = {
	.owner		= THIS_MODULE,
	.open		= vfio_group_open,
	.release	= vfio_group_release,
	.unlocked_ioctl	= vfio_group_unl_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= vfio_group_compat_ioctl,
#endif
};

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

printk("%s\n", __FUNCTION__);
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
