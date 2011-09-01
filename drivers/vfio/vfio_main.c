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

#define MAX_PATH	256

static int allow_unsafe_intrs;
module_param(allow_unsafe_intrs, int, 0);
MODULE_PARM_DESC(allow_unsafe_intrs,
        "Allow use of IOMMUs which do not support interrupt remapping");

static struct vfio vfio;
static const struct file_operations vfio_group_fops;

static inline void vfio_container_reset_read(struct vfio_container *vcontainer)
{
	kfree(vcontainer->read_buf);
	vcontainer->read_buf = NULL;
}

int vfio_group_add_dev(struct device *dev, void *data)
{
	struct vfio_device_ops *ops = data;
	struct list_head *pos;
	struct vfio_group *vgroup = NULL;
	struct vfio_device *vdev = NULL;
	unsigned int group;
	int ret = 0, new_group = 0;

	if (iommu_device_group(dev, &group))
		return 0;

	mutex_lock(&vfio.group_lock);

	list_for_each(pos, &vfio.group_list) {
		vgroup = list_entry(pos, struct vfio_group, next);
		if (vgroup->group == group)
			break;
		vgroup = NULL;
	}

	if (!vgroup) {
		int id;

		if (unlikely(idr_pre_get(&vfio.idr, GFP_KERNEL) == 0)) {
			ret = -ENOMEM;
			goto out;
		}
		vgroup = kzalloc(sizeof(*vgroup), GFP_KERNEL);
		if (!vgroup) {
			ret = -ENOMEM;
			goto out;
		}

		vgroup->group = group;
		INIT_LIST_HEAD(&vgroup->device_list);

		ret = idr_get_new(&vfio.idr, vgroup, &id);
		if (ret == 0 && id > MINORMASK) {
			idr_remove(&vfio.idr, id);
			kfree(vgroup);
			ret = -ENOSPC;
			goto out;
		}

		vgroup->devt = MKDEV(MAJOR(vfio.devt), id);
		list_add(&vgroup->next, &vfio.group_list);
		device_create(vfio.class, NULL, vgroup->devt,
			      vgroup, "%u", group);

		new_group = 1;
	} else {
		list_for_each(pos, &vgroup->device_list) {
			vdev = list_entry(pos, struct vfio_device, next);
			if (vdev->dev == dev)
				break;
			vdev = NULL;
		}
	}

	if (!vdev) {
		/* Adding a device for a group that's already in use? */
		/* Maybe we should attach to the domain so others can't */
		BUG_ON(vgroup->container &&
		       vgroup->container->iommu &&
		       vgroup->container->iommu->refcnt);

		vdev = ops->new(dev);
		if (IS_ERR(vdev)) {
			/* If we just created this vgroup, tear it down */
			if (new_group) {
				device_destroy(vfio.class, vgroup->devt);
				idr_remove(&vfio.idr, MINOR(vgroup->devt));
				list_del(&vgroup->next);
				kfree(vgroup);
			}
			ret = PTR_ERR(vdev);
			goto out;
		}
		list_add(&vdev->next, &vgroup->device_list);
		vdev->dev = dev;
		vdev->ops = ops;
		vdev->vfio = &vfio;
	}
out:
	mutex_unlock(&vfio.group_lock);
	return ret;
}

void vfio_group_del_dev(struct device *dev)
{
	struct list_head *pos;
	struct vfio_container *vcontainer;
	struct vfio_group *vgroup = NULL;
	struct vfio_device *vdev = NULL;
	unsigned int group;

	if (iommu_device_group(dev, &group))
		return;

	mutex_lock(&vfio.group_lock);

	list_for_each(pos, &vfio.group_list) {
		vgroup = list_entry(pos, struct vfio_group, next);
		if (vgroup->group == group)
			break;
		vgroup = NULL;
	}

	if (!vgroup)
		goto out;

	vcontainer = vgroup->container;

	list_for_each(pos, &vgroup->device_list) {
		vdev = list_entry(pos, struct vfio_device, next);
		if (vdev->dev == dev)
			break;
		vdev = NULL;
	}

	if (!vdev)
		goto out;

	/* XXX Did a device we're using go away? */
	BUG_ON(vdev->refcnt);

	if (vcontainer && vcontainer->iommu) {
		iommu_detach_device(vcontainer->iommu->domain, vdev->dev);
		vfio_container_reset_read(vcontainer);
	}

	list_del(&vdev->next);
	vdev->ops->free(vdev);

	if (list_empty(&vgroup->device_list) && vgroup->refcnt == 0) {
		device_destroy(vfio.class, vgroup->devt);
		idr_remove(&vfio.idr, MINOR(vgroup->devt));
		list_del(&vgroup->next);
		kfree(vgroup);
	}
out:
	mutex_unlock(&vfio.group_lock);
}

static int __vfio_group_viable(struct vfio_container *vcontainer)
{
	struct list_head *gpos, *dpos;

	list_for_each(gpos, &vfio.group_list) {
		struct vfio_group *vgroup;
		vgroup = list_entry(gpos, struct vfio_group, next);
		if (vgroup->container != vcontainer)
			continue;

		list_for_each(dpos, &vgroup->device_list) {
			struct vfio_device *vdev;
			vdev = list_entry(dpos, struct vfio_device, next);

			if (!vdev->dev->driver ||
			    vdev->dev->driver->owner != THIS_MODULE)
				return 0;
		}
	}
	return 1;
}

static int __vfio_close_iommu(struct vfio_container *vcontainer)
{
	struct list_head *gpos, *dpos;
	struct vfio_iommu *viommu = vcontainer->iommu;
	struct vfio_group *vgroup;
	struct vfio_device *vdev;

	if (!viommu)
		return 0;

	if (viommu->refcnt)
		return -EBUSY;

	list_for_each(gpos, &vfio.group_list) {
		vgroup = list_entry(gpos, struct vfio_group, next);
		if (vgroup->container != vcontainer)
			continue;

		list_for_each(dpos, &vgroup->device_list) {
			vdev = list_entry(dpos, struct vfio_device, next);
			iommu_detach_device(viommu->domain, vdev->dev);
			vdev->iommu = NULL;
		}
	}
	iommu_domain_free(viommu->domain);
	kfree(viommu);
	vcontainer->iommu = NULL;
	return 0;
}

static int __vfio_open_iommu(struct vfio_container *vcontainer)
{
	struct list_head *gpos, *dpos;
	struct vfio_iommu *viommu;
	struct vfio_group *vgroup;
	struct vfio_device *vdev;

	if (!__vfio_group_viable(vcontainer))
		return -EBUSY;

	viommu = kzalloc(sizeof(*viommu), GFP_KERNEL);
	if (!viommu)
		return -ENOMEM;

	viommu->domain = iommu_domain_alloc();
	if (!viommu->domain) {
		kfree(viommu);
		return -EFAULT;
	}

	viommu->vfio = &vfio;
	vcontainer->iommu = viommu;

	list_for_each(gpos, &vfio.group_list) {
		vgroup = list_entry(gpos, struct vfio_group, next);
		if (vgroup->container != vcontainer)
			continue;

		list_for_each(dpos, &vgroup->device_list) {
			int ret;

			vdev = list_entry(dpos, struct vfio_device, next);

			ret = iommu_attach_device(viommu->domain, vdev->dev);
			if (ret) {
				__vfio_close_iommu(vcontainer);
				return ret;
			}
			vdev->iommu = viommu;
		}
	}

	if (!allow_unsafe_intrs &&
	    !iommu_domain_has_cap(viommu->domain, IOMMU_CAP_INTR_REMAP)) {
		__vfio_close_iommu(vcontainer);
		return -EFAULT;
	}

	return 0;
}

static int vfio_group_merge(struct vfio_group *vgroup, int fd)
{
	struct vfio_group *vgroup2;
	struct iommu_domain *domain;
	struct list_head *pos;
	struct file *file;
	int ret = 0;

	mutex_lock(&vfio.group_lock);

	file = fget(fd);
	if (!file) {
		ret = -EBADF;
		goto out_noput;
	}
	if (file->f_op != &vfio_group_fops) {
		ret = -EINVAL;
		goto out;
	}

	vgroup2 = file->private_data;
	if (!vgroup2 || vgroup2 == vgroup || vgroup2->mm != vgroup->mm ||
	    (vgroup2->container->iommu && vgroup2->container->iommu->refcnt)) {
		ret = -EINVAL;
		goto out;
	}

	if (!vgroup->container->iommu) {
		ret = __vfio_open_iommu(vgroup->container);
		if (ret)
			goto out;
	}

	if (!vgroup2->container->iommu) {
		ret = __vfio_open_iommu(vgroup2->container);
		if (ret)
			goto out;
	}

	if (iommu_domain_has_cap(vgroup->container->iommu->domain,
				 IOMMU_CAP_CACHE_COHERENCY) !=
	    iommu_domain_has_cap(vgroup2->container->iommu->domain,
				 IOMMU_CAP_CACHE_COHERENCY)) {
		ret = -EINVAL;
		goto out;
	}

	ret = __vfio_close_iommu(vgroup2->container);
	if (ret)
		goto out;

	domain = vgroup->container->iommu->domain;

	list_for_each(pos, &vgroup2->device_list) {
		struct vfio_device *vdev;

		vdev = list_entry(pos, struct vfio_device, next);

		ret = iommu_attach_device(domain, vdev->dev);
		if (ret) {
			list_for_each(pos, &vgroup2->device_list) {
				struct vfio_device *vdev2;

				vdev2 = list_entry(pos,
						   struct vfio_device, next);
				if (vdev2 == vdev)
					break;

				iommu_detach_device(domain, vdev2->dev);
				vdev2->iommu = NULL;
			}
			goto out;
		}
		vdev->iommu = vgroup->container->iommu;
	}

	kfree(vgroup2->container->read_buf);
	kfree(vgroup2->container);

	vgroup2->container = vgroup->container;
	vgroup->container->refcnt++;
	vfio_container_reset_read(vgroup->container);

out:
	fput(file);
out_noput:
	mutex_unlock(&vfio.group_lock);
	return ret;
}

static int vfio_group_unmerge(struct vfio_group *vgroup, int fd)
{
	struct vfio_group *vgroup2;
	struct vfio_container *vcontainer2;
	struct vfio_device *vdev;
	struct list_head *pos;
	struct file *file;
	int ret = 0;

	vcontainer2 = kzalloc(sizeof(*vcontainer2), GFP_KERNEL);
	if (!vcontainer2)
		return -ENOMEM;

	mutex_lock(&vfio.group_lock);

	file = fget(fd);
	if (!file) {
		ret = -EBADF;
		goto out_noput;
	}
	if (file->f_op != &vfio_group_fops) {
		ret = -EINVAL;
		goto out;
	}

	vgroup2 = file->private_data;
	if (!vgroup2 || vgroup2 == vgroup ||
	    vgroup2->container != vgroup->container) {
		ret = -EINVAL;
		goto out;
	}

	list_for_each(pos, &vgroup2->device_list) {
		vdev = list_entry(pos, struct vfio_device, next);
		if (vdev->refcnt) {
			ret = -EBUSY;
			goto out;
		}
	}

	list_for_each(pos, &vgroup2->device_list) {
		vdev = list_entry(pos, struct vfio_device, next);
		iommu_detach_device(vgroup->container->iommu->domain,
				    vdev->dev);
		vdev->iommu = NULL;
	}

	vgroup2->container = vcontainer2;
	vcontainer2->refcnt++;
	vgroup->container->refcnt--;
	vfio_container_reset_read(vgroup->container);
out:
	fput(file);
out_noput:
	if (ret)
		kfree(vcontainer2);
	mutex_unlock(&vfio.group_lock);
	return ret;
}

static int vfio_group_get_iommu_fd(struct vfio_group *vgroup)
{
	int ret = 0;
	struct vfio_iommu *viommu;

	mutex_lock(&vfio.group_lock);

	if (!vgroup->container->iommu) {
		ret = __vfio_open_iommu(vgroup->container);
		if (ret)
			goto out;
	}

	viommu = vgroup->container->iommu;

	if (!viommu->file) {
		viommu->file = anon_inode_getfile("vfio-iommu",
						  &vfio_iommu_fops,
						  viommu, O_RDWR);
		if (IS_ERR(viommu->file)) {
			ret = PTR_ERR(viommu->file);
			viommu->file = NULL;
			goto out;
		}
	}
	ret = get_unused_fd();
	if (ret < 0)
		goto out;

	fd_install(ret, viommu->file);

	vgroup->container->iommu->refcnt++;
out:
	mutex_unlock(&vfio.group_lock);
	return ret;
}

static int vfio_group_get_device_fd(struct vfio_group *vgroup, char *buf)
{
	struct vfio_container *vcontainer = vgroup->container;
	struct list_head *gpos, *dpos;
	int ret = -ENODEV;

	mutex_lock(&vfio.group_lock);

	if (!vcontainer->iommu) {
		ret = __vfio_open_iommu(vcontainer);
		if (ret)
			goto out;
	}

	list_for_each(gpos, &vfio.group_list) {
		vgroup = list_entry(gpos, struct vfio_group, next);
		if (vgroup->container != vcontainer)
			continue;

		list_for_each(dpos, &vgroup->device_list) {
			struct vfio_device *vdev;
			char buf2[MAX_PATH];

			vdev = list_entry(dpos, struct vfio_device, next);

			snprintf(buf2, MAX_PATH, "%s", dev_name(vdev->dev));

			if (!strncmp(buf, buf2, MAX_PATH)) {
				if (!vdev->file) {
					vdev->file = anon_inode_getfile(
							"vfio-device",
							&vfio_device_fops,
							vdev, O_RDWR);
					if (IS_ERR(vdev->file)) {
						ret = PTR_ERR(vdev->file);
						vdev->file = NULL;
						goto out;
					}
				}
				ret = get_unused_fd();
				if (ret < 0)
					goto out;

				fd_install(ret, vdev->file);

				vdev->refcnt++;
				vcontainer->iommu->refcnt++;
				goto out;
			}
		}
	}
out:
	mutex_unlock(&vfio.group_lock);
	return ret;
}

static long vfio_group_unl_ioctl(struct file *filep,
				 unsigned int cmd, unsigned long arg)
{
	struct vfio_group *vgroup = filep->private_data;

	if (vgroup->mm != current->mm)
		return -EIO;

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
				return vfio_group_merge(vgroup, fd);
			else
				return vfio_group_unmerge(vgroup, fd);
		}
	case VFIO_GROUP_GET_IOMMU_FD:
		return vfio_group_get_iommu_fd(vgroup);
	case VFIO_GROUP_GET_DEVICE_FD:
		{
			char *buf;
			int ret;

			buf = strndup_user((const char __user *)arg, MAX_PATH);
			if (IS_ERR(buf))
				return PTR_ERR(buf);

			ret = vfio_group_get_device_fd(vgroup, buf);
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
	struct vfio_group *vgroup;
	int ret = 0;

	mutex_lock(&vfio.group_lock);

	vgroup = idr_find(&vfio.idr, iminor(inode));

	if (!vgroup) {
		ret = -ENODEV;
		goto out;
	}

	if (!vgroup->refcnt) {
		struct vfio_container *vcontainer;
		vcontainer = kzalloc(sizeof(*vcontainer), GFP_KERNEL);
		if (!vcontainer) {
			ret = -ENOMEM;
			goto out;
		}
		vgroup->container = vcontainer;
		vgroup->mm = current->mm;
	} else if (current->mm != vgroup->mm) {
		ret = -EBUSY;
		goto out;
	}
	filep->private_data = vgroup;
	vgroup->refcnt++;
	vgroup->container->refcnt++;
out:
	mutex_unlock(&vfio.group_lock);

	return ret;
}

static int vfio_group_release(struct inode *inode, struct file *filep)
{
	struct vfio_group *vgroup = filep->private_data;
	struct vfio_container *vcontainer = vgroup->container;
	struct list_head *pos;
	int ret = 0;

	mutex_lock(&vfio.group_lock);

	if (vgroup->refcnt > 1) {
		vgroup->refcnt--;
		vcontainer->refcnt--;
		goto out;
	}

	list_for_each(pos, &vgroup->device_list) {
		struct vfio_device *vdev;
		vdev = list_entry(pos, struct vfio_device, next);
		if (vdev->refcnt) {
			ret = -EBUSY;
			goto out;
		}
	}

	/* Merged group? */
	if (vcontainer->refcnt > 1) {
		if (vcontainer->iommu) {
			list_for_each(pos, &vgroup->device_list) {
				struct vfio_device *vdev;
				vdev = list_entry(pos,
						  struct vfio_device, next);
				iommu_detach_device(vcontainer->iommu->domain,
						    vdev->dev);
				vdev->iommu = NULL;
			}
		}
		vcontainer->refcnt--;
		vfio_container_reset_read(vcontainer);
	} else {
		if (vcontainer->iommu && vcontainer->iommu->refcnt) {
			ret = -EBUSY;
			goto out;
		}

		ret = __vfio_close_iommu(vcontainer);
		if (ret)
			goto out;

		kfree(vcontainer->read_buf);
		kfree(vcontainer);
	}

	vgroup->refcnt--;
	vgroup->mm = NULL;
	vgroup->container = NULL;

	/* Possible we had the group open while device members were removed */
	if (list_empty(&vgroup->device_list)) {
		device_destroy(vfio.class, vgroup->devt);
		idr_remove(&vfio.idr, MINOR(vgroup->devt));
		list_del(&vgroup->next);
		kfree(vgroup);
	}
out:
	mutex_unlock(&vfio.group_lock);
	return 0;
}

static int __vfio_container_create_read_buf(struct vfio_container *vcontainer)
{
	struct list_head *gpos, *dpos;
	struct vfio_group *vgroup;
	struct vfio_device *vdev;
	int off = 0;
	char *buf;

	buf = kzalloc(MAX_PATH, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	list_for_each(gpos, &vfio.group_list) {
		vgroup = list_entry(gpos, struct vfio_group, next);
		if (vgroup->container != vcontainer)
			continue;

		off += snprintf(buf + off, MAX_PATH,
				"group: %u\n", vgroup->group);
		buf = krealloc(buf, off + MAX_PATH, GFP_KERNEL);
		if (!buf)
			return -ENOMEM;
		memset(buf + off, 0, MAX_PATH);

		list_for_each(dpos, &vgroup->device_list) {
			vdev = list_entry(dpos, struct vfio_device, next);

			off += snprintf(buf + off, MAX_PATH,
					"device: %s\n", dev_name(vdev->dev));
			buf = krealloc(buf, off + MAX_PATH, GFP_KERNEL);
			if (!buf)
				return -ENOMEM;
			memset(buf + off, 0, MAX_PATH);
		}
	}
	buf = krealloc(buf, off + 1, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	vcontainer->read_buf = buf;
	return 0;
}

static ssize_t vfio_group_read(struct file *filep, char __user *buf,
			       size_t count, loff_t *ppos)
{
	struct vfio_group *vgroup = filep->private_data;
	struct vfio_container *vcontainer;
	ssize_t ret = 0;

	mutex_lock(&vfio.group_lock);

	vcontainer = vgroup->container;

	if (!vcontainer) {
		ret = -EINVAL;
		goto out;
	}

	if (!vcontainer->read_buf) {
		ret = __vfio_container_create_read_buf(vcontainer);
		if (ret)
			goto out;
	}

	if (*ppos >= strlen(vcontainer->read_buf) + 1) {
		ret = 0;
		goto out;
	}

	if (*ppos + count > strlen(vcontainer->read_buf) + 1)
		count = strlen(vcontainer->read_buf) + 1 - *ppos;

	if (copy_to_user(buf, vcontainer->read_buf + *ppos, count)) {
		ret = -EFAULT;
		goto out;
	}

	*ppos += count;
	ret = count;
out:
	mutex_unlock(&vfio.group_lock);
	return ret;
}

static const struct file_operations vfio_group_fops = {
	.owner		= THIS_MODULE,
	.open		= vfio_group_open,
	.release	= vfio_group_release,
	.read		= vfio_group_read,
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
	mutex_init(&vfio.group_lock);
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

	list_for_each_safe(gpos, gppos, &vfio.group_list) {
		struct vfio_group *vgroup;
		struct list_head *dpos, *dppos;

		vgroup = list_entry(gpos, struct vfio_group, next);

		list_for_each_safe(dpos, dppos, &vgroup->device_list) {
			struct vfio_device *vdev;

			vdev = list_entry(dpos, struct vfio_device, next);
			vfio_group_del_dev(vdev->dev);
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
