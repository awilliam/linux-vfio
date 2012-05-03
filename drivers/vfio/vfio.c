/*
 * VFIO framework
 *
 * Copyright (C) 2012 Red Hat, Inc.  All rights reserved.
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
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h> /* XXX for pci_bus_type hack, still need to pass bus */
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/vfio.h>
#include <linux/wait.h>

#define DRIVER_VERSION	"0.2"
#define DRIVER_AUTHOR	"Alex Williamson <alex.williamson@redhat.com>"
#define DRIVER_DESC	"VFIO - User Level meta-driver"

static struct vfio {
	struct class		*class;
	struct list_head	iommu_drivers_list;
	struct mutex		iommu_drivers_lock;
	struct list_head	group_list;
	struct idr		group_idr;
	struct mutex		group_lock;
	dev_t			group_devt;
	struct cdev		group_cdev;
	struct device		*dev;
	dev_t			devt;
	struct cdev		cdev;
	wait_queue_head_t	release_q;
} vfio;

struct vfio_iommu_driver {
	struct vfio_iommu_driver_ops	*ops;
	struct list_head		vfio_next;
	struct module			*module;
};

struct vfio_container {
	struct list_head		group_list;
	struct mutex			group_lock;
	struct vfio_iommu_driver	*iommu_driver;
	void				*iommu_data;
};

struct vfio_group {
	struct kref			kref;
	dev_t				devt;
	atomic_t			inuse_devices;
	struct iommu_group		*iommu_group;
	struct vfio_container		*container;
	struct list_head		device_list;
	struct mutex			device_lock;
	struct device			*dev;
	struct notifier_block		nb;
	struct list_head		vfio_next;
	struct list_head		container_next;
};

struct vfio_device {
	struct kref			kref;
	struct device			*dev;
	const struct vfio_device_ops	*ops;
	struct vfio_group		*group;
	struct list_head		group_next;
	void				*device_data;
};

/**
 * IOMMU driver registration
 */
int vfio_register_iommu_driver(struct module *module,
			       struct vfio_iommu_driver_ops *ops)
{
	struct vfio_iommu_driver *driver, *tmp;

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	driver = kzalloc(sizeof(*driver), GFP_KERNEL);
	if (!driver) {
		module_put(THIS_MODULE);
		return -ENOMEM;
	}

	/*
	 * Save the module so we can acquire a reference to it when we
	 * make use of this driver and prevent the driver from unloading.
	 */
	driver->module = module;
	driver->ops = ops;

	mutex_lock(&vfio.iommu_drivers_lock);

	/* Check for duplicates */
	list_for_each_entry(tmp, &vfio.iommu_drivers_list, vfio_next) {
		if (tmp->module == module && tmp->ops == ops) {
			mutex_unlock(&vfio.iommu_drivers_lock);
			kfree(driver);
			module_put(THIS_MODULE);
			return -EINVAL;
		}
	}

	list_add(&driver->vfio_next, &vfio.iommu_drivers_list);

	mutex_unlock(&vfio.iommu_drivers_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(vfio_register_iommu_driver);

void vfio_unregister_iommu_driver(struct module *module,
				  struct vfio_iommu_driver_ops *ops)
{
	struct vfio_iommu_driver *driver;

	mutex_lock(&vfio.iommu_drivers_lock);
	list_for_each_entry(driver, &vfio.iommu_drivers_list, vfio_next) {
		if (driver->module == module && driver->ops == ops) {
			list_del(&driver->vfio_next);
			kfree(driver);
			break;
		}
	}
	mutex_unlock(&vfio.iommu_drivers_lock);
	module_put(THIS_MODULE);
}

/**
 * Group minor allocation - called with vfio.group_lock held
 */
static int vfio_alloc_group_minor(struct vfio_group *group)
{
	int ret, minor;

again:
	if (unlikely(idr_pre_get(&vfio.group_idr, GFP_KERNEL) == 0))
		return -ENOMEM;

	ret = idr_get_new(&vfio.group_idr, group, &minor);
	if (ret == -EAGAIN)
		goto again;
	if (ret || minor > MINORMASK) {
		if (minor > MINORMASK)
			idr_remove(&vfio.group_idr, minor);
		return -ENOSPC;
	}

	return minor;
}

static void vfio_free_group_minor(int minor)
{
	idr_remove(&vfio.group_idr, minor);
}

static int vfio_iommu_group_notifier(struct notifier_block *nb,
				     unsigned long action, void *data);
static void vfio_group_get(struct vfio_group *group);

/**
 * Group objects - create, release, get, put, search
 */

/*
 * Registering the blocking notifier acquires a rwsem.  The place we'd
 * like to do this is under the group_lock mutex, but we likely need
 * to acquire that mutex in the notifier_call, which is also surrounded
 * by the same rwsem.  To avoid the A-B, B-A lock, register the notifier
 * before lock, but use a dummy notifier_call and later replace it with
 * the proper callback.  Registering the notifier after the critical
 * section presents a usage window that can allow a group to exist without
 * a notifier.
 */
static int vfio_iommu_group_dummy_notifier(struct notifier_block *nb,
					   unsigned long action, void *data)
{
	return NOTIFY_OK;
}

static struct vfio_group *vfio_create_group(struct iommu_group *iommu_group)
{
	struct vfio_group *group, *tmp;
	struct device *dev;
	int ret, minor;

	group = kzalloc(sizeof(*group), GFP_KERNEL);
	if (!group)
		return ERR_PTR(-ENOMEM);

	kref_init(&group->kref);
	INIT_LIST_HEAD(&group->device_list);
	mutex_init(&group->device_lock);
	atomic_set(&group->inuse_devices, 0);
	group->iommu_group = iommu_group;

	group->nb.notifier_call = vfio_iommu_group_dummy_notifier;

	ret = iommu_group_register_notifier(iommu_group, &group->nb);
	if (ret) {
		kfree(group);
		return ERR_PTR(ret);
	}

	mutex_lock(&vfio.group_lock);

	minor = vfio_alloc_group_minor(group);
	if (minor < 0) {
		mutex_unlock(&vfio.group_lock);
		kfree(group);
		return ERR_PTR(minor);
	}

	group->devt = MKDEV(MAJOR(vfio.devt), minor);

	/* Did we race creating this group? */
	list_for_each_entry(tmp, &vfio.group_list, vfio_next) {
		if (tmp->iommu_group == iommu_group) {
			vfio_group_get(tmp);
			vfio_free_group_minor(minor);
			mutex_unlock(&vfio.group_lock);
			kfree(group);
			return tmp;
		}
	}

	dev = device_create(vfio.class, NULL, group->devt,
			    group, "%d", iommu_group_id(iommu_group));
	if (IS_ERR(dev)) {
		vfio_free_group_minor(minor);
		mutex_unlock(&vfio.group_lock);
		kfree(group);
		return (struct vfio_group *)dev; /* ERR_PTR */
	}

	group->dev = dev;

	list_add(&group->vfio_next, &vfio.group_list);

	group->nb.notifier_call = vfio_iommu_group_notifier;

	mutex_unlock(&vfio.group_lock);

	return group;
}

static void vfio_group_release(struct kref *kref)
{
	struct vfio_group *group = container_of(kref, struct vfio_group, kref);

	WARN_ON(!list_empty(&group->device_list));
	WARN_ON(group->container);

	group->nb.notifier_call = vfio_iommu_group_dummy_notifier;

	device_destroy(vfio.class, group->devt);
	list_del(&group->vfio_next);
	vfio_free_group_minor(MINOR(group->devt));

	mutex_unlock(&vfio.group_lock);

	iommu_group_unregister_notifier(group->iommu_group, &group->nb);

	kfree(group);

	wake_up(&vfio.release_q);
}

static void vfio_group_put(struct vfio_group *group)
{
	mutex_lock(&vfio.group_lock);
	if (!kref_put(&group->kref, vfio_group_release))
		mutex_unlock(&vfio.group_lock);
}

/* Assume group_lock or group reference is held */
static void vfio_group_get(struct vfio_group *group)
{
	kref_get(&group->kref);
}

/*
 * Not really a try as we will sleep for mutex, but we need to make
 * sure the group pointer is valid under lock and get a reference.
 */
static struct vfio_group *vfio_group_try_get(struct vfio_group *group)
{
	struct vfio_group *target = group;

	mutex_lock(&vfio.group_lock);
	list_for_each_entry(group, &vfio.group_list, vfio_next) {
		if (group == target) {
			vfio_group_get(group);
			mutex_unlock(&vfio.group_lock);
			return group;
		}
	}
	mutex_unlock(&vfio.group_lock);

	return NULL;
}

static
struct vfio_group *vfio_group_get_from_iommu(struct iommu_group *iommu_group)
{
	struct vfio_group *group;

	mutex_lock(&vfio.group_lock);
	list_for_each_entry(group, &vfio.group_list, vfio_next) {
		if (group->iommu_group == iommu_group) {
			vfio_group_get(group);
			mutex_unlock(&vfio.group_lock);
			return group;
		}
	}
	mutex_unlock(&vfio.group_lock);

	return NULL;
}

static struct vfio_group *vfio_group_get_from_minor(int minor)
{
	struct vfio_group *group;

	mutex_lock(&vfio.group_lock);
	group = idr_find(&vfio.group_idr, minor);
	if (!group) {
		mutex_unlock(&vfio.group_lock);
		return NULL;
	}
	vfio_group_get(group);
	mutex_unlock(&vfio.group_lock);
	
	return group;
}

/**
 * Device objects - create, release, get, put, search
 */
static
struct vfio_device *vfio_group_create_device(struct vfio_group *group,
					     struct device *dev,
					     const struct vfio_device_ops *ops,
					     void *device_data)
{
	struct vfio_device *device;
	int ret;

	device = kzalloc(sizeof(*device), GFP_KERNEL);
	if (!device)
		return ERR_PTR(-ENOMEM);

	kref_init(&device->kref);
	device->dev = dev;
	device->group = group;
	device->ops = ops;
	device->device_data = device_data;

	ret = dev_set_drvdata(dev, device);
	if (ret) {
		kfree(device);
		return ERR_PTR(ret);
	}

	/* No need to get group_lock, caller has group reference */
	vfio_group_get(group);

	mutex_lock(&group->device_lock);
	list_add(&device->group_next, &group->device_list);
	mutex_unlock(&group->device_lock);

	return device;
}

static void vfio_device_release(struct kref *kref)
{
	struct vfio_device *device = container_of(kref,
						  struct vfio_device, kref);
	struct vfio_group *group = device->group;

	mutex_lock(&group->device_lock);
	list_del(&device->group_next);
	mutex_unlock(&group->device_lock);

	dev_set_drvdata(device->dev, NULL);

	kfree(device);

	wake_up(&vfio.release_q);
}

static void vfio_device_put(struct vfio_device *device)
{
	kref_put(&device->kref, vfio_device_release);
	vfio_group_put(device->group);
}

static void vfio_device_get(struct vfio_device *device)
{
	vfio_group_get(device->group);
	kref_get(&device->kref);
}

static struct vfio_device *vfio_group_get_device(struct vfio_group *group,
						 struct device *dev)
{
	struct vfio_device *device;

	mutex_lock(&group->device_lock);
	list_for_each_entry(device, &group->device_list, group_next) {
		if (device->dev == dev) {
			vfio_device_get(device);
			mutex_unlock(&group->device_lock);
			return device;
		}
	}
	mutex_unlock(&group->device_lock);
	return NULL;
}

/**
 * Async device support
 */
static int vfio_group_nb_add_dev(struct vfio_group *group, struct device *dev)
{
	struct vfio_device *device;

	/* Do we already know about it?  We shouldn't */
	device = vfio_group_get_device(group, dev);
	if (WARN_ON_ONCE(device)) {
		vfio_device_put(device);
		return 0;
	}

	/* Nothing to do for idle groups */
	if (!group->container || !group->container->iommu_driver)
		return 0;

	/* TODO Prevent device auto probing */
	WARN("Device %s added to live group %d!\n", dev_name(dev),
	     iommu_group_id(group->iommu_group));

	return 0;
}

static int vfio_group_nb_del_dev(struct vfio_group *group, struct device *dev)
{
	struct vfio_device *device;

	/*
	 * Expect to fall out here.  If a device was in use, it would
	 * have been bound to a vfio sub-driver, which would have blocked
	 * in .remove at vfio_del_group_dev.  Sanity check that we no
	 * longer track the device, so it's safe to remove.
	 */
	device = vfio_group_get_device(group, dev);
	if (likely(!device))
		return 0;

	WARN("Device %s removed from live group %d!\n", dev_name(dev),
	     iommu_group_id(group->iommu_group));

	vfio_device_put(device);
	return 0;
}

static int vfio_group_nb_verify(struct vfio_group *group, struct device *dev)
{
	struct vfio_device *device;

	/* We don't care what happens when the group isn't in use */
	if (!group->container || !group->container->iommu_driver)
		return 0;

	device = vfio_group_get_device(group, dev);
	if (device)
		vfio_device_put(device);

	return device ? 0 : -EINVAL;
}

static int vfio_iommu_group_notifier(struct notifier_block *nb,
				     unsigned long action, void *data)
{
	struct vfio_group *group = container_of(nb, struct vfio_group, nb);
	struct device *dev = data;

	/*
	 * Need to go through a group_lock lookup to get a reference or
	 * we risk racing a group being removed.  Leave a WARN_ON for
	 * debuging, but if the group no longer exists, a spurious notify
	 * is harmless.
	 */
	group = vfio_group_try_get(group);
	if (WARN_ON(!group))
		return NOTIFY_OK;

	switch (action) {
	case IOMMU_GROUP_NOTIFY_ADD_DEVICE:
		vfio_group_nb_add_dev(group, dev);
		break;
	case IOMMU_GROUP_NOTIFY_DEL_DEVICE:
		vfio_group_nb_del_dev(group, dev);
		break;
	case IOMMU_GROUP_NOTIFY_BIND_DRIVER:
		printk(KERN_INFO "%s: "
		      "Device %s, group %d binding to driver\n", __func__,
		      dev_name(dev), iommu_group_id(group->iommu_group));
		break;
	case IOMMU_GROUP_NOTIFY_BOUND_DRIVER:
		printk(KERN_INFO "%s: "
		       "Device %s, group %d bound to driver %s\n", __func__,
		       dev_name(dev), iommu_group_id(group->iommu_group),
		       dev->driver->name);
		BUG_ON(vfio_group_nb_verify(group, dev));
		break;
	case IOMMU_GROUP_NOTIFY_UNBIND_DRIVER:
		printk(KERN_INFO "%s: "
		       "Device %s, group %d unbinding from driver %s\n",
		       __func__, dev_name(dev),
		       iommu_group_id(group->iommu_group), dev->driver->name);
		break;
	case IOMMU_GROUP_NOTIFY_UNBOUND_DRIVER:
		printk(KERN_INFO "%s: "
		       "Device %s, group %d unbound from driver\n", __func__,
		       dev_name(dev), iommu_group_id(group->iommu_group));
		/* XXX lock/disable probe */
		break;
	}

	vfio_group_put(group);
	return NOTIFY_OK;
}

/**
 * VFIO driver API
 */
int vfio_add_group_dev(struct device *dev,
		       const struct vfio_device_ops *ops, void *device_data)
{
	struct iommu_group *iommu_group;
	struct vfio_group *group;
	struct vfio_device *device;

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	iommu_group = iommu_group_get(dev);
	if (!iommu_group) {
		module_put(THIS_MODULE);
		return -EINVAL;
	}

	group = vfio_group_get_from_iommu(iommu_group);
	if (!group) {
		group = vfio_create_group(iommu_group);
		if (IS_ERR(group)) {
			iommu_group_put(iommu_group);
			module_put(THIS_MODULE);
			return PTR_ERR(group);
		}
	}

	if ((device = vfio_group_get_device(group, dev))) {
		WARN(1, "Device %s already exists on group %d\n",
		     dev_name(dev), iommu_group_id(iommu_group));
		vfio_device_put(device);
		vfio_group_put(group);
		iommu_group_put(iommu_group);
		module_put(THIS_MODULE);
		return -EBUSY;
	}

	device = vfio_group_create_device(group, dev, ops, device_data);
	if (IS_ERR(device)) {
		vfio_group_put(group);
		iommu_group_put(iommu_group);
		module_put(THIS_MODULE);
		return PTR_ERR(device);
	}

	/*
	 * Added device holds reference to iommu_group and vfio_device
	 * (which in turn holds reference to vfio_group).  Drop extra
	 * group reference used while acquiring device.
	 */
	vfio_group_put(group);

	return 0;
}
EXPORT_SYMBOL_GPL(vfio_add_group_dev);

/* Test whether a struct device is present in our tracking */
static bool vfio_dev_present(struct device *dev)
{
	struct iommu_group *iommu_group;
	struct vfio_group *group;
	struct vfio_device *device;

	iommu_group = iommu_group_get(dev);
	if (!iommu_group)
		return false;

	group = vfio_group_get_from_iommu(iommu_group);
	if (!group) {
		iommu_group_put(iommu_group);
		return false;
	}

	device = vfio_group_get_device(group, dev);
	if (!device) {
		vfio_group_put(group);
		iommu_group_put(iommu_group);
		return false;
	}

	vfio_device_put(device);
	vfio_group_put(group);
	iommu_group_put(iommu_group);
	return true;
}

/*
 * Decrement the device reference count and wait for the device to be
 * removed.  Open file descriptors for the device... */
void *vfio_del_group_dev(struct device *dev)
{
	struct vfio_device *device = dev_get_drvdata(dev);
	struct vfio_group *group = device->group;
	struct iommu_group *iommu_group = group->iommu_group;
	void *device_data = device->device_data;

	vfio_device_put(device);

	/* TODO send a signal to encourage this to be released */
	wait_event(vfio.release_q, vfio_dev_present(dev));

	iommu_group_put(iommu_group);
	module_put(THIS_MODULE);

	return device_data;
}
EXPORT_SYMBOL_GPL(vfio_del_group_dev);

/**
 * VFIO base fd, /dev/vfio/vfio
 */
static long vfio_ioctl_check_extension(struct vfio_container *container,
				       unsigned long arg)
{
	struct vfio_iommu_driver *driver = container->iommu_driver;
	long ret = 0;

	switch (arg) {
		/* No base extensions yet */
	default:
		/*
		 * If no driver is set, poll all registered drivers for
		 * extensions and return the first positive result.  If
		 * a driver is already set, further queries will be passed
		 * only to that driver.
		 */
		if (!driver) {
			mutex_lock(&vfio.iommu_drivers_lock);
			list_for_each_entry(driver, &vfio.iommu_drivers_list,
					    vfio_next) {
				if (!try_module_get(driver->module))
					continue;

				ret = driver->ops->ioctl(NULL,
							 VFIO_CHECK_EXTENSION,
							 arg);
				module_put(driver->module);
				if (ret > 0)
					break;
			}
			mutex_unlock(&vfio.iommu_drivers_lock);
		} else
			ret = driver->ops->ioctl(container->iommu_data,
						 VFIO_CHECK_EXTENSION, arg);
	}

	return ret;
}

/* hold container->group_lock */
static int __vfio_container_attach_groups(struct vfio_container *container,
					  struct vfio_iommu_driver *driver,
					  void *data)
{
	struct vfio_group *group;
	int ret = -ENODEV;

	list_for_each_entry(group, &container->group_list, container_next) {
		ret = driver->ops->attach_group(data, group->iommu_group);
		if (ret)
			goto unwind;
	}

	return ret;

unwind:
	list_for_each_entry_continue_reverse(group, &container->group_list,
					     container_next) {
		driver->ops->detach_group(data, group->iommu_group);
	}

	return ret;
}

static long vfio_ioctl_set_iommu(struct vfio_container *container,
				 unsigned long arg)
{
	struct vfio_iommu_driver *driver;
	long ret = -ENODEV;

	mutex_lock(&container->group_lock);

	if (list_empty(&container->group_list) || container->iommu_driver) {
		mutex_unlock(&container->group_lock);
		return -EINVAL;
	}

	mutex_lock(&vfio.iommu_drivers_lock);
	list_for_each_entry(driver, &vfio.iommu_drivers_list, vfio_next) {
		if (!try_module_get(driver->module))
			continue;

		/*
		 * The arg magic for SET_IOMMU is the same as CHECK_EXTENSION,
		 * so test which iommu driver reported support for this
		 * extension and call open on them.  We also pass them the
		 * magic, allowing a single driver to support multiple
		 * interfaces if they'd like.
		 */
		if (driver->ops->ioctl(NULL, VFIO_CHECK_EXTENSION, arg) > 0) {
			void *data;

			mutex_unlock(&vfio.iommu_drivers_lock);

			data = driver->ops->open(arg);

			ret = __vfio_container_attach_groups(container,
							     driver, data);
			if (!ret) {
				container->iommu_driver = driver;
				container->iommu_data = data;
			} else
				driver->ops->release(data);

			goto found;
		}
		module_put(driver->module);
	}

	mutex_unlock(&vfio.iommu_drivers_lock);
found:
	mutex_unlock(&container->group_lock);

	return ret;
}

static long vfio_fops_unl_ioctl(struct file *filep,
				unsigned int cmd, unsigned long arg)
{
	struct vfio_container *container = filep->private_data;
	struct vfio_iommu_driver *driver;
	void *data;
	long ret = -EINVAL;

	if (!container)
		return ret;

	driver = container->iommu_driver;
	data = container->iommu_data;

	switch (cmd) {
	case VFIO_GET_API_VERSION:
		ret = VFIO_API_VERSION;
		break;
	case VFIO_CHECK_EXTENSION:
		ret = vfio_ioctl_check_extension(container, arg);
		break;
	case VFIO_SET_IOMMU:
		ret = vfio_ioctl_set_iommu(container, arg);
		break;
	default:
		if (driver)
			ret = driver->ops->ioctl(data, cmd, arg);
	}

	return ret;
}

#ifdef CONFIG_COMPAT
static long vfio_fops_compat_ioctl(struct file *filep,
				   unsigned int cmd, unsigned long arg)
{
	arg = (unsigned long)compat_ptr(arg);
	return vfio_fops_unl_ioctl(filep, cmd, arg);
}
#endif	/* CONFIG_COMPAT */

static int vfio_fops_open(struct inode *inode, struct file *filep)
{
	struct vfio_container *container;

	container = kzalloc(sizeof(*container), GFP_KERNEL);
	if (!container)
		return -ENOMEM;

	INIT_LIST_HEAD(&container->group_list);
	mutex_init(&container->group_lock);

	filep->private_data = container;

	return 0;
}

static bool vfio_container_empty(struct vfio_container *container)
{
	bool empty;

	mutex_lock(&container->group_lock);
	empty = list_empty(&container->group_list);
	mutex_unlock(&container->group_lock);

	return empty;
}

static int vfio_fops_release(struct inode *inode, struct file *filep)
{
	struct vfio_container *container = filep->private_data;

	filep->private_data = NULL;

	wait_event(vfio.release_q, vfio_container_empty(container));

	kfree(container);

	return 0;
}

/*
 * Once an iommu driver is set, we optionally pass read/write/mmap
 * on to the driver, allowing management interfaces beyond ioctl.
 */
static ssize_t vfio_fops_read(struct file *filep, char __user *buf,
			      size_t count, loff_t *ppos)
{
	struct vfio_container *container = filep->private_data;
	struct vfio_iommu_driver *driver = container->iommu_driver;

	if (!driver || !driver->ops->read)
		return -EINVAL;

	return driver->ops->read(container->iommu_data, buf, count, ppos);
}

static ssize_t vfio_fops_write(struct file *filep, const char __user *buf,
			       size_t count, loff_t *ppos)
{
	struct vfio_container *container = filep->private_data;
	struct vfio_iommu_driver *driver = container->iommu_driver;

	if (!driver || !driver->ops->write)
		return -EINVAL;

	return driver->ops->write(container->iommu_data, buf, count, ppos);
}

static int vfio_fops_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct vfio_container *container = filep->private_data;
	struct vfio_iommu_driver *driver = container->iommu_driver;

	if (!driver || !driver->ops->mmap)
		return -EINVAL;

	return driver->ops->mmap(container->iommu_data, vma);
}

static const struct file_operations vfio_fops = {
	.owner		= THIS_MODULE,
	.open		= vfio_fops_open,
	.release	= vfio_fops_release,
	.read		= vfio_fops_read,
	.write		= vfio_fops_write,
	.unlocked_ioctl	= vfio_fops_unl_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= vfio_fops_compat_ioctl,
#endif
	.mmap		= vfio_fops_mmap,
};

/**
 * VFIO Group fd, /dev/vfio/$GROUP
 */
static int vfio_group_unset_container(struct vfio_group *group)
{
	struct vfio_container *container;
	struct vfio_iommu_driver *driver;
	struct vfio_iommu_data *data;

	container = group->container;
	if (!container)
		return -EINVAL;

	if (atomic_read(&group->inuse_devices))
		return -EBUSY;

	mutex_lock(&container->group_lock);

	driver = container->iommu_driver;
	data = container->iommu_data;

	if (driver)
		driver->ops->detach_group(data, group->iommu_group);

	list_del(&group->container_next);

	/* Detaching the last group deprivileges a container, remove iommu */
	if (driver && list_empty(&container->group_list)) {
		driver->ops->release(container->iommu_data);
		module_put(driver->module);
		container->iommu_driver = NULL;
		container->iommu_data = NULL;
	}

	mutex_unlock(&container->group_lock);

	wake_up(&vfio.release_q);

	return 0;
}

static int vfio_group_set_container(struct vfio_group *group, int container_fd)
{
	struct file *filep;
	struct vfio_container *container;
	struct vfio_iommu_driver *driver;
	struct vfio_iommu_data *data;
	int ret = 0;

	filep = fget(container_fd);
	if (!filep)
		return -EBADF;

	/* Sanity check, is this really our fd? */
	if (filep->f_op != &vfio_fops) {
		fput(filep);
		return -EINVAL;
	}

	container = filep->private_data;
	WARN_ON(!container); /* fget ensures we don't race vfio_release */

	mutex_lock(&container->group_lock);

	driver = container->iommu_driver;
	data = container->iommu_data;

	if (driver) {
		ret = driver->ops->attach_group(data, group->iommu_group);
		if (ret)
			goto unlock_out;
	}

	list_add(&group->container_next, &container->group_list);

unlock_out:
	mutex_unlock(&container->group_lock);
	fput(filep);

	return ret;
}

static int vfio_dev_viable(struct device *dev, void *data)
{
	struct vfio_group *group = data;
	struct vfio_device *device;

	if (!dev->driver)
		return 0;

	device = vfio_group_get_device(group, dev);
	vfio_device_put(device);

	if (!device)
		return -EINVAL;

	return 0;
}

static bool vfio_group_viable(struct vfio_group *group)
{

	return (iommu_group_for_each_dev(group->iommu_group, group,
					 vfio_dev_viable) == 0);
}

static const struct file_operations vfio_device_fops;

static int vfio_group_get_device_fd(struct vfio_group *group, char *buf)
{
	struct vfio_device *device;
	struct file *filep;
	int ret = -ENODEV;

	if (!(group->container || group->container->iommu_driver))
		return -EINVAL;

	mutex_lock(&group->device_lock);
	list_for_each_entry(device, &group->device_list, group_next) {
		if (strcmp(dev_name(device->dev), buf))
			continue;

		ret = device->ops->open(device->device_data);
		if (ret)
			break;
		/*
		 * We can't use anon_inode_getfd(), like above
		 * because we need to modify the f_mode flags
		 * directly to allow more than just ioctls
		 */
		ret = get_unused_fd();
		if (ret < 0) {
			device->ops->release(device->device_data);
			break;
		}

		filep = anon_inode_getfile("[vfio-device]", &vfio_device_fops,
					   device, O_RDWR);
		if (IS_ERR(filep)) {
			put_unused_fd(ret);
			ret = PTR_ERR(filep);
			device->ops->release(device->device_data);
			break;
		}

		/*
		 * TODO: add an anon_inode interface to do this.
		 * Appears to be missing by lack of need rather than
		 * explicitly prevented.  Now there's need.
		 */
		filep->f_mode |= (FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);

		fd_install(ret, filep);

		atomic_inc(&group->inuse_devices);
		break;
	}
	mutex_unlock(&group->device_lock);

	return ret;
}

static long vfio_group_fops_unl_ioctl(struct file *filep,
				      unsigned int cmd, unsigned long arg)
{
	struct vfio_group *group = filep->private_data;
	long ret = -ENOTTY;

	switch (cmd) {
	case VFIO_GROUP_GET_STATUS:
	{
		struct vfio_group_status status;
		unsigned long minsz;

		minsz = offsetofend(struct vfio_group_status, flags);

		if (copy_from_user(&status, (void __user *)arg, minsz))
			return -EFAULT;

		if (status.argsz < minsz)
			return -EINVAL;

		status.flags = 0;

		if (vfio_group_viable(group))
			status.flags |= VFIO_GROUP_FLAGS_VIABLE;

		if (group->container)
			status.flags |= VFIO_GROUP_FLAGS_CONTAINER_SET;

		ret = copy_to_user((void __user *)arg, &status, minsz);

		break;
	}
	case VFIO_GROUP_SET_CONTAINER:
	{
		int fd;

		if (get_user(fd, (int __user *)arg))
			return -EFAULT;

		if (fd < 0)
			return -EINVAL;

		ret = vfio_group_set_container(group, fd);
		break;
	}
	case VFIO_GROUP_UNSET_CONTAINER:
		ret = vfio_group_unset_container(group);
		break;
	case VFIO_GROUP_GET_DEVICE_FD:
	{
		char *buf;

		buf = strndup_user((const char __user *)arg, PAGE_SIZE);
		if (IS_ERR(buf))
			return PTR_ERR(buf);

		ret = vfio_group_get_device_fd(group, buf);
		kfree(buf);
		break;
	}
	}

	return ret;
}

#ifdef CONFIG_COMPAT
static long vfio_group_fops_compat_ioctl(struct file *filep,
					 unsigned int cmd, unsigned long arg)
{
	arg = (unsigned long)compat_ptr(arg);
	return vfio_group_fops_unl_ioctl(filep, cmd, arg);
}
#endif	/* CONFIG_COMPAT */

static int vfio_group_fops_open(struct inode *inode, struct file *filep)
{
	struct vfio_group *group;

	group = vfio_group_get_from_minor(iminor(inode));
	if (!group)
		return -ENODEV;

	filep->private_data = group;

	return 0;
}

static int vfio_group_fops_release(struct inode *inode, struct file *filep)
{
	struct vfio_group *group = filep->private_data;

	wait_event(vfio.release_q, vfio_group_unset_container(group) != -EBUSY);

	filep->private_data = NULL;

	vfio_group_put(group);

	return 0;
}

static const struct file_operations vfio_group_fops = {
        .owner          = THIS_MODULE,
        .unlocked_ioctl = vfio_group_fops_unl_ioctl,
#ifdef CONFIG_COMPAT
        .compat_ioctl   = vfio_group_fops_compat_ioctl,
#endif
        .open           = vfio_group_fops_open,
        .release        = vfio_group_fops_release,
};      

/**
 * VFIO Device fd
 */
static int vfio_device_fops_release(struct inode *inode, struct file *filep)
{
	struct vfio_device *device = filep->private_data;

	device->ops->release(device->device_data);

	atomic_dec(&device->group->inuse_devices);

	wake_up(&vfio.release_q);

	return 0;
}

static long vfio_device_fops_unl_ioctl(struct file *filep,
				       unsigned int cmd, unsigned long arg)
{
	struct vfio_device *device = filep->private_data;

	return device->ops->ioctl(device->device_data, cmd, arg);
}

static ssize_t vfio_device_fops_read(struct file *filep, char __user *buf,
				     size_t count, loff_t *ppos)
{
	struct vfio_device *device = filep->private_data;

	return device->ops->read(device->device_data, buf, count, ppos);
}

static ssize_t vfio_device_fops_write(struct file *filep,
				      const char __user *buf,
				      size_t count, loff_t *ppos)
{
	struct vfio_device *device = filep->private_data;

	return device->ops->write(device->device_data, buf, count, ppos);
}

static int vfio_device_fops_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct vfio_device *device = filep->private_data;

	return device->ops->mmap(device->device_data, vma);
}

#ifdef CONFIG_COMPAT
static long vfio_device_fops_compat_ioctl(struct file *filep,
					  unsigned int cmd, unsigned long arg)
{
	arg = (unsigned long)compat_ptr(arg);
	return vfio_device_fops_unl_ioctl(filep, cmd, arg);
}
#endif	/* CONFIG_COMPAT */

static const struct file_operations vfio_device_fops = {
	.owner		= THIS_MODULE,
	.release	= vfio_device_fops_release,
	.read		= vfio_device_fops_read,
	.write		= vfio_device_fops_write,
	.unlocked_ioctl	= vfio_device_fops_unl_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= vfio_device_fops_compat_ioctl,
#endif
	.mmap		= vfio_device_fops_mmap,
};

/**
 * Module/class support
 */
static char *vfio_devnode(struct device *dev, umode_t *mode)
{
	return kasprintf(GFP_KERNEL, "vfio/%s", dev_name(dev));
}

static int __init vfio_init(void)
{
	int ret;

	idr_init(&vfio.group_idr);
	mutex_init(&vfio.group_lock);
	mutex_init(&vfio.iommu_drivers_lock);
	INIT_LIST_HEAD(&vfio.group_list);
	INIT_LIST_HEAD(&vfio.iommu_drivers_list);
	init_waitqueue_head(&vfio.release_q);

	vfio.class = class_create(THIS_MODULE, "vfio");
	if (IS_ERR(vfio.class)) {
		ret = PTR_ERR(vfio.class);
		goto err_class;
	}

	vfio.class->devnode = vfio_devnode;

	/* /dev/vfio/vfio */
	ret = alloc_chrdev_region(&vfio.devt, 0, 1, "vfio");
	if (ret)
		goto err_base_chrdev;

	cdev_init(&vfio.cdev, &vfio_fops);
	ret = cdev_add(&vfio.cdev, vfio.devt, 1);
	if (ret)
		goto err_base_cdev;

	vfio.dev = device_create(vfio.class, NULL, vfio.devt, NULL, "vfio");
	if (IS_ERR(vfio.dev)) {
		ret = PTR_ERR(vfio.dev);
		goto err_base_dev;
	}

	/* /dev/vfio/$GROUP */
	ret = alloc_chrdev_region(&vfio.group_devt, 0, MINORMASK,
				  "vfio-groups");
	if (ret)
		goto err_groups_chrdev;

	cdev_init(&vfio.group_cdev, &vfio_group_fops);
	ret = cdev_add(&vfio.group_cdev, vfio.group_devt, MINORMASK);
	if (ret)
		goto err_groups_cdev;

	pr_info(DRIVER_DESC " version: " DRIVER_VERSION "\n");

	return 0;

err_groups_cdev:
	unregister_chrdev_region(vfio.group_devt, MINORMASK);
err_groups_chrdev:
	device_destroy(vfio.class, vfio.group_devt);
err_base_dev:
	cdev_del(&vfio.cdev);
err_base_cdev:
	unregister_chrdev_region(vfio.devt, 1);
err_base_chrdev:
	class_destroy(vfio.class);
	vfio.class = NULL;
err_class:
	return ret;
}

static void __exit vfio_cleanup(void)
{
	WARN_ON(!list_empty(&vfio.group_list));

	idr_destroy(&vfio.group_idr);
	cdev_del(&vfio.group_cdev);
	unregister_chrdev_region(vfio.group_devt, MINORMASK);
	device_destroy(vfio.class, vfio.devt);
	cdev_del(&vfio.cdev);
	unregister_chrdev_region(vfio.devt, 1);
	class_destroy(vfio.class);
	vfio.class = NULL;
}

module_init(vfio_init);
module_exit(vfio_cleanup);

MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
