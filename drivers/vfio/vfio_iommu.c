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
 * VFIO iomm module: iommu fd callbacks
 */

#include <linux/compat.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/iommu.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/vfio.h>

#include "vfio_private.h"

static int vfio_iommu_release(struct inode *inode, struct file *filep)
{
	struct vfio_iommu *viommu = filep->private_data;

	mutex_lock(&viommu->vfio->group_lock);
	viommu->refcnt--;
	mutex_unlock(&viommu->vfio->group_lock);
	return 0;
}

static long vfio_iommu_unl_ioctl(struct file *filep,
				 unsigned int cmd, unsigned long arg)
{
	struct vfio_iommu *viommu = filep->private_data;
	struct vfio_dma_map dm;
	int ret = -ENOSYS;

	switch (cmd) {
	case VFIO_IOMMU_MAP_DMA:
		if (copy_from_user(&dm, (void __user *)arg, sizeof dm))
			return -EFAULT;
		ret = 0; // XXX - Do something
		if (!ret && copy_to_user((void __user *)arg, &dm, sizeof dm))
			ret = -EFAULT;
		break;

	case VFIO_IOMMU_UNMAP_DMA:
		if (copy_from_user(&dm, (void __user *)arg, sizeof dm))
			return -EFAULT;
		ret = 0; // XXX - Do something
		if (!ret && copy_to_user((void __user *)arg, &dm, sizeof dm))
			ret = -EFAULT;
		break;
	}
	return ret;
}

#ifdef CONFIG_COMPAT
static long vfio_iommu_compat_ioctl(struct file *filep,
				    unsigned int cmd, unsigned long arg)
{
	arg = (unsigned long)compat_ptr(arg);
	return vfio_iommu_unl_ioctl(filep, cmd, arg);
}
#endif	/* CONFIG_COMPAT */

const struct file_operations vfio_iommu_fops = {
	.owner		= THIS_MODULE,
	.release	= vfio_iommu_release,
	.unlocked_ioctl	= vfio_iommu_unl_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= vfio_iommu_compat_ioctl,
#endif
};
