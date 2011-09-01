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

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/iommu.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mutex.h>

#ifndef VFIO_PRIVATE_H
#define VFIO_PRIVATE_H

extern const struct file_operations vfio_iommu_fops;
extern const struct file_operations vfio_device_fops;

struct vfio {
	dev_t			devt;
	struct cdev		cdev;
	struct list_head	group_list;
	struct mutex		group_lock;
	struct kref		kref;
	struct class		*class;
	struct idr		idr;
};

struct vfio_device_ops {
	struct vfio_device	*(* new)(struct device *);
	void			(* free)(struct vfio_device *);
	struct file_operations	fops;
};

struct vfio_iommu {
	struct iommu_domain	*domain;
	struct vfio		*vfio;
	int			refcnt;
	struct file		*file;
};

struct vfio_device {
	struct device		*dev;
	struct list_head	next;
	struct file		*file;
	struct vfio_device_ops	*ops;
	struct vfio		*vfio;
	struct vfio_iommu	*iommu;
	int			refcnt;
};

struct vfio_container {
	struct vfio_iommu	*iommu;
	char			*read_buf;
	int			refcnt;
};

struct vfio_group {
	dev_t			devt;
	unsigned int		group;
	int			refcnt;
	struct mm_struct	*mm;
	struct vfio_container	*container;
	struct list_head	device_list;
	struct list_head	next;
};

extern int vfio_group_add_dev(struct device *dev, void *data);
extern void vfio_group_del_dev(struct device *dev);

#ifdef CONFIG_VFIO_PCI
extern int vfio_pci_init(struct vfio *vfio);
extern void vfio_pci_cleanup(struct vfio *vfio);
#endif

#endif /* VFIO_PRIVATE_H */
