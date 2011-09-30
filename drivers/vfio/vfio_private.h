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

struct vfio_device_ops {
	struct vfio_device	*(* alloc)(struct device *);
	void			(* free)(struct vfio_device *);
	bool			(*match)(struct vfio_device *, char *);
	int			(*get)(struct vfio_device *);
	void			(*put)(struct vfio_device *);
        ssize_t			(*read)(struct vfio_device *,
					char __user *, size_t, loff_t *);
        ssize_t			(*write)(struct vfio_device *,
					 const char __user *, size_t, loff_t *);
        long			(*ioctl)(struct vfio_device *,
					 unsigned int, unsigned long);
	int			(*mmap)(struct vfio_device *,
					struct vm_area_struct *);
	struct module		*owner;
};

struct vfio_device {
	struct device		*dev;
	struct vfio_device_ops	*ops;
	struct vfio_iommu	*iommu;
	struct vfio_group	*group;
	struct list_head	device_next;
	bool			attached;
	int			refcnt;
};

struct vfio_iommu {
	struct iommu_domain	*domain;
	struct mm_struct	*mm;
	struct list_head	group_list;
	int			refcnt;
};
	
extern int vfio_group_add_dev(struct device *device, void *data);
extern void vfio_group_del_dev(struct device *device);

#endif /* VFIO_PRIVATE_H */
