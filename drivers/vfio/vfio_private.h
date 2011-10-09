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

#include <linux/list.h>
#include <linux/mutex.h>

#ifndef VFIO_PRIVATE_H
#define VFIO_PRIVATE_H

struct vfio_device {
	struct device			*dev;
	const struct vfio_device_ops	*ops;
	struct vfio_iommu		*iommu;
	struct vfio_group		*group;
	struct list_head		device_next;
	bool				attached;
	int				refcnt;
	void				*device_data;
};

struct vfio_iommu {
	struct iommu_domain		*domain;
	struct mutex			dgate;
	struct list_head		dm_list;
	struct mm_struct		*mm;
	struct list_head		group_list;
	int				refcnt;
	bool				cache;
};
	
#endif /* VFIO_PRIVATE_H */
