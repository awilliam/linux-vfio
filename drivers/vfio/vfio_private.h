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

struct vfio_iommu {
	struct iommu_domain		*domain;
	struct bus_type			*bus;
	struct mutex			lock;
	struct list_head		dma_list;
	struct mm_struct		*mm;
	struct list_head		group_list;
	int				refcnt;
	bool				cache;
};

extern int vfio_release_iommu(struct vfio_iommu *iommu);
extern void vfio_iommu_unmapall(struct vfio_iommu *iommu);

#endif /* VFIO_PRIVATE_H */
