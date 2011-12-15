/*
 * VFIO API definition
 *
 * Copyright (C) 2011 Red Hat, Inc.  All rights reserved.
 * 	Author: Alex Williamson <alex.williamson@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef VFIO_H
#define VFIO_H

#include <linux/types.h>

#ifdef __KERNEL__	/* Internal VFIO-core/bus driver API */

/**
 * struct vfio_device_ops - VFIO bus driver device callbacks
 *
 * @match: Return true if buf describes the device
 * @claim: Force driver to attach to device
 * @open: Called when userspace receives file descriptor for device
 * @release: Called when userspace releases file descriptor for device
 * @read: Perform read(2) on device file descriptor
 * @write: Perform write(2) on device file descriptor
 * @ioctl: Perform ioctl(2) on device file descriptor, supporting VFIO_DEVICE_*
 *         operations documented below
 * @mmap: Perform mmap(2) on a region of the device file descriptor
 */
struct vfio_device_ops {
	bool	(*match)(struct device *dev, const char *buf);
	int	(*claim)(struct device *dev);
	int	(*open)(void *device_data);
	void	(*release)(void *device_data);
	ssize_t	(*read)(void *device_data, char __user *buf,
			size_t count, loff_t *ppos);
	ssize_t	(*write)(void *device_data, const char __user *buf,
			 size_t count, loff_t *size);
	long	(*ioctl)(void *device_data, unsigned int cmd,
			 unsigned long arg);
	int	(*mmap)(void *device_data, struct vm_area_struct *vma);
};

/**
 * vfio_group_add_dev() - Add a device to the vfio-core
 *
 * @dev: Device to add
 * @ops: VFIO bus driver callbacks for device
 *
 * This registration makes the VFIO core aware of the device, creates
 * groups objects as required and exposes chardevs under /dev/vfio.
 *
 * Return 0 on success, errno on failure.
 */
extern int vfio_group_add_dev(struct device *dev,
			      const struct vfio_device_ops *ops);

/**
 * vfio_group_del_dev() - Remove a device from the vfio-core
 *
 * @dev: Device to remove
 *
 * Remove a device previously added to the VFIO core, removing groups
 * and chardevs as necessary.
 */
extern void vfio_group_del_dev(struct device *dev);

/**
 * vfio_bind_dev() - Indicate device is bound to the VFIO bus driver and
 *                   register private data structure for ops callbacks.
 *
 * @dev: Device being bound
 * @device_data: VFIO bus driver private data
 *
 * This registration indicate that a device previously registered with
 * vfio_group_add_dev() is now available for use by the VFIO core.  When
 * all devices within a group are available, the group is viable and my
 * be used by userspace drivers.  Typically called from VFIO bus driver
 * probe function.
 *
 * Return 0 on success, errno on failure
 */
extern int vfio_bind_dev(struct device *dev, void *device_data);

/**
 * vfio_unbind_dev() - Indicate device is unbinding from VFIO bus driver
 *
 * @dev: Device being unbound
 *
 * De-registration of the device previously registered with vfio_bind_dev()
 * from VFIO.  Upon completion, the device is no longer available for use by
 * the VFIO core.  Typically called from the VFIO bus driver remove function.
 * The VFIO core will attempt to release the device from users and may take
 * measures to free the device and/or block as necessary.
 *
 * Returns pointer to private device_data structure registered with
 * vfio_bind_dev().
 */
extern void *vfio_unbind_dev(struct device *dev);

#define offsetofend(TYPE, MEMBER) ({				\
	TYPE tmp;						\
	offsetof(TYPE, MEMBER) + sizeof(tmp.MEMBER); })		\
	
#endif /* __KERNEL__ */

/* Kernel & User level defines for VFIO IOCTLs. */

/*
 * The IOCTL interface is designed for extensibility by embedding the
 * structure length (argsz) and flags into structures passed between
 * kernel and userspace.  We therefore use the _IO() macro for these
 * defines to avoid implicitly embedding a size into the ioctl request.  
 * As structure fields are added, argsz will increase to match and flag
 * bits will be defined to indicate additional fields with valid data.
 * It's *always* the caller's responsibility to indicate the size of
 * the structure passed by setting argsz appropriately.
 */

#define VFIO_TYPE	';'
#define VFIO_BASE	100

/* --------------- IOCTLs for GROUP file descriptors --------------- */

/**
 * VFIO_GROUP_GET_INFO - _IOR(VFIO_TYPE, VFIO_BASE + 0, struct vfio_group_info)
 *
 * Retrieve information about the group.  Fills in provided
 * struct vfio_group_info.  Caller sets argsz.
 */
struct vfio_group_info {
	__u32	argsz;
	__u32	flags;
#define VFIO_GROUP_FLAGS_VIABLE		(1 << 0)
#define VFIO_GROUP_FLAGS_MM_LOCKED	(1 << 1)
};

#define VFIO_GROUP_GET_INFO		_IO(VFIO_TYPE, VFIO_BASE + 0)

/**
 * VFIO_GROUP_MERGE - _IOW(VFIO_TYPE, VFIO_BASE + 1, __s32)
 *
 * Merge group indicated by passed file descriptor into current group.
 * Current group may be in use, group indicated by file descriptor
 * cannot be in use (no open iommu or devices).
 */
#define VFIO_GROUP_MERGE		_IOW(VFIO_TYPE, VFIO_BASE + 1, __s32)

/**
 * VFIO_GROUP_UNMERGE - _IO(VFIO_TYPE, VFIO_BASE + 2)
 *
 * Remove the current group from a merged set.  The current group cannot
 * have any open devices.
 */
#define VFIO_GROUP_UNMERGE		_IO(VFIO_TYPE, VFIO_BASE + 2)

/**
 * VFIO_GROUP_GET_IOMMU_FD - _IO(VFIO_TYPE, VFIO_BASE + 3)
 *
 * Return a new file descriptor for the IOMMU object.  The IOMMU object
 * is shared among members of a merged group.
 */
#define VFIO_GROUP_GET_IOMMU_FD		_IO(VFIO_TYPE, VFIO_BASE + 3)

/**
 * VFIO_GROUP_GET_DEVICE_FD - _IOW(VFIO_TYPE, VFIO_BASE + 4, char)
 *
 * Return a new file descriptor for the device object described by
 * the provided char array.
 */
#define VFIO_GROUP_GET_DEVICE_FD	_IOW(VFIO_TYPE, VFIO_BASE + 4, char)


/* --------------- IOCTLs for IOMMU file descriptors --------------- */

/**
 * VFIO_IOMMU_GET_INFO - _IOR(VFIO_TYPE, VFIO_BASE + 5, struct vfio_iommu_info)
 *
 * Retrieve information about the IOMMU object.  Fills in provided
 * struct vfio_iommu_info.  Caller sets argsz.
 */
struct vfio_iommu_info {
	__u32	argsz;
	__u32	flags;
	__u64	iova_max;	/* Maximum IOVA address */
	__u64	iova_min;	/* Minimum IOVA address */
	__u64	pgsize_bitmap;	/* Bitmap of supported page sizes */
};

#define	VFIO_IOMMU_GET_INFO		_IO(VFIO_TYPE, VFIO_BASE + 5)

/**
 * VFIO_IOMMU_MAP_DMA - _IOW(VFIO_TYPE, VFIO_BASE + 6, struct vfio_dma_map)
 *
 * Map process virtual addresses to IO virtual addresses using the
 * provided struct vfio_dma_map.  Caller sets argsz.  READ &/ WRITE required.
 */
struct vfio_dma_map {
	__u32	argsz;
	__u32	flags;
#define VFIO_DMA_MAP_FLAG_READ	(1 << 0)	/* readable from device */
#define VFIO_DMA_MAP_FLAG_WRITE	(1 << 1)	/* writable from device */
	__u64	vaddr;		/* Process virtual address */
	__u64	iova;		/* IO virtual address */
	__u64	size;		/* Size of mapping (bytes) */
};

#define	VFIO_IOMMU_MAP_DMA		_IO(VFIO_TYPE, VFIO_BASE + 6)

/**
 * VFIO_IOMMU_UNMAP_DMA - _IOW(VFIO_TYPE, VFIO_BASE + 7, struct vfio_dma_unmap)
 *
 * Unmap IO virtual addresses using the provided struct vfio_dma_unmap.
 * Caller sets argsz.
 */
struct vfio_dma_unmap {
	__u32	argsz;
	__u32	flags;
	__u64	iova;		/* IO virtual address */
	__u64	size;		/* Size of mapping (bytes) */
};

#define	VFIO_IOMMU_UNMAP_DMA		_IO(VFIO_TYPE, VFIO_BASE + 7)


/* --------------- IOCTLs for DEVICE file descriptors --------------- */

/**
 * VFIO_DEVICE_GET_INFO - _IOR(VFIO_TYPE, VFIO_BASE + 8,
 *			       struct vfio_device_info)
 *
 * Retrieve information about the device.  Fills in provided
 * struct vfio_device_info.  Caller sets argsz.
 */
struct vfio_device_info {
	__u32	argsz;
	__u32	flags;
#define VFIO_DEVICE_FLAGS_RESET	(1 << 0)	/* Device supports reset */
	__u32	num_regions;	/* Max region index + 1 */
	__u32	num_irqs;	/* Max IRQ index + 1 */
};

#define VFIO_DEVICE_GET_INFO		_IO(VFIO_TYPE, VFIO_BASE + 8)

/**
 * VFIO_DEVICE_GET_REGION_INFO - _IOWR(VFIO_TYPE, VFIO_BASE + 9,
 *				       struct vfio_region_info)
 *
 * Retrieve information about a device region.  Caller provides
 * struct vfio_region_info with index value set.  Caller sets argsz.
 */
struct vfio_region_info {
	__u32	argsz;
	__u32	flags;
#define VFIO_REGION_INFO_FLAG_MMAP	(1 << 0) /* Region supports mmap */
#define VFIO_REGION_INFO_FLAG_RO	(1 << 1) /* Region is read-only */
	__u32	index;		/* Region index */
	__u32	resv;		/* Reserved for alignment */
	__u64	size;		/* Region size (bytes) */
	__u64	offset;		/* Region offset from start of device fd */
};

#define VFIO_DEVICE_GET_REGION_INFO	_IO(VFIO_TYPE, VFIO_BASE + 9)

/**
 * VFIO_DEVICE_GET_IRQ_INFO - _IOWR(VFIO_TYPE, VFIO_BASE + 10,
 *				    struct vfio_irq_info)
 *
 * Retrieve information about a device IRQ.  Caller provides
 * struct vfio_irq_info with index value set.  Caller sets argsz.
 */
struct vfio_irq_info {
	__u32	argsz;
	__u32	flags;
#define VFIO_IRQ_INFO_FLAG_LEVEL	(1 << 0) /* Level (1) vs Edge (0) */
	__u32	index;		/* IRQ index */
	__u32	count;		/* Number of IRQs within this index */
};

#define VFIO_DEVICE_GET_IRQ_INFO	_IO(VFIO_TYPE, VFIO_BASE + 10)

/**
 * VFIO_DEVICE_SET_IRQ_EVENTFDS - _IOW(VFIO_TYPE, VFIO_BASE + 11,
 *				       struct vfio_irq_eventfds)
 *
 * Set eventfds for IRQs using the struct vfio_irq_eventfds provided.
 * Setting the eventfds also enables the interrupt.  Caller sets argsz.
 */
struct vfio_irq_eventfds {
	__u32	argsz;
	__u32	flags;
	__u32	index;		/* IRQ index */
	__u32	count;		/* Number of eventfds */
	__s32	eventfds[];	/* eventfd for sub-index, -1 to unset */
};

#define VFIO_DEVICE_SET_IRQ_EVENTFDS	_IO(VFIO_TYPE, VFIO_BASE + 11)

/**
 * VFIO_DEVICE_UNMASK_IRQ - _IOW(VFIO_TYPE, VFIO_BASE + 12,
 *				 struct vfio_unmask_irq)
 *
 * Unmask the IRQ described by the provided struct vfio_unmask_irq.
 * Level triggered IRQs are masked when posted to userspace and must
 * be unmasked to re-trigger.  IRQ index is enabled when set, disabled
 * when called with count == 0.  Caller sets argsz.
 */
struct vfio_unmask_irq {
	__u32	argsz;
	__u32	flags;
	__u32	index;		/* IRQ index */
	__u32	subindex;	/* Sub-index to unmask */
};

#define VFIO_DEVICE_UNMASK_IRQ		_IO(VFIO_TYPE, VFIO_BASE + 12)

/**
 * VFIO_DEVICE_SET_UNMASK_IRQ_EVENTFDS - _IOW(VFIO_TYPE, VFIO_BASE + 13,
 *					      struct vfio_irq_eventfds)
 *
 * Set eventfds to be used for unmasking IRQs using the provided
 * struct vfio_irq_eventfds.  Disable with count == 0.  Caller sets argsz.
 */
#define VFIO_DEVICE_SET_UNMASK_IRQ_EVENTFDS	_IO(VFIO_TYPE, VFIO_BASE + 13)

/**
 * VFIO_DEVICE_RESET - _IO(VFIO_TYPE, VFIO_BASE + 14)
 *
 * Reset a device.
 */
#define VFIO_DEVICE_RESET		_IO(VFIO_TYPE, VFIO_BASE + 14)

#endif /* VFIO_H */
