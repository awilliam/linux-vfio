/*
 * VFIO API definition
 *
 * Copyright (C) 2012 Red Hat, Inc.  All rights reserved.
 *     Author: Alex Williamson <alex.williamson@redhat.com>
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


/**
 * offsetofend(TYPE, MEMBER)
 *
 * @TYPE: The type of the structure
 * @MEMBER: The member within the structure to get the end offset of
 *
 * Simple helper macro for dealing with variable sized structures passed
 * from user space.  This allows us to easily determine if the provided
 * structure is sized to include various fields.
 */
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

#define VFIO_TYPE	(';')
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
	__u64	iova_start;	/* IOVA base address */
	__u64	iova_size;	/* IOVA window size */
	__u64	iova_entries;	/* Number mapping entries available */
	__u64	iova_pgsizes;	/* Bitmap of supported page sizes */
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
#define VFIO_DEVICE_FLAGS_PCI	(1 << 1)	/* vfio-pci device */
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
 * Implementation of region mapping is bus driver specific.  This is
 * intended to describe MMIO, I/O port, as well as bus specific
 * regions (ex. PCI config space).  Zero sized regions may be used
 * to describe unimplemented regions (ex. unimplemented PCI BARs).
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
 * Implementation of IRQ mapping is bus driver specific.  Indexes
 * using multiple IRQs are primarily intended to support MSI-like
 * interrupt blocks.  Zero count irq blocks may be used to describe
 * unimplemented interrupt types.
 *
 * The EVENTFD flag indicates the interrupt index supports eventfd based
 * signaling.
 *
 * The MASKABLE flags indicates the index supports MASK and UNMASK
 * actions described below.
 *
 * AUTOMASKED indicates that after signaling, the interrupt line is
 * automatically masked by VFIO and the user needs to unmask the line
 * to receive new interrupts.  This is primarily intended to distinguish
 * level triggered interrupts.
 *
 * The NORESIZE flag indicates that the interrupt lines within the index
 * are setup as a set and new subindexes cannot be enabled without first
 * disabling the entire index.  This is used for interrupts like PCI MSI
 * and MSI-X where the driver may only use a subset of the available
 * indexes, but VFIO needs to enable a specific number of vectors
 * upfront.  In the case of MSI-X, where the user can enable MSI-X and
 * then add and unmask vectors, it's up to userspace to make the decision
 * whether to allocate the maximum supported number of vectors or tear
 * down setup and incrementally increase the vectors as each is enabled.
 */
struct vfio_irq_info {
	__u32	argsz;
	__u32	flags;
#define VFIO_IRQ_INFO_EVENTFD		(1 << 0)
#define VFIO_IRQ_INFO_MASKABLE		(1 << 1)
#define VFIO_IRQ_INFO_AUTOMASKED	(1 << 2)
#define VFIO_IRQ_INFO_NORESIZE		(1 << 3)
	__u32	index;		/* IRQ index */
	__s32	count;		/* Number of IRQs within this index */
};

#define VFIO_DEVICE_GET_IRQ_INFO	_IO(VFIO_TYPE, VFIO_BASE + 10)

/**
 * VFIO_DEVICE_SET_IRQS - _IOW(VFIO_TYPE, VFIO_BASE + 11, struct vfio_irq_set)
 *
 * Set signaling, masking, and unmasking of interrupts.  Caller provides
 * struct vfio_irq_set with all fields set.  'start' and 'count' indicate
 * the range of subindexes being specified.
 *
 * The DATA flags specify the type of data provided.  If DATA_NONE, the
 * operation performs the specified action immediately on the specified
 * interrupt(s).  For example, to unmask AUTOMASKED interrupt [0,0]:
 * flags = (DATA_NONE|ACTION_UNMASK), index = 0, start = 0, count = 1.
 *
 * DATA_BOOL allows sparse support for the same on arrays of interrupts.
 * For example, to mask interrupts [0,1] and [0,3] (but not [0,2]):
 * flags = (DATA_BOOL|ACTION_MASK), index = 0, start = 1, count = 3,
 * data = {1,0,1}
 *
 * DATA_EVENTFD binds the specified ACTION to the provided __s32 eventfd.
 * A value of -1 can be used to either de-assign interrupts if already
 * assigned or skip un-assigned interrupts.  For example, to set an eventfd
 * to be trigger for interrupts [0,0] and [0,2]:
 * flags = (DATA_EVENTFD|ACTION_TRIGGER), index = 0, start = 0, count = 3,
 * data = {fd1, -1, fd2}
 * If index [0,1] is previously set, two count = 1 ioctls calls would be
 * required to set [0,0] and [0,2] without changing [0,1].
 *
 * Once a signaling mechanism is set, DATA_BOOL or DATA_NONE can be used
 * with ACTION_TRIGGER to perform kernel level interrupt loopback testing
 * from userspace (ie. simulate hardware triggering).
 *
 * Setting of an event triggering mechanism to userspace for ACTION_TRIGGER
 * enables the interrupt index for the device.  Individual subindex interrupts
 * can be disabled using the -1 value for DATA_EVENTFD or the index can be
 * disabled as a whole with: flags = (DATA_NONE|ACTION_TRIGGER), count = 0.
 *
 * Note that ACTION_[UN]MASK specify user->kernel signaling (irqfds) while
 * ACTION_TRIGGER specifies kernel->user signaling.
 */
struct vfio_irq_set {
	__u32	argsz;
	__u32	flags;
#define VFIO_IRQ_SET_DATA_NONE		(1 << 0) /* Data not present */
#define VFIO_IRQ_SET_DATA_BOOL		(1 << 1) /* Data is bool (u8) */
#define VFIO_IRQ_SET_DATA_EVENTFD	(1 << 2) /* Data is eventfd (s32) */
#define VFIO_IRQ_SET_ACTION_MASK	(1 << 3) /* Mask interrupt */
#define VFIO_IRQ_SET_ACTION_UNMASK	(1 << 4) /* Unmask interrupt */
#define VFIO_IRQ_SET_ACTION_TRIGGER	(1 << 5) /* Trigger interrupt */
	__u32	index;
	__s32	start;
	__s32	count;
	__u8	data[];
};

#define VFIO_DEVICE_SET_IRQS		_IO(VFIO_TYPE, VFIO_BASE + 11)

#define VFIO_IRQ_SET_DATA_TYPE_MASK	(VFIO_IRQ_SET_DATA_NONE | \
					 VFIO_IRQ_SET_DATA_BOOL | \
					 VFIO_IRQ_SET_DATA_EVENTFD)
#define VFIO_IRQ_SET_ACTION_TYPE_MASK	(VFIO_IRQ_SET_ACTION_MASK | \
					 VFIO_IRQ_SET_ACTION_UNMASK | \
					 VFIO_IRQ_SET_ACTION_TRIGGER)
/**
 * VFIO_DEVICE_RESET - _IO(VFIO_TYPE, VFIO_BASE + 12)
 *
 * Reset a device.
 */
#define VFIO_DEVICE_RESET		_IO(VFIO_TYPE, VFIO_BASE + 12)


/*
 * The VFIO-PCI bus driver makes use of the following fixed region and
 * IRQ index mapping.  Unimplemented regions return a size of zero.
 * Unimplemented IRQ types return a count of zero.
 */

enum {
	VFIO_PCI_BAR0_REGION_INDEX,
	VFIO_PCI_BAR1_REGION_INDEX,
	VFIO_PCI_BAR2_REGION_INDEX,
	VFIO_PCI_BAR3_REGION_INDEX,
	VFIO_PCI_BAR4_REGION_INDEX,
	VFIO_PCI_BAR5_REGION_INDEX,
	VFIO_PCI_ROM_REGION_INDEX,
	VFIO_PCI_CONFIG_REGION_INDEX,
	VFIO_PCI_NUM_REGIONS
};

enum {
	VFIO_PCI_INTX_IRQ_INDEX,
	VFIO_PCI_MSI_IRQ_INDEX,
	VFIO_PCI_MSIX_IRQ_INDEX,
	VFIO_PCI_NUM_IRQS
};

#endif /* VFIO_H */
