/*
 * Copyright 2010 Cisco Systems, Inc.  All rights reserved.
 * Author: Tom Lyon, pugs@cisco.com
 *
 * This program is free software; you may redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Portions derived from drivers/uio/uio.c:
 * Copyright(C) 2005, Benedikt Spranger <b.spranger@linutronix.de>
 * Copyright(C) 2005, Thomas Gleixner <tglx@linutronix.de>
 * Copyright(C) 2006, Hans J. Koch <hjk@linutronix.de>
 * Copyright(C) 2006, Greg Kroah-Hartman <greg@kroah.com>
 *
 * Portions derived from drivers/uio/uio_pci_generic.c:
 * Copyright (C) 2009 Red Hat, Inc.
 * Author: Michael S. Tsirkin <mst@redhat.com>
 */
#include <linux/types.h>

/*
 * VFIO driver - allow mapping and use of certain PCI devices
 * in unprivileged user processes. (If IOMMU is present)
 * Especially useful for Virtual Function parts of SR-IOV devices
 */


/* Kernel & User level defines for ioctls */

#define VFIO_GROUP_MERGE		_IOW(';', 101, int)
#define VFIO_GROUP_UNMERGE		_IOW(';', 102, int)
#define VFIO_GROUP_GET_IOMMU_FD		_IO(';', 103)
#define VFIO_GROUP_GET_DEVICE_FD	_IOW(';', 104, char *)

/*
 * Structure for DMA mapping of user buffers
 * vaddr, dmaaddr, and size must all be page aligned
 */
struct vfio_dma_map {
	__u64	len;		/* length of structure */
	__u64	vaddr;		/* process virtual addr */
	__u64	dmaaddr;	/* desired and/or returned dma address */
	__u64	size;		/* size in bytes */
	__u64	flags;
#define	VFIO_DMA_MAP_FLAG_WRITE		(1 << 0) /* req writeable DMA mem */
};

#define	VFIO_IOMMU_MAP_DMA		_IOWR(';', 105, struct vfio_dma_map)
#define	VFIO_IOMMU_UNMAP_DMA		_IOWR(';', 106, struct vfio_dma_map)

#define VFIO_DEVICE_GET_FLAGS		_IOR(';', 107, __u64)
 #define VFIO_DEVICE_FLAGS_PCI		(1 << 0)
 #define VFIO_DEVICE_FLAGS_DT		(1 << 1)
 #define VFIO_DEVICE_FLAGS_RESET	(1 << 2)
#define VFIO_DEVICE_GET_NUM_REGIONS	_IOR(';', 108, int)

struct vfio_region_info {
	__u32	len;		/* length of structure */
	__u32	index;		/* region number */
	__u64	size;		/* size in bytes of region */
	__u64	offset;		/* start offset of region */
	__u64	flags;
#define VFIO_REGION_INFO_FLAG_MMAP		(1 << 0)
#define VFIO_REGION_INFO_FLAG_RO		(1 << 1)
#define VFIO_REGION_INFO_FLAG_PHYS_VALID	(1 << 2)
	__u64	phys;		/* physical address of region */
};

#define VFIO_DEVICE_GET_REGION_INFO	_IOWR(';', 109, struct vfio_region_info)

#define VFIO_DEVICE_GET_NUM_IRQS	_IOR(';', 110, int)

struct vfio_irq_info {
	__u32	len;		/* length of structure */
	__u32	index;		/* IRQ number */
	__u32	count;		/* number of individual IRQs */
	__u64	flags;
#define VFIO_IRQ_INFO_FLAG_LEVEL		(1 << 0)
};

#define VFIO_DEVICE_GET_IRQ_INFO	_IOWR(';', 111, struct vfio_irq_info)

/* Set IRQ eventfds, arg[0] = index, arg[1] = count, arg[2-n] = eventfds */
#define VFIO_DEVICE_SET_IRQ_EVENTFDS	_IOW(';', 112, int)

/* Unmask IRQ index, arg[0] = index */
#define VFIO_DEVICE_UNMASK_IRQ		_IOW(';', 113, int)

/* Set unmask eventfd, arg[0] = index, arg[1] = eventfd */
#define VFIO_DEVICE_SET_UNMASK_IRQ_EVENTFD	_IOW(';', 114, int)

#define VFIO_DEVICE_RESET		_IO(';', 115)

struct vfio_dtpath {
	__u32	len;		/* length of structure */
	__u32	index;
	__u64	flags;
#define VFIO_DTPATH_FLAGS_REGION	(1 << 0)
#define VFIO_DTPATH_FLAGS_IRQ		(1 << 1)
	char	*path;
};
#define VFIO_DEVICE_GET_DTPATH		_IOWR(';', 116, struct vfio_dtpath)

struct vfio_dtindex {
	__u32	len;		/* length of structure */
	__u32	index;
	__u32	prop_type;
	__u32	prop_index;
	__u64	flags;
#define VFIO_DTINDEX_FLAGS_REGION	(1 << 0)
#define VFIO_DTINDEX_FLAGS_IRQ		(1 << 1)
};
#define VFIO_DEVICE_GET_DTINDEX		_IOWR(';', 117, struct vfio_dtindex)

/* PCI devices have a fixed region and irq mapping */
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
