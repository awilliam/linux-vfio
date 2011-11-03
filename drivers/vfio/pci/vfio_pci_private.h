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

#include <linux/mutex.h>
#include <linux/pci.h>

#ifndef VFIO_PCI_PRIVATE_H
#define VFIO_PCI_PRIVATE_H

#define VFIO_PCI_OFFSET_SHIFT   40

#define VFIO_PCI_OFFSET_TO_INDEX(off)	(off >> VFIO_PCI_OFFSET_SHIFT)
#define VFIO_PCI_INDEX_TO_OFFSET(index)	((u64)(index) << VFIO_PCI_OFFSET_SHIFT)
#define VFIO_PCI_OFFSET_MASK	(((u64)(1) << VFIO_PCI_OFFSET_SHIFT) - 1)

struct vfio_pci_device {
	struct pci_dev		*pdev;
	void __iomem		*barmap[PCI_STD_RESOURCE_END + 1];
	u8			*pci_config_map;
	spinlock_t		irqlock;
	struct mutex		igate;
	struct msix_entry	*msix;
	struct eventfd_ctx	*ev_irq;
	struct eventfd_ctx	**ev_msi;
	struct eventfd_ctx	**ev_msix;
	int			msi_nvec;
	int			msix_nvec;
	u8			*vconfig;
	u8			msi_qmax;
	u8			bardirty;
	u32			rbar[7];
	struct perm_bits	*msi_perm;
	bool			pci_2_3;
	bool			irq_disabled;
	bool			virq_disabled;
	bool			reset_works;
	struct eoi_eventfd	*ev_eoi;
	struct pci_saved_state	*pci_saved_state;
	int			refcnt;
};

extern irqreturn_t vfio_pci_interrupt(int irq, void *dev_id);

extern void vfio_pci_enable_intx(struct vfio_pci_device *vdev);
extern irqreturn_t vfio_pci_disable_intx(struct vfio_pci_device *vdev);

extern int vfio_pci_setup_msi(struct vfio_pci_device *vdev,
			      int nvec, int __user *intargp);
extern void vfio_pci_drop_msi(struct vfio_pci_device *vdev);

extern int vfio_pci_setup_msix(struct vfio_pci_device *vdev,
			       int nvec, int __user *intargp);
extern void vfio_pci_drop_msix(struct vfio_pci_device *vdev);

extern int vfio_pci_irq_eoi(struct vfio_pci_device *vdev);
extern int vfio_pci_irq_eoi_eventfd(struct vfio_pci_device *vdev, int fd);

extern ssize_t vfio_pci_config_readwrite(int write,
					 struct vfio_pci_device *vdev,
					 char __user *buf, size_t count,
					 loff_t *ppos);
extern ssize_t vfio_pci_mem_readwrite(int write, struct vfio_pci_device *vdev,
				      char __user *buf, size_t count,
				      loff_t *ppos);
extern ssize_t vfio_pci_io_readwrite(int write, struct vfio_pci_device *vdev,
				     char __user *buf, size_t count,
				     loff_t *ppos);

extern int vfio_pci_init_perm_bits(void);
extern void vfio_pci_uninit_perm_bits(void);

extern int vfio_pci_eoi_eventfd_init(void);
extern void vfio_pci_eoi_eventfd_exit(void);
#endif /* VFIO_PCI_PRIVATE_H */
