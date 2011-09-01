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

#include <linux/device.h>
#include <linux/notifier.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/vfio.h>

#include "vfio_private.h"

struct vfio_pci_device {
	struct vfio_device	vdev;
	struct pci_dev		*pdev;
};

static int vfio_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	return 0;
}

static void vfio_pci_remove(struct pci_dev *pdev)
{
}

static struct pci_driver vfio_pci_driver = {
	.name		= "vfio",
	.id_table	= NULL, /* only dynamic id's */
	.probe		= vfio_pci_probe,
	.remove		= vfio_pci_remove,
};

static struct vfio_device *vfio_pci_new(struct device *dev)
{
	struct vfio_pci_device *pvdev;

	pvdev = kzalloc(sizeof(*pvdev), GFP_KERNEL);
	if (!pvdev)
		return ERR_PTR(-ENOMEM);

	printk("%s: alloc pvdev @%p\n", __FUNCTION__, pvdev);
	pvdev->pdev = container_of(dev, struct pci_dev, dev);

	// PCI stuff...

	return &pvdev->vdev;
}

static void vfio_pci_free(struct vfio_device *vdev)
{
	struct vfio_pci_device *pvdev;

	pvdev = container_of(vdev, struct vfio_pci_device, vdev);

	// PCI stuff...

	printk("%s: freeing pvdev @%p\n", __FUNCTION__, pvdev);
	kfree(pvdev);
}

static const struct vfio_device_ops vfio_pci_ops = {
	.new	= vfio_pci_new,
	.free	= vfio_pci_free,
};

static int vfio_pci_device_notifier(struct notifier_block *nb,
				    unsigned long action, void *data)
{
        struct device *dev = data;
	struct pci_dev *pdev = container_of(dev, struct pci_dev, dev);

        if (pdev->hdr_type != PCI_HEADER_TYPE_NORMAL)
		return 0;

        if (action == BUS_NOTIFY_ADD_DEVICE)
                return vfio_group_add_dev(dev, (void *)&vfio_pci_ops);
        else if (action == BUS_NOTIFY_DEL_DEVICE)
                vfio_group_del_dev(dev);
        return 0;
}

static int vfio_pci_add_dev(struct device *dev, void *unused)
{
	struct pci_dev *pdev = container_of(dev, struct pci_dev, dev);

        if (pdev->hdr_type != PCI_HEADER_TYPE_NORMAL)
		return 0;

	return vfio_group_add_dev(dev, (void *)&vfio_pci_ops);
}

static struct notifier_block vfio_pci_device_nb = {
        .notifier_call = vfio_pci_device_notifier,
};

void __exit vfio_pci_cleanup(struct vfio *vfio)
{
	bus_unregister_notifier(&pci_bus_type, &vfio_pci_device_nb);
	pci_unregister_driver(&vfio_pci_driver);
}

int __init vfio_pci_init(struct vfio *vfio)
{
	int ret;

	ret = pci_register_driver(&vfio_pci_driver);
	if (ret)
		return ret;

	bus_register_notifier(&pci_bus_type, &vfio_pci_device_nb);
	bus_for_each_dev(&pci_bus_type, NULL, NULL, vfio_pci_add_dev);

	return 0;
}
