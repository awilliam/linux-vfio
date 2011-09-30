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
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/vfio.h>

#include "vfio_private.h"

#define DRIVER_VERSION  "0.1"
#define DRIVER_AUTHOR   "Alex Williamson <alex.williamson@redhat.com>"
#define DRIVER_DESC     "VFIO PCI - User Level meta-driver"

struct vfio_pci_device {
	struct vfio_device	device;
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

static struct vfio_device *vfio_pci_alloc(struct device *dev)
{
	struct vfio_pci_device *pvdev;

	pvdev = kzalloc(sizeof(*pvdev), GFP_KERNEL);
	if (!pvdev)
		return ERR_PTR(-ENOMEM);

	pvdev->pdev = container_of(dev, struct pci_dev, dev);

	// PCI stuff...

	return &pvdev->device;
}

static void vfio_pci_free(struct vfio_device *device)
{
	struct vfio_pci_device *pvdev;

	pvdev = container_of(device, struct vfio_pci_device, device);

	// PCI stuff...

	kfree(pvdev);
}

static bool vfio_pci_match(struct vfio_device *device, char *buf)
{
	return strcmp(dev_name(device->dev), buf) == 0;
}

static int vfio_pci_get(struct vfio_device *device)
{
	return try_module_get(THIS_MODULE);
}

static void vfio_pci_put(struct vfio_device *device)
{
	module_put(THIS_MODULE);
}

static const struct vfio_device_ops vfio_pci_ops = {
	.alloc	= vfio_pci_alloc,
	.free	= vfio_pci_free,
	.match	= vfio_pci_match,
	.get	= vfio_pci_get,
	.put	= vfio_pci_put,
	.owner	= THIS_MODULE,
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

static int vfio_pci_do_dev(struct device *dev, void *data)
{
	struct pci_dev *pdev = container_of(dev, struct pci_dev, dev);
	bool add = *(bool *)data;

        if (pdev->hdr_type != PCI_HEADER_TYPE_NORMAL)
		return 0;

	if (add)
		return vfio_group_add_dev(dev, (void *)&vfio_pci_ops);

	vfio_group_del_dev(dev);
	return 0;
}

static struct notifier_block vfio_pci_device_nb = {
        .notifier_call = vfio_pci_device_notifier,
};

void __exit vfio_pci_cleanup(void)
{
	bool add = false;

	bus_unregister_notifier(&pci_bus_type, &vfio_pci_device_nb);
	pci_unregister_driver(&vfio_pci_driver);
	bus_for_each_dev(&pci_bus_type, NULL, &add, vfio_pci_do_dev);
}

int __init vfio_pci_init(void)
{
	int ret;
	bool add = true;

	ret = pci_register_driver(&vfio_pci_driver);
	if (ret)
		return ret;

	bus_register_notifier(&pci_bus_type, &vfio_pci_device_nb);
	bus_for_each_dev(&pci_bus_type, NULL, &add, vfio_pci_do_dev);

	return 0;
}

module_init(vfio_pci_init);
module_exit(vfio_pci_cleanup);

MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);

