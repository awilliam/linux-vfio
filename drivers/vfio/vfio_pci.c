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
#include <linux/uaccess.h>
#include <linux/vfio.h>

#include "vfio_private.h"

#define DRIVER_VERSION  "0.1"
#define DRIVER_AUTHOR   "Alex Williamson <alex.williamson@redhat.com>"
#define DRIVER_DESC     "VFIO PCI - User Level meta-driver"

#define VFIO_PCI_OFFSET_SHIFT	40

struct vfio_pci_device {
	struct vfio_device	device;
	struct pci_dev		*pdev;
	void __iomem		*barmap[PCI_STD_RESOURCE_END + 1];
	bool			pci_2_3;
	bool			reset_works;
	struct pci_saved_state	*pci_saved_state;
};

/*
 * Verify that the device supports Interrupt Disable bit in command register,
 * per PCI 2.3, by flipping this bit and reading it back: this bit was readonly
 * in PCI 2.2.  (from uio_pci_generic)
 */
static int verify_pci_2_3(struct pci_dev *pdev)
{
	u16 orig, new;
	u8 pin;

	pci_read_config_byte(pdev, PCI_INTERRUPT_PIN, &pin);
	if (pin == 0)           /* irqs not needed */
		return 0;

	pci_read_config_word(pdev, PCI_COMMAND, &orig);
	pci_write_config_word(pdev, PCI_COMMAND,
			      orig ^ PCI_COMMAND_INTX_DISABLE);
	pci_read_config_word(pdev, PCI_COMMAND, &new);
	/* There's no way to protect against
	 * hardware bugs or detect them reliably, but as long as we know
	 * what the value should be, let's go ahead and check it. */
	if ((new ^ orig) & ~PCI_COMMAND_INTX_DISABLE) {
		dev_err(&pdev->dev, "Command changed from 0x%x to 0x%x: "
			"driver or HW bug?\n", orig, new);
		return -EBUSY;
	}
	if (!((new ^ orig) & PCI_COMMAND_INTX_DISABLE)) {
		dev_warn(&pdev->dev, "Device does not support disabling "
			 "interrupts, exclusive interrupt required.\n");
		return -ENODEV;
	}
	/* Now restore the original value. */
	pci_write_config_word(pdev, PCI_COMMAND, orig);
	return 0;
}

static int vfio_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	u8 type;

	pci_read_config_byte(pdev, PCI_HEADER_TYPE, &type);
	if ((type & PCI_HEADER_TYPE) != PCI_HEADER_TYPE_NORMAL)
		return -EINVAL;

	return vfio_bind_dev(&pdev->dev);
}

static void vfio_pci_remove(struct pci_dev *pdev)
{
	vfio_unbind_dev(&pdev->dev);
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

	pvdev->pdev = to_pci_dev(dev);

	return &pvdev->device;
}

static void vfio_pci_free(struct vfio_device *device)
{
	struct vfio_pci_device *pvdev;

	pvdev = container_of(device, struct vfio_pci_device, device);

	kfree(pvdev);
}

static bool vfio_pci_match(struct vfio_device *device, char *buf)
{
	return strcmp(dev_name(device->dev), buf) == 0;
}

static int vfio_pci_enable(struct vfio_device *device)
{
	struct vfio_pci_device *pvdev;
	int ret = 0;
	u16 cmd;

	pvdev = container_of(device, struct vfio_pci_device, device);

	pvdev->reset_works = (pci_reset_function(pvdev->pdev) == 0);
	pci_save_state(pvdev->pdev);
	pvdev->pci_saved_state = pci_store_saved_state(pvdev->pdev);
	if (!pvdev->pci_saved_state)
		printk(KERN_DEBUG "%s: Couldn't store %s saved state\n",
		       __func__, dev_name(device->dev));

	pvdev->pci_2_3 = (verify_pci_2_3(pvdev->pdev) == 0);

	pci_read_config_word(pvdev->pdev, PCI_COMMAND, &cmd);
	if (pvdev->pci_2_3 && (cmd & PCI_COMMAND_INTX_DISABLE)) {
		cmd &= ~PCI_COMMAND_INTX_DISABLE;
		pci_write_config_word(pvdev->pdev, PCI_COMMAND, cmd);
	}

	ret = pci_enable_device(pvdev->pdev);
	if (ret) {
		if (pvdev->pci_saved_state)
			kfree(pvdev->pci_saved_state);
		pvdev->pci_saved_state = NULL;
	}

	return ret;
}

static void vfio_pci_disable(struct vfio_device *device)
{
	struct vfio_pci_device *pvdev;
	int bar;

	pvdev = container_of(device, struct vfio_pci_device, device);

	if (pci_reset_function(pvdev->pdev) == 0) {
		if (pci_load_and_free_saved_state(pvdev->pdev,
						  &pvdev->pci_saved_state) != 0)
			printk(KERN_INFO "%s: Couldn't reload %s saved state\n",
			       __func__, dev_name(device->dev));
		else
			pci_restore_state(pvdev->pdev);
	}

	for (bar = PCI_STD_RESOURCES; bar <= PCI_STD_RESOURCE_END; bar++) {
		if (!pvdev->barmap[bar])
			continue;
		pci_iounmap(pvdev->pdev, pvdev->barmap[bar]);
		pci_release_selected_regions(pvdev->pdev, 1 << bar);
		pvdev->barmap[bar] = NULL;
	}

	pci_disable_device(pvdev->pdev);
}

static int vfio_pci_get(struct vfio_device *device)
{
	if (device->refcnt == 0) {
		int ret = vfio_pci_enable(device);
		if (ret)
			return ret;
	}
		
	return try_module_get(THIS_MODULE);
}

static void vfio_pci_put(struct vfio_device *device)
{
	if (device->refcnt == 0)
		vfio_pci_disable(device);

	module_put(THIS_MODULE);
}

static long vfio_pci_ioctl(struct vfio_device *device,
			   unsigned int cmd, unsigned long arg)
{
	struct vfio_pci_device *pvdev;

	pvdev = container_of(device, struct vfio_pci_device, device);

	switch (cmd) {
	case VFIO_DEVICE_GET_FLAGS:
	{
		u64 flags = VFIO_DEVICE_FLAGS_PCI;

		if (pvdev->reset_works)
			flags |= VFIO_DEVICE_FLAGS_RESET;

		return put_user(flags, (u64 __user *)arg);
	}

	case VFIO_DEVICE_GET_NUM_REGIONS:
		return put_user(VFIO_PCI_NUM_REGIONS, (u32 __user *)arg);

	case VFIO_DEVICE_GET_REGION_INFO:
	{
		struct vfio_region_info info = { };
		u32 len;

		if (get_user(len, (u32 __user *)arg))
			return -EFAULT;

		if (len > sizeof(info) ||
		    len < offsetof(struct vfio_region_info, phys))
			return -EINVAL;

		if (copy_from_user(&info, (void __user *)arg, len))
			return -EFAULT;

		if (info.index >= VFIO_PCI_NUM_REGIONS)
			return -EINVAL;

		memset(&info.size, 0,
		       len - offsetof(struct vfio_region_info, size));

		info.offset = (u64)info.index << VFIO_PCI_OFFSET_SHIFT;

		if (info.index == VFIO_PCI_CONFIG_REGION_INDEX) {
			info.size = pvdev->pdev->cfg_size;
		} else if (pci_resource_start(pvdev->pdev, info.index)) {
			info.size = pci_resource_len(pvdev->pdev, info.index);
			if (info.index == VFIO_PCI_ROM_REGION_INDEX)
				info.flags |= VFIO_REGION_INFO_FLAG_RO;
			else if (pci_resource_flags(pvdev->pdev,info.index) &
				 IORESOURCE_MEM)
				info.flags |= VFIO_REGION_INFO_FLAG_MMAP;
		}

		if (copy_to_user((void __user *)arg, &info, len))
			return -EFAULT;

		return 0;
	}

	case VFIO_DEVICE_GET_NUM_IRQS:
		return put_user(VFIO_PCI_NUM_IRQS, (u32 __user *)arg);

	case VFIO_DEVICE_GET_IRQ_INFO:
	{
		struct vfio_irq_info info = { };
		u32 len;

		if (get_user(len, (u32 __user *)arg))
			return -EFAULT;

		if (len != sizeof(info))
			return -EINVAL;

		if (copy_from_user(&info, (void __user *)arg, len))
			return -EFAULT;

		memset(&info.count, 0,
		       len - offsetof(struct vfio_irq_info, count));

		if (info.index == VFIO_PCI_INTX_IRQ_INDEX) {
			u8 pin;
			pci_read_config_byte(pvdev->pdev,
					     PCI_INTERRUPT_PIN, &pin);
			if (pin) {
				info.count = 1;
				info.flags = VFIO_IRQ_INFO_FLAG_LEVEL;
			}
		} else if (info.index == VFIO_PCI_MSI_IRQ_INDEX) {
			u8 pos;
			u16 flags;

			pos = pci_find_capability(pvdev->pdev, PCI_CAP_ID_MSI);
			if (pos) {
				pci_read_config_word(pvdev->pdev,
						     pos + PCI_MSI_FLAGS,
						     &flags);

				info.count = 1 << (flags & PCI_MSI_FLAGS_QMASK);
			}
		} else if (info.index == VFIO_PCI_MSIX_IRQ_INDEX) {
			u8 pos;
			u16 flags;

			pos = pci_find_capability(pvdev->pdev, PCI_CAP_ID_MSIX);
			if (pos) {
				pci_read_config_word(pvdev->pdev,
						     pos + PCI_MSIX_FLAGS,
						     &flags);

				info.count = (flags & PCI_MSIX_FLAGS_QSIZE) + 1;
			}
		} else
			return -EINVAL;
	
		if (copy_to_user((void __user *)arg, &info, len))
			return -EFAULT;

		return 0;
	}

	case VFIO_DEVICE_SET_IRQ_EVENTFDS:
		break; // Implement me...

	case VFIO_DEVICE_UNMASK_IRQ:
		break; // Implement me...

	case VFIO_DEVICE_SET_UNMASK_IRQ_EVENTFD:
		break; // Implement me...

	case VFIO_DEVICE_RESET:
		if (pvdev->reset_works)
			return pci_reset_function(pvdev->pdev);
		else
			return -EINVAL;
	}
	return -ENOSYS;
}

static const struct vfio_device_ops vfio_pci_ops = {
	.alloc	= vfio_pci_alloc,
	.free	= vfio_pci_free,
	.match	= vfio_pci_match,
	.get	= vfio_pci_get,
	.put	= vfio_pci_put,
	.ioctl	= vfio_pci_ioctl,
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

