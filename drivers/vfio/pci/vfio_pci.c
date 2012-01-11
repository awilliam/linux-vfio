/*
 * Copyright (C) 2012 Red Hat, Inc.  All rights reserved.
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
#include <linux/eventfd.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/pci.h>
#include <linux/pm_runtime.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vfio.h>

#include "vfio_pci_private.h"

#define DRIVER_VERSION  "0.1"
#define DRIVER_AUTHOR   "Alex Williamson <alex.williamson@redhat.com>"
#define DRIVER_DESC     "VFIO PCI - User Level meta-driver"

/* Bind a device to vfio-pci.  We'll do more init once it's opened */
static int vfio_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	u8 type;
	struct vfio_pci_device *vdev;
	int ret;

	pci_read_config_byte(pdev, PCI_HEADER_TYPE, &type);
	if ((type & PCI_HEADER_TYPE) != PCI_HEADER_TYPE_NORMAL)
		return -EINVAL;

	vdev = kzalloc(sizeof(*vdev), GFP_KERNEL);
	if (!vdev)
		return -ENOMEM;

	vdev->pdev = pdev;
	mutex_init(&vdev->igate);
	atomic_set(&vdev->refcnt, 0);

	ret = vfio_bind_dev(&pdev->dev, vdev);
	if (ret)
		kfree(vdev);

	return ret;
}

static void vfio_pci_remove(struct pci_dev *pdev)
{
	struct vfio_pci_device *vdev;

	vdev = vfio_unbind_dev(&pdev->dev);
	if (!vdev)
		return;

	kfree(vdev);
}

static struct pci_driver vfio_pci_driver = {
	.name		= "vfio",
	.id_table	= NULL, /* only dynamic ids */
	.probe		= vfio_pci_probe,
	.remove		= vfio_pci_remove,
};

static bool vfio_pci_match(struct device *dev, const char *buf)
{
	return strcmp(dev_name(dev), buf) == 0;
}

static int vfio_pci_enable(struct vfio_pci_device *vdev)
{
	struct pci_dev *pdev = vdev->pdev;
	int ret;
	u16 cmd;
	u8 msix_pos;

	vdev->reset_works = (pci_reset_function(pdev) == 0);
	pci_save_state(pdev);
	vdev->pci_saved_state = pci_store_saved_state(pdev);
	if (!vdev->pci_saved_state)
		printk(KERN_DEBUG "%s: Couldn't store %s saved state\n",
		       __func__, dev_name(&pdev->dev));

	ret = vfio_config_init(vdev);
	if (ret)
		goto out;

	vdev->pci_2_3 = pci_intx_mask_supported(pdev);

	pci_read_config_word(pdev, PCI_COMMAND, &cmd);
	if (vdev->pci_2_3 && (cmd & PCI_COMMAND_INTX_DISABLE)) {
		cmd &= ~PCI_COMMAND_INTX_DISABLE;
		pci_write_config_word(pdev, PCI_COMMAND, cmd);
	}

	msix_pos = pci_find_capability(pdev, PCI_CAP_ID_MSIX);
	if (msix_pos) {
		u16 flags;
		u32 table;

		pci_read_config_word(pdev, msix_pos + PCI_MSIX_FLAGS, &flags);
		pci_read_config_dword(pdev, msix_pos + PCI_MSIX_TABLE, &table);

		vdev->msix_bar = table & PCI_MSIX_FLAGS_BIRMASK;
		vdev->msix_offset = table & ~PCI_MSIX_FLAGS_BIRMASK;
		vdev->msix_size = ((flags & PCI_MSIX_FLAGS_QSIZE) + 1) * 16;
	} else
		vdev->msix_bar = 0xFF;

	ret = pci_enable_device(pdev);
	if (ret)
		goto out;

	return ret;

out:
	kfree(vdev->pci_saved_state);
	vdev->pci_saved_state = NULL;
	vfio_config_free(vdev);
	return ret;
}

static void vfio_pci_disable(struct vfio_pci_device *vdev)
{
	int bar;

	pci_disable_device(vdev->pdev);

	if (vdev->ev_msix)
		vfio_pci_drop_msix(vdev);
	if (vdev->ev_msi)
		vfio_pci_drop_msi(vdev);
	if (vdev->ev_irq) {
		vfio_pci_drop_intx(vdev);
		vdev->virq_disabled = false;
	}

	vfio_config_free(vdev);

	if (pci_reset_function(vdev->pdev) == 0) {
		if (pci_load_and_free_saved_state(vdev->pdev,
						  &vdev->pci_saved_state) == 0)
			pci_restore_state(vdev->pdev);
		else
			printk(KERN_INFO "%s: Couldn't reload %s saved state\n",
			       __func__, dev_name(&vdev->pdev->dev));
	}

	for (bar = PCI_STD_RESOURCES; bar <= PCI_STD_RESOURCE_END; bar++) {
		if (!vdev->barmap[bar])
			continue;
		pci_iounmap(vdev->pdev, vdev->barmap[bar]);
		pci_release_selected_regions(vdev->pdev, 1 << bar);
		vdev->barmap[bar] = NULL;
	}
}

static void vfio_pci_release(void *device_data)
{
	struct vfio_pci_device *vdev = device_data;

	if (atomic_dec_and_test(&vdev->refcnt))
		vfio_pci_disable(vdev);

	module_put(THIS_MODULE);
}

static int vfio_pci_open(void *device_data)
{
	struct vfio_pci_device *vdev = device_data;

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	if (atomic_inc_return(&vdev->refcnt) == 1) {
		int ret = vfio_pci_enable(vdev);
		if (ret) {
			module_put(THIS_MODULE);
			return ret;
		}
	}

	return 0;
}

static int vfio_pci_get_irq_count(struct vfio_pci_device *vdev, int irq_type)
{
	if (irq_type == VFIO_PCI_INTX_IRQ_INDEX) {
		u8 pin;
		pci_read_config_byte(vdev->pdev, PCI_INTERRUPT_PIN, &pin);
		if (pin)
			return 1;

	} else if (irq_type == VFIO_PCI_MSI_IRQ_INDEX) {
		u8 pos;
		u16 flags;

		pos = pci_find_capability(vdev->pdev, PCI_CAP_ID_MSI);
		if (pos) {
			pci_read_config_word(vdev->pdev,
					     pos + PCI_MSI_FLAGS, &flags);

			return 1 << (flags & PCI_MSI_FLAGS_QMASK);
		}
	} else if (irq_type == VFIO_PCI_MSIX_IRQ_INDEX) {
		u8 pos;
		u16 flags;

		pos = pci_find_capability(vdev->pdev, PCI_CAP_ID_MSIX);
		if (pos) {
			pci_read_config_word(vdev->pdev,
					     pos + PCI_MSIX_FLAGS, &flags);

			return (flags & PCI_MSIX_FLAGS_QSIZE) + 1;
		}
	}

	return 0;
}

static long vfio_pci_ioctl(void *device_data,
			   unsigned int cmd, unsigned long arg)
{
	struct vfio_pci_device *vdev = device_data;
	unsigned long minsz;

	if (cmd == VFIO_DEVICE_GET_INFO) {
		struct vfio_device_info info;

		minsz = offsetofend(struct vfio_device_info, num_irqs);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz)
			return -EINVAL;

		info.flags = VFIO_DEVICE_FLAGS_PCI;

		if (vdev->reset_works)
			info.flags |= VFIO_DEVICE_FLAGS_RESET;

		info.num_regions = VFIO_PCI_NUM_REGIONS;
		info.num_irqs = VFIO_PCI_NUM_IRQS;

		return copy_to_user((void __user *)arg, &info, minsz);

	} else if (cmd == VFIO_DEVICE_GET_REGION_INFO) {
		struct pci_dev *pdev = vdev->pdev;
		struct vfio_region_info info;

		minsz = offsetofend(struct vfio_region_info, offset);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz || info.index >= VFIO_PCI_NUM_REGIONS)
			return -EINVAL;

		info.flags = 0;
		info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);

		if (info.index == VFIO_PCI_CONFIG_REGION_INDEX) {
			info.size = pdev->cfg_size;
		} else if (pci_resource_start(pdev, info.index)) {
			unsigned long flags;

			flags = pci_resource_flags(pdev, info.index);

			/* Report the actual ROM size instead of the BAR size,
			 * this gives the user an easy way to determine whether
			 * there's anything here w/o trying to read it. */
			if (info.index == VFIO_PCI_ROM_REGION_INDEX) {
				void __iomem *io;
				size_t size;

				io = pci_map_rom(pdev, &size);
				info.size = io ? size : 0;
				pci_unmap_rom(pdev, io);
				info.flags |= VFIO_REGION_INFO_FLAG_RO;
			} else if (flags & IORESOURCE_MEM) {
				info.size = pci_resource_len(pdev, info.index);
				info.flags |= VFIO_REGION_INFO_FLAG_MMAP;
			} else
				info.size = pci_resource_len(pdev, info.index);
		} else
			info.size = 0;

		return copy_to_user((void __user *)arg, &info, minsz);

	} else if (cmd == VFIO_DEVICE_GET_IRQ_INFO) {
		struct vfio_irq_info info;

		minsz = offsetofend(struct vfio_irq_info, count);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz || info.index >= VFIO_PCI_NUM_IRQS)
			return -EINVAL;

		info.flags = 0;

		info.count = vfio_pci_get_irq_count(vdev, info.index);

		if (info.count && info.index == VFIO_PCI_INTX_IRQ_INDEX)
			info.flags = VFIO_IRQ_INFO_FLAG_LEVEL;

		return copy_to_user((void __user *)arg, &info, minsz);

	} else if (cmd == VFIO_DEVICE_SET_IRQ_EVENTFDS) {
		struct vfio_irq_eventfds hdr;
		int32_t *fds = NULL;
		int ret = 0;

		minsz = offsetofend(struct vfio_irq_eventfds, count);

		if (copy_from_user(&hdr, (void __user *)arg, minsz))
			return -EFAULT;

		if (hdr.argsz < minsz || hdr.flags ||
		    hdr.index >= VFIO_PCI_NUM_IRQS)
			return -EINVAL;

		if (hdr.count) {
			if (hdr.argsz - minsz < hdr.count * sizeof(*fds) ||
			    hdr.count > vfio_pci_get_irq_count(vdev, hdr.index))
				return -EINVAL;

			fds = kmalloc(hdr.count * sizeof(*fds), GFP_KERNEL);
			if (!fds)
				return -ENOMEM;

			if (copy_from_user(fds, (void __user *)(arg + minsz),
					   hdr.count * sizeof(*fds))) {
				kfree(fds);
				return -EFAULT;
			}
		}

		mutex_lock(&vdev->igate);

		if (hdr.index == VFIO_PCI_INTX_IRQ_INDEX) {
			if (vdev->ev_msi) {
				ret = -EINVAL;
				goto out_unlock;
			}

			if (hdr.count && !vdev->ev_irq)
				ret = vfio_pci_setup_intx(vdev, hdr.count, fds);
			else if (!hdr.count && vdev->ev_irq)
				vfio_pci_drop_intx(vdev);
			else
				ret = -EINVAL;

		} else if (hdr.index == VFIO_PCI_MSI_IRQ_INDEX) {
			if (vdev->ev_irq) {
				ret = -EINVAL;
				goto out_unlock;
			}

			if (hdr.count && !vdev->ev_msi)
				ret = vfio_pci_setup_msi(vdev, hdr.count, fds);
			else if (!hdr.count && vdev->ev_msi)
				vfio_pci_drop_msi(vdev);
			else
				ret = -EINVAL;

		} else if (hdr.index == VFIO_PCI_MSIX_IRQ_INDEX) {
			if (hdr.count && !vdev->ev_msix)
				ret = vfio_pci_setup_msix(vdev, hdr.count, fds);
			else if (!hdr.count && vdev->ev_msix)
				vfio_pci_drop_msix(vdev);
			else
				ret = -EINVAL;
		}
out_unlock:
		mutex_unlock(&vdev->igate);
		kfree(fds);

		return ret;

	} else if (cmd == VFIO_DEVICE_UNMASK_IRQ) {
		struct vfio_unmask_irq unmask;

		minsz = offsetofend(struct vfio_unmask_irq, subindex);

		if (copy_from_user(&unmask, (void __user *)arg, minsz))
			return -EFAULT;

		if (unmask.argsz < minsz || unmask.subindex != 0 ||
		    unmask.flags || unmask.index != VFIO_PCI_INTX_IRQ_INDEX)
			return -EINVAL;

		return vfio_pci_irq_eoi(vdev);

	} else if (cmd == VFIO_DEVICE_SET_UNMASK_IRQ_EVENTFDS) {
		struct vfio_irq_eventfds hdr;
		int fd = -1;

		minsz = offsetofend(struct vfio_irq_eventfds, count);

		if (copy_from_user(&hdr, (void __user *)arg, minsz))
			return -EFAULT;

		if (hdr.argsz < minsz || hdr.count > 1 || hdr.flags ||
		    hdr.index != VFIO_PCI_INTX_IRQ_INDEX)
			return -EINVAL;

		if (hdr.count) {
			if (hdr.argsz < minsz + sizeof(fd))
				return -EINVAL;

			if (get_user(fd, (int __user *)(arg + minsz)))
				return -EFAULT;
		}

		return vfio_pci_irq_eoi_eventfd(vdev, fd);

	} else if (cmd == VFIO_DEVICE_RESET)
		return vdev->reset_works ?
			pci_reset_function(vdev->pdev) : -EINVAL;

	return -ENOTTY;
}

static ssize_t vfio_pci_read(void *device_data, char __user *buf,
			     size_t count, loff_t *ppos)
{
	unsigned int index = VFIO_PCI_OFFSET_TO_INDEX(*ppos);
	struct vfio_pci_device *vdev = device_data;
	struct pci_dev *pdev = vdev->pdev;

	if (index >= VFIO_PCI_NUM_REGIONS)
		return -EINVAL;

	if (index == VFIO_PCI_CONFIG_REGION_INDEX)
		return vfio_pci_config_readwrite(vdev, buf, count, ppos, false);
	else if (index == VFIO_PCI_ROM_REGION_INDEX)
		return vfio_pci_mem_readwrite(vdev, buf, count, ppos, false);
	else if (pci_resource_flags(pdev, index) & IORESOURCE_IO)
		return vfio_pci_io_readwrite(vdev, buf, count, ppos, false);
	else if (pci_resource_flags(pdev, index) & IORESOURCE_MEM)
		return vfio_pci_mem_readwrite(vdev, buf, count, ppos, false);

	return -EINVAL;
}

static ssize_t vfio_pci_write(void *device_data, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	unsigned int index = VFIO_PCI_OFFSET_TO_INDEX(*ppos);
	struct vfio_pci_device *vdev = device_data;
	struct pci_dev *pdev = vdev->pdev;

	if (index >= VFIO_PCI_NUM_REGIONS)
		return -EINVAL;

	if (index == VFIO_PCI_CONFIG_REGION_INDEX)
		return vfio_pci_config_readwrite(vdev, (char __user *)buf,
						 count, ppos, true);
	else if (index == VFIO_PCI_ROM_REGION_INDEX)
		return -EINVAL;
	else if (pci_resource_flags(pdev, index) & IORESOURCE_IO)
		return vfio_pci_io_readwrite(vdev, (char __user *)buf,
					     count, ppos, true);
	else if (pci_resource_flags(pdev, index) & IORESOURCE_MEM) {
		return vfio_pci_mem_readwrite(vdev, (char __user *)buf,
					      count, ppos, true);
	}

	return -EINVAL;
}

static int vfio_pci_mmap(void *device_data, struct vm_area_struct *vma)
{
	struct vfio_pci_device *vdev = device_data;
	struct pci_dev *pdev = vdev->pdev;
	unsigned int index;
	u64 phys_len, req_len, pgoff, req_start, phys;
	int ret;

	index = vma->vm_pgoff >> (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT);

	if (vma->vm_end < vma->vm_start)
		return -EINVAL;
	if ((vma->vm_flags & VM_SHARED) == 0)
		return -EINVAL;
	if (index >= VFIO_PCI_ROM_REGION_INDEX)
		return -EINVAL;
	if (!(pci_resource_flags(pdev, index) & IORESOURCE_MEM))
		return -EINVAL;

	phys_len = pci_resource_len(pdev, index);
	req_len = vma->vm_end - vma->vm_start;
	pgoff = vma->vm_pgoff &
		((1U << (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT)) - 1);
	req_start = pgoff << PAGE_SHIFT;

	if (phys_len < PAGE_SIZE || req_start + req_len > phys_len)
		return -EINVAL;

	if (index == vdev->msix_bar) {
		/*
		 * Disallow mmaps overlapping the MSI-X table; users don't
		 * get to touch this directly.  We could find somewhere
		 * else to map the overlap, but page granularity is only
		 * a recommendation, not a requirement, so the user needs
		 * to know which bits are real.  Requiring them to mmap
		 * around the table makes that clear.
		 */

		/* If neither entirely above nor below, then it overlaps */
		if (!(req_start >= vdev->msix_offset + vdev->msix_size ||
		      req_start + req_len <= vdev->msix_offset))
			return -EINVAL;
	}

	/*
	 * Even though we don't make use of the barmap for the mmap,
	 * we need to request the region and the barmap tracks that.
	 */
	if (!vdev->barmap[index]) {
		ret = pci_request_selected_regions(pdev, 1 << index, "vfio");
		if (ret)
			return ret;

		vdev->barmap[index] = pci_iomap(pdev, index, 0);
	}

	vma->vm_private_data = vdev;
	vma->vm_flags |= (VM_IO | VM_RESERVED);
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	phys = (pci_resource_start(pdev, index) >> PAGE_SHIFT) + pgoff;

	return remap_pfn_range(vma, vma->vm_start, phys,
			       req_len, vma->vm_page_prot);
}

static int vfio_pci_claim(struct device *dev)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	int ret;

	get_driver(&vfio_pci_driver.driver);

	pm_runtime_get_noresume(dev);
	pm_runtime_barrier(dev);

	dev->driver = &vfio_pci_driver.driver;

	pci_dev_get(pci_dev);

	pci_dev->driver = &vfio_pci_driver;

	ret = device_bind_driver(dev);
	if (ret)
		goto out_bind;

	pm_runtime_set_active(dev);
	pm_runtime_enable(dev);

	ret = vfio_pci_probe(pci_dev, NULL);
	if (ret)
		goto out_probe;

	pm_runtime_put_sync(dev);

	put_driver(&vfio_pci_driver.driver);

	return 0;

out_probe:
	pm_runtime_disable(dev);
	pm_runtime_set_suspended(dev);
	pm_runtime_put_noidle(dev);

out_bind:
	pci_dev_put(pci_dev);

	dev->driver = NULL;
	pci_dev->driver = NULL;

	put_driver(&vfio_pci_driver.driver);

	return ret;
}

static const struct vfio_device_ops vfio_pci_ops = {
	.match		= vfio_pci_match,
	.claim		= vfio_pci_claim,
	.open		= vfio_pci_open,
	.release	= vfio_pci_release,
	.ioctl		= vfio_pci_ioctl,
	.read		= vfio_pci_read,
	.write		= vfio_pci_write,
	.mmap		= vfio_pci_mmap,
};

static int vfio_pci_device_notifier(struct notifier_block *nb,
				    unsigned long action, void *data)
{
	struct device *dev = data;
	struct pci_dev *pdev = container_of(dev, struct pci_dev, dev);

	if (pdev->hdr_type != PCI_HEADER_TYPE_NORMAL)
		return 0;

	if (action == BUS_NOTIFY_ADD_DEVICE)
		return vfio_group_add_dev(dev, &vfio_pci_ops);
	else if (action == BUS_NOTIFY_DEL_DEVICE)
		vfio_group_del_dev(dev);

	return 0;
}

static int vfio_pci_do_dev_add(struct device *dev, void *data)
{
	struct pci_dev *pdev = container_of(dev, struct pci_dev, dev);

	if (pdev->hdr_type != PCI_HEADER_TYPE_NORMAL)
		return 0;

	return vfio_group_add_dev(dev, &vfio_pci_ops);
}

static int vfio_pci_do_dev_del(struct device *dev, void *data)
{
	struct pci_dev *pdev = container_of(dev, struct pci_dev, dev);

	if (pdev->hdr_type != PCI_HEADER_TYPE_NORMAL)
		return 0;

	vfio_group_del_dev(dev);
	return 0;
}

static struct notifier_block vfio_pci_device_nb = {
	.notifier_call = vfio_pci_device_notifier,
};

void __exit vfio_pci_cleanup(void)
{
	bus_unregister_notifier(&pci_bus_type, &vfio_pci_device_nb);
	pci_unregister_driver(&vfio_pci_driver);
	bus_for_each_dev(&pci_bus_type, NULL, NULL, vfio_pci_do_dev_del);
	vfio_pci_eoi_eventfd_exit();
	vfio_pci_uninit_perm_bits();
}

int __init vfio_pci_init(void)
{
	int ret;

	/* Allocate shared config space permision data used by all devices */
	ret = vfio_pci_init_perm_bits();
	if (ret)
		return ret;

	/* Start the eoi eventfd handler */
	ret = vfio_pci_eoi_eventfd_init();
	if (ret)
		goto out_eoi;

	/* Register and scan for devices */
	ret = pci_register_driver(&vfio_pci_driver);
	if (ret)
		goto out_driver;

	bus_register_notifier(&pci_bus_type, &vfio_pci_device_nb);
	bus_for_each_dev(&pci_bus_type, NULL, NULL, vfio_pci_do_dev_add);

	return 0;

out_eoi:
	vfio_pci_eoi_eventfd_exit();
out_driver:
	vfio_pci_uninit_perm_bits();
	return ret;
}

module_init(vfio_pci_init);
module_exit(vfio_pci_cleanup);

MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
