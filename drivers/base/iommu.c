/*
 * Copyright (C) 2007-2008 Advanced Micro Devices, Inc.
 * Author: Joerg Roedel <joerg.roedel@amd.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <linux/bug.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/iommu.h>
#include <linux/pci.h>

static struct iommu_ops *iommu_ops;

static ssize_t show_iommu_group(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	unsigned int groupid;

	if (iommu_device_group(dev, &groupid))
		return 0;

	return sprintf(buf, "%u", groupid);
}
static DEVICE_ATTR(iommu_group, S_IRUGO, show_iommu_group, NULL);

static int add_iommu_group(struct device *dev, void *unused)
{
	unsigned int groupid;

	if (iommu_device_group(dev, &groupid) == 0)
		return device_create_file(dev, &dev_attr_iommu_group);

	return 0;
}

static int device_notifier(struct notifier_block *nb,
			   unsigned long action, void *data)
{
	struct device *dev = data;

	if (action == BUS_NOTIFY_ADD_DEVICE)
		return add_iommu_group(dev, NULL);

	return 0;
}

static struct notifier_block device_nb = {
	.notifier_call = device_notifier,
};

void register_iommu(struct iommu_ops *ops)
{
	if (iommu_ops)
		BUG();

	iommu_ops = ops;

	/* FIXME - non-PCI, really want for_each_bus() */
	bus_register_notifier(&pci_bus_type, &device_nb);
	bus_for_each_dev(&pci_bus_type, NULL, NULL, add_iommu_group);
}

bool iommu_found(void)
{
	return iommu_ops != NULL;
}
EXPORT_SYMBOL_GPL(iommu_found);

struct iommu_domain *iommu_domain_alloc(void)
{
	struct iommu_domain *domain;
	int ret;

	domain = kmalloc(sizeof(*domain), GFP_KERNEL);
	if (!domain)
		return NULL;

	ret = iommu_ops->domain_init(domain);
	if (ret)
		goto out_free;

	return domain;

out_free:
	kfree(domain);

	return NULL;
}
EXPORT_SYMBOL_GPL(iommu_domain_alloc);

void iommu_domain_free(struct iommu_domain *domain)
{
	iommu_ops->domain_destroy(domain);
	kfree(domain);
}
EXPORT_SYMBOL_GPL(iommu_domain_free);

int iommu_attach_device(struct iommu_domain *domain, struct device *dev)
{
	return iommu_ops->attach_dev(domain, dev);
}
EXPORT_SYMBOL_GPL(iommu_attach_device);

void iommu_detach_device(struct iommu_domain *domain, struct device *dev)
{
	iommu_ops->detach_dev(domain, dev);
}
EXPORT_SYMBOL_GPL(iommu_detach_device);

phys_addr_t iommu_iova_to_phys(struct iommu_domain *domain,
			       unsigned long iova)
{
	return iommu_ops->iova_to_phys(domain, iova);
}
EXPORT_SYMBOL_GPL(iommu_iova_to_phys);

int iommu_domain_has_cap(struct iommu_domain *domain,
			 unsigned long cap)
{
	return iommu_ops->domain_has_cap(domain, cap);
}
EXPORT_SYMBOL_GPL(iommu_domain_has_cap);

int iommu_device_group(struct device *dev, unsigned int *groupid)
{
	if (iommu_ops->device_group)
		return iommu_ops->device_group(dev, groupid);
	return -ENODEV;
}
EXPORT_SYMBOL_GPL(iommu_device_group);

int iommu_map(struct iommu_domain *domain, unsigned long iova,
	      phys_addr_t paddr, int gfp_order, int prot)
{
	unsigned long invalid_mask;
	size_t size;

	size         = 0x1000UL << gfp_order;
	invalid_mask = size - 1;

	BUG_ON((iova | paddr) & invalid_mask);

	return iommu_ops->map(domain, iova, paddr, gfp_order, prot);
}
EXPORT_SYMBOL_GPL(iommu_map);

int iommu_unmap(struct iommu_domain *domain, unsigned long iova, int gfp_order)
{
	unsigned long invalid_mask;
	size_t size;

	size         = 0x1000UL << gfp_order;
	invalid_mask = size - 1;

	BUG_ON(iova & invalid_mask);

	return iommu_ops->unmap(domain, iova, gfp_order);
}
EXPORT_SYMBOL_GPL(iommu_unmap);
