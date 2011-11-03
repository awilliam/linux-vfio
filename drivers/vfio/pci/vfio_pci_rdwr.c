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

/*
 * This code handles normal read and write system calls; allowing
 * access to device memory or I/O registers
 * without the need for mmap'ing.
 */

#include <linux/fs.h>
#include <linux/pci.h>
#include <linux/uaccess.h>
#include <linux/io.h>

#include "vfio_pci_private.h"

ssize_t vfio_pci_io_readwrite(
		int write,
		struct vfio_pci_device *vdev,
		char __user *buf,
		size_t count,
		loff_t *ppos)
{
	struct pci_dev *pdev = vdev->pdev;
	size_t done = 0;
	resource_size_t end;
	void __iomem *io;
	loff_t pos;
	u8 pci_space;
	int unit;

	pci_space = VFIO_PCI_OFFSET_TO_INDEX(*ppos);
	pos = *ppos & VFIO_PCI_OFFSET_MASK;

	if (!pci_resource_start(pdev, pci_space))
		return -EINVAL;
	end = pci_resource_len(pdev, pci_space);
	if (pos + count > end)
		return -EINVAL;
	if (!vdev->barmap[pci_space]) {
		int ret;

		ret = pci_request_selected_regions(pdev,
			(1 << pci_space), "vfio");
		if (ret)
			return ret;
		vdev->barmap[pci_space] = pci_iomap(pdev, pci_space, 0);
	}
	if (!vdev->barmap[pci_space])
		return -EINVAL;
	io = vdev->barmap[pci_space];

	while (count > 0) {
		if ((pos % 4) == 0 && count >= 4) {
			u32 val;

			if (write) {
				if (copy_from_user(&val, buf, 4))
					return -EFAULT;
				iowrite32(val, io + pos);
			} else {
				val = ioread32(io + pos);
				if (copy_to_user(buf, &val, 4))
					return -EFAULT;
			}
			unit = 4;
		} else if ((pos % 2) == 0 && count >= 2) {
			u16 val;

			if (write) {
				if (copy_from_user(&val, buf, 2))
					return -EFAULT;
				iowrite16(val, io + pos);
			} else {
				val = ioread16(io + pos);
				if (copy_to_user(buf, &val, 2))
					return -EFAULT;
			}
			unit = 2;
		} else {
			u8 val;

			if (write) {
				if (copy_from_user(&val, buf, 1))
					return -EFAULT;
				iowrite8(val, io + pos);
			} else {
				val = ioread8(io + pos);
				if (copy_to_user(buf, &val, 1))
					return -EFAULT;
			}
			unit = 1;
		}
		pos += unit;
		buf += unit;
		count -= unit;
		done += unit;
	}
	*ppos += done;
	return done;
}

/*
 * Read and write memory BARs
 * ROM is special because the ROM decoder can be shared with
 * other BAR decoders. Practically, that means you can't use
 * the ROM BAR if anything else is going on in the device.
 * The pci_map_rom and pci_unmap_rom calls will leave the ROM
 * BAR disabled upon return.
 */
ssize_t vfio_pci_mem_readwrite(
		int write,
		struct vfio_pci_device *vdev,
		char __user *buf,
		size_t count,
		loff_t *ppos)
{
	struct pci_dev *pdev = vdev->pdev;
	size_t done = 0;
	resource_size_t end;
	void __iomem *io;
	loff_t pos;
	u8 pci_space;
	int unit, ret;

	pci_space = VFIO_PCI_OFFSET_TO_INDEX(*ppos);
	pos = *ppos & VFIO_PCI_OFFSET_MASK;

	if (!pci_resource_start(pdev, pci_space))
		return -EINVAL;

	end = pci_resource_len(pdev, pci_space);

	if (pos > end)
		return -EINVAL;

	if (pos == end)
		return 0;

	if (pos + count > end)
		count = end - pos;

	if (pci_space == PCI_ROM_RESOURCE) {
		size_t size = end;

		io = pci_map_rom(pdev, &size);
	} else {
		if (!vdev->barmap[pci_space]) {
			int ret;

			ret = pci_request_selected_regions(pdev,
				(1 << pci_space), "vfio");
			if (ret)
				return ret;
			vdev->barmap[pci_space] =
				pci_iomap(pdev, pci_space, 0);
		}
		io = vdev->barmap[pci_space];
	}
	if (!io)
		return -EINVAL;

	ret = -EFAULT;

	while (count > 0) {
		if ((pos % 4) == 0 && count >= 4) {
			u32 val;

			if (write) {
				if (copy_from_user(&val, buf, 4))
					goto out;
				iowrite32(val, io + pos);
			} else {
				val = ioread32(io + pos);
				if (copy_to_user(buf, &val, 4))
					goto out;
			}
			unit = 4;
		} else if ((pos % 2) == 0 && count >= 2) {
			u16 val;

			if (write) {
				if (copy_from_user(&val, buf, 2))
					goto out;
				iowrite16(val, io + pos);
			} else {
				val = ioread16(io + pos);
				if (copy_to_user(buf, &val, 2))
					goto out;
			}
			unit = 2;
		} else {
			u8 val;

			if (write) {
				if (copy_from_user(&val, buf, 1))
					goto out;
				iowrite8(val, io + pos);
			} else {
				val = ioread8(io + pos);
				if (copy_to_user(buf, &val, 1))
					goto out;
			}
			unit = 1;
		}
		pos += unit;
		buf += unit;
		count -= unit;
		done += unit;
	}
	*ppos += done;
	ret = done;
out:
	if (pci_space == PCI_ROM_RESOURCE && io)
		pci_unmap_rom(pdev, io);
	return ret;
}
