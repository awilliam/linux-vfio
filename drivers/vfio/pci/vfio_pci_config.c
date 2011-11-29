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
 * This code handles reading and writing of PCI configuration registers.
 * This is hairy because we want to allow a lot of flexibility to the
 * user driver, but cannot trust it with all of the config fields.
 * Tables determine which fields can be read and written, as well as
 * which fields are 'virtualized' - special actions and translations to
 * make it appear to the user that he has control, when in fact things
 * must be negotiated with the underlying OS.
 */

#include <linux/fs.h>
#include <linux/pci.h>
#include <linux/uaccess.h>

#include "vfio_pci_private.h"

#define	PCI_CFG_SPACE_SIZE	256

/* treat the standard header region as capability '0' */
#define PCI_CAP_ID_BASIC	0

/*
 * Lengths of PCI Config Capabilities
 * 0 means unknown (but at least 4)
 * FF means special/variable
 */
static u8 pci_capability_length[] = {
	[PCI_CAP_ID_BASIC]	= PCI_STD_HEADER_SIZEOF, /* pci config header */
	[PCI_CAP_ID_PM]		= PCI_PM_SIZEOF,
	[PCI_CAP_ID_AGP]	= PCI_AGP_SIZEOF,
	[PCI_CAP_ID_VPD]	= PCI_CAP_VPD_SIZEOF,
	[PCI_CAP_ID_SLOTID]	= 0,		/* bridge - don't care */
	[PCI_CAP_ID_MSI]	= 0xFF,		/* 10, 14, 20, or 24 */
	[PCI_CAP_ID_CHSWP]	= 0,		/* cpci - not yet */
	[PCI_CAP_ID_PCIX]	= 0xFF,		/* 8 or 24 */
	[PCI_CAP_ID_HT]		= 0xFF,		/* hypertransport */
	[PCI_CAP_ID_VNDR]	= 0xFF,		/* variable */
	[PCI_CAP_ID_DBG]	= 0,		/* debug - don't care */
	[PCI_CAP_ID_CCRC]	= 0,		/* cpci - not yet */
	[PCI_CAP_ID_SHPC]	= 0,		/* hotswap - not yet */
	[PCI_CAP_ID_SSVID]	= 0,		/* bridge - don't care */
	[PCI_CAP_ID_AGP3]	= 0,		/* AGP8x - not yet */
	[PCI_CAP_ID_SECDEV]	= 0,		/* secure device not yet */
	[PCI_CAP_ID_EXP]	= 0xFF,		/* 20 or 44 */
	[PCI_CAP_ID_MSIX]	= PCI_CAP_MSIX_SIZEOF,
	[PCI_CAP_ID_SATA]	= 0xFF,
	[PCI_CAP_ID_AF]		= PCI_CAP_AF_SIZEOF,
};

/*
 * Lengths of PCIe/PCI-X Extended Config Capabilities
 * 0 means unknown (but at least 4)
 * FF means special/variable
 */
static u16 pci_ext_capability_length[] = {
	[PCI_EXT_CAP_ID_ERR]	=	PCI_ERR_ROOT_COMMAND,
	[PCI_EXT_CAP_ID_VC]	=	0xFF,
	[PCI_EXT_CAP_ID_DSN]	=	PCI_EXT_CAP_DSN_SIZEOF,
	[PCI_EXT_CAP_ID_PWR]	=	PCI_EXT_CAP_PWR_SIZEOF,
	[PCI_EXT_CAP_ID_RCLD]	=	0,	/* root only - don't care */
	[PCI_EXT_CAP_ID_RCILC]	=	0,	/* root only - don't care */
	[PCI_EXT_CAP_ID_RCEC]	=	0,	/* root only - don't care */
	[PCI_EXT_CAP_ID_MFVC]	=	0xFF,
	[PCI_EXT_CAP_ID_VC9]	=	0xFF,	/* same as CAP_ID_VC */
	[PCI_EXT_CAP_ID_RCRB]	=	0,	/* root only - don't care */
	[PCI_EXT_CAP_ID_VNDR]	=	0xFF,
	[PCI_EXT_CAP_ID_CAC]	=	0,	/* obsolete */
	[PCI_EXT_CAP_ID_ACS]	=	0xFF,
	[PCI_EXT_CAP_ID_ARI]	=	PCI_EXT_CAP_ARI_SIZEOF,
	[PCI_EXT_CAP_ID_ATS]	=	PCI_EXT_CAP_ATS_SIZEOF,
	[PCI_EXT_CAP_ID_SRIOV]	=	PCI_EXT_CAP_SRIOV_SIZEOF,
	[PCI_EXT_CAP_ID_MRIOV]	=	0,	/* not yet */
	[PCI_EXT_CAP_ID_MCAST]	=	PCI_EXT_CAP_MCAST_ENDPOINT_SIZEOF,
	[PCI_EXT_CAP_ID_PRI]	=	PCI_EXT_CAP_PRI_SIZEOF,
	[PCI_EXT_CAP_ID_AMD_XXX] =	0,	/* not yet */
	[PCI_EXT_CAP_ID_REBAR]	=	0xFF,
	[PCI_EXT_CAP_ID_DPA]	=	0xFF,
	[PCI_EXT_CAP_ID_TPH]	=	0xFF,
	[PCI_EXT_CAP_ID_LTR]	=	PCI_EXT_CAP_LTR_SIZEOF,
	[PCI_EXT_CAP_ID_SECPCI]	=	0,	/* not yet */
	[PCI_EXT_CAP_ID_PMUX]	=	0,	/* not yet */
	[PCI_EXT_CAP_ID_PASID]	=	0,	/* not yet */
};

/*
 * Read/Write Permission Bits - one bit for each bit in capability
 * Any field can be read if it exists,
 * but what is read depends on whether the field
 * is 'virtualized', or just pass thru to the hardware.
 * Any virtualized field is also virtualized for writes.
 * Writes are only permitted if they have a 1 bit here.
 * Any virtualized fields need corresponding code in
 * vfio_config_rwbyte
 */
struct perm_bits {
	u8	*virt;		/* bits which must be virtualized */
	u8	*write;		/* writeable bits */
};

static struct perm_bits pci_cap_perms[PCI_CAP_ID_MAX+1];
static struct perm_bits pci_ext_cap_perms[PCI_EXT_CAP_ID_MAX+1];

#define	NO_VIRT		0
#define	ALL_VIRT	0xFFFFFFFFU
#define	NO_WRITE	0
#define	ALL_WRITE	0xFFFFFFFFU

static void free_perm_bits(struct perm_bits *perm)
{
	kfree(perm->virt);
	kfree(perm->write);
	perm->virt = NULL;
	perm->write = NULL;
}

static int alloc_perm_bits(struct perm_bits *perm, int sz)
{
	/*
	 * Zero state is
	 * - All Readable, None Writeable, None Virtualized
	 */
	perm->virt = kzalloc(sz, GFP_KERNEL);
	perm->write = kzalloc(sz, GFP_KERNEL);
	if (!perm->virt || !perm->write) {
		free_perm_bits(perm);
		return -ENOMEM;
	}
	return 0;
}

/*
 * Helper functions for filling in permission tables
 */
static inline void p_setb(struct perm_bits *p, int off, u32 virt, u32 write)
{
	p->virt[off] = (u8)virt;
	p->write[off] = (u8)write;
}

/* handle endian-ness - pci and tables are little-endian */
static inline void p_setw(struct perm_bits *p, int off, u32 virt, u32 write)
{
	*(u16 *)(&p->virt[off]) = cpu_to_le16((u16)virt);
	*(u16 *)(&p->write[off]) = cpu_to_le16((u16)write);
}

/* handle endian-ness - pci and tables are little-endian */
static inline void p_setd(struct perm_bits *p, int off, u32 virt, u32 write)
{
	*(u32 *)(&p->virt[off]) = cpu_to_le32(virt);
	*(u32 *)(&p->write[off]) = cpu_to_le32(write);
}

/* permissions for the Basic PCI Header */
static int __init init_pci_cap_basic_perm(struct perm_bits *perm)
{
	if (alloc_perm_bits(perm, PCI_STD_HEADER_SIZEOF))
		return -ENOMEM;

	/* virtualized for SR-IOV functions, which just have FFFF */
	p_setw(perm, PCI_VENDOR_ID,		ALL_VIRT, NO_WRITE);
	p_setw(perm, PCI_DEVICE_ID,		ALL_VIRT, NO_WRITE);

	/* for catching resume-after-reset */
	p_setw(perm, PCI_COMMAND,
		PCI_COMMAND_MEMORY + PCI_COMMAND_IO + PCI_COMMAND_INTX_DISABLE,
		ALL_WRITE);

	/* no harm to write */
	p_setb(perm, PCI_CACHE_LINE_SIZE,	NO_VIRT,  ALL_WRITE);
	p_setb(perm, PCI_LATENCY_TIMER,		NO_VIRT,  ALL_WRITE);
	p_setb(perm, PCI_BIST,			NO_VIRT,  ALL_WRITE);

	/* virtualize all bars, can't touch the real ones */
	p_setd(perm, PCI_BASE_ADDRESS_0,	ALL_VIRT, ALL_WRITE);
	p_setd(perm, PCI_BASE_ADDRESS_1,	ALL_VIRT, ALL_WRITE);
	p_setd(perm, PCI_BASE_ADDRESS_2,	ALL_VIRT, ALL_WRITE);
	p_setd(perm, PCI_BASE_ADDRESS_3,	ALL_VIRT, ALL_WRITE);
	p_setd(perm, PCI_BASE_ADDRESS_4,	ALL_VIRT, ALL_WRITE);
	p_setd(perm, PCI_BASE_ADDRESS_5,	ALL_VIRT, ALL_WRITE);
	p_setd(perm, PCI_ROM_ADDRESS,		ALL_VIRT, ALL_WRITE);

	/* sometimes used by sw, just virtualize */
	p_setb(perm, PCI_INTERRUPT_LINE,	ALL_VIRT, ALL_WRITE);
	return 0;
}

/* Permissions for the Power Management capability */
static int __init init_pci_cap_pm_perm(struct perm_bits *perm)
{
	if (alloc_perm_bits(perm, pci_capability_length[PCI_CAP_ID_PM]))
		return -ENOMEM;
	/*
	 * power management is defined *per function*,
	 * so we let the user write this
	 */
	p_setd(perm, PCI_PM_CTRL, NO_VIRT, ALL_WRITE);
	return 0;
}

/* Permissions for Vital Product Data capability */
static int __init init_pci_cap_vpd_perm(struct perm_bits *perm)
{
	if (alloc_perm_bits(perm, pci_capability_length[PCI_CAP_ID_VPD]))
		return -ENOMEM;
	p_setw(perm, PCI_VPD_ADDR, NO_VIRT, ALL_WRITE);
	p_setd(perm, PCI_VPD_DATA, NO_VIRT, ALL_WRITE);
	return 0;
}

/* Permissions for PCI-X capability */
static int __init init_pci_cap_pcix_perm(struct perm_bits *perm)
{
	/* alloc 24, but only 8 are used in v0 */
	if (alloc_perm_bits(perm, PCI_CAP_PCIX_SIZEOF_V12))
		return -ENOMEM;
	p_setw(perm, PCI_X_CMD, NO_VIRT, ALL_WRITE);
	p_setd(perm, PCI_X_ECC_CSR, NO_VIRT, ALL_WRITE);
	return 0;
}

/* Permissions for PCI Express capability */
static int __init init_pci_cap_exp_perm(struct perm_bits *perm)
{
	/* alloc larger of two possible sizes */
	if (alloc_perm_bits(perm, PCI_CAP_EXP_ENDPOINT_SIZEOF_V2))
		return -ENOMEM;
	/*
	 * allow writes to device control fields (includes FLR!)
	 * but not to devctl_phantom which could confuse IOMMU
	 * or to the ARI bit in devctl2 which is set at probe time
	 */
	p_setw(perm, PCI_EXP_DEVCTL, NO_VIRT, ~PCI_EXP_DEVCTL_PHANTOM);
	p_setw(perm, PCI_EXP_DEVCTL2, NO_VIRT, ~PCI_EXP_DEVCTL2_ARI);
	return 0;
}

/* Permissions for MSI-X capability */
static int __init init_pci_cap_msix_perm(struct perm_bits *perm)
{
	/* all default - only written via ioctl */
	return 0;
}

/* Permissions for Advanced Function capability */
static int __init init_pci_cap_af_perm(struct perm_bits *perm)
{
	if (alloc_perm_bits(perm, pci_capability_length[PCI_CAP_ID_AF]))
		return -ENOMEM;
	p_setb(perm, PCI_AF_CTRL, NO_VIRT, PCI_AF_CTRL_FLR);
	return 0;
}

/* Permissions for Advanced Error Reporting extended capability */
static int __init init_pci_ext_cap_err_perm(struct perm_bits *perm)
{
	u32 mask;

	if (alloc_perm_bits(perm,
	    pci_ext_capability_length[PCI_EXT_CAP_ID_ERR]))
		return -ENOMEM;
	mask =    PCI_ERR_UNC_TRAIN	/* Training */
		| PCI_ERR_UNC_DLP	/* Data Link Protocol */
		| PCI_ERR_UNC_SURPDN	/* Surprise Down */
		| PCI_ERR_UNC_POISON_TLP	/* Poisoned TLP */
		| PCI_ERR_UNC_FCP	/* Flow Control Protocol */
		| PCI_ERR_UNC_COMP_TIME	/* Completion Timeout */
		| PCI_ERR_UNC_COMP_ABORT	/* Completer Abort */
		| PCI_ERR_UNC_UNX_COMP	/* Unexpected Completion */
		| PCI_ERR_UNC_RX_OVER	/* Receiver Overflow */
		| PCI_ERR_UNC_MALF_TLP	/* Malformed TLP */
		| PCI_ERR_UNC_ECRC	/* ECRC Error Status */
		| PCI_ERR_UNC_UNSUP	/* Unsupported Request */
		| PCI_ERR_UNC_ACSV	/* ACS Violation */
		| PCI_ERR_UNC_INTN	/* internal error */
		| PCI_ERR_UNC_MCBTLP	/* MC blocked TLP */
		| PCI_ERR_UNC_ATOMEG	/* Atomic egress blocked */
		| PCI_ERR_UNC_TLPPRE;	/* TLP prefix blocked */
	p_setd(perm, PCI_ERR_UNCOR_STATUS, NO_VIRT, mask);
	p_setd(perm, PCI_ERR_UNCOR_MASK,   NO_VIRT, mask);
	p_setd(perm, PCI_ERR_UNCOR_SEVER,  NO_VIRT, mask);

	mask =    PCI_ERR_COR_RCVR	/* Receiver Error Status */
		| PCI_ERR_COR_BAD_TLP	/* Bad TLP Status */
		| PCI_ERR_COR_BAD_DLLP	/* Bad DLLP Status */
		| PCI_ERR_COR_REP_ROLL	/* REPLAY_NUM Rollover */
		| PCI_ERR_COR_REP_TIMER	/* Replay Timer Timeout */
		| PCI_ERR_COR_ADV_NFAT	/* Advisory Non-Fatal */
		| PCI_ERR_COR_INTERNAL	/* Corrected Internal */
		| PCI_ERR_COR_LOG_OVER;	/* Header Log Overflow */
	p_setd(perm, PCI_ERR_COR_STATUS, NO_VIRT, mask);
	p_setd(perm, PCI_ERR_COR_MASK,   NO_VIRT, mask);

	mask =    PCI_ERR_CAP_ECRC_GENC
		| PCI_ERR_CAP_ECRC_GENE
		| PCI_ERR_CAP_ECRC_CHKE;
	p_setd(perm, PCI_ERR_CAP,	NO_VIRT, mask);
	return 0;
}

/* Permissions for Power Budgeting extended capability */
static int __init init_pci_ext_cap_pwr_perm(struct perm_bits *perm)
{
	if (alloc_perm_bits(perm,
	    pci_ext_capability_length[PCI_EXT_CAP_ID_PWR]))
		return -ENOMEM;
	/* writing the data selector is OK, the info is still read-only */
	p_setb(perm, PCI_PWR_DATA,	NO_VIRT, ALL_WRITE);
	return 0;
}

/*
 * Initialize the shared permission tables
 */
void __exit vfio_pci_uninit_perm_bits(void)
{
	free_perm_bits(&pci_cap_perms[PCI_CAP_ID_BASIC]);
	free_perm_bits(&pci_cap_perms[PCI_CAP_ID_PM]);
	free_perm_bits(&pci_cap_perms[PCI_CAP_ID_VPD]);
	free_perm_bits(&pci_cap_perms[PCI_CAP_ID_PCIX]);
	free_perm_bits(&pci_cap_perms[PCI_CAP_ID_EXP]);
	free_perm_bits(&pci_cap_perms[PCI_CAP_ID_AF]);
	free_perm_bits(&pci_ext_cap_perms[PCI_EXT_CAP_ID_ERR]);
	free_perm_bits(&pci_ext_cap_perms[PCI_EXT_CAP_ID_PWR]);
}

int __init vfio_pci_init_perm_bits(void)
{
	int ret;

	/* basic config space */
	ret = init_pci_cap_basic_perm(&pci_cap_perms[PCI_CAP_ID_BASIC]);
	/* capabilities */
	ret |= init_pci_cap_pm_perm(&pci_cap_perms[PCI_CAP_ID_PM]);
	ret |= init_pci_cap_vpd_perm(&pci_cap_perms[PCI_CAP_ID_VPD]);
	ret |= init_pci_cap_pcix_perm(&pci_cap_perms[PCI_CAP_ID_PCIX]);
	ret |= init_pci_cap_exp_perm(&pci_cap_perms[PCI_CAP_ID_EXP]);
	ret |= init_pci_cap_msix_perm(&pci_cap_perms[PCI_CAP_ID_MSIX]);
	ret |= init_pci_cap_af_perm(&pci_cap_perms[PCI_CAP_ID_AF]);
	/* extended capabilities */
	ret |= init_pci_ext_cap_err_perm(
		&pci_ext_cap_perms[PCI_EXT_CAP_ID_ERR]);
	ret |= init_pci_ext_cap_pwr_perm(
		&pci_ext_cap_perms[PCI_EXT_CAP_ID_PWR]);

	if (ret)
		vfio_pci_uninit_perm_bits();

	return ret;
}

/*
 * MSI determination is per-device, so this routine
 * gets used beyond initialization time
 * Don't add __init
 */
static int init_pci_cap_msi_perm(struct perm_bits *perm, int len, u16 flags)
{
	if (alloc_perm_bits(perm, len))
		return -ENOMEM;
	/* next is byte only, not word, hi byte remains default */
	p_setb(perm, PCI_MSI_FLAGS,		ALL_VIRT, ALL_WRITE);
	p_setd(perm, PCI_MSI_ADDRESS_LO,	ALL_VIRT, ALL_WRITE);
	if (flags & PCI_MSI_FLAGS_64BIT) {
		p_setd(perm, PCI_MSI_ADDRESS_HI, ALL_VIRT, ALL_WRITE);
		p_setw(perm, PCI_MSI_DATA_64,	 ALL_VIRT, ALL_WRITE);
		if (flags & PCI_MSI_FLAGS_MASKBIT) {
			p_setd(perm, PCI_MSI_MASK_64,	 NO_VIRT, ALL_WRITE);
			p_setd(perm, PCI_MSI_PENDING_64, NO_VIRT, ALL_WRITE);
		}
	} else {
		p_setw(perm, PCI_MSI_DATA_32,	 ALL_VIRT, ALL_WRITE);
		if (flags & PCI_MSI_FLAGS_MASKBIT) {
			p_setd(perm, PCI_MSI_MASK_32,	 NO_VIRT, ALL_WRITE);
			p_setd(perm, PCI_MSI_PENDING_32, NO_VIRT, ALL_WRITE);
		}
	}
	return 0;
}

/*
 * Determine MSI CAP field length; also initialize permissions
 */
static int vfio_msi_cap_len(struct vfio_pci_device *vdev, u8 pos)
{
	struct pci_dev *pdev = vdev->pdev;
	int len;
	int ret;
	u16 flags;

	ret = pci_read_config_word(pdev, pos + PCI_MSI_FLAGS, &flags);
	if (ret < 0)
		return ret;
	len = 10;
	if (flags & PCI_MSI_FLAGS_64BIT)
		len += 4;
	if (flags & PCI_MSI_FLAGS_MASKBIT)
		len += 10;

	if (vdev->msi_perm)
		return len;
	vdev->msi_perm = kmalloc(sizeof(struct perm_bits), GFP_KERNEL);
	if (vdev->msi_perm)
		init_pci_cap_msi_perm(vdev->msi_perm, len, flags);
	return len;
}

/*
 * Determine extended capability length for VC (2 & 9) and
 * MFVC capabilities
 */
static int vfio_vc_cap_len(struct vfio_pci_device *vdev, u16 pos)
{
	struct pci_dev *pdev = vdev->pdev;
	u32 dw;
	int ret;
	int evcc, ph, vc_arb;
	int len = PCI_CAP_VC_BASE_SIZEOF;

	ret = pci_read_config_dword(pdev, pos + PCI_VC_PORT_REG1, &dw);
	if (ret < 0)
		return 0;
	evcc = dw & PCI_VC_REG1_EVCC;
	ret = pci_read_config_dword(pdev, pos + PCI_VC_PORT_REG2, &dw);
	if (ret < 0)
		return 0;
	if (dw & PCI_VC_REG2_128_PHASE)
		ph = 128;
	else if (dw & PCI_VC_REG2_64_PHASE)
		ph = 64;
	else if (dw & PCI_VC_REG2_32_PHASE)
		ph = 32;
	else
		ph = 0;
	vc_arb = ph * 4;
	/*
	 * port arbitration tables are root & switch only;
	 * function arbitration tables are function 0 only.
	 * In either case, we'll never let user write them so
	 * we don't care how big they are
	 */
	len += (1 + evcc) * PCI_CAP_VC_PER_VC_SIZEOF;
	if (vc_arb) {
		len = round_up(len, 16);
		len += vc_arb/8;
	}
	return len;
}

/*
 * We build a map of the config space that tells us where
 * and what capabilities exist, so that we can map reads and
 * writes back to capabilities, and thus figure out what to
 * allow, deny, or virtualize
 */
int vfio_pci_build_config_map(struct vfio_pci_device *vdev)
{
	struct pci_dev *pdev = vdev->pdev;
	u8 *map;
	int i, len;
	u8 pos, cap, tmp, httype;
	u16 epos, ecap;
	u16 flags;
	int ret;
	int loops;
	int extended_caps = 0;
	u32 header, dw;

	map = kmalloc(pdev->cfg_size, GFP_KERNEL);
	if (!map)
		return -ENOMEM;
	for (i = 0; i < pdev->cfg_size; i++)
		map[i] = 0xFF;
	vdev->pci_config_map = map;

	/* default config space */
	for (i = 0; i < PCI_STD_HEADER_SIZEOF; i++)
		map[i] = 0;

	/* any capabilities? */
	ret = pci_read_config_word(pdev, PCI_STATUS, &flags);
	if (ret < 0)
		return ret;
	if ((flags & PCI_STATUS_CAP_LIST) == 0)
		return 0;

	ret = pci_read_config_byte(pdev, PCI_CAPABILITY_LIST, &pos);
	if (ret < 0)
		return ret;
	loops = (PCI_CFG_SPACE_SIZE - PCI_STD_HEADER_SIZEOF) / PCI_CAP_SIZEOF;
	while (pos && --loops > 0) {
		ret = pci_read_config_byte(pdev, pos, &cap);
		if (ret < 0)
			return ret;
		if (cap == 0) {
			printk(KERN_WARNING "%s: cap 0\n", __func__);
			break;
		}
		if (cap > PCI_CAP_ID_MAX) {
			printk(KERN_WARNING
				"%s: unknown pci capability id %x\n",
				__func__, cap);
			len = 0;
		} else
			len = pci_capability_length[cap];
		if (len == 0) {
			printk(KERN_WARNING
				"%s: unknown length for pci cap %x\n",
				__func__, cap);
			len = PCI_CAP_SIZEOF;
		}
		if (len == 0xFF) {	/* variable field */
			switch (cap) {
			case PCI_CAP_ID_MSI:
				len = vfio_msi_cap_len(vdev, pos);
				if (len < 0)
					return len;
				break;
			case PCI_CAP_ID_PCIX:
				ret = pci_read_config_word(pdev,
					pos + PCI_X_CMD, &flags);
				if (ret < 0)
					return ret;
				if (PCI_X_CMD_VERSION(flags)) {
					extended_caps++;
					len = PCI_CAP_PCIX_SIZEOF_V12;
				} else
					len = PCI_CAP_PCIX_SIZEOF_V0;
				break;
			case PCI_CAP_ID_VNDR:
				/* length follows next field */
				ret = pci_read_config_byte(pdev, pos + 2, &tmp);
				if (ret < 0)
					return ret;
				len = tmp;
				break;
			case PCI_CAP_ID_EXP:
				/* length based on version */
				ret = pci_read_config_word(pdev,
					pos + PCI_EXP_FLAGS, &flags);
				if (ret < 0)
					return ret;
				if ((flags & PCI_EXP_FLAGS_VERS) == 1)
					len = PCI_CAP_EXP_ENDPOINT_SIZEOF_V1;
				else
					len = PCI_CAP_EXP_ENDPOINT_SIZEOF_V2;
				extended_caps++;
				break;
			case PCI_CAP_ID_HT:
				ret = pci_read_config_byte(pdev,
					pos + 3, &httype);
				if (ret < 0)
					return ret;
				len = (httype & HT_3BIT_CAP_MASK) ?
					HT_CAP_SIZEOF_SHORT :
					HT_CAP_SIZEOF_LONG;
				break;
			case PCI_CAP_ID_SATA:
				ret = pci_read_config_byte(pdev,
					pos + PCI_SATA_REGS, &tmp);
				if (ret < 0)
					return ret;
				tmp &= PCI_SATA_REGS_MASK;
				if (tmp == PCI_SATA_REGS_INLINE)
					len = PCI_SATA_SIZEOF_LONG;
				else
					len = PCI_SATA_SIZEOF_SHORT;
			default:
				printk(KERN_WARNING
					"%s: unknown length for pci cap %x\n",
					__func__, cap);
				len = PCI_CAP_SIZEOF;
				break;
			}
		}

		for (i = 0; i < len; i++) {
			if (map[pos+i] != 0xFF)
				printk(KERN_WARNING
					"%s: pci config conflict at %x, "
					"caps %x %x\n",
					__func__, pos+i, map[pos+i], cap);
			map[pos+i] = cap;
		}
		ret = pci_read_config_byte(pdev, pos + PCI_CAP_LIST_NEXT, &pos);
		if (ret < 0)
			return ret;
	}
	if (loops <= 0)
		printk(KERN_ERR "%s: config space loop!\n", __func__);
	if (!extended_caps)
		return 0;
	/*
	 * We get here if there are PCIe or PCI-X extended capabilities
	 */
	epos = PCI_CFG_SPACE_SIZE;
	loops = (4096 - PCI_CFG_SPACE_SIZE) / PCI_CAP_SIZEOF;
	while (loops-- > 0) {
		ret = pci_read_config_dword(pdev, epos, &header);
		if (ret || header == 0)
			break;
		ecap = PCI_EXT_CAP_ID(header);
		if (ecap > PCI_EXT_CAP_ID_MAX) {
			printk(KERN_WARNING
				"%s: unknown pci ext capability id %x\n",
				__func__, ecap);
			len = 0;
		} else
			len = pci_ext_capability_length[ecap];
		if (len == 0xFF) {	/* variable field */
			switch (ecap) {
			case PCI_EXT_CAP_ID_VNDR:
				ret = pci_read_config_dword(pdev,
					epos + PCI_VSEC_HDR, &dw);
				if (ret)
					break;
				len = dw >> PCI_VSEC_HDR_LEN_SHIFT;
				break;
			case PCI_EXT_CAP_ID_VC:
			case PCI_EXT_CAP_ID_VC9:
			case PCI_EXT_CAP_ID_MFVC:
				len = vfio_vc_cap_len(vdev, epos);
				break;
			case PCI_EXT_CAP_ID_ACS:
				ret = pci_read_config_byte(pdev,
					epos + PCI_ACS_CAP, &tmp);
				if (ret)
					break;
				len = 8;
				if (tmp & PCI_ACS_EC) {
					int bits;

					ret = pci_read_config_byte(pdev,
						epos + PCI_ACS_EGRESS_BITS,
						 &tmp);
					if (ret)
						break;
					bits = tmp ? tmp : 256;
					bits = round_up(bits, 32);
					len += bits/8;
				}
				break;
			case PCI_EXT_CAP_ID_REBAR:
				ret = pci_read_config_byte(pdev,
					epos + PCI_REBAR_CTRL, &tmp);
				if (ret)
					break;
				len = 4;
				tmp = (tmp & PCI_REBAR_CTRL_NBAR_MASK)
					>> PCI_REBAR_CTRL_NBAR_SHIFT;
				len += tmp * 8;
				break;
			case PCI_EXT_CAP_ID_DPA:
				ret = pci_read_config_byte(pdev,
					epos + PCI_DPA_CAP, &tmp);
				if (ret)
					break;
				tmp &= PCI_DPA_CAP_SUBSTATE_MASK;
				tmp = round_up(tmp+1, 4);
				len = PCI_DPA_BASE_SIZEOF + tmp;
				break;
			case PCI_EXT_CAP_ID_TPH:
				ret = pci_read_config_dword(pdev,
					epos + PCI_TPH_CAP, &dw);
				if (ret)
					break;
				len = PCI_TPH_BASE_SIZEOF;
				flags = dw & PCI_TPH_CAP_LOC_MASK;
				if (flags == PCI_TPH_LOC_CAP) {
					int sts;

					sts = (dw & PCI_TPH_CAP_ST_MASK)
						>> PCI_TPH_CAP_ST_SHIFT;
					len += round_up(2 * sts, 4);
				}
				break;
			default:
				len = 0;
				break;
			}
		}
		if (len == 0 || len == 0xFF) {
			printk(KERN_WARNING
				"%s: unknown length for pci ext cap %x\n",
				__func__, ecap);
			len = PCI_CAP_SIZEOF;
		}
		for (i = 0; i < len; i++) {
			if (map[epos+i] != 0xFF)
				printk(KERN_WARNING
					"%s: pci config conflict at %x, "
					"caps %x %x\n",
					__func__, epos+i, map[epos+i], ecap);
			map[epos+i] = ecap;
		}

		epos = PCI_EXT_CAP_NEXT(header);
		if (epos < PCI_CFG_SPACE_SIZE)
			break;
	}
	return 0;
}

/*
 * Initialize the virtual fields with the contents
 * of the real hardware fields
 */
static int vfio_virt_init(struct vfio_pci_device *vdev)
{
	struct pci_dev *pdev = vdev->pdev;
	u32 *lp;
	int i;

	vdev->vconfig = kmalloc(pdev->cfg_size, GFP_KERNEL);
	if (!vdev->vconfig)
		return -ENOMEM;

	lp = (u32 *)vdev->vconfig;
	for (i = 0; i < pdev->cfg_size/sizeof(u32); i++, lp++)
		pci_read_config_dword(pdev, i * sizeof(u32), lp);
	vdev->bardirty = 1;

	/* for restore after reset */
	vdev->rbar[0] = *(u32 *)&vdev->vconfig[PCI_BASE_ADDRESS_0];
	vdev->rbar[1] = *(u32 *)&vdev->vconfig[PCI_BASE_ADDRESS_1];
	vdev->rbar[2] = *(u32 *)&vdev->vconfig[PCI_BASE_ADDRESS_2];
	vdev->rbar[3] = *(u32 *)&vdev->vconfig[PCI_BASE_ADDRESS_3];
	vdev->rbar[4] = *(u32 *)&vdev->vconfig[PCI_BASE_ADDRESS_4];
	vdev->rbar[5] = *(u32 *)&vdev->vconfig[PCI_BASE_ADDRESS_5];
	vdev->rbar[6] = *(u32 *)&vdev->vconfig[PCI_ROM_ADDRESS];

	/* for sr-iov devices */
	vdev->vconfig[PCI_VENDOR_ID] = pdev->vendor & 0xFF;
	vdev->vconfig[PCI_VENDOR_ID+1] = pdev->vendor >> 8;
	vdev->vconfig[PCI_DEVICE_ID] = pdev->device & 0xFF;
	vdev->vconfig[PCI_DEVICE_ID+1] = pdev->device >> 8;

	return 0;
}

/*
 * Restore the *real* BARs after we detect a FLR or backdoor reset.
 * (backdoor = some device specific technique that we didn't catch)
 */
static void vfio_bar_restore(struct vfio_pci_device *vdev)
{
	if (vdev->pdev->is_virtfn)
		return;
	printk(KERN_WARNING "%s: reset recovery - restoring bars\n", __func__);

#define do_bar(off, which) \
	pci_user_write_config_dword(vdev->pdev, off, vdev->rbar[which])

	do_bar(PCI_BASE_ADDRESS_0, 0);
	do_bar(PCI_BASE_ADDRESS_1, 1);
	do_bar(PCI_BASE_ADDRESS_2, 2);
	do_bar(PCI_BASE_ADDRESS_3, 3);
	do_bar(PCI_BASE_ADDRESS_4, 4);
	do_bar(PCI_BASE_ADDRESS_5, 5);
	do_bar(PCI_ROM_ADDRESS, 6);
#undef do_bar
}

/*
 * Pretend we're hardware and tweak the values
 * of the *virtual* pci BARs to reflect the hardware
 * capabilities
 */
static void vfio_bar_fixup(struct vfio_pci_device *vdev)
{
	struct pci_dev *pdev = vdev->pdev;
	int bar;
	u32 *lp;
	u64 mask;

	for (bar = 0; bar <= 5; bar++) {
		if (pci_resource_start(pdev, bar))
			mask = ~(pci_resource_len(pdev, bar) - 1);
		else
			mask = 0;
		lp = (u32 *)(vdev->vconfig + PCI_BASE_ADDRESS_0 + 4*bar);
		*lp &= (u32)mask;

		if (pci_resource_flags(pdev, bar) & IORESOURCE_IO)
			*lp |= PCI_BASE_ADDRESS_SPACE_IO;
		else if (pci_resource_flags(pdev, bar) & IORESOURCE_MEM) {
			*lp |= PCI_BASE_ADDRESS_SPACE_MEMORY;
			if (pci_resource_flags(pdev, bar) & IORESOURCE_PREFETCH)
				*lp |= PCI_BASE_ADDRESS_MEM_PREFETCH;
			if (pci_resource_flags(pdev, bar) & IORESOURCE_MEM_64) {
				*lp |= PCI_BASE_ADDRESS_MEM_TYPE_64;
				lp++;
				*lp &= (u32)(mask >> 32);
				bar++;
			}
		}
	}

	if (pci_resource_start(pdev, PCI_ROM_RESOURCE)) {
		mask = ~(pci_resource_len(pdev, PCI_ROM_RESOURCE) - 1);
		mask |= PCI_ROM_ADDRESS_ENABLE;
	} else
		mask = 0;
	lp = (u32 *)(vdev->vconfig + PCI_ROM_ADDRESS);
	*lp &= (u32)mask;

	vdev->bardirty = 0;
}

static inline int vfio_read_config_byte(struct vfio_pci_device *vdev,
					int pos, u8 *valp)
{
	return pci_user_read_config_byte(vdev->pdev, pos, valp);
}

static inline int vfio_write_config_byte(struct vfio_pci_device *vdev,
					int pos, u8 val)
{
	return pci_user_write_config_byte(vdev->pdev, pos, val);
}

/* handle virtualized fields in the basic config space */
static void vfio_virt_basic(struct vfio_pci_device *vdev, int write, u16 pos, u8 *rbp)
{
	u8 val;

	switch (pos) {
	case PCI_COMMAND:
		/*
		 * If the real mem or IO enable bits are zero
		 * then there may have been a FLR or backdoor reset.
		 * Restore the real BARs before allowing those
		 * bits to re-enable
		 */
		val = vdev->vconfig[pos];
		if (vdev->pdev->is_virtfn)
			val |= PCI_COMMAND_MEMORY;
		if (write) {

			if (((val & PCI_COMMAND_MEMORY) >
				(*rbp & PCI_COMMAND_MEMORY)) ||
			    ((val & PCI_COMMAND_IO) >
				(*rbp & PCI_COMMAND_IO)))
					vfio_bar_restore(vdev);
			*rbp &= ~(PCI_COMMAND_MEMORY + PCI_COMMAND_IO);
			*rbp |= val & (PCI_COMMAND_MEMORY + PCI_COMMAND_IO);
		}
		vdev->vconfig[pos] = val;
		break;
	case PCI_COMMAND + 1:
		if (write) {
			u16 cmd = vdev->vconfig[pos] << 8;

			if ((cmd & PCI_COMMAND_INTX_DISABLE) &&
			    !vdev->virq_disabled) {
				vdev->virq_disabled = 1;
				vfio_pci_disable_intx(vdev);
			}
			if (!(cmd & PCI_COMMAND_INTX_DISABLE) &&
			    vdev->virq_disabled) {
				vdev->virq_disabled = 0;
				vfio_pci_enable_intx(vdev);
			}
		}
		break;
	case PCI_BASE_ADDRESS_0 ... PCI_BASE_ADDRESS_5 + 3:
	case PCI_ROM_ADDRESS ... PCI_ROM_ADDRESS + 3:
		if (write)
			vdev->bardirty = 1;
		else if (vdev->bardirty)
			vfio_bar_fixup(vdev);
		break;
	}
}

/*
 * handle virtualized fields in msi capability
 * easy, except for multiple-msi fields in flags byte
 */
static void vfio_virt_msi(struct vfio_pci_device *vdev, int write,
				u16 pos, u16 off, u8 *rbp)
{
	u8 val;
	u8 num;

	val = vdev->vconfig[pos];
	if (off == PCI_MSI_FLAGS) {
		if (write) {
			if (!vdev->ev_msi)
				val &= ~PCI_MSI_FLAGS_ENABLE;
			num = (val & PCI_MSI_FLAGS_QSIZE) >> 4;
			if (num > vdev->msi_qmax)
				num = vdev->msi_qmax;
			val &= ~PCI_MSI_FLAGS_QSIZE;
			val |= num << 4;
			*rbp = val;
		} else {
			val &= ~PCI_MSI_FLAGS_QMASK;
			val |= vdev->msi_qmax << 1;
		}
	}
	vdev->vconfig[pos] = val;
}

static int vfio_config_rwbyte(int write,
				struct vfio_pci_device *vdev,
				int pos,
				char __user *buf)
{
	u8 *map = vdev->pci_config_map;
	u8 cap, val, newval;
	u16 start = 0, off;
	int p, bottom;
	struct perm_bits *perm;
	u8 wr, virt;
	int ret;
	u8 realbits = 0;

	cap = map[pos];
	if (cap == 0xFF) {	/* unknown region */
		if (write)
			return 0;	/* silent no-op */
		val = 0;
		if (pos <= pci_capability_length[0])	/* ok to read */
			(void) vfio_read_config_byte(vdev, pos, &val);
		if (copy_to_user(buf, &val, 1))
			return -EFAULT;
		return 0;
	}

	/* scan back to start of cap region */
	bottom = (pos >= PCI_CFG_SPACE_SIZE) ? PCI_CFG_SPACE_SIZE : 0;
	for (p = pos; p >= bottom; p--) {
		if (map[p] != cap)
			break;
		start = p;
	}
	off = pos - start;	/* offset within capability */

	/* lookup permissions for this capability */
	if (pos >= PCI_CFG_SPACE_SIZE)
		perm = &pci_ext_cap_perms[cap];
	else if (cap != PCI_CAP_ID_MSI)
		perm = &pci_cap_perms[cap];
	else
		perm = vdev->msi_perm;

	if (perm) {
		wr = perm->write ? perm->write[off] : 0;
		virt = perm->virt ? perm->virt[off] : 0;
	} else {
		wr = 0;
		virt = 0;
	}
	if (write && !wr)		/* no writeable bits */
		return 0;
	if (!virt) {			/* no virtual bits */
		if (write) {
			if (copy_from_user(&val, buf, 1))
				return -EFAULT;
			val &= wr;
			if (wr != 0xFF) {
				u8 existing;

				ret = vfio_read_config_byte(vdev, pos,
							&existing);
				if (ret < 0)
					return ret;
				val |= (existing & ~wr);
			}
			vfio_write_config_byte(vdev, pos, val);
		} else {
			ret = vfio_read_config_byte(vdev, pos, &val);
			if (ret < 0)
				return ret;
			if (copy_to_user(buf, &val, 1))
				return -EFAULT;
		}
		return 0;
	}

	if (~virt) {	/* mix of real and virt bits */
		/* update vconfig with latest hw bits */
		ret = vfio_read_config_byte(vdev, pos, &realbits);
		if (ret < 0)
			return ret;
		vdev->vconfig[pos] =
			(vdev->vconfig[pos] & virt) | (realbits & ~virt);
	}

	if (write) {
		if (copy_from_user(&newval, buf, 1))
			return -EFAULT;

		/* update vconfig with writeable bits */
		vdev->vconfig[pos] =
			(vdev->vconfig[pos] & ~wr) | (newval & wr);
	}

	/*
	 * Now massage virtual fields
	 */
	if (pos < PCI_CFG_SPACE_SIZE) {
		switch (cap) {
		case PCI_CAP_ID_BASIC:	/* virtualize BARs */
			vfio_virt_basic(vdev, write, pos, &realbits);
			break;
		case PCI_CAP_ID_MSI:	/* virtualize (parts of) MSI */
			vfio_virt_msi(vdev, write, pos, off, &realbits);
			break;
		}
	} else {
		/* no virt fields yet in ecaps */
		switch (cap) {	/* extended capabilities */
		default:
			break;
		}
	}
	if (write && ~virt) {
		realbits = (realbits & virt) | (vdev->vconfig[pos] & ~virt);
		vfio_write_config_byte(vdev, pos, realbits);
	}
	if (!write && copy_to_user(buf, &vdev->vconfig[pos], 1))
		return -EFAULT;
	return 0;
}

ssize_t vfio_pci_config_readwrite(int write,
		struct vfio_pci_device *vdev,
		char __user *buf,
		size_t count,
		loff_t *ppos)
{
	struct pci_dev *pdev = vdev->pdev;
	int done = 0;
	int ret;
	u16 pos;


	if (!vdev->pci_config_map) {
		ret = vfio_pci_build_config_map(vdev);
		if (ret)
			goto out;
	}
	if (!vdev->vconfig) {
		ret = vfio_virt_init(vdev);
		if (ret)
			goto out;
	}

	while (count > 0) {
		pos = (u16)*ppos;
		if (pos == pdev->cfg_size)
			break;
		if (pos > pdev->cfg_size) {
			ret = -EINVAL;
			goto out;
		}

		ret = vfio_config_rwbyte(write, vdev, pos, buf);

		if (ret < 0)
			goto out;
		buf++;
		done++;
		count--;
		(*ppos)++;
	}
	ret = done;
out:
	return ret;
}
