/*
 * VFIO: IOMMU DMA mapping support
 *
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

#include <linux/compat.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/iommu.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vfio.h>
#include <linux/workqueue.h>

#include "vfio_private.h"

struct vfio_dma_map_entry {
	struct list_head	list;
	dma_addr_t		iova;		/* Device address */
	unsigned long		vaddr;		/* Process virtual addr */
	long			npage;		/* Number of pages */
	int			prot;		/* IOMMU_READ/WRITE */
};

/*
 * This code handles mapping and unmapping of user data buffers
 * into DMA'ble space using the IOMMU
 */

#define NPAGE_TO_SIZE(npage)	((size_t)(npage) << PAGE_SHIFT)

struct vwork {
	struct mm_struct	*mm;
	long			npage;
	struct work_struct	work;
};

/* delayed decrement/increment for locked_vm */
static void vfio_lock_acct_bg(struct work_struct *work)
{
	struct vwork *vwork = container_of(work, struct vwork, work);
	struct mm_struct *mm;

	mm = vwork->mm;
	down_write(&mm->mmap_sem);
	mm->locked_vm += vwork->npage;
	up_write(&mm->mmap_sem);
	mmput(mm);		/* unref mm */
	kfree(vwork);
}

static void vfio_lock_acct(long npage)
{
	struct vwork *vwork;
	struct mm_struct *mm;

	if (!current->mm) {
		/* process exited */
		return;
	}
	if (down_write_trylock(&current->mm->mmap_sem)) {
		current->mm->locked_vm += npage;
		up_write(&current->mm->mmap_sem);
		return;
	}
	/*
	 * Couldn't get mmap_sem lock, so must setup to update
	 * mm->locked_vm later. If locked_vm were atomic, we
	 * wouldn't need this silliness
	 */
	vwork = kmalloc(sizeof(struct vwork), GFP_KERNEL);
	if (!vwork)
		return;
	mm = get_task_mm(current);	/* take ref mm */
	if (!mm) {
		kfree(vwork);
		return;
	}
	INIT_WORK(&vwork->work, vfio_lock_acct_bg);
	vwork->mm = mm;
	vwork->npage = npage;
	schedule_work(&vwork->work);
}

/* Some mappings aren't backed by a struct page, for example an mmap'd
 * MMIO range for our own or another device.  These use a different
 * pfn conversion and shouldn't be tracked as locked pages. */
static bool is_invalid_reserved_pfn(unsigned long pfn)
{
	if (pfn_valid(pfn)) {
		bool reserved;
		struct page *tail = pfn_to_page(pfn);
		struct page *head = compound_trans_head(tail);
		reserved = !!(PageReserved(head));
		if (head != tail) {
			/* "head" is not a dangling pointer
			 * (compound_trans_head takes care of that)
			 * but the hugepage may have been split
			 * from under us (and we may not hold a
			 * reference count on the head page so it can
			 * be reused before we run PageReferenced), so
			 * we've to check PageTail before returning
			 * what we just read.
			 */
			smp_rmb();
			if (PageTail(tail))
				return reserved;
		}
		return PageReserved(tail);
	}

	return true;
}

static int put_pfn(unsigned long pfn, int prot)
{
	if (!is_invalid_reserved_pfn(pfn)) {
		struct page *page = pfn_to_page(pfn);
		if (prot & IOMMU_WRITE)
			SetPageDirty(page);
		put_page(page);
		return 1;
	}
	return 0;
}

/* Unmap DMA region */
static long __vfio_dma_do_unmap(struct vfio_iommu *iommu, dma_addr_t iova,
			     long npage, int prot)
{
	long i, unlocked = 0;

	for (i = 0; i < npage; i++, iova += PAGE_SIZE) {
		unsigned long pfn;

		pfn = iommu_iova_to_phys(iommu->domain, iova) >> PAGE_SHIFT;
		if (pfn) {
			iommu_unmap(iommu->domain, iova, PAGE_SIZE);
			unlocked += put_pfn(pfn, prot);
		}
	}
	return unlocked;
}

static void vfio_dma_unmap(struct vfio_iommu *iommu, dma_addr_t iova,
			   long npage, int prot)
{
	long unlocked;

	unlocked = __vfio_dma_do_unmap(iommu, iova, npage, prot);
	vfio_lock_acct(-unlocked);
}

/* Unmap ALL DMA regions */
void vfio_iommu_unmapall(struct vfio_iommu *iommu)
{
	struct list_head *pos, *tmp;

	mutex_lock(&iommu->lock);
	list_for_each_safe(pos, tmp, &iommu->dma_list) {
		struct vfio_dma_map_entry *dma;

		dma = list_entry(pos, struct vfio_dma_map_entry, list);
		vfio_dma_unmap(iommu, dma->iova, dma->npage, dma->prot);
		list_del(&dma->list);
		kfree(dma);
	}
	mutex_unlock(&iommu->lock);
}

static int vaddr_get_pfn(unsigned long vaddr, int prot, unsigned long *pfn)
{
	struct page *page[1];
	struct vm_area_struct *vma;
	int ret = -EFAULT;

	if (get_user_pages_fast(vaddr, 1, !!(prot & IOMMU_WRITE), page) == 1) {
		*pfn = page_to_pfn(page[0]);
		return 0;
	}

	down_read(&current->mm->mmap_sem);

	vma = find_vma_intersection(current->mm, vaddr, vaddr + 1);

	if (vma && vma->vm_flags & VM_PFNMAP) {
		*pfn = ((vaddr - vma->vm_start) >> PAGE_SHIFT) + vma->vm_pgoff;
		if (is_invalid_reserved_pfn(*pfn))
			ret = 0;
	}

	up_read(&current->mm->mmap_sem);

	return ret;
}

/* Map DMA region */
static int __vfio_dma_map(struct vfio_iommu *iommu, dma_addr_t iova,
			  unsigned long vaddr, long npage, int prot)
{
	dma_addr_t start = iova;
	long i, locked = 0;
	int ret;

	/* Verify that pages are not already mapped */
	for (i = 0; i < npage; i++, iova += PAGE_SIZE)
		if (iommu_iova_to_phys(iommu->domain, iova))
			return -EBUSY;

	iova = start;

	if (iommu->cache)
		prot |= IOMMU_CACHE;

	/* XXX We break mappings into pages and use get_user_pages_fast to
	 * pin the pages in memory.  It's been suggested that mlock might
	 * provide a more efficient mechanism, but nothing prevents the
	 * user from munlocking the pages, which could then allow the user
	 * access to random host memory.  We also have no guarantee from the
	 * IOMMU API that the iommu driver can unmap sub-pages of previous
	 * mappings.  This means we might lose an entire range if a single
	 * page within it is unmapped.  Single page mappings are inefficient,
	 * but provide the most flexibility for now. */

	for (i = 0; i < npage; i++, iova += PAGE_SIZE, vaddr += PAGE_SIZE) {
		unsigned long pfn = 0;

		ret = vaddr_get_pfn(vaddr, prot, &pfn);
		if (ret) {
			__vfio_dma_do_unmap(iommu, start, i, prot);
			return ret;
		}

		/* Only add actual locked pages to accounting */
		/* XXX We're effectively marking a page locked for every
		 * IOVA page even though it's possible the user could be
		 * backing multiple IOVAs with the same vaddr.  This over-
		 * penalizes the user process, but we currently have no
		 * easy way to do this properly. */
		if (!is_invalid_reserved_pfn(pfn))
			locked++;

		ret = iommu_map(iommu->domain, iova,
				(phys_addr_t)pfn << PAGE_SHIFT,
				PAGE_SIZE, prot);
		if (ret) {
			/* Back out mappings on error */
			put_pfn(pfn, prot);
			__vfio_dma_do_unmap(iommu, start, i, prot);
			return ret;
		}
	}
	vfio_lock_acct(locked);
	return 0;
}

static inline bool ranges_overlap(dma_addr_t start1, size_t size1,
				  dma_addr_t start2, size_t size2)
{
	if (start1 < start2)
		return (start2 - start1 < size1);
	else if (start2 < start1)
		return (start1 - start2 < size2);
	return (size1 > 0 && size2 > 0);
}

static struct vfio_dma_map_entry *vfio_find_dma(struct vfio_iommu *iommu,
						dma_addr_t start, size_t size)
{
	struct list_head *pos;

	list_for_each(pos, &iommu->dma_list) {
		struct vfio_dma_map_entry *dma;

		dma = list_entry(pos, struct vfio_dma_map_entry, list);
		if (ranges_overlap(dma->iova, NPAGE_TO_SIZE(dma->npage),
				   start, size))
			return dma;
	}
	return NULL;
}

static long vfio_remove_dma_overlap(struct vfio_iommu *iommu, dma_addr_t start,
				    size_t size, struct vfio_dma_map_entry *dma)
{
	struct vfio_dma_map_entry *split;
	long npage_lo, npage_hi;

	/* Existing dma region is completely covered, unmap all */
	if (start <= dma->iova &&
	    start + size >= dma->iova + NPAGE_TO_SIZE(dma->npage)) {
		vfio_dma_unmap(iommu, dma->iova, dma->npage, dma->prot);
		list_del(&dma->list);
		npage_lo = dma->npage;
		kfree(dma);
		return npage_lo;
	}

	/* Overlap low address of existing range */
	if (start <= dma->iova) {
		size_t overlap;

		overlap = start + size - dma->iova;
		npage_lo = overlap >> PAGE_SHIFT;

		vfio_dma_unmap(iommu, dma->iova, npage_lo, dma->prot);
		dma->iova += overlap;
		dma->vaddr += overlap;
		dma->npage -= npage_lo;
		return npage_lo;
	}

	/* Overlap high address of existing range */
	if (start + size >= dma->iova + NPAGE_TO_SIZE(dma->npage)) {
		size_t overlap;

		overlap = dma->iova + NPAGE_TO_SIZE(dma->npage) - start;
		npage_hi = overlap >> PAGE_SHIFT;

		vfio_dma_unmap(iommu, start, npage_hi, dma->prot);
		dma->npage -= npage_hi;
		return npage_hi;
	}

	/* Split existing */
	npage_lo = (start - dma->iova) >> PAGE_SHIFT;
	npage_hi = dma->npage - (size >> PAGE_SHIFT) - npage_lo;

	split = kzalloc(sizeof *split, GFP_KERNEL);
	if (!split)
		return -ENOMEM;

	vfio_dma_unmap(iommu, start, size >> PAGE_SHIFT, dma->prot);

	dma->npage = npage_lo;

	split->npage = npage_hi;
	split->iova = start + size;
	split->vaddr = dma->vaddr + NPAGE_TO_SIZE(npage_lo) + size;
	split->prot = dma->prot;
	list_add(&split->list, &iommu->dma_list);
	return size >> PAGE_SHIFT;
}

static int vfio_dma_do_unmap(struct vfio_iommu *iommu,
			     struct vfio_dma_unmap *unmap)
{
	long ret = 0, npage = unmap->size >> PAGE_SHIFT;
	struct list_head *pos, *tmp;
	uint64_t mask;

	mask = ((uint64_t)1 << __ffs(iommu->domain->ops->pgsize_bitmap)) - 1;

	if (unmap->iova & mask)
		return -EINVAL;
	if (unmap->size & mask)
		return -EINVAL;

	/* XXX We still break these down into PAGE_SIZE */
	WARN_ON(mask & PAGE_MASK);

	mutex_lock(&iommu->lock);

	list_for_each_safe(pos, tmp, &iommu->dma_list) {
		struct vfio_dma_map_entry *dma;

		dma = list_entry(pos, struct vfio_dma_map_entry, list);
		if (ranges_overlap(dma->iova, NPAGE_TO_SIZE(dma->npage),
				   unmap->iova, unmap->size)) {
			ret = vfio_remove_dma_overlap(iommu, unmap->iova,
						      unmap->size, dma);
			if (ret > 0)
				npage -= ret;
			if (ret < 0 || npage == 0)
				break;
		}
	}
	mutex_unlock(&iommu->lock);
	return ret > 0 ? 0 : (int)ret;
}

static int vfio_dma_do_map(struct vfio_iommu *iommu, struct vfio_dma_map *map)
{
	struct vfio_dma_map_entry *dma, *pdma = NULL;
	dma_addr_t iova = map->iova;
	unsigned long locked, lock_limit, vaddr = map->vaddr;
	size_t size = map->size;
	int ret = 0, prot = 0;
	uint64_t mask;
	long npage;

	mask = ((uint64_t)1 << __ffs(iommu->domain->ops->pgsize_bitmap)) - 1;

	/* READ/WRITE from device perspective */
	if (map->flags & VFIO_DMA_MAP_FLAG_WRITE)
		prot |= IOMMU_WRITE;
	if (map->flags & VFIO_DMA_MAP_FLAG_READ)
		prot |= IOMMU_READ;

	if (!prot)
		return -EINVAL; /* No READ/WRITE? */

	if (vaddr & mask)
		return -EINVAL;
	if (iova & mask)
		return -EINVAL;
	if (size & mask)
		return -EINVAL;

	/* XXX We still break these down into PAGE_SIZE */
	WARN_ON(mask & PAGE_MASK);

	/* Don't allow IOVA wrap */
	if (iova + size && iova + size < iova)
		return -EINVAL;

	/* Don't allow virtual address wrap */
	if (vaddr + size && vaddr + size < vaddr)
		return -EINVAL;

	npage = size >> PAGE_SHIFT;
	if (!npage)
		return -EINVAL;

	mutex_lock(&iommu->lock);

	if (vfio_find_dma(iommu, iova, size)) {
		ret = -EBUSY;
		goto out_lock;
	}

	/* account for locked pages */
	locked = current->mm->locked_vm + npage;
	lock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;
	if (locked > lock_limit && !capable(CAP_IPC_LOCK)) {
		printk(KERN_WARNING "%s: RLIMIT_MEMLOCK (%ld) exceeded\n",
			__func__, rlimit(RLIMIT_MEMLOCK));
		ret = -ENOMEM;
		goto out_lock;
	}

	ret = __vfio_dma_map(iommu, iova, vaddr, npage, prot);
	if (ret)
		goto out_lock;

	/* Check if we abut a region below - nothing below 0 */
	if (iova) {
		dma = vfio_find_dma(iommu, iova - 1, 1);
		if (dma && dma->prot == prot &&
		    dma->vaddr + NPAGE_TO_SIZE(dma->npage) == vaddr) {

			dma->npage += npage;
			iova = dma->iova;
			vaddr = dma->vaddr;
			npage = dma->npage;
			size = NPAGE_TO_SIZE(npage);

			pdma = dma;
		}
	}

	/* Check if we abut a region above - nothing above ~0 + 1 */
	if (iova + size) {
		dma = vfio_find_dma(iommu, iova + size, 1);
		if (dma && dma->prot == prot &&
		    dma->vaddr == vaddr + size) {

			dma->npage += npage;
			dma->iova = iova;
			dma->vaddr = vaddr;

			/* If merged above and below, remove previously
			 * merged entry.  New entry covers it.  */
			if (pdma) {
				list_del(&pdma->list);
				kfree(pdma);
			}
			pdma = dma;
		}
	}

	/* Isolated, new region */
	if (!pdma) {
		dma = kzalloc(sizeof *dma, GFP_KERNEL);
		if (!dma) {
			ret = -ENOMEM;
			vfio_dma_unmap(iommu, iova, npage, prot);
			goto out_lock;
		}

		dma->npage = npage;
		dma->iova = iova;
		dma->vaddr = vaddr;
		dma->prot = prot;
		list_add(&dma->list, &iommu->dma_list);
	}

out_lock:
	mutex_unlock(&iommu->lock);
	return ret;
}

static int vfio_iommu_release(struct inode *inode, struct file *filep)
{
	struct vfio_iommu *iommu = filep->private_data;

	vfio_release_iommu(iommu);
	return 0;
}

static long vfio_iommu_unl_ioctl(struct file *filep,
				 unsigned int cmd, unsigned long arg)
{
	struct vfio_iommu *iommu = filep->private_data;
	unsigned long minsz;

	if (cmd == VFIO_IOMMU_GET_INFO) {
		struct vfio_iommu_info info;

		minsz = offsetofend(struct vfio_iommu_info, pgsize_bitmap);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz)
			return -EINVAL;

		info.flags = 0;

		/* XXX Need to define an interface in IOMMU API for this */
		info.iova_min = 0;
		info.iova_max = ~info.iova_min;
		info.pgsize_bitmap = iommu->domain->ops->pgsize_bitmap;

		return copy_to_user((void __user *)arg, &info, minsz);

	} else if (cmd == VFIO_IOMMU_MAP_DMA) {
		struct vfio_dma_map map;
		uint32_t mask = VFIO_DMA_MAP_FLAG_READ |
				VFIO_DMA_MAP_FLAG_WRITE;

		minsz = offsetofend(struct vfio_dma_map, size);

		if (copy_from_user(&map, (void __user *)arg, minsz))
			return -EFAULT;

		if (map.argsz < minsz || map.flags & ~mask)
			return -EINVAL;

		return vfio_dma_do_map(iommu, &map);
	} else if (cmd == VFIO_IOMMU_UNMAP_DMA) {
		struct vfio_dma_unmap unmap;

		minsz = offsetofend(struct vfio_dma_unmap, size);

		if (copy_from_user(&unmap, (void __user *)arg, minsz))
			return -EFAULT;

		if (unmap.argsz < minsz || unmap.flags)
			return -EINVAL;

		return vfio_dma_do_unmap(iommu, &unmap);
	}

	return -ENOTTY;
}

#ifdef CONFIG_COMPAT
static long vfio_iommu_compat_ioctl(struct file *filep,
				    unsigned int cmd, unsigned long arg)
{
	arg = (unsigned long)compat_ptr(arg);
	return vfio_iommu_unl_ioctl(filep, cmd, arg);
}
#endif	/* CONFIG_COMPAT */

const struct file_operations vfio_iommu_fops = {
	.owner		= THIS_MODULE,
	.release	= vfio_iommu_release,
	.unlocked_ioctl	= vfio_iommu_unl_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= vfio_iommu_compat_ioctl,
#endif
};
