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

struct dma_map_page {
	struct list_head	list;
	dma_addr_t		daddr;
	unsigned long		vaddr;
	int			npage;
	int			rdwr;
};

/*
 * This code handles mapping and unmapping of user data buffers
 * into DMA'ble space using the IOMMU
 */

#define NPAGE_TO_SIZE(npage)	((size_t)(npage) << PAGE_SHIFT)

struct vwork {
	struct mm_struct	*mm;
	int			npage;
	struct work_struct	work;
};

/* delayed decrement for locked_vm */
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

static void vfio_lock_acct(int npage)
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
	 * Couldn't get mmap_sem lock, so must setup to decrement
	 * mm->locked_vm later. If locked_vm were atomic, we wouldn't
	 * need this silliness
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
static int is_invalid_reserved_pfn(unsigned long pfn)
{
	if (pfn_valid(pfn)) {
		int reserved;
		struct page *tail = pfn_to_page(pfn);
		struct page *head = compound_trans_head(tail);
		reserved = PageReserved(head);
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

static int put_pfn(unsigned long pfn, int rdwr)
{
	if (!is_invalid_reserved_pfn(pfn)) {
		struct page *page = pfn_to_page(pfn);
		if (rdwr)
			SetPageDirty(page);
		put_page(page);
		return 1;
	}
	return 0;
}

/* Unmap DMA region */
/* dgate must be held */
static int __vfio_dma_unmap(struct vfio_iommu *iommu, unsigned long iova,
			    int npage, int rdwr)
{
	int i, unlocked = 0;

	for (i = 0; i < npage; i++, iova += PAGE_SIZE) {
		unsigned long pfn;

		pfn = iommu_iova_to_phys(iommu->domain, iova) >> PAGE_SHIFT;
		if (pfn) {
			iommu_unmap(iommu->domain, iova, 0);
			unlocked += put_pfn(pfn, rdwr);
		}
	}
	return unlocked;
}

static void vfio_dma_unmap(struct vfio_iommu *iommu, unsigned long iova,
			   unsigned long npage, int rdwr)
{
	int unlocked;

	unlocked = __vfio_dma_unmap(iommu, iova, npage, rdwr);
	vfio_lock_acct(-unlocked);
}

/* Unmap ALL DMA regions */
void vfio_iommu_unmapall(struct vfio_iommu *iommu)
{
	struct list_head *pos, *pos2;
	struct dma_map_page *mlp;

	mutex_lock(&iommu->dgate);
	list_for_each_safe(pos, pos2, &iommu->dm_list) {
		mlp = list_entry(pos, struct dma_map_page, list);
		vfio_dma_unmap(iommu, mlp->daddr, mlp->npage, mlp->rdwr);
		list_del(&mlp->list);
		kfree(mlp);
	}
	mutex_unlock(&iommu->dgate);
}

static int vaddr_get_pfn(unsigned long vaddr, int rdwr, unsigned long *pfn)
{
	struct page *page[1];
	struct vm_area_struct *vma;
	int ret = -EFAULT;

	if (get_user_pages_fast(vaddr, 1, rdwr, page) == 1) {
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
/* dgate must be held */
static int vfio_dma_map(struct vfio_iommu *iommu, unsigned long iova,
			unsigned long vaddr, int npage, int rdwr)
{
	unsigned long start = iova;
	int i, ret, locked = 0, prot = IOMMU_READ;

	/* Verify pages are not already mapped */
	for (i = 0; i < npage; i++, iova += PAGE_SIZE)
		if (iommu_iova_to_phys(iommu->domain, iova))
			return -EBUSY;

	iova = start;

	if (rdwr)
		prot |= IOMMU_WRITE;
	if (iommu->cache)
		prot |= IOMMU_CACHE;

	for (i = 0; i < npage; i++, iova += PAGE_SIZE, vaddr += PAGE_SIZE) {
		unsigned long pfn = 0;

		ret = vaddr_get_pfn(vaddr, rdwr, &pfn);
		if (ret) {
			__vfio_dma_unmap(iommu, start, i, rdwr);
			return ret;
		}

		/* Only add actual locked pages to accounting */
		if (!is_invalid_reserved_pfn(pfn))
			locked++;

		ret = iommu_map(iommu->domain, iova,
				(phys_addr_t)pfn << PAGE_SHIFT, 0, prot);
		if (ret) {
			/* Back out mappings on error */
			put_pfn(pfn, rdwr);
			__vfio_dma_unmap(iommu, start, i, rdwr);
			return ret;
		}
	}
	vfio_lock_acct(locked);
	return 0;
}

static inline int ranges_overlap(unsigned long start1, size_t size1,
				 unsigned long start2, size_t size2)
{
	return !(start1 + size1 <= start2 || start2 + size2 <= start1);
}

static struct dma_map_page *vfio_find_dma(struct vfio_iommu *iommu,
					  dma_addr_t start, size_t size)
{
	struct list_head *pos;
	struct dma_map_page *mlp;

	list_for_each(pos, &iommu->dm_list) {
		mlp = list_entry(pos, struct dma_map_page, list);
		if (ranges_overlap(mlp->daddr, NPAGE_TO_SIZE(mlp->npage),
				   start, size))
			return mlp;
	}
	return NULL;
}

int vfio_remove_dma_overlap(struct vfio_iommu *iommu, dma_addr_t start,
			    size_t size, struct dma_map_page *mlp)
{
	struct dma_map_page *split;
	int npage_lo, npage_hi;

	/* Existing dma region is completely covered, unmap all */
	if (start <= mlp->daddr &&
	    start + size >= mlp->daddr + NPAGE_TO_SIZE(mlp->npage)) {
		vfio_dma_unmap(iommu, mlp->daddr, mlp->npage, mlp->rdwr);
		list_del(&mlp->list);
		npage_lo = mlp->npage;
		kfree(mlp);
		return npage_lo;
	}

	/* Overlap low address of existing range */
	if (start <= mlp->daddr) {
		size_t overlap;

		overlap = start + size - mlp->daddr;
		npage_lo = overlap >> PAGE_SHIFT;
		npage_hi = mlp->npage - npage_lo;

		vfio_dma_unmap(iommu, mlp->daddr, npage_lo, mlp->rdwr);
		mlp->daddr += overlap;
		mlp->vaddr += overlap;
		mlp->npage -= npage_lo;
		return npage_lo;
	}

	/* Overlap high address of existing range */
	if (start + size >= mlp->daddr + NPAGE_TO_SIZE(mlp->npage)) {
		size_t overlap;

		overlap = mlp->daddr + NPAGE_TO_SIZE(mlp->npage) - start;
		npage_hi = overlap >> PAGE_SHIFT;
		npage_lo = mlp->npage - npage_hi;

		vfio_dma_unmap(iommu, start, npage_hi, mlp->rdwr);
		mlp->npage -= npage_hi;
		return npage_hi;
	}

	/* Split existing */
	npage_lo = (start - mlp->daddr) >> PAGE_SHIFT;
	npage_hi = mlp->npage - (size >> PAGE_SHIFT) - npage_lo;

	split = kzalloc(sizeof *split, GFP_KERNEL);
	if (!split)
		return -ENOMEM;

	vfio_dma_unmap(iommu, start, size >> PAGE_SHIFT, mlp->rdwr);

	mlp->npage = npage_lo;

	split->npage = npage_hi;
	split->daddr = start + size;
	split->vaddr = mlp->vaddr + NPAGE_TO_SIZE(npage_lo) + size;
	split->rdwr = mlp->rdwr;
	list_add(&split->list, &iommu->dm_list);
	return size >> PAGE_SHIFT;
}

int vfio_dma_unmap_dm(struct vfio_iommu *iommu, struct vfio_dma_map *dmp)
{
	int ret = 0;
	size_t npage = dmp->size >> PAGE_SHIFT;
	struct list_head *pos, *n;

	if (dmp->dmaaddr & ~PAGE_MASK)
		return -EINVAL;
	if (dmp->size & ~PAGE_MASK)
		return -EINVAL;

	mutex_lock(&iommu->dgate);

	list_for_each_safe(pos, n, &iommu->dm_list) {
		struct dma_map_page *mlp;

		mlp = list_entry(pos, struct dma_map_page, list);
		if (ranges_overlap(mlp->daddr, NPAGE_TO_SIZE(mlp->npage),
				   dmp->dmaaddr, dmp->size)) {
			ret = vfio_remove_dma_overlap(iommu, dmp->dmaaddr,
						      dmp->size, mlp);
			if (ret > 0)
				npage -= NPAGE_TO_SIZE(ret);
			if (ret < 0 || npage == 0)
				break;
		}
	}
	mutex_unlock(&iommu->dgate);
	return ret > 0 ? 0 : ret;
}

int vfio_dma_map_dm(struct vfio_iommu *iommu, struct vfio_dma_map *dmp)
{
	int npage;
	struct dma_map_page *mlp, *mmlp = NULL;
	dma_addr_t daddr = dmp->dmaaddr;
	unsigned long locked, lock_limit, vaddr = dmp->vaddr;
	size_t size = dmp->size;
	int ret = 0, rdwr = dmp->flags & VFIO_DMA_MAP_FLAG_WRITE;

	if (vaddr & (PAGE_SIZE-1))
		return -EINVAL;
	if (daddr & (PAGE_SIZE-1))
		return -EINVAL;
	if (size & (PAGE_SIZE-1))
		return -EINVAL;

	npage = size >> PAGE_SHIFT;
	if (!npage)
		return -EINVAL;

	if (!iommu)
		return -EINVAL;

	mutex_lock(&iommu->dgate);

	if (vfio_find_dma(iommu, daddr, size)) {
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

	ret = vfio_dma_map(iommu, daddr, vaddr, npage, rdwr);
	if (ret)
		goto out_lock;

	/* Check if we abut a region below */
	if (daddr) {
		mlp = vfio_find_dma(iommu, daddr - 1, 1);
		if (mlp && mlp->rdwr == rdwr &&
		    mlp->vaddr + NPAGE_TO_SIZE(mlp->npage) == vaddr) {

			mlp->npage += npage;
			daddr = mlp->daddr;
			vaddr = mlp->vaddr;
			npage = mlp->npage;
			size = NPAGE_TO_SIZE(npage);

			mmlp = mlp;
		}
	}

	if (daddr + size) {
		mlp = vfio_find_dma(iommu, daddr + size, 1);
		if (mlp && mlp->rdwr == rdwr && mlp->vaddr == vaddr + size) {

			mlp->npage += npage;
			mlp->daddr = daddr;
			mlp->vaddr = vaddr;

			/* If merged above and below, remove previously
			 * merged entry.  New entry covers it.  */
			if (mmlp) {
				list_del(&mmlp->list);
				kfree(mmlp);
			}
			mmlp = mlp;
		}
	}

	if (!mmlp) {
		mlp = kzalloc(sizeof *mlp, GFP_KERNEL);
		if (!mlp) {
			ret = -ENOMEM;
			vfio_dma_unmap(iommu, daddr, npage, rdwr);
			goto out_lock;
		}

		mlp->npage = npage;
		mlp->daddr = daddr;
		mlp->vaddr = vaddr;
		mlp->rdwr = rdwr;
		list_add(&mlp->list, &iommu->dm_list);
	}

out_lock:
	mutex_unlock(&iommu->dgate);
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
	int ret = -ENOSYS;

        if (cmd == VFIO_IOMMU_GET_FLAGS) {
                u64 flags = VFIO_IOMMU_FLAGS_MAP_ANY;

                ret = put_user(flags, (u64 __user *)arg);

        } else if (cmd == VFIO_IOMMU_MAP_DMA) {
		struct vfio_dma_map dm;

		if (copy_from_user(&dm, (void __user *)arg, sizeof dm))
			return -EFAULT;

		ret = vfio_dma_map_dm(iommu, &dm);

		if (!ret && copy_to_user((void __user *)arg, &dm, sizeof dm))
			ret = -EFAULT;

	} else if (cmd == VFIO_IOMMU_UNMAP_DMA) {
		struct vfio_dma_map dm;

		if (copy_from_user(&dm, (void __user *)arg, sizeof dm))
			return -EFAULT;

		ret = vfio_dma_unmap_dm(iommu, &dm);

		if (!ret && copy_to_user((void __user *)arg, &dm, sizeof dm))
			ret = -EFAULT;
	}
	return ret;
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
