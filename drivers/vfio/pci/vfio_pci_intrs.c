/*
 * VFIO PCI interrupt handling
 *
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
#include <linux/interrupt.h>
#include <linux/eventfd.h>
#include <linux/pci.h>
#include <linux/file.h>
#include <linux/poll.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "vfio_pci_private.h"

static inline void send_intx_eventfd(struct vfio_pci_device *vdev)
{
	if (likely(vdev->ev_irq && !vdev->virq_disabled))
		eventfd_signal(vdev->ev_irq, 1);
}

void vfio_pci_disable_intx(struct vfio_pci_device *vdev)
{
	struct pci_dev *pdev = vdev->pdev;

	spin_lock_irq(&vdev->irqlock);

	if (vdev->pci_2_3) {
		pci_intx(pdev, 0);
	} else {
		if (vdev->ev_irq)
			disable_irq_nosync(pdev->irq);
	}

	spin_unlock_irq(&vdev->irqlock);
}

void vfio_pci_enable_intx(struct vfio_pci_device *vdev)
{
	struct pci_dev *pdev = vdev->pdev;
	bool signal = false;

	spin_lock_irq(&vdev->irqlock);

	if (vdev->pci_2_3) {
		if (!vdev->ev_irq)
			pci_intx(pdev, 1);
		else if (!pci_check_and_unmask_intx(pdev))
			signal = true;
	} else {
		if (vdev->ev_irq)
			enable_irq(pdev->irq);
	}

	spin_unlock_irq(&vdev->irqlock);

	if (signal)
		send_intx_eventfd(vdev);
}

static irqreturn_t vfio_pci_intx_handler(int irq, void *dev_id)
{
	struct vfio_pci_device *vdev = dev_id;
	struct pci_dev *pdev = vdev->pdev;
	irqreturn_t ret = IRQ_NONE;
	unsigned long flags;

	spin_lock_irqsave(&vdev->irqlock, flags);

	if (vdev->irq_disabled) {
		spin_unlock_irqrestore(&vdev->irqlock, flags);
		return ret;
	}

	if (vdev->pci_2_3) {
		if (pci_check_and_mask_intx(pdev))
			ret = IRQ_WAKE_THREAD;
	} else
		ret = IRQ_WAKE_THREAD;

	if (ret == IRQ_WAKE_THREAD)
		vdev->irq_disabled = true;

	spin_unlock_irqrestore(&vdev->irqlock, flags);

	return ret;
}

static irqreturn_t vfio_pci_intx_thread(int irq, void *dev_id)
{
	struct vfio_pci_device *vdev = dev_id;

	if (!vdev->pci_2_3)
		disable_irq_nosync(vdev->pdev->irq);

	send_intx_eventfd(vdev);
	return IRQ_HANDLED;
}

int vfio_pci_irq_eoi(struct vfio_pci_device *vdev)
{
	struct pci_dev *pdev = vdev->pdev;
	bool signal = false;

	spin_lock_irq(&vdev->irqlock);

	if (vdev->irq_disabled) {
		if (vdev->pci_2_3) {
			if (!pci_check_and_unmask_intx(pdev)) {
				signal = true;
				goto unlock;
			}
		} else
			enable_irq(pdev->irq);

		vdev->irq_disabled = false;
	}

unlock:
	spin_unlock_irq(&vdev->irqlock);

	if (signal)
		send_intx_eventfd(vdev);

	return 0;
}

int vfio_pci_setup_intx(struct vfio_pci_device *vdev, int nvec, int *fds)
{
	int ret;

	if (nvec != 1)
		return -EINVAL;

	vdev->ev_irq = eventfd_ctx_fdget(fds[0]);
	if (!vdev->ev_irq)
		return -EINVAL;

	ret = request_threaded_irq(vdev->pdev->irq, vfio_pci_intx_handler,
				   vfio_pci_intx_thread,
				   vdev->pci_2_3 ? IRQF_SHARED : 0,
				   "vfio", vdev);
	if (ret) {
		eventfd_ctx_put(vdev->ev_irq);
		vdev->ev_irq = NULL;
	} else if (vdev->virq_disabled)
		vfio_pci_disable_intx(vdev);

	return ret;
}

void vfio_pci_drop_intx(struct vfio_pci_device *vdev)
{
	free_irq(vdev->pdev->irq, vdev);
	eventfd_ctx_put(vdev->ev_irq);
	vdev->ev_irq = NULL;
	vdev->irq_disabled = false;
}

struct eoi_eventfd {
	struct vfio_pci_device	*vdev;
	struct eventfd_ctx	*eventfd;
	poll_table		pt;
	wait_queue_t		wait;
	struct work_struct	inject;
	struct work_struct	shutdown;
};

static struct workqueue_struct *eoi_cleanup_wq;

static void inject_eoi(struct work_struct *work)
{
	struct eoi_eventfd *ev_eoi = container_of(work, struct eoi_eventfd,
						  inject);
	vfio_pci_irq_eoi(ev_eoi->vdev);
}

static void shutdown_eoi(struct work_struct *work)
{
	u64 cnt;
	struct eoi_eventfd *ev_eoi = container_of(work, struct eoi_eventfd,
						  shutdown);
	struct vfio_pci_device *vdev = ev_eoi->vdev;

	eventfd_ctx_remove_wait_queue(ev_eoi->eventfd, &ev_eoi->wait, &cnt);
	flush_work(&ev_eoi->inject);
	eventfd_ctx_put(ev_eoi->eventfd);
	kfree(vdev->ev_eoi);
	vdev->ev_eoi = NULL;
}

static void deactivate_eoi(struct eoi_eventfd *ev_eoi)
{
	queue_work(eoi_cleanup_wq, &ev_eoi->shutdown);
}

static int wakeup_eoi(wait_queue_t *wait, unsigned mode, int sync, void *key)
{
	struct eoi_eventfd *ev_eoi = container_of(wait, struct eoi_eventfd,
						  wait);
	unsigned long flags = (unsigned long)key;

	if (flags & POLLIN)
		/* An event has been signaled, inject an interrupt */
		schedule_work(&ev_eoi->inject);

	if (flags & POLLHUP)
		/* The eventfd is closing, detach from VFIO */
		deactivate_eoi(ev_eoi);

	return 0;
}

static void
eoi_ptable_queue_proc(struct file *file, wait_queue_head_t *wqh, poll_table *pt)
{
	struct eoi_eventfd *ev_eoi = container_of(pt, struct eoi_eventfd, pt);
	add_wait_queue(wqh, &ev_eoi->wait);
}

static int vfio_irq_eoi_eventfd_enable(struct vfio_pci_device *vdev, int fd)
{
	struct file *file = NULL;
	struct eventfd_ctx *eventfd = NULL;
	struct eoi_eventfd *ev_eoi;
	int ret = 0;
	unsigned int events;

	if (vdev->ev_eoi)
		return -EBUSY;

	ev_eoi = kzalloc(sizeof(struct eoi_eventfd), GFP_KERNEL);
	if (!ev_eoi)
		return -ENOMEM;

	vdev->ev_eoi = ev_eoi;
	ev_eoi->vdev = vdev;

	INIT_WORK(&ev_eoi->inject, inject_eoi);
	INIT_WORK(&ev_eoi->shutdown, shutdown_eoi);

	file = eventfd_fget(fd);
	if (IS_ERR(eventfd)) {
		ret = PTR_ERR(eventfd);
		goto fail;
	}

	eventfd = eventfd_ctx_fileget(file);
	if (IS_ERR(eventfd)) {
		ret = PTR_ERR(eventfd);
		goto fail;
	}

	ev_eoi->eventfd = eventfd;

	/*
	 * Install our own custom wake-up handling so we are notified via
	 * a callback whenever someone signals the underlying eventfd.
	 */
	init_waitqueue_func_entry(&ev_eoi->wait, wakeup_eoi);
	init_poll_funcptr(&ev_eoi->pt, eoi_ptable_queue_proc);

	events = file->f_op->poll(file, &ev_eoi->pt);

	/*
	 * Check if there was an event already pending on the eventfd
	 * before we registered and trigger it as if we didn't miss it.
	 */
	if (events & POLLIN)
		schedule_work(&ev_eoi->inject);

	/*
	 * Do not drop the file until the irqfd is fully initialized,
	 * otherwise we might race against the POLLHUP.
	 */
	fput(file);

	return 0;

fail:
	if (eventfd && !IS_ERR(eventfd))
		eventfd_ctx_put(eventfd);

	if (!IS_ERR(file))
		fput(file);

	return ret;
}

static int vfio_irq_eoi_eventfd_disable(struct vfio_pci_device *vdev, int fd)
{
	if (!vdev->ev_eoi)
		return -ENODEV;

	deactivate_eoi(vdev->ev_eoi);

	/* Block until we know all outstanding shutdown jobs have completed. */
	flush_workqueue(eoi_cleanup_wq);

	return 0;
}

int vfio_pci_irq_eoi_eventfd(struct vfio_pci_device *vdev, int fd)
{
	if (fd < 0)
		return vfio_irq_eoi_eventfd_disable(vdev, fd);

	return vfio_irq_eoi_eventfd_enable(vdev, fd);
}

int __init vfio_pci_eoi_eventfd_init(void)
{
	eoi_cleanup_wq = create_singlethread_workqueue("vfio-eoi-cleanup");
	if (!eoi_cleanup_wq)
		return -ENOMEM;

	return 0;
}

void __exit vfio_pci_eoi_eventfd_exit(void)
{
	destroy_workqueue(eoi_cleanup_wq);
}

/*
 * MSI and MSI-X Interrupt handler.
 * Just signal an event
 */
static irqreturn_t msihandler(int irq, void *arg)
{
	struct eventfd_ctx *ctx = arg;

	eventfd_signal(ctx, 1);
	return IRQ_HANDLED;
}

void vfio_pci_drop_msi(struct vfio_pci_device *vdev)
{
	struct pci_dev *pdev = vdev->pdev;
	int i;

	if (vdev->ev_msi) {
		for (i = 0; i < vdev->msi_nvec; i++) {
			free_irq(pdev->irq + i, vdev->ev_msi[i]);
			eventfd_ctx_put(vdev->ev_msi[i]);
		}
	}
	kfree(vdev->ev_msi);
	vdev->ev_msi = NULL;
	vdev->msi_nvec = 0;
	pci_disable_msi(pdev);
}

int vfio_pci_setup_msi(struct vfio_pci_device *vdev, int nvec, int *fds)
{
	struct pci_dev *pdev = vdev->pdev;
	struct eventfd_ctx *ctx;
	int i, ret;

	vdev->ev_msi = kzalloc(nvec * sizeof(ctx), GFP_KERNEL);
	if (!vdev->ev_msi)
		return -ENOMEM;

	for (i = 0; i < nvec; i++) {
		ctx = eventfd_ctx_fdget(fds[i]);
		if (IS_ERR(ctx)) {
			ret = PTR_ERR(ctx);
			goto out_put_ctx;
		}
		vdev->ev_msi[i] = ctx;
	}

	ret = pci_enable_msi_block(pdev, nvec);
	if (ret) /* >0 if request exceeds what the platform can provide */
		goto out_put_ctx;

	for (i = 0; i < nvec; i++) {
		ret = request_threaded_irq(pdev->irq + i, NULL, msihandler, 0,
					   "vfio", vdev->ev_msi[i]);
		if (ret)
			goto out_free_irq;
	}

	vdev->msi_nvec = nvec;

	/*
	 * Compute the virtual hardware field for max msi vectors -
	 * it is the log base 2 of the number of vectors.
	 */
	vdev->msi_qmax = fls(vdev->msi_nvec * 2 - 1) - 1;

	return 0;

out_free_irq:
	for (--i; i >= 0; i--)
		free_irq(pdev->irq + i, vdev->ev_msi[i]);

	pci_disable_msi(pdev);

	i = nvec; /* Reset for full clear below */

out_put_ctx:
	for (--i; i >= 0; i--)
		eventfd_ctx_put(vdev->ev_msi[i]);

	kfree(vdev->ev_msi);
	vdev->ev_msi = NULL;

	return ret;
}

void vfio_pci_drop_msix(struct vfio_pci_device *vdev)
{
	struct pci_dev *pdev = vdev->pdev;
	int i;

	if (vdev->ev_msix && vdev->msix) {
		for (i = 0; i < vdev->msix_nvec; i++) {
			free_irq(vdev->msix[i].vector, vdev->ev_msix[i]);
			eventfd_ctx_put(vdev->ev_msix[i]);
		}
	}
	kfree(vdev->ev_msix);
	vdev->ev_msix = NULL;
	kfree(vdev->msix);
	vdev->msix = NULL;
	vdev->msix_nvec = 0;
	pci_disable_msix(pdev);
}

int vfio_pci_setup_msix(struct vfio_pci_device *vdev, int nvec, int *fds)
{
	struct pci_dev *pdev = vdev->pdev;
	struct eventfd_ctx *ctx;
	int i, ret;

	vdev->msix = kzalloc(nvec * sizeof(struct msix_entry), GFP_KERNEL);
	if (!vdev->msix)
		return -ENOMEM;

	vdev->ev_msix = kzalloc(nvec * sizeof(ctx), GFP_KERNEL);
	if (!vdev->ev_msix) {
		kfree(vdev->msix);
		return -ENOMEM;
	}

	for (i = 0; i < nvec; i++) {
		ctx = eventfd_ctx_fdget(fds[i]);
		if (IS_ERR(ctx)) {
			ret = PTR_ERR(ctx);
			goto out_put_ctx;
		}
		vdev->msix[i].entry = i;
		vdev->ev_msix[i] = ctx;
	}

	ret = pci_enable_msix(pdev, vdev->msix, nvec);
	if (ret) /* >0 if request exceeds what the platform can provide */
		goto out_put_ctx;

	for (i = 0; i < nvec; i++) {
		ret = request_threaded_irq(vdev->msix[i].vector, NULL,
					   msihandler, 0, "vfio",
					   vdev->ev_msix[i]);
		if (ret)
			goto out_free_irq;
	}

	vdev->msix_nvec = nvec;

	return 0;

out_free_irq:
	for (--i; i >= 0; i--)
		free_irq(vdev->msix[i].vector, vdev->ev_msix[i]);

	pci_disable_msix(pdev);

	i = nvec; /* Reset for full clear below */

out_put_ctx:
	for (--i; i >= 0; i--)
		eventfd_ctx_put(vdev->ev_msix[i]);

	kfree(vdev->ev_msix);
	vdev->ev_msix = NULL;
	kfree(vdev->msix);
	vdev->msix = NULL;

	return ret;
}
