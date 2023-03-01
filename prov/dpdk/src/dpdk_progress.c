#include "fi_dpdk.h"

static struct ofi_sockapi dpdk_sockapi_uring = {
    .send  = ofi_sockapi_send_uring,
    .sendv = ofi_sockapi_sendv_uring,
    .recv  = ofi_sockapi_recv_uring,
    .recvv = ofi_sockapi_recvv_uring,
};

static struct ofi_sockapi dpdk_sockapi_socket = {
    .send  = ofi_sockapi_send_socket,
    .sendv = ofi_sockapi_sendv_socket,
    .recv  = ofi_sockapi_recv_socket,
    .recvv = ofi_sockapi_recvv_socket,
};

void dpdk_tx_queue_insert(struct dpdk_ep *ep, struct dpdk_xfer_entry *tx_entry) {

    printf("[dpdk_tx_queue_insert] UNIMPLEMENTED\n");
    // struct dpdk_progress *progress;

    // progress = dpdk_ep2_progress(ep);
    // assert(dpdk_progress_locked(progress));

    // if (!ep->cur_tx.entry) {
    // 	ep->cur_tx.entry = tx_entry;
    // 	ep->cur_tx.data_left = tx_entry->hdr.base_hdr.size;
    // 	OFI_DBG_SET(tx_entry->hdr.base_hdr.id, ep->tx_id++);
    // 	ep->hdr_bswap(ep, &tx_entry->hdr.base_hdr);
    // 	dpdk_progress_tx(ep);
    // 	if (dpdk_io_uring)
    // 		dpdk_submit_uring(&progress->tx_uring);
    // } else if (tx_entry->ctrl_flags & DPDK_INTERNAL_XFER) {
    // 	slist_insert_tail(&tx_entry->entry, &ep->priority_queue);
    // } else {
    // 	slist_insert_tail(&tx_entry->entry, &ep->tx_queue);
    // }
}

static int dpdk_init_uring(struct dpdk_uring *uring, size_t entries,
                           struct ofi_sockapi_uring *sockapi, struct ofi_dynpoll *dynpoll) {
    int ret = 0;
    printf("UNIMPLEMENTED: dpdk_init_uring\n");

    // ret = ofi_uring_init(&uring->ring, entries);
    // if (ret)
    // 	return ret;

    // uring->fid.fclass = DPDK_CLASS_URING;
    // uring->sockapi = sockapi;
    // uring->sockapi->io_uring = &uring->ring;
    // uring->sockapi->credits = ofi_uring_sq_space_left(&uring->ring);

    // ret = ofi_dynpoll_add(dynpoll,
    // 		      ofi_uring_get_fd(&uring->ring),
    // 		      POLLIN, &uring->fid);
    // if (ret)
    // 	(void) ofi_uring_destroy(&uring->ring);

    return ret;
}

static void *dpdk_auto_progress(void *arg) {
    printf("UNIMPLEMENTED: dpdk_auto_progress\n");
    // struct dpdk_progress *progress = arg;
    // int                   nfds;

    // FI_INFO(&dpdk_prov, FI_LOG_DOMAIN, "progress thread starting\n");
    // ofi_genlock_lock(progress->active_lock);
    // while (progress->auto_progress) {
    //     ofi_genlock_unlock(progress->active_lock);

    //     nfds = dpdk_progress_wait(progress, -1);
    //     ofi_genlock_lock(progress->active_lock);
    //     if (nfds >= 0)
    //         dpdk_run_progress(progress, true);
    // }
    // ofi_genlock_unlock(progress->active_lock);
    // FI_INFO(&dpdk_prov, FI_LOG_DOMAIN, "progress thread exiting\n");
    return NULL;
}

void dpdk_progress_rx(struct dpdk_ep *ep) {
    int ret;

    // TODO: Implement
    printf("UNIMPLEMENTED: dpdk_progress_rx\n");

    // assert(dpdk_progress_locked(dpdk_ep2_progress(ep)));
    // do {
    //     if (ep->cur_rx.hdr_done < ep->cur_rx.hdr_len) {
    //         ret = dpdk_recv_hdr(ep);
    //     } else {
    //         ret = ep->cur_rx.handler(ep);
    //     }

    //     if (OFI_SOCK_TRY_SND_RCV_AGAIN(-ret) || ret == -OFI_EINPROGRESS_URING)
    //         break;

    //     if (ep->cur_rx.entry)
    //         dpdk_complete_rx(ep, ret);
    //     else if (ret)
    //         dpdk_ep_disable(ep, 0, NULL, 0);

    // } while (!ret && ofi_bsock_readable(&ep->bsock));

    // if (dpdk_io_uring) {
    //     if (ret == -OFI_EINPROGRESS_URING)
    //         dpdk_update_pollflag(ep, POLLIN, false);
    //     else if (!ret || OFI_SOCK_TRY_SND_RCV_AGAIN(-ret))
    //         dpdk_update_pollflag(ep, POLLIN, true);
    // }
}

static void dpdk_submit_uring(struct dpdk_uring *uring) {
    int submitted;
    int ready;

    assert(dpdk_io_uring);

    ready = ofi_uring_sq_ready(&uring->ring);
    if (!ready)
        return;

    submitted = ofi_uring_submit(&uring->ring);
    assert(ready == submitted);
}

static void dpdk_handle_events(struct dpdk_progress *progress, struct ofi_epollfds_event *events,
                               int nfds, bool clear_signal) {
    struct fid *fid;
    bool        pin, pout, perr;
    int         i;

    assert(ofi_genlock_held(progress->active_lock));
    for (i = 0; i < nfds; i++) {
        fid = events[i].data.ptr;
        assert(fid);

        pin  = events[i].events & POLLIN;
        pout = events[i].events & POLLOUT;
        perr = events[i].events & POLLERR;

        switch (fid->fclass) {
        case FI_CLASS_EP:
            printf("UNIMPLEMENTED: dpdk_handle_events FI_CLASS_EP\n");
            // dpdk_run_ep(events[i].data.ptr, pin, pout, perr);
            break;
        case FI_CLASS_PEP:
            printf("UNIMPLEMENTED: dpdk_handle_events FI_CLASS_PEP\n");
            // dpdk_accept_sock(events[i].data.ptr);
            break;
        case FI_CLASS_CONNREQ:
            printf("UNIMPLEMENTED: dpdk_handle_events FI_CLASS_CONNREQ\n");
            // dpdk_run_conn(events[i].data.ptr, pin, pout, perr);
            break;
        case DPDK_CLASS_URING:
            printf("UNIMPLEMENTED: dpdk_handle_events DPDK_CLASS_URING\n");
            // dpdk_progress_uring(progress, events[i].data.ptr);
            break;
        default:
            assert(fid->fclass == DPDK_CLASS_PROGRESS);
            if (clear_signal)
                fd_signal_reset(&progress->signal);
            break;
        }
    }

    dpdk_handle_event_list(progress);
    if (dpdk_io_uring) {
        dpdk_submit_uring(&progress->tx_uring);
        dpdk_submit_uring(&progress->rx_uring);
    }
}

void dpdk_run_progress(struct dpdk_progress *progress, bool clear_signal) {
    struct ofi_epollfds_event events[DPDK_MAX_EVENTS];
    int                       nfds;

    assert(ofi_genlock_held(progress->active_lock));
    nfds = ofi_dynpoll_wait(&progress->epoll_fd, events, DPDK_MAX_EVENTS, 0);
    dpdk_handle_events(progress, events, nfds, clear_signal);
}

int dpdk_start_progress(struct dpdk_progress *progress) {
    int ret;

    if (dpdk_disable_autoprog)
        return 0;

    ofi_genlock_lock(progress->active_lock);
    if (progress->auto_progress) {
        ret = 0;
        goto unlock;
    }

    progress->auto_progress = true;
    ret                     = pthread_create(&progress->thread, NULL, dpdk_auto_progress, progress);
    if (ret) {
        FI_WARN(&dpdk_prov, FI_LOG_DOMAIN, "unable to start progress thread\n");
        progress->auto_progress = false;
        ret                     = -ret;
    }

unlock:
    ofi_genlock_unlock(progress->active_lock);
    return ret;
}

int dpdk_start_all(struct dpdk_fabric *fabric) {
    struct dpdk_domain *domain;
    struct dlist_entry *item;
    int                 ret;

    ret = dpdk_start_progress(&fabric->progress);
    if (ret)
        return ret;

    ofi_mutex_lock(&fabric->util_fabric.lock);
    dlist_foreach(&fabric->util_fabric.domain_list, item) {
        domain = container_of(item, struct dpdk_domain, util_domain.list_entry);
        ret    = dpdk_start_progress(&domain->progress);
        if (ret)
            break;
    }

    ofi_mutex_unlock(&fabric->util_fabric.lock);
    return ret;
}

static int dpdk_init_locks(struct dpdk_progress *progress, struct fi_info *info) {
    enum ofi_lock_type base_type, rdm_type;
    int                ret;

    if (info && info->ep_attr && info->ep_attr->type == FI_EP_RDM) {
        base_type             = OFI_LOCK_NONE;
        rdm_type              = OFI_LOCK_MUTEX;
        progress->active_lock = &progress->rdm_lock;
    } else {
        base_type             = OFI_LOCK_MUTEX;
        rdm_type              = OFI_LOCK_NONE;
        progress->active_lock = &progress->lock;
    }

    ret = ofi_genlock_init(&progress->lock, base_type);
    if (ret)
        return ret;

    ret = ofi_genlock_init(&progress->rdm_lock, rdm_type);
    if (ret)
        ofi_genlock_destroy(&progress->lock);

    return ret;
}

static void dpdk_destroy_uring(struct dpdk_uring *uring, struct ofi_dynpoll *dynpoll) {
    int ret;

    // assert(dpdk_io_uring);
    ofi_dynpoll_del(dynpoll, ofi_uring_get_fd(&uring->ring));
    assert(ofi_uring_sq_ready(&uring->ring) == 0);
    ret = ofi_uring_destroy(&uring->ring);
    if (ret) {
        FI_WARN(&dpdk_prov, FI_LOG_EP_CTRL, "Failed to destroy io_uring\n");
    }
}

int dpdk_init_progress(struct dpdk_progress *progress, struct fi_info *info) {
    int ret;

    progress->fid.fclass    = DPDK_CLASS_PROGRESS;
    progress->auto_progress = false;
    dlist_init(&progress->unexp_msg_list);
    dlist_init(&progress->unexp_tag_list);
    dlist_init(&progress->saved_tag_list);
    slist_init(&progress->event_list);

    ret = fd_signal_init(&progress->signal);
    if (ret)
        return ret;

    ret = dpdk_init_locks(progress, info);
    if (ret)
        goto err1;

    /* We may expose epoll fd to app, need a lock. */
    ret = ofi_dynpoll_create(&progress->epoll_fd, OFI_DYNPOLL_EPOLL, OFI_LOCK_MUTEX);
    if (ret)
        goto err2;

    ret = ofi_bufpool_create(&progress->xfer_pool, sizeof(struct dpdk_xfer_entry) + dpdk_max_inject,
                             16, 0, 1024, 0);
    if (ret)
        goto err3;

    ret = ofi_dynpoll_add(&progress->epoll_fd, progress->signal.fd[FI_READ_FD], POLLIN,
                          &progress->fid);
    if (ret)
        goto err4;

    if (dpdk_io_uring) {
        progress->sockapi = dpdk_sockapi_uring;

        ret =
            dpdk_init_uring(&progress->tx_uring, info ? info->tx_attr->size : dpdk_default_tx_size,
                            &progress->sockapi.tx_uring, &progress->epoll_fd);
        if (ret)
            goto err5;

        ret =
            dpdk_init_uring(&progress->rx_uring, info ? info->rx_attr->size : dpdk_default_rx_size,
                            &progress->sockapi.rx_uring, &progress->epoll_fd);
        if (ret)
            goto err6;
    } else {
        progress->sockapi = dpdk_sockapi_socket;
    }

    return 0;
err6:
    dpdk_destroy_uring(&progress->tx_uring, &progress->epoll_fd);
err5:
    ofi_dynpoll_del(&progress->epoll_fd, progress->signal.fd[FI_READ_FD]);
err4:
    ofi_bufpool_destroy(progress->xfer_pool);
err3:
    ofi_dynpoll_close(&progress->epoll_fd);
err2:
    ofi_genlock_destroy(&progress->rdm_lock);
    ofi_genlock_destroy(&progress->lock);
err1:
    fd_signal_free(&progress->signal);
    return ret;
}

void dpdk_progress(struct dpdk_progress *progress, bool clear_signal) {
    ofi_genlock_lock(progress->active_lock);
    dpdk_run_progress(progress, clear_signal);
    ofi_genlock_unlock(progress->active_lock);
}

void dpdk_progress_all(struct dpdk_fabric *fabric) {
    struct dpdk_domain *domain;
    struct dlist_entry *item;

    ofi_mutex_lock(&fabric->util_fabric.lock);
    dlist_foreach(&fabric->util_fabric.domain_list, item) {
        domain = container_of(item, struct dpdk_domain, util_domain.list_entry);
        dpdk_progress(&domain->progress, false);
    }

    ofi_mutex_unlock(&fabric->util_fabric.lock);

    dpdk_progress(&fabric->progress, false);
}

void dpdk_close_progress(struct dpdk_progress *progress) {
    printf("dpdk_close_progress: UNIMPLEMENTED\n");
    // assert(dlist_empty(&progress->unexp_msg_list));
    // assert(dlist_empty(&progress->unexp_tag_list));
    // assert(dlist_empty(&progress->saved_tag_list));
    // assert(slist_empty(&progress->event_list));
    // dpdk_stop_progress(progress);
    // if (dpdk_io_uring) {
    // 	dpdk_destroy_uring(&progress->rx_uring, &progress->epoll_fd);
    // 	dpdk_destroy_uring(&progress->tx_uring, &progress->epoll_fd);
    // }
    // ofi_dynpoll_close(&progress->epoll_fd);
    // ofi_bufpool_destroy(progress->xfer_pool);
    // ofi_genlock_destroy(&progress->lock);
    // ofi_genlock_destroy(&progress->rdm_lock);
    // fd_signal_free(&progress->signal);
}