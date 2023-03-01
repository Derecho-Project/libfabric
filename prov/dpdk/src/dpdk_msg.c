#include "fi_dpdk.h"

////// Helper functions
static inline int dpdk_queue_recv(struct dpdk_ep *ep, struct dpdk_xfer_entry *recv_entry) {
    int ret;

    assert(dpdk_progress_locked(dpdk_ep2_progress(ep)));
    ret = ep->rx_avail;
    if (ret) {
        slist_insert_tail(&recv_entry->entry, &ep->rx_queue);
        ep->rx_avail--;

        if (dpdk_has_unexp(ep)) {
            assert(!dlist_empty(&ep->unexp_entry));
            dpdk_progress_rx(ep);
        }
    }
    return ret;
}

static inline struct dpdk_xfer_entry *dpdk_alloc_send(struct dpdk_ep *ep) {
    struct dpdk_xfer_entry *send_entry;

    assert(dpdk_progress_locked(dpdk_ep2_progress(ep)));
    send_entry = dpdk_alloc_tx(ep);

    printf("[dpdk_alloc_send] UNIMPLEMENTED\n");
    // if (send_entry) {
    //     send_entry->hdr.base_hdr.op = ofi_op_msg;
    //     send_entry->cntr            = ep->util_ep.tx_cntr;
    // }

    return send_entry;
}

////// OPS
static ssize_t dpdk_recv(struct fid_ep *ep_fid, void *buf, size_t len, void *desc,
                         fi_addr_t src_addr, void *context) {
    struct dpdk_xfer_entry *recv_entry;
    struct dpdk_ep         *ep;
    ssize_t                 ret = 0;

    ep = container_of(ep_fid, struct dpdk_ep, util_ep.ep_fid);

    ofi_genlock_lock(&dpdk_ep2_progress(ep)->lock);
    recv_entry = dpdk_alloc_rx(ep);
    if (!recv_entry) {
        ret = -FI_EAGAIN;
        goto unlock;
    }

    recv_entry->user_buf        = buf;
    recv_entry->iov_cnt         = 1;
    recv_entry->iov[0].iov_base = buf;
    recv_entry->iov[0].iov_len  = len;

    recv_entry->cq_flags = FI_MSG | FI_RECV;
    recv_entry->context  = context;

    if (!dpdk_queue_recv(ep, recv_entry)) {
        dpdk_free_xfer(dpdk_ep2_progress(ep), recv_entry);
        ret = -FI_EAGAIN;
    }
unlock:
    ofi_genlock_unlock(&dpdk_ep2_progress(ep)->lock);
    return ret;
}

static ssize_t dpdk_recvv(struct fid_ep *ep_fid, const struct iovec *iov, void **desc, size_t count,
                          fi_addr_t src_addr, void *context) {
    struct dpdk_xfer_entry *recv_entry;
    struct dpdk_ep         *ep;
    ssize_t                 ret = 0;

    ep = container_of(ep_fid, struct dpdk_ep, util_ep.ep_fid);

    assert(count <= DPDK_IOV_LIMIT);

    ofi_genlock_lock(&dpdk_ep2_progress(ep)->lock);
    recv_entry = dpdk_alloc_rx(ep);
    if (!recv_entry) {
        ret = -FI_EAGAIN;
        goto unlock;
    }

    recv_entry->iov_cnt = count;
    if (count) {
        recv_entry->user_buf = iov[0].iov_base;
        memcpy(recv_entry->iov, iov, count * sizeof(*iov));
    }
    recv_entry->cq_flags = FI_MSG | FI_RECV;
    recv_entry->context  = context;

    if (!dpdk_queue_recv(ep, recv_entry)) {
        dpdk_free_xfer(dpdk_ep2_progress(ep), recv_entry);
        ret = -FI_EAGAIN;
    }
unlock:
    ofi_genlock_unlock(&dpdk_ep2_progress(ep)->lock);
    return ret;
}

static ssize_t dpdk_recvmsg(struct fid_ep *ep_fid, const struct fi_msg *msg, uint64_t flags) {
    struct dpdk_xfer_entry *recv_entry;
    struct dpdk_ep         *ep;
    ssize_t                 ret = 0;

    printf("[dpdk_recvmsg] WAITING FOR MSG\n");

    ep = container_of(ep_fid, struct dpdk_ep, util_ep.ep_fid);

    assert(msg->iov_count <= DPDK_IOV_LIMIT);

    ofi_genlock_lock(&dpdk_ep2_progress(ep)->lock);
    recv_entry = dpdk_alloc_rx(ep);
    if (!recv_entry) {
        ret = -FI_EAGAIN;
        goto unlock;
    }

    recv_entry->iov_cnt = msg->iov_count;
    if (msg->iov_count) {
        recv_entry->user_buf = msg->msg_iov[0].iov_base;
        memcpy(&recv_entry->iov[0], &msg->msg_iov[0], msg->iov_count * sizeof(struct iovec));
    }

    recv_entry->cq_flags = (flags & FI_COMPLETION) | FI_MSG | FI_RECV;
    recv_entry->context  = msg->context;

    if (!dpdk_queue_recv(ep, recv_entry)) {
        dpdk_free_xfer(dpdk_ep2_progress(ep), recv_entry);
        ret = -FI_EAGAIN;
    }
unlock:
    ofi_genlock_unlock(&dpdk_ep2_progress(ep)->lock);
    return ret;
}

static ssize_t dpdk_send(struct fid_ep *ep_fid, const void *buf, size_t len, void *desc,
                         fi_addr_t dest_addr, void *context) {
    printf("[dpdk_send] UNIMPLEMENTED\n");
    return len;
}

static ssize_t dpdk_sendv(struct fid_ep *ep_fid, const struct iovec *iov, void **desc, size_t count,
                          fi_addr_t dest_addr, void *context) {
    printf("[dpdk_sendv] UNIMPLEMENTED\n");
    return iov->iov_len;
}

static ssize_t dpdk_sendmsg(struct fid_ep *ep_fid, const struct fi_msg *msg, uint64_t flags) {
    printf("[dpdk_sendmsg] UNIMPLEMENTED\n");
    fflush(stdout);
    return 0;
}

static ssize_t dpdk_inject(struct fid_ep *ep_fid, const void *buf, size_t len,
                           fi_addr_t dest_addr) {
    printf("[dpdk_inject] UNIMPLEMENTED\n");
    return len;
}

static ssize_t dpdk_senddata(struct fid_ep *ep_fid, const void *buf, size_t len, void *desc,
                             uint64_t data, fi_addr_t dest_addr, void *context) {
    printf("[dpdk_senddata] UNIMPLEMENTED\n");
    return len;
}

static ssize_t dpdk_injectdata(struct fid_ep *ep_fid, const void *buf, size_t len, uint64_t data,
                               fi_addr_t dest_addr) {
    printf("[dpdk_injectdata] UNIMPLEMENTED\n");
    return len;
}

struct fi_ops_msg dpdk_msg_ops = {
    .size       = sizeof(struct fi_ops_msg),
    .recv       = dpdk_recv,
    .recvv      = dpdk_recvv,
    .recvmsg    = dpdk_recvmsg,
    .send       = dpdk_send,
    .sendv      = dpdk_sendv,
    .sendmsg    = dpdk_sendmsg,
    .inject     = dpdk_inject,
    .senddata   = dpdk_senddata,
    .injectdata = dpdk_injectdata,
};