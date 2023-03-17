#include "fi_dpdk.h"

///////////////////////// Helper functions
static void free_extbuf_cb(void *addr, void *opaque) {
    return;
}

static int ep_get_next_recv_entry(struct dpdk_ep *ep, struct dpdk_xfer_entry **xfer_entry) {
    int ret;

    rte_spinlock_lock(&ep->rq.lock);
    ret = rte_ring_dequeue(ep->rq.free_ring, (void **)xfer_entry);
    rte_spinlock_unlock(&ep->rq.lock);
    if (ret == -ENOENT)
        ret = -ENOSPC;
    return ret;
} /* ep_get_next_recv_xfer */

// Returns the given receive XFER back to the free pool.  It is removed from the active set if
// still_in_hash is true. The rq lock MUST be locked when calling this function.
// TODO; This isn't called by anyone? really? Why?
void ep_free_recv_xfer(struct dpdk_ep *ep, struct dpdk_xfer_entry *wqe) {
    dlist_remove(&wqe->entry);
    rte_ring_enqueue(ep->rq.free_ring, wqe);
} /* ep_free_recv_xfer */

static int ep_get_next_send_entry(struct dpdk_ep *ep, struct dpdk_xfer_entry **xfer_entry) {
    int ret;

    rte_spinlock_lock(&ep->sq.lock);
    ret = rte_ring_dequeue(ep->sq.free_ring, (void **)xfer_entry);
    rte_spinlock_unlock(&ep->sq.lock);
    if (ret == -ENOENT) {
        FI_WARN(&dpdk_prov, FI_LOG_EP_CTRL, "Send queue full!");
        ret = -ENOSPC;
    }
    return ret;
} /* qp_get_next_send_entry */

static int32_t ep_connected(struct dpdk_ep *ep) {
    uint16_t tmp = atomic_load(&ep->conn_state);
    return tmp == ep_conn_state_connected;
} /* qp_connected */

///////////////////////// OPS
static ssize_t dpdk_recv(struct fid_ep *ep_fid, void *buf, size_t len, void *desc,
                         fi_addr_t src_addr, void *context) {

    // Here I should access the RX queue of the endpoint
    // and see if there are events I can deliver
    printf("[dpdk_recv] UNIMPLEMENTED\n");
    return 0;
}

static ssize_t dpdk_recvv(struct fid_ep *ep_fid, const struct iovec *iov, void **desc, size_t count,
                          fi_addr_t src_addr, void *context) {
    // Here I should access the RX queue of the endpoint
    // and see if there are events I can deliver
    printf("[dpdk_recv] UNIMPLEMENTED\n");
    return 0;
}

static ssize_t dpdk_recvmsg(struct fid_ep *ep_fid, const struct fi_msg *msg, uint64_t flags) {
    // This function posts a receive request to the RX queue of the endpoint
    struct dpdk_ep         *ep = container_of(ep_fid, struct dpdk_ep, util_ep.ep_fid);
    struct dpdk_xfer_entry *rx_entry;
    struct rte_mbuf        *mbuf;
    int                     ret;

    if (atomic_load(&ep->conn_state) == ep_conn_state_error) {
        FI_WARN(&dpdk_prov, FI_LOG_EP_CTRL,
                "Tried to post a receive on an endpoint in error state");
        ret = -EINVAL;
        goto errout;
    }

    if (msg->iov_count > ep->rq.max_sge) {
        ret = -EINVAL;
        FI_WARN(&dpdk_prov, FI_LOG_EP_CTRL, "Invalid iov_count posted for receive.\n");
        goto errout;
    }

    ret = ep_get_next_recv_entry(ep, &rx_entry);
    if (ret < 0) {
        ret = -ret;
        goto errout;
    }

    rx_entry->context      = msg->context;
    rx_entry->total_length = 0;
    rx_entry->iov_count    = msg->iov_count;
    for (int x = 0; x < rx_entry->iov_count; ++x) {
        rx_entry->iov[x].iov_base = msg->msg_iov[x].iov_base;
        rx_entry->iov[x].iov_len  = msg->msg_iov[x].iov_len;
        rx_entry->total_length += rx_entry->iov[x].iov_len;
    }
    rx_entry->remote_ep  = &ep->remote_ep;
    rx_entry->msn        = 0;
    rx_entry->recv_size  = 0;
    rx_entry->input_size = 0;
    rx_entry->complete   = false;

    printf("ENQUEUE READ REQUEST with total length of %u\n", rx_entry->total_length);

    ret = rte_ring_enqueue(ep->rq.ring, rx_entry);
    if (ret < 0) {
        ret = -ret;
        goto errout;
    }

    return 0;

errout:
    return ret;
}

static ssize_t dpdk_send(struct fid_ep *ep_fid, const void *buf, size_t len, void *desc,
                         fi_addr_t dest_addr, void *context) {

    // Here I should access the TX queue of the endpoint
    // insert the message and return
    printf("[dpdk_send] UNIMPLEMENTED\n");
    return len;
}

static ssize_t dpdk_sendv(struct fid_ep *ep_fid, const struct iovec *iov, void **desc, size_t count,
                          fi_addr_t dest_addr, void *context) {
    printf("[dpdk_sendv] UNIMPLEMENTED\n");
    return iov->iov_len;
}

static ssize_t dpdk_sendmsg(struct fid_ep *ep_fid, const struct fi_msg *msg, uint64_t flags) {
    struct dpdk_ep         *ep;
    struct dpdk_xfer_entry *tx_entry;
    struct ee_state        *ee;
    ssize_t                 ret;
    uint32_t                y;

    ep = container_of(ep_fid, struct dpdk_ep, util_ep.ep_fid);
    if (!ep && !ep_connected(ep)) {
        return -EINVAL;
    }

    if (msg->iov_count > dpdk_util_prov.info->tx_attr->iov_limit) {
        FI_WARN(&dpdk_prov, FI_LOG_EP_DATA, "IOV size is too high\n");
        return -EINVAL;
    }

    ee = &ep->remote_ep;
    if (!ee) {
        FI_WARN(&dpdk_prov, FI_LOG_EP_DATA, "Remote endpoint descriptor is not available\n");
        return -EINVAL;
    }

    // Get a free TX entry from the TX queue ring associated to the EP
    ret = ep_get_next_send_entry(ep, &tx_entry);
    if (ret < 0) {
        return ret;
    }

    // TODO: support libfabric flags

    // Fill the TX entry with the data from the msg
    tx_entry->opcode  = xfer_send;
    tx_entry->context = msg->context;
    memcpy(tx_entry->iov, msg->msg_iov, msg->iov_count * sizeof(*msg->msg_iov));
    tx_entry->iov_count    = msg->iov_count;
    tx_entry->remote_ep    = ee;
    tx_entry->state        = SEND_XFER_INIT;
    tx_entry->msn          = 0; /* will be assigned at send time */
    tx_entry->total_length = 0;
    for (y = 0; y < msg->iov_count; ++y) {
        tx_entry->total_length += tx_entry->iov[y].iov_len;
    }
    tx_entry->bytes_sent  = 0;
    tx_entry->bytes_acked = 0;
    ret                   = rte_ring_enqueue(ep->sq.ring, tx_entry);

    return ret;
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