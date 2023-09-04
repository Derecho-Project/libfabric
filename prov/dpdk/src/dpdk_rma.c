#include "fi_dpdk.h"

///////////////////////// Helper functions
static int ep_get_next_recv_entry(struct dpdk_ep *ep, struct dpdk_xfer_entry **xfer_entry) {
    int ret;

    ret = rte_ring_dequeue(ep->rq.free_ring, (void **)xfer_entry);
    if (ret == -ENOENT)
        ret = -ENOSPC;
    return ret;
} /* ep_get_next_recv_xfer */

static int ep_get_next_send_entry(struct dpdk_ep *ep, struct dpdk_xfer_entry **xfer_entry) {
    int ret;

    ret = rte_ring_dequeue(ep->sq.free_ring, (void **)xfer_entry);
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

// ///////////////////////// OPS
static ssize_t dpdk_readmsg(struct fid_ep *ep_fid, const struct fi_msg_rma *msg, uint64_t flags) {
    struct dpdk_ep         *ep;
    struct dpdk_xfer_entry *tx_entry;
    struct ee_state        *ee;
    ssize_t                 ret;
    uint32_t                y;

    ep = container_of(ep_fid, struct dpdk_ep, util_ep.ep_fid);
    if (!ep && !ep_connected(ep)) {
        return -EINVAL;
    }

    if (atomic_load(&ep->conn_state) == ep_conn_state_error) {
        FI_WARN(&dpdk_prov, FI_LOG_EP_CTRL,
                "Tried to post a receive on an endpoint in error state");
        ret = -EINVAL;
        goto errout;
    }

    if (msg->iov_count > ep->rq.max_sge) {
        ret = -EINVAL;
        FI_WARN(&dpdk_prov, FI_LOG_EP_CTRL, "Invalid iov_count posted for read.\n");
        goto errout;
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

    // TODO: I did not check the meaning of the flags wrt the Libfabric specification
    // We should really do a check here to make sure which flags must be supported. So far I only
    // care about FI_COMPLETION, but not in a careful way.
    tx_entry->flags = flags;

    // Fill the TX entry with the data from the msg
    tx_entry->opcode  = xfer_read;
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

    // IOV of remote buffer
    tx_entry->rma_iov_count = msg->rma_iov_count;
    memcpy(tx_entry->rma_iov, msg->rma_iov, msg->rma_iov_count * sizeof(*msg->rma_iov));

    // Enqueue
    ret = rte_ring_enqueue(ep->sq.ring, tx_entry);

    return 0;

errout:
    return ret;
}

static ssize_t dpdk_read(struct fid_ep *ep_fid, void *buf, size_t len, void *desc,
                         fi_addr_t src_addr, uint64_t addr, uint64_t key, void *context) {

    struct fi_msg_rma msg;

    struct iovec msg_iov;
    msg_iov.iov_base = buf;
    msg_iov.iov_len  = len;
    msg.msg_iov      = &msg_iov;
    msg.iov_count    = 1;

    struct fi_rma_iov rma_iov;
    rma_iov.addr      = addr;
    rma_iov.len       = len;
    rma_iov.key       = key;
    msg.rma_iov       = &rma_iov;
    msg.rma_iov_count = 1;

    msg.desc    = &desc;
    msg.addr    = src_addr; // this is ignored in the currendly DPDK impl.
    msg.context = context;

    return dpdk_readmsg(ep_fid, &msg, 0);
}

static ssize_t dpdk_readv(struct fid_ep *ep_fid, const struct iovec *iov, void **desc, size_t count,
                          fi_addr_t src_addr, uint64_t addr, uint64_t key, void *context) {
    struct fi_msg_rma msg;

    msg.msg_iov   = iov;
    msg.iov_count = count;

    struct fi_rma_iov rma_iov;
    rma_iov.addr      = addr;
    rma_iov.len       = iov->iov_len;
    rma_iov.key       = key;
    msg.rma_iov       = &rma_iov;
    msg.rma_iov_count = 1;

    msg.desc    = desc;
    msg.addr    = src_addr; // this is ignored in the currendly DPDK impl.
    msg.context = context;

    return dpdk_readmsg(ep_fid, &msg, 0);
}

static ssize_t dpdk_writemsg(struct fid_ep *ep_fid, const struct fi_msg_rma *msg, uint64_t flags) {
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

    // TODO: I did not check the meaning of the flags wrt the Libfabric specification
    // We should really do a check here to make sure which flags must be supported. So far I only
    // care about FI_COMPLETION, but not in a careful way.
    tx_entry->flags = flags;

    // Fill the TX entry with the data from the msg
    tx_entry->opcode  = (flags & FI_REMOTE_CQ_DATA) ? xfer_write_with_imm : xfer_write;
    tx_entry->context = msg->context;
    rte_memcpy(tx_entry->iov, msg->msg_iov, msg->iov_count * sizeof(*msg->msg_iov));
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

    // IOV of remote buffer
    tx_entry->rma_iov_count = msg->rma_iov_count;
    rte_memcpy(tx_entry->rma_iov, msg->rma_iov, msg->rma_iov_count * sizeof(*msg->rma_iov));

    // Immediate data
    tx_entry->imm_data = (uint32_t)msg->data;

    // Enqueue
    ret = rte_ring_enqueue(ep->sq.ring, tx_entry);

    return ret;
}

static ssize_t dpdk_write(struct fid_ep *ep_fid, const void *buf, size_t len, void *desc,
                          fi_addr_t dest_addr, uint64_t addr, uint64_t key, void *context) {

    struct fi_msg_rma msg;

    // Prepare IOVEC for the local buffer
    struct iovec msg_iov;
    msg_iov.iov_base = buf;
    msg_iov.iov_len  = len;
    msg.msg_iov      = &msg_iov;
    msg.iov_count    = 1;

    // Prepare IOVEC for the remote buffer
    struct fi_rma_iov rma_iov;
    rma_iov.addr      = addr;
    rma_iov.len       = len;
    rma_iov.key       = key;
    msg.rma_iov       = &rma_iov;
    msg.rma_iov_count = 1;

    // Other parameters
    msg.desc    = &desc;
    msg.data    = 0;
    msg.context = context;
    msg.addr    = dest_addr; // this is ignored in the current DPDK impl.

    return dpdk_writemsg(ep_fid, &msg, 0);
}

static ssize_t dpdk_writev(struct fid_ep *ep_fid, const struct iovec *iov, void **desc,
                           size_t count, fi_addr_t dest_addr, uint64_t addr, uint64_t key,
                           void *context) {
    struct fi_msg_rma msg;

    // IOV for the local buffer
    msg.msg_iov   = iov;
    msg.iov_count = count;

    // Prepare IOVEC for the remote buffer
    struct fi_rma_iov rma_iov;
    rma_iov.addr      = addr;
    rma_iov.len       = iov->iov_len;
    rma_iov.key       = key;
    msg.rma_iov       = &rma_iov;
    msg.rma_iov_count = 1;

    msg.desc    = desc;
    msg.addr    = dest_addr;
    msg.context = context;

    return dpdk_writemsg(ep_fid, &msg, 0);
}

struct fi_ops_rma dpdk_rma_ops = {
    .size       = sizeof(struct fi_ops_rma),
    .read       = dpdk_read,
    .readv      = dpdk_readv,
    .readmsg    = dpdk_readmsg,
    .write      = dpdk_write,
    .writev     = dpdk_writev,
    .writemsg   = dpdk_writemsg,
    .inject     = fi_no_rma_inject,
    .writedata  = fi_no_rma_writedata,
    .injectdata = fi_no_rma_injectdata,
};
