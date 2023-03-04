#include "fi_dpdk.h"

////// Helper functions
void free_extbuf_cb(void *addr, void *opaque) {
    return;
}

// Modified from DPDK fragmentation library
static inline void rte_pktmbuf_ext_shinfo_init_helper_custom(
    struct rte_mbuf_ext_shared_info *ret_shinfo, rte_mbuf_extbuf_free_callback_t free_cb,
    void *fcb_opaque) {

    struct rte_mbuf_ext_shared_info *shinfo = ret_shinfo;
    shinfo->free_cb                         = free_cb;
    shinfo->fcb_opaque                      = fcb_opaque;
    rte_mbuf_ext_refcnt_set(shinfo, 1);
    return;
}

////// OPS
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
    // Here I should access the RX queue of the endpoint
    // and see if there are events I can deliver

    struct dpdk_ep         *ep = container_of(ep_fid, struct dpdk_ep, util_ep.ep_fid);
    struct dpdk_xfer_entry *rx_entry;
    struct rte_mbuf        *mbuf;

    ofi_genlock_lock(&ep->rx_mutex);
    if (slist_empty(&ep->rx_queue)) {
        ofi_genlock_unlock(&ep->rx_mutex);
        return -FI_EAGAIN;
    }
    slist_remove_head_container(&ep->rx_queue, struct dpdk_xfer_entry, rx_entry, entry);
    ofi_genlock_unlock(&ep->rx_mutex);

    // Fill the msg with the data from the rx_entry
    // Is the copy necessary?
    mbuf          = (struct rte_mbuf *)rx_entry->msg_data;
    char *payload = rte_pktmbuf_mtod(mbuf, char *);

    // Why couldn't I pass directly the pointer to the payload?
    // I could avoid this copy
    memcpy(msg->msg_iov[0].iov_base, payload, mbuf->pkt_len);

    // Once delivered, free the packet descriptor
    rte_pktmbuf_free(mbuf);

    return 0;
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
    struct dpdk_domain     *domain;
    struct dpdk_xfer_entry *tx_entry;
    ssize_t                 ret = 0;

    ep     = container_of(ep_fid, struct dpdk_ep, util_ep.ep_fid);
    domain = container_of(&ep->util_ep.domain->domain_fid, struct dpdk_domain, util_domain);

    // 1. Allocate an entry from the pool => That would be an mbuf
    tx_entry = ofi_buf_alloc(domain->progress.xfer_pool);
    if (!tx_entry) {
        return -FI_EAGAIN;
    }
    tx_entry->context  = 0;
    tx_entry->cq_flags = 0;
    tx_entry->cq       = container_of(ep->util_ep.tx_cq, struct dpdk_cq, util_cq);
    tx_entry->cntr     = ep->util_ep.tx_cntr;

    // 2. Fill the entry with the data from msg, based on flag
    // If there is an immediate data, write it there
    // Here we should invoke the DDP protocol, probably!
    if (flags & FI_REMOTE_CQ_DATA) {
        tx_entry->has_immediate_data = 1;
        tx_entry->immediate_data     = msg->data;
    }

    // 3. Create a DPDK pkt_mbuf to describe the payload
    struct rte_mbuf                *payload_mbuf;
    struct rte_mbuf                *payload_mbuf_base;
    rte_iova_t                      iova;
    struct rte_mbuf_ext_shared_info ret_shinfo;
    for (int i = 0; i < msg->iov_count; i++) {
        payload_mbuf = rte_pktmbuf_alloc(domain->ext_pool);
        if (i == 0 && payload_mbuf) {
            // Keep track of the head of the chain and set initial values for the chain
            payload_mbuf_base          = payload_mbuf;
            payload_mbuf_base->nb_segs = 1;
            payload_mbuf_base->pkt_len = msg->msg_iov[i].iov_len;
        }
        // In case of failure...
        if (unlikely(!payload_mbuf)) {
            if (i != 0) {
                uint16_t allocated_segs = payload_mbuf_base->nb_segs;
                for (int j = 0; j < allocated_segs; j++) {
                    struct rte_mbuf *cur = payload_mbuf_base->next;
                    rte_pktmbuf_free(cur);
                }
                rte_pktmbuf_free(payload_mbuf_base);
            }
            return -FI_EAGAIN;
        }

        iova = rte_mem_virt2iova(msg->msg_iov[i].iov_base);
        // Create the descriptor for the external memory. Important note: DO NOT pass a NULL
        // free callback, as it would be called in the detach() function and will cause a
        // segmentation fault. If not interested in it, just pass a pointer to a function
        // that does nothing!
        rte_pktmbuf_ext_shinfo_init_helper_custom(&ret_shinfo, &free_extbuf_cb, NULL);
        // Attach the memory buffer to the mbuf
        rte_pktmbuf_attach_extbuf(payload_mbuf, msg->msg_iov[i].iov_base, iova,
                                  msg->msg_iov[i].iov_len, &ret_shinfo);
        payload_mbuf->data_len = msg->msg_iov[i].iov_len;

        if (i != 0) {
            // Append the mbuf to the chain. Assumes there are not many iovs
            // Also updates overall length and nb_segments
            rte_pktmbuf_chain(payload_mbuf_base, payload_mbuf);
        }
    }

    // 4. Add the pkt_mbuf chain to the entry
    tx_entry->msg_data     = (void *)payload_mbuf_base;
    tx_entry->msg_data_len = sizeof(struct rte_mbuf *);

    // TODO: Many flags should be set here. For the moment we ignore them. E.g., src_addr!
    // tx_entry->src_addr = ep->src_addr;

    // 5. Enqueue the entry in the TX queue => IF WE USED RTE_RING, NO NEED for locks
    ofi_genlock_lock(&ep->tx_mutex);
    slist_insert_tail(&tx_entry->entry, &ep->tx_queue);
    ofi_genlock_unlock(&ep->tx_mutex);

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