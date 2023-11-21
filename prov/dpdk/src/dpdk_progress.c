#include "fi_dpdk.h"
#include "protocols.h"

// ================ Helper functions =================
bool serial_less_32(uint32_t s1, uint32_t s2) {
    return (s1 < s2 && s2 - s1 < (UINT32_C(1) << 31)) || (s1 > s2 && s1 - s2 > (UINT32_C(1) << 31));
} /* serial_less_32 */

bool serial_greater_32(uint32_t s1, uint32_t s2) {
    return (s1 < s2 && s2 - s1 > (UINT32_C(1) << 31)) || (s1 > s2 && s1 - s2 < (UINT32_C(1) << 31));
} /* serial_greater_32 */

// TODO: This function can likely be optimized
static void memcpy_mbuf_to_iov(struct iovec *restrict dst, size_t          dst_count,
                               const struct rte_mbuf *restrict src, size_t payload_length,
                               size_t offset) {
    // Total amount of bytes copied
    size_t total_copied = 0;
    // Amount of bytes to copy in the current iteration
    size_t max_copy = 0;
    // Number of source iov chunks
    size_t src_count = src->nb_segs;
    // Current dst iov chunk
    size_t cur_dst_chunk;
    // Current mbuf being copied
    struct rte_mbuf *cur_mbuf;
    // Amount of bytes consumed from src or dst iov chuncks
    size_t src_bytes_copied, dst_bytes_copied;

    // 1. Find the right dst segment taking offset into account
    cur_dst_chunk = 0;
    while (offset > 0) {
        if (offset >= dst[cur_dst_chunk].iov_len) {
            offset -= dst[cur_dst_chunk].iov_len;
            cur_dst_chunk++;
        } else {
            break;
        }
    }

    // 2. For each source chunk, copy it to the destination
    cur_mbuf         = (struct rte_mbuf *)src;
    dst_bytes_copied = 0;
    for (int i = 0; i < src->nb_segs; i++) {

        // Bytes copied from this src chunk
        src_bytes_copied = 0;
        while (src_bytes_copied < cur_mbuf->data_len) {
            max_copy =
                RTE_MIN(dst[cur_dst_chunk].iov_len - offset - dst_bytes_copied, cur_mbuf->data_len);
            rte_memcpy(dst[cur_dst_chunk].iov_base + offset + dst_bytes_copied,
                       rte_pktmbuf_mtod(cur_mbuf, char *), max_copy);

            dst_bytes_copied += max_copy;
            src_bytes_copied += max_copy;
            total_copied += max_copy;

            // Check if the current dst chunk is full
            if (dst[cur_dst_chunk].iov_len - offset - dst_bytes_copied == 0) {
                cur_dst_chunk++;
                dst_bytes_copied = 0;
                offset           = 0;
            }
        }

        cur_mbuf = cur_mbuf->next;
    }
    assert(total_copied == payload_length);

} /* memcpy_to_iov */

// TODO: do we really need a separate function for this?
static void xfer_queue_add_active(struct dpdk_xfer_queue *q, struct dpdk_xfer_entry *wqe) {
    dlist_insert_tail(&wqe->entry, &q->active_head);

} /* xfer_queue_add_active */

// Looks for a specific entry in the queue
static int xfer_recv_queue_lookup(struct dpdk_xfer_queue *q, uint32_t msn,
                                  struct dpdk_xfer_entry **xfer_entry) {

    // TODO: can we use dlist_find_first_match?

    struct dpdk_xfer_entry *lptr;
    struct dlist_entry     *entry, *tmp;
    DPDK_DBG(FI_LOG_EP_CTRL, "LOOKUP active recv XFE msn=%u\n", msn);
    dlist_foreach_safe(&q->active_head, entry, tmp) {
        lptr = container_of(entry, struct dpdk_xfer_entry, entry);
        if (lptr->msn == msn) {
            *xfer_entry = lptr;
            return 0;
        }
    }
    return -ENOENT;
} /* usiw_recv_wqe_queue_lookup */

static void dequeue_recv_entries(struct dpdk_ep *ep) {
    struct dpdk_xfer_entry *xfer[ep->rq.max_wr + 1];
    int                     ret;

    while ((ret = rte_ring_dequeue_burst(ep->rq.ring, (void **)xfer, ep->rq.max_wr + 1, NULL)) > 0)
    {
        for (int i = 0; i < ret; i++) {
            xfer[i]->remote_ep = &ep->remote_ep;
            xfer[i]->msn       = ep->rq.next_msn++;
            xfer_queue_add_active(&ep->rq, xfer[i]);
        }
    }
} /* dequeue_recv_wqes */

static int xfer_send_queue_lookup(struct dpdk_xfer_queue *q, uint16_t wr_opcode,
                                  uint32_t wr_key_data, struct dpdk_xfer_entry **wqe) {
    struct dpdk_xfer_entry *lptr;
    struct dlist_entry     *entry, *tmp;
    dlist_foreach_safe(&q->active_head, entry, tmp) {
        lptr = container_of(entry, struct dpdk_xfer_entry, entry);
        if (lptr->opcode != wr_opcode) {
            continue;
        }
        switch (lptr->opcode) {
        case xfer_send:
        case xfer_atomic:
            if (wr_key_data == lptr->msn) {
                *wqe = lptr;
                return 0;
            }
            break;
        case xfer_write:
            if (wr_key_data == lptr->rma_iov[0].key) {
                *wqe = lptr;
                return 0;
            }
            break;
        case xfer_read:
            if (wr_key_data == lptr->local_stag) {
                *wqe = lptr;
                return 0;
            }
            break;
        }
    }
    return -ENOENT;
} /* usiw_send_wqe_queue_lookup */

/** Retrieves a free CQE from the completion queue. */
static int get_next_cqe(struct dpdk_cq *cq, struct fi_dpdk_wc **cqe) {
    void *p;
    int   ret;

    ret = rte_ring_dequeue(cq->free_ring, &p);
    if (ret < 0) {
        *cqe = NULL;
        return ret;
    }
    *cqe = p;
    return 0;
} /* get_next_cqe */

/** Returns the given send WQE back to the free pool.  It is removed from the
 * active set if still_active is true.  The sq lock MUST be locked when
 * calling this function. */
void ep_free_send_wqe(struct dpdk_ep *ep, struct dpdk_xfer_entry *wqe, bool still_active) {
    if (still_active) {
        dlist_remove(&wqe->entry);
    }
    rte_ring_enqueue(ep->sq.free_ring, wqe);
} /* ep_free_send_wqe */

/** post_recv_cqe posts a CQE corresponding to a receive WQE, and frees the
 * completed WQE.  Locking on the CQ ensures that any operation done prior to
 * this will be seen by other threads prior to the completion being delivered.
 * This ensures that new operations can be posted immediately. */
static int post_recv_cqe(struct dpdk_ep *ep, struct dpdk_xfer_entry *xfe,
                         enum fi_wc_status status) {
    struct fi_dpdk_wc *cqe;
    struct dpdk_cq    *cq;
    int                ret;

    cq  = container_of(ep->util_ep.rx_cq, struct dpdk_cq, util_cq);
    ret = get_next_cqe(cq, &cqe);
    if (ret < 0) {
        DPDK_INFO(FI_LOG_EP_CTRL, "Failed to post recv CQE: %s\n", strerror(-ret));
        return ret;
    }
    cqe->wr_context = xfe->context;
    cqe->status     = status;
    cqe->opcode     = FI_WC_RECV;
    cqe->byte_len   = xfe->input_size;
    cqe->ep_id      = ep->udp_port;
    cqe->imm_data   = xfe->imm_data;
    cqe->wc_flags   = FI_WC_WITH_IMM;

    /** Returns the given receive WQE back to the free pool.  It is removed from
     * the active set if still_in_hash is true.  The rq lock MUST be locked when
     * calling this function. */
    dlist_remove(&xfe->entry);
    rte_ring_enqueue(ep->rq.free_ring, xfe);

    /* Actually post the CQE to the CQ */
    rte_ring_enqueue(cq->cqe_ring, cqe);

    return 0;
} /* post_recv_cqe */

static enum fi_wc_opcode get_send_wc_opcode(struct dpdk_xfer_entry *wqe) {
    switch (wqe->opcode) {
    case xfer_send:
    case xfer_send_with_imm:
        return FI_WC_SEND;
    case xfer_write:
    case xfer_write_with_imm:
        return FI_WC_RDMA_WRITE;
    case xfer_read:
        return FI_WC_RDMA_READ;
    case xfer_atomic:
        switch (wqe->atomic_opcode) {
        case rdmap_atomic_fetchadd:
            return FI_WC_FETCH_ADD;
            break;
        case rdmap_atomic_cmpswap:
            return FI_WC_COMP_SWAP;
            break;
        }
        break;
    default:
        assert(0);
        return -1;
    }
} /* get_send_wc_opcode */

/** post_send_cqe posts a CQE corresponding to a WQE, and frees the
 * completed WQE.  Locking on the CQ ensures that any operation done prior to
 * this will be seen by other threads prior to the completion being delivered.
 * This ensures that new operations can be posted immediately. */
static int post_send_cqe(struct dpdk_ep *ep, struct dpdk_xfer_entry *wqe,
                         enum fi_wc_status status) {
    struct fi_dpdk_wc *cqe;
    struct dpdk_cq    *cq;
    int                ret;

    cq = container_of(ep->util_ep.tx_cq, struct dpdk_cq, util_cq);
    if (!cq) {
        DPDK_WARN(FI_LOG_EP_CTRL, "Failed to get EP CQ\n");
        return ret;
    }
    ret = get_next_cqe(cq, &cqe);
    if (ret < 0) {
        DPDK_WARN(FI_LOG_EP_CTRL, "Failed to post send CQE: %s\n", strerror(-ret));
        return ret;
    }
    cqe->wr_context = wqe->context;
    cqe->status     = status;
    cqe->opcode     = get_send_wc_opcode(wqe);
    cqe->ep_id      = ep->udp_port;

    ep_free_send_wqe(ep, wqe, true);
    rte_ring_enqueue(cq->cqe_ring, cqe);

    return 0;
} /* post_send_cqe */

/** Complete the requested WQE if and only if all completion ordering rules
 * have been met. */
static void try_complete_wqe(struct dpdk_ep *ep, struct dpdk_xfer_entry *wqe) {
    /* We cannot post the completion until all previous WQEs have
     * completed. */
    if (wqe == container_of(ep->sq.active_head.next, struct dpdk_xfer_entry, entry)) {
        rte_spinlock_lock(&ep->sq.lock);
        if (wqe->flags & FI_COMPLETION || ep->util_ep.tx_msg_flags & FI_COMPLETION ||
            ep->util_ep.rx_msg_flags & FI_COMPLETION)
        {
            post_send_cqe(ep, wqe, FI_WC_SUCCESS);
        } else {
            FI_TRACE(&dpdk_prov, FI_LOG_EP_CTRL,
                     "<ep=%u> Dropping TX completion, as FI_SELECTIVE_COMPLETION is set and "
                     "FI_COMPLETION flag is not set on this specific operation\n",
                     ep->udp_port);
            ep_free_send_wqe(ep, wqe, true);
        }
        rte_spinlock_unlock(&ep->sq.lock);
        if (wqe->opcode == xfer_read || wqe->opcode == xfer_atomic) {
            assert(ep->ord_active > 0);
            ep->ord_active--;
        }
    }
} /* try_complete_wqe */

/* Process RDMAP Send OPcode */
// 0 - if the send has been successfully posted
// > 0 - if the send needs to wait for the corresponding receive
// < 0 - if there was an error
static int process_rdma_send(struct dpdk_ep *ep, struct packet_context *orig, bool retry) {
    struct dpdk_xfer_entry       *xfer_e;
    struct dlist_entry           *tmp;
    struct rdmap_untagged_packet *rdmap = (struct rdmap_untagged_packet *)orig->rdmap;
    uint32_t                      msn, expected_msn;
    size_t                        offset;
    size_t                        payload_length;
    int                           ret;

    /* Pull all the *new* EP recv requests off of the ring and enqueues them in a dlist instead.
     * Because we need to look the right recv request to match the incoming send request, the
     * uRDMA implementation dequeues all the entries from the ring, places them into a queue,
     * looks for the queue entry that matches the incoming send request. The dequeued entries
     * remain in the queue. If the queue is empty, we try to refill it by reading new requests
     * from the ring.*/
    if (dlist_empty(&ep->rq.active_head)) {
        dequeue_recv_entries(ep);
    }

    // Find the matching recv request.
    msn = rte_be_to_cpu_32(rdmap->msn);
    ret = xfer_recv_queue_lookup(&ep->rq, msn, &xfer_e);
    assert(ret != -EINVAL);

    // If not found and this is a retry, we have to wait more
    if (ret < 0 && retry) {
        return 1;
    }
    // If not found and this is the first time we try to match with a recv, we've got either a
    // duplicate or a message with no matching recv request.
    if (ret < 0) {
        if (!dlist_empty(&ep->rq.active_head)) {
            /* This is a duplicate of a previously received
             * message --- should never happen since TRP will not
             * give us a duplicate packet. */
            expected_msn = container_of(&ep->rq.active_head, struct dpdk_xfer_entry, entry)->msn;
            DPDK_WARN(FI_LOG_EP_CTRL, "<ep=%u> Received msn=%u but expected msn=%u\n", ep->udp_port,
                      msn, expected_msn);
            do_rdmap_terminate(ep, orig, ddp_error_untagged_invalid_msn);
            return -1;
        } else {
            DPDK_DBG(FI_LOG_EP_CTRL, "<ep=%u> Received SEND msn=%u to empty receive queue\n",
                     ep->udp_port, msn);
            // This send is orphan: we will try to complete it later
            struct dpdk_domain *domain =
                container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);
            struct packet_context *ctx;
            rte_ring_dequeue(domain->free_ctx_ring, (void **)&ctx);
            *ctx = *orig;
            dlist_insert_tail(&ctx->entry, &domain->orphan_sends);
            return 1;
        }
    }

    // Process the matching request
    offset         = rte_be_to_cpu_32(rdmap->mo);
    payload_length = orig->ddp_seg_length - sizeof(struct rdmap_untagged_packet);
    if (offset + payload_length > xfer_e->total_length) {
        DPDK_INFO(FI_LOG_EP_CTRL, "<ep=%u> DROP: offset=%zu + payload_length=%zu > wr_len=%zu\n",
                  ep->udp_port, offset, payload_length, xfer_e->total_length);
        do_rdmap_terminate(ep, orig, ddp_error_untagged_message_too_long);
        return -1;
    }

    if (DDP_GET_L(rdmap->head.ddp_flags)) {
        if (xfer_e->input_size != 0) {
            DPDK_DBG(FI_LOG_EP_CTRL, "<ep=%u> silently DROP duplicate last packet.\n",
                     ep->udp_port);
            return -1;
        }
        xfer_e->input_size = offset + payload_length;
    }

    DPDK_DBG(FI_LOG_EP_CTRL, "<ep=%u> recv_size=%u, iov_count=%u, data_buffer=%p\n", ep->udp_port,
             xfer_e->recv_size + payload_length, xfer_e->iov_count, xfer_e->iov[0].iov_base);

    rte_pktmbuf_adj(orig->mbuf_head, sizeof(struct rdmap_untagged_packet));
    memcpy_mbuf_to_iov(xfer_e->iov, xfer_e->iov_count, orig->mbuf_head, payload_length, offset);
    xfer_e->recv_size += payload_length;
    assert(xfer_e->input_size == 0 || xfer_e->recv_size <= xfer_e->input_size);
    if (xfer_e->recv_size == xfer_e->input_size) {
        xfer_e->complete = true;
    }

    // Immediate data
    xfer_e->imm_data = rdmap->head.immediate;

    /* Post completion, but only if there are no holes in the LLP packet
     * sequence. This ensures that even in the case of missing packets,
     * we maintain the ordering between received Tagged and Untagged
     * frames. Walk the queue starting at the head to make sure we post
     * completions that we had previously deferred.
     * Calling post_recv_cqe will remove the current entry from the list
     */

    if (serial_less_32(orig->psn, xfer_e->remote_ep->recv_ack_psn)) {
        dlist_foreach_container_safe(&ep->rq.active_head, struct dpdk_xfer_entry, xfer_e, entry,
                                     tmp) {
            if (xfer_e->complete) {
                rte_spinlock_lock(&ep->rq.lock);
                post_recv_cqe(ep, xfer_e, FI_WC_SUCCESS);
                rte_spinlock_unlock(&ep->rq.lock);
            } else {
                break;
            }
        }
    }

    return 0;
} /* process_send */

/* Try to match SEND requests with RECV requests that were posted later */
static void try_match_orphan_sends(struct dpdk_domain *domain) {
    struct packet_context *ctx;
    struct dlist_entry    *tmp;

    if (dlist_empty(&domain->orphan_sends)) {
        return;
    }

    // For each orphan, try to re-process the send
    dlist_foreach_container_safe(&domain->orphan_sends, struct packet_context, ctx, entry, tmp) {

        // Dequeue the recv entries still in the ring. If none, continue to wait.
        // If some, there could be a match, so try to process the send again.
        dequeue_recv_entries(ctx->dst_ep);
        if (dlist_empty(&ctx->dst_ep->rq.active_head)) {
            continue;
        }

        // In case the match is found (0), or in case of error (<0),  the orphan is removed from the
        // list, the mbuf is freed, the descriptor is reused. Otherwise, just wait more.
        if (process_rdma_send(ctx->dst_ep, ctx, true) <= 0) {
            dlist_remove(&ctx->entry);
            rte_pktmbuf_free(ctx->mbuf_head);
            rte_ring_enqueue(domain->free_ctx_ring, ctx);
        }
    }
}

static void process_rdma_read_request(struct dpdk_ep *ep, struct packet_context *orig) {
    struct rdmap_readreq_packet       *rdmap = (struct rdmap_readreq_packet *)orig->rdmap;
    struct read_atomic_response_state *readresp;
    uint32_t                           rkey;
    uint32_t                           msn;
    struct dpdk_mr                    *mr;
    struct dpdk_domain *domain = container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);

    msn = rte_be_to_cpu_32(rdmap->untagged.msn);
    if (msn < orig->src_ep->expected_read_msn || msn >= ep->readresp_head_msn + dpdk_max_ird) {
        DPDK_WARN(FI_LOG_EP_CTRL,
                  "<ep=%u> RDMA READ failure: expected MSN in range [%u, %u] received %u\n",
                  ep->udp_port, orig->src_ep->expected_read_msn,
                  ep->readresp_head_msn + dpdk_max_ird, msn);
        do_rdmap_terminate(ep, orig, ddp_error_untagged_invalid_msn);
        return;
    }
    if (msn == orig->src_ep->expected_read_msn)
        orig->src_ep->expected_read_msn++;

    rkey = rte_be_to_cpu_32(rdmap->source_stag);

    struct dpdk_domain *dpdk_domain =
        container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);
    ofi_genlock_lock(&dpdk_domain->mr_tbl_lock);
    mr = dpdk_mr_lookup(&domain->mr_tbl, rkey);
    ofi_genlock_unlock(&dpdk_domain->mr_tbl_lock);

    if (!mr) {
        DPDK_WARN(FI_LOG_EP_CTRL, "<ep=%u> RDMA READ failure: invalid rkey %x\n", ep->udp_port,
                  rkey);
        do_rdmap_terminate(ep, orig, rdmap_error_stag_invalid);
        return;
    }

    uintptr_t vaddr       = (uintptr_t)rte_be_to_cpu_64(rdmap->source_offset);
    uint32_t  rdma_length = rte_be_to_cpu_32(rdmap->read_msg_size);
    if (vaddr < (uintptr_t)mr->buf || vaddr + rdma_length > (uintptr_t)mr->buf + mr->len) {
        DPDK_WARN(FI_LOG_EP_CTRL,
                  "<ep=%u> RDMA READ failure: source [%p, %p] outside of memory region "
                  "[%p, %p]\n",
                  ep->udp_port, vaddr, vaddr + rdma_length, (uintptr_t)mr->buf,
                  (uintptr_t)mr->buf + mr->len);
        do_rdmap_terminate(ep, orig, rdmap_error_base_or_bounds_violation);
        return;
    }

    readresp = &ep->readresp_store[msn % dpdk_max_ird];
    if (readresp->active) {
        DPDK_WARN(FI_LOG_EP_CTRL, "<ep=%u> RDMA READ failure: duplicate MSN %u\n", ep->udp_port,
                  msn);
        do_rdmap_terminate(ep, orig, rdmap_error_remote_stream_catastrophic);
        return;
    }
    readresp->active           = true;
    readresp->type             = read_response;
    readresp->vaddr            = (void *)vaddr;
    readresp->sink_stag        = rdmap->untagged.head.sink_stag;
    readresp->sink_ep          = orig->src_ep;
    readresp->read.msg_size    = rdma_length;
    readresp->read.sink_offset = rte_be_to_cpu_64(rdmap->sink_offset);
} /* process_rdma_read_request */

static void process_rdma_read_response(struct dpdk_ep *ep, struct packet_context *orig) {
    struct rdmap_tagged_packet *rdmap;
    struct dpdk_xfer_entry     *read_wqe;
    int                         ret;

    /* This ensures that at least one RDMA READ Request is active for this
     * STag. We don't need to know exactly which one; this just ensures
     * that we don't accept a random RDMA READ Response. */
    rdmap = (struct rdmap_tagged_packet *)orig->rdmap;
    ret   = xfer_send_queue_lookup(&ep->sq, xfer_read, rte_be_to_cpu_32(rdmap->head.sink_stag),
                                   &read_wqe);

    if (ret < 0 || !read_wqe || read_wqe->opcode != xfer_read) {
        DPDK_DBG(FI_LOG_EP_CTRL, "<ep=%u> Unexpected RDMA READ response!\n", ep->udp_port);
        do_rdmap_terminate(ep, orig, rdmap_error_opcode_unexpected);
        return;
    }

    /* If this was the last segment of an RDMA READ Response message, insert
     * its PSN into the heap. Next time we receive a burst of packets, we
     * will retrieve this PSN from the heap if we have received all prior
     * packets and complete the corresponding WQE in the correct order. */
    if (DDP_GET_L(rdmap->head.ddp_flags)) {
        binheap_insert(ep->remote_ep.recv_rresp_last_psn, orig->psn);

        // TODO: If we need to generate a completion for this, we need to do it here
        // but should we?
    }
} /* process_rdma_read_response */

/* Transmits all packets currently in the transmit queue.  The queue will be
 * empty when this function returns. FIXME: It may be possible for this to never return
 * if there is any error that prevents packets from being transmitted. */
void flush_tx_queue(struct dpdk_ep *ep) {
    struct dpdk_domain *domain;
    struct rte_mbuf   **begin;
    int                 ret;

    domain = container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);
    assert(domain->res);

    begin            = ep->txq;
    uint32_t nb_segs = ep->txq_end - begin;
    if (!nb_segs) {
        return;
    }

    /* Transmit the enqueued packets. It is the responsibility of the rte_eth_tx_burst()
     * function to transparently free the memory buffers of packets previously sent. So we
     * should have cloned those that we do not want to free */
    while (begin != ep->txq_end) {
        ret = rte_eth_tx_burst(domain->res->port_id, domain->res->data_txq_id, begin, nb_segs);
        DPDK_DBG(FI_LOG_EP_DATA, "Transmitted %d packets\n", ret);
        begin += ret;
    }

    ep->txq_end = ep->txq;

} /* flush_tx_queue */

static void progress_send_xfer(struct dpdk_ep *ep, struct dpdk_xfer_entry *entry) {
    if (entry->state == SEND_XFER_COMPLETE) {
        try_complete_wqe(ep, entry);
        return;
    }

    // These are functions that process the xfer_entry and prepare the header files
    // effectively execuring the userspace protocol processing.
    switch (entry->opcode) {
    case xfer_send:
    case xfer_send_with_imm:
        do_rdmap_send(ep, entry);
        break;
    case xfer_write:
    case xfer_write_with_imm:
        do_rdmap_write(ep, entry);
        break;
    case xfer_read:
        do_rdmap_read_request(ep, entry);
        break;
        // TODO: Finish implementation for the fi_atomic
        // case xfer_atomic:
        //     do_rdmap_atomic(qp, wqe);
        //     break;
    }
} /* progress_send_xfer */

static void process_terminate(struct dpdk_ep *ep, struct packet_context *orig) {
    struct dpdk_xfer_entry         *wqe;
    struct rdmap_terminate_packet  *rdmap;
    struct rdmap_terminate_payload *rreq;
    struct rdmap_tagged_packet     *t;
    enum fi_wc_status               wc_status;
    struct dpdk_mr                **mr;
    uint_fast16_t                   errcode;
    int                             ret;

    rdmap   = (struct rdmap_terminate_packet *)orig->rdmap;
    errcode = rte_be_to_cpu_16(rdmap->error_code);
    if (!(rdmap->hdrct & rdmap_hdrct_d)) {
        DPDK_WARN(FI_LOG_EP_CTRL,
                  "<ep=%u> Received TERMINATE with error code %#x and no DDP header\n",
                  ep->udp_port, errcode);
        wqe = NULL;
        goto out;
    }

    switch (errcode & 0xff00) {
    case 0x0100:
        /* RDMA Read Request Error */
        rreq = (struct rdmap_terminate_payload *)(rdmap + 1);
        ret  = xfer_send_queue_lookup(&ep->sq, xfer_read, rte_be_to_cpu_32(rreq->payload.sink_stag),
                                      &wqe);
        if (ret < 0 || !wqe || wqe->opcode != xfer_read) {
            DPDK_DBG(FI_LOG_EP_CTRL,
                     "<ep=%u> TERMINATE sink_stag=%u has no matching RDMA Read Request\n",
                     ep->udp_port, rte_be_to_cpu_32(rreq->payload.sink_stag));
            return;
        }
        // TODO: We should consider the DE-registration of the memory regions
        // mr = usiw_mr_lookup(ep->pd, STAG_RDMA_READ(wqe->msn));
        // if (mr) {
        //     usiw_dereg_mr_real(qp->pd, mr);
        // }
        // wc_status = IBV_WC_REM_ACCESS_ERR;
        break;
    case 0x1100:
        /* DDP Tagged Message Error (RDMA Write/RDMA Read Response) */
        t         = (struct rdmap_tagged_packet *)(rdmap + 1);
        wc_status = FI_WC_REM_ACCESS_ERR;
        switch (RDMAP_GET_OPCODE(t->head.rdmap_info)) {
        case rdmap_opcode_rdma_write:
            ret = xfer_send_queue_lookup(&ep->sq, xfer_write, rte_be_to_cpu_32(t->head.sink_stag),
                                         &wqe);
            if (ret < 0 || !wqe) {
                DPDK_DBG(FI_LOG_EP_CTRL,
                         "<ep=%u> TERMINATE sink_stag=%" PRIu32
                         " has no matching RDMA WRITE operation\n",
                         ep->udp_port, rte_be_to_cpu_32(t->head.sink_stag));
            }
            break;
        case rdmap_opcode_rdma_read_response:
            DPDK_DBG(FI_LOG_EP_CTRL,
                     "<ep=%u> TERMINATE sink_stag=%u has tagged message error but no "
                     "matching RDMA "
                     "READ Response\n",
                     ep->udp_port, rte_be_to_cpu_32(t->head.sink_stag));
        default:
            DPDK_DBG(FI_LOG_EP_CTRL,
                     "<ep=%u> TERMINATE sink_stag=%u has tagged message error but invalid "
                     "opcode %u\n",
                     ep->udp_port, rte_be_to_cpu_32(t->head.sink_stag),
                     RDMAP_GET_OPCODE(t->head.rdmap_info));
        }
        break;
    default:
        DPDK_DBG(FI_LOG_EP_CTRL,
                 "<ep=%u> Received TERMINATE with unhandled error code %#" PRIxFAST16 "\n",
                 ep->udp_port, errcode);
        wqe = NULL;
        break;
    }

out:
    if (wqe) {
        rte_spinlock_lock(&ep->sq.lock);
        post_send_cqe(ep, wqe, wc_status);
        rte_spinlock_unlock(&ep->sq.lock);
    } else {
        // TODO: Close the endpoint?
        ep->util_ep.ep_fid.fid.ops->close(&ep->util_ep.ep_fid.fid);
    }
} /* process_terminate */

static void do_process_ack(struct dpdk_ep *ep, struct dpdk_xfer_entry *wqe,
                           struct pending_datagram_info *pending) {
    if (wqe->opcode == xfer_read) {
        // READ completion is handled in progress_ep().
        return;
    } else if (wqe->opcode == xfer_send || wqe->opcode == xfer_send_with_imm) {
        wqe->bytes_acked += (pending->ddp_length - sizeof(struct rdmap_untagged_packet));
    } else {
        uint16_t header_len = RTE_ETHER_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + TRP_HDR_LEN;
        wqe->bytes_acked += (pending->ddp_length - sizeof(struct rdmap_tagged_packet));
    }

    if (wqe->bytes_acked == wqe->total_length) {
        assert(wqe->bytes_sent >= wqe->bytes_acked && wqe->state == SEND_XFER_WAIT);
        wqe->state = SEND_XFER_COMPLETE;
        try_complete_wqe(ep, wqe);
    }

} /* do_process_ack */

static void sweep_unacked_packets(struct dpdk_ep *ep) {
    struct pending_datagram_info *pending;
    struct ee_state              *ee = &ep->remote_ep;
    struct rte_mbuf             **end, **p, *sendmsg;
    int                           count;

    end = ee->tx_pending + ee->tx_pending_size;
    if (!*ee->tx_head) {
        return;
    }

    for (count = 0; count < ee->tx_pending_size && (sendmsg = *ee->tx_head) != NULL; count++) {
        pending = (struct pending_datagram_info *)(sendmsg + 1);

        if (serial_less_32(pending->psn, ee->send_last_acked_psn)) {
            /* Packet was acked */
            if (pending->wqe) {
                do_process_ack(ep, pending->wqe, pending);
            }
            pending->psn = UINT32_MAX;
            /* We free the original copy of the packet that we hold */
            rte_pktmbuf_free(sendmsg);
            *ee->tx_head = NULL;
            if (++ee->tx_head == end) {
                ee->tx_head = ee->tx_pending;
            }
        } else {
            break;
        }
    }

    // Get current time
    uint64_t now = rte_get_timer_cycles();

    p = ee->tx_head;
    while (count < ee->tx_pending_size && (sendmsg = *p) != NULL) {
        int ret, cstatus;
        pending = (struct pending_datagram_info *)(sendmsg + 1);
        if (now > pending->next_retransmit && (ret = resend_ddp_segment(ep, sendmsg, ee)) < 0) {
            cstatus = FI_WC_FATAL_ERR;
            switch (ret) {
            case -EIO:
                cstatus = FI_WC_RETRY_EXC_ERR;
                DPDK_WARN(FI_LOG_EP_CTRL, "<ep=%u> retransmit failed psn=%u\n", ep->udp_port,
                          pending->psn);
                break;
            case -ENOMEM:
                DPDK_WARN(FI_LOG_EP_CTRL, "<ep=%u> OOM on retransmit psn=%u\n", ep->udp_port,
                          pending->psn);
                break;
            default:
                DPDK_WARN(FI_LOG_EP_CTRL, "<ep=%u> unknown error on retransmit psn=%u: %s\n",
                          ep->udp_port, pending->psn, rte_strerror(-ret));
            }
            if (pending->wqe) {
                rte_spinlock_lock(&ep->sq.lock);
                post_send_cqe(ep, pending->wqe, cstatus);
                rte_spinlock_unlock(&ep->sq.lock);
            } else if (pending->readresp) {
                struct rdmap_tagged_packet *rdmap;
                rdmap = rte_pktmbuf_mtod_offset(
                    sendmsg, struct rdmap_tagged_packet *,
                    sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
                        sizeof(struct rte_udp_hdr) + sizeof(struct trp_hdr));
                DPDK_INFO(FI_LOG_EP_CTRL, "was read response; L=%d bytes left=%" PRIu32 "\n",
                          DDP_GET_L(rdmap->head.ddp_flags), pending->readresp->read.msg_size);
            }
            DPDK_WARN(FI_LOG_EP_CTRL, "Shutdown EP %u\n", ep->udp_port);
            // TODO: Handle the shutdown
            // Should we free the mbuf here?
            atomic_store(&ep->conn_state, ep_conn_state_error);
            if (p == ee->tx_head) {
                *ee->tx_head = NULL;
                if (++ee->tx_head == end) {
                    ee->tx_head = ee->tx_pending;
                }
            } else {
                pending->next_retransmit = UINT64_MAX;
            }
        }
        if (++p == end) {
            p = ee->tx_pending;
        }
        count++;
    }
} /* sweep_unacked_packets */

static void ddp_place_tagged_data(struct dpdk_ep *ep, struct packet_context *orig) {
    struct rdmap_tagged_packet *rdmap;
    struct dpdk_mr             *mr;
    uintptr_t                   vaddr;
    uint32_t                    rkey;
    uint32_t                    rdma_length;
    unsigned int                opcode;
    int                         ret;

    // Get the domain
    struct dpdk_domain *dpdk_domain =
        container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);

    rdmap = (struct rdmap_tagged_packet *)orig->rdmap;
    rkey  = rte_be_to_cpu_32(rdmap->head.sink_stag);
    ofi_genlock_lock(&dpdk_domain->mr_tbl_lock);
    mr = dpdk_mr_lookup(&dpdk_domain->mr_tbl, rkey);
    ofi_genlock_unlock(&dpdk_domain->mr_tbl_lock);
    if (!mr) {
        DPDK_WARN(FI_LOG_EP_CTRL, "<ep=%u> received DDP tagged message with invalid stag %u\n",
                  ep->udp_port, rkey);
        do_rdmap_terminate(ep, orig, ddp_error_tagged_stag_invalid);
        return;
    }

    vaddr       = (uintptr_t)rte_be_to_cpu_64(rdmap->offset);
    rdma_length = orig->ddp_seg_length - sizeof(*rdmap);
    if (vaddr < (uintptr_t)mr->buf || vaddr + rdma_length > (uintptr_t)mr->buf + mr->len) {

        DPDK_WARN(FI_LOG_EP_CTRL,
                  "<ep=%u> received DDP tagged message with destination [%p, %p] outside "
                  "of memory "
                  "region [%p, %p]\n",
                  ep->udp_port, vaddr, vaddr + rdma_length, mr->buf, mr->buf + mr->len);
        do_rdmap_terminate(ep, orig, ddp_error_tagged_base_or_bounds_violation);
        return;
    }

    // Copy data to the application buffer
    rte_memcpy((void *)vaddr, PAYLOAD_OF(rdmap), rdma_length);
    DPDK_INFO(FI_LOG_EP_CTRL, "<ep=%u> Wrote %u bytes to tagged buffer with stag=%u at %p\n",
              ep->udp_port, rdma_length, rkey, vaddr);

    opcode = RDMAP_GET_OPCODE(orig->rdmap->rdmap_info);
    switch (opcode) {
    case rdmap_opcode_rdma_write:
        break;
    case rdmap_opcode_rdma_read_response:
        process_rdma_read_response(ep, orig);
        break;
    case rdmap_opcode_rdma_write_with_imm:
        // If inline data, we should post a CQE to notify the receiver of the immediate
        // data. but only if this is the last segment!
        if (DDP_GET_L(orig->rdmap->ddp_flags)) {
            struct fi_dpdk_wc *cqe;
            struct dpdk_cq    *cq = container_of(ep->util_ep.rx_cq, struct dpdk_cq, util_cq);
            ret                   = get_next_cqe(cq, &cqe);
            if (ret < 0) {
                DPDK_INFO(FI_LOG_EP_CTRL, "Failed to post recv CQE: %s\n", strerror(-ret));
                return ret;
            }
            cqe->wr_context = NULL; // This is not associated to any read WQE, so no user ctx
            cqe->status     = FI_WC_SUCCESS;
            cqe->opcode     = FI_WC_RDMA_WRITE_WITH_IMM;
            cqe->byte_len   = 0; // Should we  somehow track the len of the write?
            cqe->ep_id      = ep->udp_port;
            cqe->imm_data   = orig->rdmap->immediate;
            cqe->wc_flags   = FI_WC_WITH_IMM;

            /* Actually post the CQE to the CQ */
            rte_ring_enqueue(cq->cqe_ring, cqe);
        }
        break;
    default:
        DPDK_WARN(FI_LOG_EP_CTRL, "<ep=%u> received DDP tagged message with invalid opcode %x\n",
                  ep->udp_port, opcode);
        do_rdmap_terminate(ep, orig, rdmap_error_opcode_unexpected);
    }
} /* ddp_place_tagged_data */

static int respond_next_read_atomic(struct dpdk_ep *ep) {
    struct read_atomic_response_state *readresp;
    unsigned long                      msn, end;
    int                                count;

    count = 0;
    for (msn = ep->readresp_head_msn, end = msn + dpdk_max_ird; msn != end; ++msn) {
        readresp = &ep->readresp_store[msn % dpdk_max_ird];
        if (!readresp->active) {
            break;
        }

        switch (readresp->type) {
        // TODO: Support atomic operations
        // case atomic_response:
        //     count += respond_atomic(ep, readresp);
        //     break;
        case read_response:
            count += do_rdmap_read_response(ep, readresp);
            break;
        }
    }
    return count;
} /* respond_next_read_atomic */

static struct dpdk_xfer_entry *find_first_rdma_read_atomic(struct dpdk_ep *ep) {
    struct dpdk_xfer_entry *lptr, *next;

    // Libfabric
    struct dlist_entry *tmp;
    dlist_foreach_container_safe(&ep->sq.active_head, struct dpdk_xfer_entry, lptr, entry, next) {
        if (lptr->opcode == xfer_read || lptr->opcode == xfer_atomic) {
            return lptr;
        }
    }

    return NULL;
} /* find_first_rdma_read */

// This function is to be enabled only if NIC filtering is active
static int process_receive_queue(struct dpdk_ep *ep, void *prefetch_addr) {
    // struct rte_mbuf *rxmbuf[dpdk_default_tx_burst_size];
    // uint16_t         rx_count, pkt;

    // This seems a nice way to have the hardware filter the packets directed to this
    // specific QP instead of having to receive them in a single point, use a rte_ring to
    // dispatch them, and here insert them in the right queue. Is this right? TODO: check
    // flow director. if (qp->dev->flags & port_fdir) {
    //     rx_count = rte_eth_rx_burst(qp->dev->portid, qp->shm_qp->rx_queue, rxmbuf,
    //                                 qp->shm_qp->rx_burst_size);
    // } else if...

    // /* Get burst of RX packets */
    // if (ep->remote_ep.rx_queue) {
    //     rx_count = rte_ring_dequeue_burst(ep->remote_ep.rx_queue, (void **)rxmbuf,
    //                                       dpdk_default_rx_burst_size, NULL);
    // } else {
    //     rx_count = 0;
    // }

    // // TODO: Should we enable stats? or not?
    // // ep->stats.base.recv_count_histo[rx_count]++;

    // if (rx_count != 0) {
    //     rte_prefetch0(rte_pktmbuf_mtod(rxmbuf[0], void *));
    //     if (now) {
    //         *now = rte_get_timer_cycles();
    //     }
    //     for (pkt = 0; pkt < rx_count - 1; ++pkt) {
    //         rte_prefetch0(rte_pktmbuf_mtod(rxmbuf[pkt + 1], void *));
    //         process_data_packet(ep, rxmbuf[pkt]);
    //         rte_pktmbuf_free(rxmbuf[pkt]);
    //     }
    //     if (prefetch_addr) {
    //         rte_prefetch0(prefetch_addr);
    //     }
    //     process_data_packet(ep, rxmbuf[rx_count - 1]);
    //     rte_pktmbuf_free(rxmbuf[rx_count - 1]);
    // } else if (now) {
    //     *now = rte_get_timer_cycles();
    // }

    // return rx_count;
    return 0;
}

static void process_rx_packet(struct dpdk_domain *domain, struct rte_mbuf *mbuf) {
    struct packet_context ctx;
    struct dpdk_ep       *dst_ep;
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr  *ipv4_hdr;
    struct rte_udp_hdr   *udp_hdr;
    struct trp_hdr       *trp_hdr;
    uint16_t              trp_opcode;

    uint16_t base_port = rte_be_to_cpu_16(domain->res->local_cm_addr.sin_port);

    // TODO: We cannot discard packets absed on UDP checksum if we do not know how to
    // compute it... If some checksums are bad, we don't want to process the packet if
    // (mbuf->ol_flags & (RTE_MBUF_F_RX_L4_CKSUM_BAD | RTE_MBUF_F_RX_IP_CKSUM_BAD)) {
    //     if (rte_log_get_global_level() >= RTE_LOG_DEBUG) {
    //         uint16_t actual_udp_checksum, actual_ipv4_cksum;
    //         ipv4_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *,
    //         sizeof(*eth_hdr)); udp_hdr  = rte_pktmbuf_mtod_offset(mbuf, struct
    //         rte_udp_hdr *,
    //                                            sizeof(*eth_hdr) + sizeof(*ipv4_hdr));
    //         actual_udp_checksum    = udp_hdr->dgram_cksum;
    //         udp_hdr->dgram_cksum   = 0;
    //         actual_ipv4_cksum      = ipv4_hdr->hdr_checksum;
    //         ipv4_hdr->hdr_checksum = 0;
    //         RTE_LOG(DEBUG, USER1, "ipv4 expected cksum %#" PRIx16 " got %#" PRIx16 "\n",
    //                 rte_ipv4_cksum(ipv4_hdr), actual_ipv4_cksum);
    //         RTE_LOG(DEBUG, USER1, "udp expected cksum %#" PRIx16 " got %#" PRIx16 "\n",
    //                 rte_ipv4_udptcp_cksum(ipv4_hdr, udp_hdr), actual_udp_checksum);
    //     }
    //     RTE_LOG(NOTICE, USER1, "<dev=%s> Drop packet with bad UDP/IP checksum\n",
    //             domain->util_domain.name);

    //     return;
    // }

    // Check if the packet is UDP and is for us (IP address)
    eth_hdr  = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    ipv4_hdr = (struct rte_ipv4_hdr *)rte_pktmbuf_adj(mbuf, sizeof(*eth_hdr));
    if (ipv4_hdr->next_proto_id != IP_UDP) {
        DPDK_DBG(FI_LOG_EP_DATA, "<dev=%s> Drop packet with IPv4 next header %" PRIu8 " not UDP\n",
                 domain->util_domain.name, ipv4_hdr->next_proto_id);
        goto free_and_exit;
    }

    if (ipv4_hdr->dst_addr != domain->res->local_cm_addr.sin_addr.s_addr) {
        RTE_LOG(DEBUG, USER1,
                "<dev=%s> Drop packet with IPv4 dst addr %" PRIx32 "; expected %" PRIx32 "\n",
                domain->util_domain.name, rte_be_to_cpu_32(ipv4_hdr->dst_addr),
                rte_be_to_cpu_32(domain->res->local_cm_addr.sin_addr.s_addr));
        goto free_and_exit;
    }

    // Check the UDP port. We can have three cases:
    // 1. The packet is for the base_port => This is a connection request
    // 2. The packet is for the base_port + n => This is a data packet for the n'th EP, if
    // it exists
    // 3. The packet is for another port => Not for us, drop it
    udp_hdr          = (struct rte_udp_hdr *)rte_pktmbuf_adj(mbuf, sizeof(*ipv4_hdr));
    uint16_t rx_port = rte_be_to_cpu_16(udp_hdr->dst_port);
    if (rx_port > base_port && rx_port < base_port + MAX_ENDPOINTS_PER_APP) {
        // Find the EP for this port
        dst_ep = domain->udp_port_to_ep[rx_port - (base_port + 1)];
        if (!dst_ep) {
            DPDK_INFO(FI_LOG_EP_DATA, "<dev=%s> Drop packet with UDP dst port %u;\n",
                      domain->util_domain.name, rx_port);
            goto free_and_exit;
        }
    } else if (rx_port == 2509) {
        rte_pktmbuf_prepend(mbuf, RTE_ETHER_HDR_LEN + IP_HDR_LEN);
        dpdk_cm_recv(mbuf, domain->res);
        goto free_and_exit;
    } else {
        DPDK_INFO(FI_LOG_EP_DATA, "<dev=%s> drop packet with UDP dst port %u;\n",
                  domain->util_domain.name, rx_port);
        goto free_and_exit;
    }

    // If we got here, we have a valid packet for a valid EP
    assert(dst_ep);
    DPDK_DBG(FI_LOG_EP_DATA, "<ep=%u> received packet\n", dst_ep->udp_port);

    // This is a data message that arrives before the connection ack
    if (dst_ep->remote_udp_port == 0) {
        assert(dst_ep->conn_state == ep_conn_state_connecting);
        // TODO: Should we use a lock? Or an atomic?
        DPDK_WARN(FI_LOG_EP_DATA, "<dev=%s> Packet is for a CONNECTING endpoint (%u)\n",
                  domain->util_domain.name, dst_ep->udp_port);
        dst_ep->remote_udp_port = rte_be_to_cpu_16(udp_hdr->src_port);
    }

    ctx.dst_ep = dst_ep;
    ctx.src_ep = &dst_ep->remote_ep;
    if (!ctx.src_ep) {
        /* Drop the packet; do not send TERMINATE */
        goto free_and_exit;
    }

    trp_hdr    = (struct trp_hdr *)rte_pktmbuf_adj(mbuf, sizeof(*udp_hdr));
    trp_opcode = rte_be_to_cpu_16(trp_hdr->opcode) & trp_opcode_mask;
    switch (trp_opcode) {
    case 0:
        /* Normal opcode */
        break;
    case trp_sack:
        /* This is a selective acknowledgement */
        DPDK_DBG(FI_LOG_EP_DATA,
                 "<dev=%s ep=%u> receive SACK [%" PRIu32 ", %" PRIu32 "); send_ack_psn %" PRIu32
                 "\n",
                 domain->util_domain.name, dst_ep->udp_port, rte_be_to_cpu_32(trp_hdr->psn),
                 rte_be_to_cpu_32(trp_hdr->ack_psn), ctx.src_ep->send_last_acked_psn);
        // dst_ep->stats.recv_sack_count++; //TODO: stats not implemented yet
        process_trp_sack(ctx.src_ep, rte_be_to_cpu_32(trp_hdr->psn),
                         rte_be_to_cpu_32(trp_hdr->ack_psn));
        goto free_and_exit;
    case trp_fin:
        /* This is a finalize packet */
        // TODO: Handle communication shutdown
        dst_ep->util_ep.ep_fid.fid.ops->close(&dst_ep->util_ep.ep_fid.fid);
        goto free_and_exit;
    default:
        DPDK_WARN(FI_LOG_EP_DATA, "<dev=%s ep=%u> receive unexpected opcode %u; dropping\n",
                  domain->util_domain.name, dst_ep->udp_port, trp_opcode >> trp_opcode_shift);
        goto free_and_exit;
    }

    /* Update sender state based on received ack_psn */
    ctx.src_ep->send_last_acked_psn = rte_be_to_cpu_32(trp_hdr->ack_psn);
    ctx.src_ep->send_max_psn = ctx.src_ep->send_last_acked_psn + ctx.src_ep->tx_pending_size - 1;

    /* If no DDP segment attached; ignore PSN */
    if (rte_be_to_cpu_16(udp_hdr->dgram_len) <= sizeof(*udp_hdr) + sizeof(*trp_hdr)) {
        DPDK_DBG(FI_LOG_EP_DATA,
                 "<dev=%s ep=%u> got ACK psn %u; now last_acked_psn %u send_next_psn "
                 "%u send_max_psn %u\n",
                 domain->util_domain.name, dst_ep->udp_port, ctx.src_ep->send_last_acked_psn,
                 ctx.src_ep->send_next_psn, ctx.src_ep->send_max_psn);
        goto free_and_exit;
    }

    /* Now take care of ordered delivery */
    ctx.psn = rte_be_to_cpu_32(trp_hdr->psn);
    if (ctx.psn == ctx.src_ep->recv_ack_psn) {
        ctx.src_ep->recv_ack_psn++;
        if ((ctx.src_ep->trp_flags & trp_recv_missing) &&
            ctx.src_ep->recv_ack_psn == ctx.src_ep->recv_sack_psn.min)
        {
            ctx.src_ep->recv_ack_psn = ctx.src_ep->recv_sack_psn.max;
            ctx.src_ep->trp_flags &= ~trp_recv_missing;
        }
        ctx.src_ep->trp_flags |= trp_ack_update;
    } else if (serial_less_32(ctx.src_ep->recv_ack_psn, ctx.psn)) {
        /* We detected a sequence number gap.  Try to build a
         * contiguous range so we can send a SACK to lower the number
         * of retransmissions. */
        DPDK_DBG(FI_LOG_EP_DATA, "<dev=%s ep=%u> receive psn %u; next expected psn %u\n",
                 domain->util_domain.name, dst_ep->udp_port, ctx.psn, ctx.src_ep->recv_ack_psn);
        // dst_ep->stats.recv_psn_gap_count++; //TODO: stats not implemented yet
        if (ctx.src_ep->trp_flags & trp_recv_missing) {
            if (ctx.psn == ctx.src_ep->recv_sack_psn.max) {
                ctx.src_ep->recv_sack_psn.max = ctx.psn + 1;
                ctx.src_ep->trp_flags |= trp_ack_update;
            } else if (ctx.psn + 1 == ctx.src_ep->recv_sack_psn.min) {
                ctx.src_ep->recv_sack_psn.min = ctx.psn;
                if (ctx.src_ep->recv_sack_psn.min == ctx.src_ep->recv_ack_psn) {
                    ctx.src_ep->recv_ack_psn = ctx.src_ep->recv_sack_psn.max;
                    ctx.src_ep->trp_flags &= ~trp_recv_missing;
                }
                ctx.src_ep->trp_flags |= trp_ack_update;
            } else if (serial_less_32(ctx.psn, ctx.src_ep->recv_sack_psn.min) ||
                       serial_greater_32(ctx.psn, ctx.src_ep->recv_sack_psn.max))
            {
                /* We've run out of ways to track this
                 * datagram; drop it and wait for it to be
                 * retransmitted along with the surrounding
                 * datagrams. */
                DPDK_INFO(FI_LOG_EP_DATA,
                          "<dev=%s ep=%u> got out of range psn %u; next expected %u sack range: "
                          "[%u,%u]\n",
                          domain->util_domain.name, dst_ep->udp_port, ctx.psn,
                          ctx.src_ep->recv_ack_psn, ctx.src_ep->recv_sack_psn.min,
                          ctx.src_ep->recv_sack_psn.max);
                goto free_and_exit;
            } else {
                /* This segment has been handled; drop the
                 * duplicate. */
                goto free_and_exit;
            }
        } else {
            ctx.src_ep->trp_flags |= trp_recv_missing | trp_ack_update;
            ctx.src_ep->recv_sack_psn.min = ctx.psn;
            ctx.src_ep->recv_sack_psn.max = ctx.psn + 1;
        }
    } else {
        /* This is a retransmission of a packet which we have already
         * acknowledged; throw it away. */
        // TODO: Check this!!
        DPDK_DBG(FI_LOG_EP_DATA, "<dev=%s ep=%u> got retransmission psn %u; expected psn %u\n",
                 domain->util_domain.name, dst_ep->udp_port, ctx.psn, ctx.src_ep->recv_ack_psn);
        // dst_ep->stats.recv_retransmit_count++; //TODO: stats not implemented yet
        goto free_and_exit;
    }

    // Now process the DDP and RDMAP headers
    ctx.ddp_seg_length = rte_be_to_cpu_16(udp_hdr->dgram_len) - sizeof(*udp_hdr) - sizeof(*trp_hdr);
    ctx.rdmap          = (struct rdmap_packet *)rte_pktmbuf_adj(mbuf, sizeof(*trp_hdr));
    ctx.mbuf_head      = mbuf;

    if (DDP_GET_DV(ctx.rdmap->ddp_flags) != 0x1) {
        do_rdmap_terminate(dst_ep, &ctx,
                           DDP_GET_T(ctx.rdmap->ddp_flags) ? ddp_error_tagged_version_invalid
                                                           : ddp_error_untagged_version_invalid);
        goto free_and_exit;
    }

    if (RDMAP_GET_RV(ctx.rdmap->rdmap_info) != 0x1) {
        do_rdmap_terminate(dst_ep, &ctx, rdmap_error_version_invalid);
        goto free_and_exit;
    }

    // "Tagged data" is WRITE
    if (DDP_GET_T(ctx.rdmap->ddp_flags)) {
        ddp_place_tagged_data(dst_ep, &ctx);
    } else {
        switch (RDMAP_GET_OPCODE(ctx.rdmap->rdmap_info)) {
        case rdmap_opcode_send_with_imm:
        case rdmap_opcode_send:
        case rdmap_opcode_send_inv:
        case rdmap_opcode_send_se:
        case rdmap_opcode_send_se_inv:
            if (process_rdma_send(dst_ep, &ctx, false) > 0) {
                // This is the case we received a send but the
                // corresponding recv was not posted yet...
                goto only_exit;
            }
            break;
        case rdmap_opcode_rdma_read_request:
            process_rdma_read_request(dst_ep, &ctx);
            break;
        case rdmap_opcode_terminate:
            process_terminate(dst_ep, &ctx);
            break;
        // TODO: Support atomic operations
        // case rdmap_opcode_atomic_request:
        //     process_atomic_request(dst_ep, &ctx);
        //     break;
        // case rdmap_opcode_atomic_response:
        //     process_atomic_response(dst_ep, &ctx);
        //     break;
        default:
            do_rdmap_terminate(dst_ep, &ctx, rdmap_error_opcode_unexpected);
            break;
        }
    }
free_and_exit:
    rte_pktmbuf_free(mbuf);
only_exit:
    return;
} /* process_rx_packet */

/* Receive action on the network. Takes care of IPv4 defragmentation, and foreach
 * reassembled packet invokes the process_rx_packet function */
static void do_receive(struct dpdk_domain *domain) {
    struct rte_mbuf *pkts_burst[dpdk_default_tx_burst_size];
    struct rte_mbuf *reassembled;
    uint16_t         rx_count;
    uint64_t         cur_tsc;
    int              j;

    /* RX packets */
    rx_count = rte_eth_rx_burst(domain->res->port_id, domain->res->data_rxq_id, pkts_burst,
                                dpdk_default_rx_burst_size);

    /* Prefetch first packets */
    for (j = 0; j < PREFETCH_OFFSET && j < rx_count; j++) {
        rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j], void *));
    }

    /* Process already prefetched packets */
    // TODO: Why we replicate the code? This is code copied from DPDK examples in case of
    // fragmentation/reassembly But how does it work exactly?
    for (j = 0; j < (rx_count - PREFETCH_OFFSET); j++) {
        rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j + PREFETCH_OFFSET], void *));
        // TODO: We do not support VLAN or VXLAN yet. See dpdk-playground for an example
        struct rte_ether_hdr *eth_hdr    = rte_pktmbuf_mtod(pkts_burst[j], struct rte_ether_hdr *);
        uint16_t              ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
        switch (rte_be_to_cpu_16(eth_hdr->ether_type)) {
        case RTE_ETHER_TYPE_ARP:
            DPDK_INFO(FI_LOG_EP_DATA, "Received ARP packet.\n");
            arp_receive(domain->res, pkts_burst[j]);
            rte_pktmbuf_free(pkts_burst[j]);
            break;
        case RTE_ETHER_TYPE_IPV4:
            reassembled = reassemble(pkts_burst[j], &domain->lcore_queue_conf, 0, cur_tsc);
            if (reassembled) {
                process_rx_packet(domain, reassembled);
            }
            break;
        case RTE_ETHER_TYPE_IPV6:
            // [Weijia]: IPv6 needs more care.
            DPDK_INFO(FI_LOG_EP_DATA, "IPv6 is not supported yet\n");
            rte_pktmbuf_free(pkts_burst[j]);
            break;
        default:
            DPDK_INFO(FI_LOG_EP_DATA, "Unknown Ether type %#x\n",
                      rte_be_to_cpu_16(eth_hdr->ether_type));
            rte_pktmbuf_free(pkts_burst[j]);
            break;
        }
    }

    /* Process remaining prefetched packets */
    for (; j < rx_count; j++) {
        struct rte_ether_hdr *eth_hdr    = rte_pktmbuf_mtod(pkts_burst[j], struct rte_ether_hdr *);
        uint16_t              ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
        // TODO: We do not support VLAN or VXLAN yet. See dpdk-playground for an example
        switch (rte_be_to_cpu_16(eth_hdr->ether_type)) {
        case RTE_ETHER_TYPE_ARP:
            DPDK_INFO(FI_LOG_EP_DATA, "Received ARP packet\n");
            arp_receive(domain->res, pkts_burst[j]);
            rte_pktmbuf_free(pkts_burst[j]);
            break;
        case RTE_ETHER_TYPE_IPV4:
            reassembled = reassemble(pkts_burst[j], &domain->lcore_queue_conf, 0, cur_tsc);
            if (reassembled) {
                process_rx_packet(domain, reassembled);
            }
            break;
        case RTE_ETHER_TYPE_IPV6:
            // [Weijia]: IPv6 needs more care.
            DPDK_INFO(FI_LOG_EP_DATA, "IPv6 is not supported yet\n");
            rte_pktmbuf_free(pkts_burst[j]);
            break;
        default:
            DPDK_INFO(FI_LOG_EP_DATA, "Unknown Ether type %#x\n",
                      rte_be_to_cpu_16(eth_hdr->ether_type));
            rte_pktmbuf_free(pkts_burst[j]);
            break;
        }

        rte_ip_frag_free_death_row(&domain->lcore_queue_conf.death_row, PREFETCH_OFFSET);
    }
} /* do_receive */

/* Make forward progress on the queue pair. */
static void progress_ep(struct dpdk_ep *ep) {
    struct dlist_entry     *cur, *tmp;
    struct dpdk_xfer_entry *send_xfer, *next;
    uint32_t                psn;
    int                     scount, ret;

    /* The following is a per-EP receive we can enable only if we support NIC filtering */
    // TODO: Consider checking if the NIC supports NIC filtering, and enabling this
    // in alternative to the process_receive_queue() call in the main loop.
    // send_xfer = container_of(&ep->sq.active_head, struct dpdk_xfer_entry, entry);
    // process_receive_queue(ep, send_xfer);

    /* Call any timers only once per millisecond */
    sweep_unacked_packets(ep);

    /* Process READ OPCODE Response last segments. */
    while (!binheap_empty(ep->remote_ep.recv_rresp_last_psn)) {
        binheap_peek(ep->remote_ep.recv_rresp_last_psn, &psn);
        if (psn < ep->remote_ep.recv_ack_psn) {
            /* We have received all prior packets, so since we have
             * received the RDMA READ Response segment with L=1, we
             * are guaranteed to have placed all data corresponding
             * to this RDMA READ Response, and can complete the
             * corresponding WQE. The heap ensures that we process
             * the segments in the correct order, and
             * try_complete_wqe() ensures that we do not complete an
             * RDMA READ request out of order. */
            send_xfer = find_first_rdma_read_atomic(ep);
            if (!(WARN_ONCE(!send_xfer, "No RDMA READ request pending\n"))) {
                send_xfer->state = SEND_XFER_COMPLETE;
                try_complete_wqe(ep, send_xfer);
            }
            binheap_pop(ep->remote_ep.recv_rresp_last_psn);
        } else {
            break;
        }
    }

    scount = 0;
    dlist_foreach_safe(&ep->sq.active_head, cur, tmp) {
        send_xfer = container_of(cur, struct dpdk_xfer_entry, entry);
        if (cur->next) {
            next = container_of(cur->next, struct dpdk_xfer_entry, entry);
            rte_prefetch0(next);
        }
        assert(send_xfer->state != SEND_XFER_INIT);
        progress_send_xfer(ep, send_xfer);
        if (send_xfer->state == SEND_XFER_TRANSFER) {
            scount++;
        }
    }

    if (scount == 0) {
        ret = rte_ring_dequeue(ep->sq.ring, (void **)&send_xfer);
        if (ret == 0) {
            assert(send_xfer->state == SEND_XFER_INIT);
            send_xfer->state = SEND_XFER_TRANSFER;
            switch (send_xfer->opcode) {
            case xfer_send_with_imm:
            case xfer_write_with_imm:
            case xfer_send:
                send_xfer->msn = send_xfer->remote_ep->next_send_msn++;
                break;
            case xfer_read:
            case xfer_atomic:
                send_xfer->msn = send_xfer->remote_ep->next_read_msn++;
                break;
            case xfer_write:
                break;
            }
            xfer_queue_add_active(&ep->sq, send_xfer);
            progress_send_xfer(ep, send_xfer);
            scount = 1;
        }
    }

    scount += respond_next_read_atomic(ep);

    if (ep->remote_ep.trp_flags & trp_ack_update) {
        if (unlikely(ep->remote_ep.trp_flags & trp_recv_missing)) {
            send_trp_sack(ep);
        } else {
            send_trp_ack(ep);
        }
    }

    flush_tx_queue(ep);

} /* progress_ep */

// ================ Main Progress Functions =================
struct progress_arg {
    struct dpdk_progress *progress;
    bool                  clear_signal;
};

/* This function initializes the progress */
int dpdk_init_progress(struct dpdk_progress *progress, struct fi_info *info, int lcore_id) {
    int ret;

    // TODO: this should become a parameter in some way
    progress->lcore_id = lcore_id;
    atomic_store(&progress->stop_progress, false);
    progress->fid.fclass = DPDK_CLASS_PROGRESS;
    slist_init(&progress->event_list);

    // Mutex to access EP list
    ret = ofi_genlock_init(&progress->lock, OFI_LOCK_MUTEX);
    if (ret) {
        return ret;
    }

    return 0;
}

int dpdk_start_progress(struct dpdk_progress *progress) {
    int ret;

    struct progress_arg arg = {
        .progress     = progress,
        .clear_signal = false,
    };

    ret = rte_eal_remote_launch(dpdk_run_progress, &arg, progress->lcore_id);
    if (ret) {
        DPDK_WARN(FI_LOG_DOMAIN, "unable to start progress lcore thread\n");
        ret = -ret;
    }

    return ret;
}

// This is the main DPDK lcore loop => one polling thread PER DEVICE (= per domain)
int dpdk_run_progress(void *arg) {

    // Arguments
    struct progress_arg  *arguments = (struct progress_arg *)arg;
    struct dpdk_progress *progress  = arguments->progress;

    struct slist_entry *prev, *cur;
    struct dpdk_domain *domain = container_of(progress, struct dpdk_domain, progress);
    struct dpdk_ep     *ep;

    while (likely(!atomic_load(&progress->stop_progress))) {
        // outgoing data plane
        ofi_genlock_lock(&domain->ep_mutex);
        slist_foreach(&domain->endpoint_list, cur, prev) {
            ep = container_of(cur, struct dpdk_ep, entry);
            switch (atomic_load(&ep->conn_state)) {
            case ep_conn_state_unbound:
                /* code */
                break;
            case ep_conn_state_connecting:
            case ep_conn_state_connected:
                progress_ep(ep);
                break;
            case ep_conn_state_shutdown:
                /* code */
                break;
            case ep_conn_state_error:
                /* code */
                break;
            default:
                break;
            }
        }
        ofi_genlock_unlock(&domain->ep_mutex);

        // handling both data and control incoming packets.
        do_receive(domain);

        try_match_orphan_sends(domain);
    }

    return -1;
}

void dpdk_close_progress(struct dpdk_progress *progress) {
    printf("dpdk_close_progress: UNIMPLEMENTED\n");
    atomic_store(&progress->stop_progress, true);
}
