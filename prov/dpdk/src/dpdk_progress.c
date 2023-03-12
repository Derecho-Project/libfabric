#include "fi_dpdk.h"
#include "protocols.h"

// ================ Helper functions =================
// TODO: is this needed? Is it called more than once? Why can't be just an instruction?
static void xfer_queue_add_active(struct dpdk_xfer_queue *q, struct dpdk_xfer_entry *xfer_entry) {
    dlist_insert_tail(&xfer_entry->entry, &q->active_head);
} /* xfer_queue_add_active */

// Looks for a specific entry in the queue
static int xfer_queue_lookup(struct dpdk_xfer_queue *q, uint32_t msn,
                             struct dpdk_xfer_entry **xfer_entry) {

    // TODO: can we use dlist_find_first_match?

    struct dpdk_xfer_entry *lptr;
    struct dlist_entry     *entry, *tmp;
    RTE_LOG(DEBUG, USER1, "LOOKUP active recv WQE msn=%" PRIu32 "\n", msn);
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

/** post_recv_cqe posts a CQE corresponding to a receive WQE, and frees the
 * completed WQE.  Locking on the CQ ensures that any operation done prior to
 * this will be seen by other threads prior to the completion being delivered.
 * This ensures that new operations can be posted immediately. */
static int post_recv_cqe(struct dpdk_ep *ep, struct dpdk_xfer_entry *xfe,
                         enum fi_cq_status status) {
    // struct usiw_wc *cqe;
    // struct usiw_cq *cq;
    // int             ret;

    /* TODO: Here!! Implement */
    printf("[post_recv_cqe] POST COMPLETION TO COMPLETION QUEUE: UNIMPLEMENTED!\n");

    // cq  = qp->recv_cq;
    // ret = get_next_cqe(cq, &cqe);
    // if (ret < 0) {
    //     RTE_LOG(NOTICE, USER1, "Failed to post recv CQE: %s\n", strerror(-ret));
    //     return ret;
    // }
    // cqe->wr_context = wqe->wr_context;
    // cqe->status     = status;
    // cqe->opcode     = IBV_WC_RECV;
    // cqe->byte_len   = wqe->input_size;
    // cqe->qp_num     = qp->ib_qp.qp_num;
    // cqe->imm_data   = wqe->imm_data;
    // cqe->wc_flags   = IBV_WC_WITH_IMM;

    // qp_free_recv_wqe(qp, wqe);
    // finish_post_cqe(cq, cqe);
    return 0;
} /* post_recv_cqe */

/* Process RDMAP Send OPcode */
static void process_rdma_send(struct dpdk_ep *ep, struct packet_context *orig) {
    struct dpdk_xfer_entry       *xfer_e;
    struct rdmap_untagged_packet *rdmap = (struct rdmap_untagged_packet *)orig->rdmap;
    uint32_t                      msn, expected_msn;
    size_t                        offset;
    size_t                        payload_length;
    int                           ret;

    /** Pull all the *new* EP recv requests off of the ring and enqueues them in a dlist instead */
    // Because we need to look the right recv request to match the incoming send request, the uRDMA
    // implementation dequeues all the entries from the ring, places them into a queue, looks for
    // the queue entry that matches the incoming send request. The dequeued entries remain in the
    // queue. If the queue is empty, we try to refill it by reading new requests from the ring.
    if (dlist_empty(&ep->rq.active_head)) {
        dequeue_recv_entries(ep);
    }

    // Find the matching recv request.
    msn = rte_be_to_cpu_32(rdmap->msn);
    ret = xfer_queue_lookup(&ep->rq, msn, &xfer_e);
    assert(ret != -EINVAL);

    // If not found, we've got either a duplicate or a message with no matching recv request (=> the
    // queue is empty)
    if (ret < 0) {
        if (!dlist_empty(&ep->rq.active_head)) {
            /* This is a duplicate of a previously received
             * message --- should never happen since TRP will not
             * give us a duplicate packet. */
            expected_msn = container_of(&ep->rq.active_head, struct dpdk_xfer_entry, entry)->msn;
            RTE_LOG(INFO, USER1,
                    "<ep=%" PRIx16 "> Received msn=%" PRIu32 " but expected msn=%" PRIu32 "\n",
                    ep->udp_port, msn, expected_msn);
            do_rdmap_terminate(ep, orig, ddp_error_untagged_invalid_msn);
        } else {
            RTE_LOG(INFO, USER1,
                    "<qp=%" PRIx16 "> Received SEND msn=%" PRIu32 " to empty receive queue\n",
                    ep->udp_port, msn);
            assert(rte_ring_empty(ep->rq.ring));
            do_rdmap_terminate(ep, orig, ddp_error_untagged_no_buffer);
        }
        return;
    }

    // Process the matching request
    offset         = rte_be_to_cpu_32(rdmap->mo);
    payload_length = orig->ddp_seg_length - sizeof(struct rdmap_untagged_packet);
    if (offset + payload_length > xfer_e->total_length) {
        RTE_LOG(DEBUG, USER1,
                "<ep=%" PRIx16 "> DROP: offset=%zu + payload_length=%zu > wr_len=%zu\n",
                ep->udp_port, offset, payload_length, xfer_e->total_length);
        do_rdmap_terminate(ep, orig, ddp_error_untagged_message_too_long);
        return;
    }

    if (DDP_GET_L(rdmap->head.ddp_flags)) {
        if (xfer_e->input_size != 0) {
            RTE_LOG(DEBUG, USER1, "<qp=%" PRIx16 "> silently DROP duplicate last packet.\n",
                    ep->udp_port);
            return;
        }
        xfer_e->input_size = offset + payload_length;
    }

    // This is the "famous" receiver-side COPY that apparently we cannot avoid.
    memcpy_to_iov(xfer_e->iov, xfer_e->iov_count, PAYLOAD_OF(rdmap), payload_length, offset);
    xfer_e->recv_size += payload_length;
    assert(xfer_e->input_size == 0 || xfer_e->recv_size <= xfer_e->input_size);
    if (xfer_e->recv_size == xfer_e->input_size) {
        xfer_e->complete = true;
    }

    xfer_e->imm_data = rdmap->head.immediate;

    /* Post completion, but only if there are no holes in the LLP packet
     * sequence. This ensures that even in the case of missing packets,
     * we maintain the ordering between received Tagged and Untagged
     * frames. Walk the queue starting at the head to make sure we post
     * completions that we had previously deferred. */

    // TODO: This implementation does not actually walk the queue!
    // Is this an error?
    if (serial_less_32(orig->psn, xfer_e->remote_ep->recv_ack_psn)) {
        xfer_e = container_of(&ep->rq.active_head, struct dpdk_xfer_entry, entry);
        while (xfer_e && xfer_e->complete) {
            rte_spinlock_lock(&ep->rq.lock);
            post_recv_cqe(ep, xfer_e, FI_CQ_SUCCESS);
            rte_spinlock_unlock(&ep->rq.lock);
            xfer_e = container_of(&ep->rq.active_head, struct dpdk_xfer_entry, entry);
        }
    }
} /* process_send */

/* Transmits all packets currently in the transmit queue.  The queue will be
 * empty when this function returns.
 *
 * FIXME: It may be possible for this to never return if there is any error
 * that prevents packets from being transmitted. */
static void flush_tx_queue(struct dpdk_ep *ep) {
    struct dpdk_domain *domain;
    struct rte_mbuf   **begin;
    int                 ret;

    domain = container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);

    begin = ep->txq;
    do {
        ret = rte_eth_tx_burst(domain->port_id, domain->queue_id, begin, ep->txq_end - begin);

        if (ret > 0) {
            RTE_LOG(DEBUG, USER1, "Transmitted %d packets\n", ret);
        }

        begin += ret;
    } while (begin != ep->txq_end);
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
        // case xfer_write:
        // case xfer_write_with_imm:
        //     do_rdmap_write((struct usiw_qp *)qp, wqe);
        //     break;
        // case xfer_read:
        //     do_rdmap_read_request((struct usiw_qp *)qp, wqe);
        //     break;
        // case xfer_atomic:
        //     do_rdmap_atomic(qp, wqe);
        //     break;
    }
} /* progress_send_xfer */

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
            if (pending->xfer_entry) {
                do_process_ack(ep, pending->xfer_entry, pending);
            }
            pending->psn = UINT32_MAX;
            rte_pktmbuf_free(sendmsg);
            *ee->tx_head = NULL;
            if (++ee->tx_head == end) {
                ee->tx_head = ee->tx_pending;
            }
        } else {
            break;
        }
    }

    p = ee->tx_head;
    while (count++ < ee->tx_pending_size && (sendmsg = *p) != NULL) {
        int ret, cstatus;
        pending = (struct pending_datagram_info *)(sendmsg + 1);
        if (ep->now > pending->next_retransmit && (ret = resend_ddp_segment(ep, sendmsg, ee)) < 0) {
            // cstatus = IBV_WC_FATAL_ERR; //TODO: Do we have an equivalent?
            switch (ret) {
            case -EIO:
                // cstatus = IBV_WC_RETRY_EXC_ERR; //TODO: Do we have an equivalent?
                RTE_LOG(NOTICE, USER1,
                        "<qp=%" PRIx16 "> retransmit limit (%d) exceeded psn=%" PRIu32 "\n",
                        ep->udp_port, RETRANSMIT_MAX, pending->psn);
                break;
            case -ENOMEM:
                RTE_LOG(NOTICE, USER1, "<qp=%" PRIx16 "> OOM on retransmit psn=%" PRIu32 "\n",
                        ep->udp_port, pending->psn);
                break;
            default:
                RTE_LOG(NOTICE, USER1,
                        "<ep=%" PRIx16 "> unknown error on retransmit psn=%" PRIu32 ": %s\n",
                        ep->udp_port, pending->psn, rte_strerror(-ret));
            }
            if (pending->xfer_entry) {
                rte_spinlock_lock(&ep->sq.lock);
                post_send_cqe(ep, pending->xfer_entry, cstatus);
                rte_spinlock_unlock(&ep->sq.lock);
            } else if (pending->readresp) {
                struct rdmap_tagged_packet *rdmap;
                rdmap = rte_pktmbuf_mtod_offset(
                    sendmsg, struct rdmap_tagged_packet *,
                    sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
                        sizeof(struct rte_udp_hdr) + sizeof(struct trp_hdr));
                RTE_LOG(NOTICE, USER1, "was read response; L=%d bytes left=%" PRIu32 "\n",
                        DDP_GET_L(rdmap->head.ddp_flags), pending->readresp->read.msg_size);
            }
            RTE_LOG(DEBUG, USER1, "Shutdown EP %u\n", ep->udp_port);
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
    }
} /* sweep_unacked_packets */

// This function is to be enabled only if NIC filtering is active
static int process_receive_queue(struct dpdk_ep *ep, void *prefetch_addr, uint64_t *now) {
    // struct rte_mbuf *rxmbuf[dpdk_default_tx_burst_size];
    // uint16_t         rx_count, pkt;

    // // This seems a nice way to have the hardware filter the packets directed to this specific QP
    // // instead of having to receive them in a single point, use a rte_ring to dispatch them, and
    // // here insert them in the right queue. Is this right? TODO: check flow director.
    // // if (qp->dev->flags & port_fdir) {
    // //     rx_count = rte_eth_rx_burst(qp->dev->portid, qp->shm_qp->rx_queue, rxmbuf,
    // //                                 qp->shm_qp->rx_burst_size);
    // // } else if...

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

    uint32_t ip_addr   = domain->address >> 32;
    uint16_t base_port = domain->address & 0xFFFF;

    // If some checksums are bad, we don't want to process the packet
    if (mbuf->ol_flags & (RTE_MBUF_F_RX_L4_CKSUM_BAD | RTE_MBUF_F_RX_IP_CKSUM_BAD)) {
        if (rte_log_get_global_level() >= RTE_LOG_DEBUG) {
            uint16_t actual_udp_checksum, actual_ipv4_cksum;
            ipv4_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, sizeof(*eth_hdr));
            udp_hdr  = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *,
                                               sizeof(*eth_hdr) + sizeof(*ipv4_hdr));
            actual_udp_checksum    = udp_hdr->dgram_cksum;
            udp_hdr->dgram_cksum   = 0;
            actual_ipv4_cksum      = ipv4_hdr->hdr_checksum;
            ipv4_hdr->hdr_checksum = 0;
            RTE_LOG(DEBUG, USER1, "ipv4 expected cksum %#" PRIx16 " got %#" PRIx16 "\n",
                    rte_ipv4_cksum(ipv4_hdr), actual_ipv4_cksum);
            RTE_LOG(DEBUG, USER1, "udp expected cksum %#" PRIx16 " got %#" PRIx16 "\n",
                    rte_ipv4_udptcp_cksum(ipv4_hdr, udp_hdr), actual_udp_checksum);
        }
        RTE_LOG(DEBUG, USER1, "<dev=%s> Drop packet with bad UDP/IP checksum\n", domain->address);

        return;
    }

    eth_hdr  = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    ipv4_hdr = (struct ipv4_hdr *)rte_pktmbuf_adj(mbuf, sizeof(*eth_hdr));

    // Check if the packet is UDP and is for us (IP address)
    if (ipv4_hdr->next_proto_id != IP_UDP) {
        RTE_LOG(NOTICE, USER1, "<dev=%s> Drop packet with IPv4 next header %" PRIu8 " not UDP\n",
                domain->address, ipv4_hdr->next_proto_id);
        rte_pktmbuf_free(mbuf);
    }
    if (ipv4_hdr->dst_addr != rte_cpu_to_be_32(ip_addr)) {
        RTE_LOG(NOTICE, USER1,
                "<dev=%s> Drop packet with IPv4 dst addr %" PRIx32 "; expected %" PRIx32 "\n",
                domain->address, rte_be_to_cpu_32(ipv4_hdr->dst_addr), ip_addr);
    }

    // Check the UDP port. We can have three cases:
    // 1. The packet is for the base_port => This is a connection request
    // 2. The packet is for the base_port + n => This is a data packet for the n'th EP, if it exists
    // 3. The packet is for another port => Not for us, drop it
    udp_hdr          = (struct udp_hdr *)rte_pktmbuf_adj(mbuf, sizeof(*ipv4_hdr));
    uint16_t rx_port = rte_be_to_cpu_16(udp_hdr->dst_port);
    if (rx_port == base_port) {
        // TODO: Handle connection request.
        // Probably need to insert in some ring
    } else if (rx_port > base_port && rx_port < base_port + MAX_ENDPOINTS_PER_APP) {
        // Find the EP for this port
        dst_ep = domain->udp_port_to_ep[rx_port - (base_port + 1)];
        if (!dst_ep) {
            RTE_LOG(NOTICE, USER1, "<dev=%s> Drop packet with UDP dst port %" PRIu16 ";\n",
                    domain->address, rx_port);
            rte_pktmbuf_free(mbuf);
        }
    } else {
        RTE_LOG(NOTICE, USER1, "<dev=%s> Drop packet with UDP dst port %" PRIu16 ";\n",
                domain->address, rx_port);
        rte_pktmbuf_free(mbuf);
    }

    // If we got here, we have a valid packet for a valid EP
    assert(dst_ep);

    ctx.src_ep = &dst_ep->remote_ep;
    if (!ctx.src_ep) {
        /* Drop the packet; do not send TERMINATE */
        rte_pktmbuf_free(mbuf);
        return;
    }

    trp_hdr    = (struct trp_hdr *)rte_pktmbuf_adj(mbuf, sizeof(*udp_hdr));
    trp_opcode = rte_be_to_cpu_16(trp_hdr->opcode) & trp_opcode_mask;
    switch (trp_opcode) {
    case 0:
        /* Normal opcode */
        break;
    case trp_sack:
        /* This is a selective acknowledgement */
        RTE_LOG(DEBUG, USER1,
                "<dev=%s qp=%" PRIx16 "> receive SACK [%" PRIu32 ", %" PRIu32
                "); send_ack_psn %" PRIu32 "\n",
                domain->address, dst_ep->udp_port, rte_be_to_cpu_32(trp_hdr->psn),
                rte_be_to_cpu_32(trp_hdr->ack_psn), ctx.src_ep->send_last_acked_psn);
        // dst_ep->stats.recv_sack_count++; //TODO: stats not implemented yet
        process_trp_sack(ctx.src_ep, rte_be_to_cpu_32(trp_hdr->psn),
                         rte_be_to_cpu_32(trp_hdr->ack_psn));
        return;
    case trp_fin:
        /* This is a finalize packet */
        ep_shutdown(dst_ep);
        return;
    default:
        RTE_LOG(NOTICE, USER1,
                "<dev=%s qp=%" PRIx16 "> receive unexpected opcode %" PRIu16 "; dropping\n",
                domain->address, dst_ep->udp_port, trp_opcode >> trp_opcode_shift);
        return;
    }

    /* Update sender state based on received ack_psn */
    ctx.src_ep->send_last_acked_psn = rte_be_to_cpu_32(trp_hdr->ack_psn);
    ctx.src_ep->send_max_psn = ctx.src_ep->send_last_acked_psn + ctx.src_ep->tx_pending_size - 1;

    /* If no DDP segment attached; ignore PSN */
    if (rte_be_to_cpu_16(udp_hdr->dgram_len) <= sizeof(*udp_hdr) + sizeof(*trp_hdr)) {
        RTE_LOG(DEBUG, USER1,
                "<dev=%s qp=%" PRIx16 "> got ACK psn %" PRIu32 "; now last_acked_psn %" PRIu32
                " send_next_psn %" PRIu32 " send_max_psn %" PRIu32 "\n",
                domain->address, dst_ep->udp_port, ctx.psn, ctx.src_ep->send_last_acked_psn,
                ctx.src_ep->send_next_psn, ctx.src_ep->send_max_psn);
        return;
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
        RTE_LOG(DEBUG, USER1,
                "<dev=%s qp=%" PRIx16 "> receive psn %" PRIu32 "; next expected psn %" PRIu32 "\n",
                domain->address, dst_ep->udp_port, ctx.psn, ctx.src_ep->recv_ack_psn);
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
                RTE_LOG(NOTICE, USER1,
                        "<dev=%s qp=%" PRIx16 "> got out of range psn %" PRIu32
                        "; next expected %" PRIu32 " sack range: [%" PRIu32 ",%" PRIu32 "]\n",
                        domain->address, dst_ep->udp_port, ctx.psn, ctx.src_ep->recv_ack_psn,
                        ctx.src_ep->recv_sack_psn.min, ctx.src_ep->recv_sack_psn.max);
                return;
            } else {
                /* This segment has been handled; drop the
                 * duplicate. */
                return;
            }
        } else {
            ctx.src_ep->trp_flags |= trp_recv_missing | trp_ack_update;
            ctx.src_ep->recv_sack_psn.min = ctx.psn;
            ctx.src_ep->recv_sack_psn.max = ctx.psn + 1;
        }
    } else {
        /* This is a retransmission of a packet which we have already
         * acknowledged; throw it away. */
        RTE_LOG(DEBUG, USER1,
                "<dev=%s qp=%" PRIx16 "> got retransmission psn %" PRIu32 "; expected psn %" PRIu32
                "\n",
                domain->address, dst_ep->udp_port, ctx.psn, ctx.src_ep->recv_ack_psn);
        // dst_ep->stats.recv_retransmit_count++; //TODO: stats not implemented yet
        return;
    }

    // Now process the DDP and RDMAP headers
    ctx.ddp_seg_length = rte_be_to_cpu_16(udp_hdr->dgram_len) - sizeof(*udp_hdr) - sizeof(*trp_hdr);
    ctx.rdmap          = (struct rdmap_packet *)rte_pktmbuf_adj(mbuf, sizeof(*trp_hdr));

    if (DDP_GET_DV(ctx.rdmap->ddp_flags) != 0x1) {
        do_rdmap_terminate(dst_ep, &ctx,
                           DDP_GET_T(ctx.rdmap->ddp_flags) ? ddp_error_tagged_version_invalid
                                                           : ddp_error_untagged_version_invalid);
        return;
    }

    if (RDMAP_GET_RV(ctx.rdmap->rdmap_info) != 0x1) {
        do_rdmap_terminate(dst_ep, &ctx, rdmap_error_version_invalid);
        return;
    }

    if (DDP_GET_T(ctx.rdmap->ddp_flags)) {
        return ddp_place_tagged_data(dst_ep, &ctx);
    } else {
        switch (RDMAP_GET_OPCODE(ctx.rdmap->rdmap_info)) {
        case rdmap_opcode_send_with_imm:
        case rdmap_opcode_send:
        case rdmap_opcode_send_inv:
        case rdmap_opcode_send_se:
        case rdmap_opcode_send_se_inv:
            process_rdma_send(dst_ep, &ctx);
            break;
        // TODO: The following will need to be implemented to support fi_rma
        // case rdmap_opcode_rdma_read_request:
        //     process_rdma_read_request(dst_ep, &ctx);
        //     break;
        // case rdmap_opcode_terminate:
        //     process_terminate(dst_ep, &ctx);
        //     break;
        // case rdmap_opcode_atomic_request:
        //     process_atomic_request(dst_ep, &ctx);
        //     break;
        // case rdmap_opcode_atomic_response:
        //     process_atomic_response(dst_ep, &ctx);
        //     break;
        default:
            do_rdmap_terminate(dst_ep, &ctx, rdmap_error_opcode_unexpected);
            return;
        }
    }
} /* process_rx_packet */

static void do_receive(struct dpdk_domain *domain) {
    struct rte_mbuf *rxmbuf[dpdk_default_tx_burst_size];
    uint16_t         rx_count, pkt;

    /* RX packets */
    rx_count =
        rte_eth_rx_burst(domain->port_id, domain->queue_id, rxmbuf, dpdk_default_rx_burst_size);

    for (int i = 0; i < rx_count; i++) {
        process_rx_packet(domain, rxmbuf[i]);
    }

    // ep->now = .... in case no received packets in this loop for this packets => where do we place
    // this?
}

/* Make forward progress on the queue pair. */
static void progress_ep(struct dpdk_ep *ep) {
    struct dlist_entry     *cur, *tmp;
    struct dpdk_xfer_entry *send_xfer, *next;
    uint32_t                psn;
    int                     scount, ret;

    /* This is a per-EP receive we can enable only if we support NIC filtering */
    // TODO: Consider checking if the NIC supports NIC filtering, and enabling this
    // in alternative to the process_receive_queue() call in the main loop.
    // send_xfer = container_of(&ep->sq.active_head, struct dpdk_xfer_entry, entry);
    // process_receive_queue(ep, send_xfer, &now);

    /* Call any timers only once per millisecond */
    sweep_unacked_packets(ep);

    /* Process READ OPCODE Response last segments. */
    // TODO: Enable when implementing fi_rma
    // while (!binheap_empty(ep->remote_ep.recv_rresp_last_psn)) {
    //     binheap_peek(ep->remote_ep.recv_rresp_last_psn, &psn);
    //     if (psn < ep->remote_ep.recv_ack_psn) {
    //         /* We have received all prior packets, so since we have
    //          * received the RDMA READ Response segment with L=1, we
    //          * are guaranteed to have placed all data corresponding
    //          * to this RDMA READ Response, and can complete the
    //          * corresponding WQE. The heap ensures that we process
    //          * the segments in the correct order, and
    //          * try_complete_wqe() ensures that we do not complete an
    //          * RDMA READ request out of order. */
    //         send_xfer = find_first_rdma_read_atomic(ep);
    //         if (!(WARN_ONCE(!send_xfer, "No RDMA READ request pending\n"))) {
    //             send_xfer->state = SEND_XFER_COMPLETE;
    //             try_complete_wqe(ep, send_xfer);
    //         }
    //         binheap_pop(ep->remote_ep.recv_rresp_last_psn);
    //     } else {
    //         break;
    //     }
    // }

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
            case xfer_send:
                send_xfer->msn = send_xfer->remote_ep->next_send_msn++;
                break;
                // case xfer_read:
                // case xfer_atomic:
                //     send_wqe->msn = send_wqe->remote_ep->next_read_msn++;
                //     break;
                // case xfer_write:
                //     break;
            }
            xfer_queue_add_active(&ep->sq, send_xfer);
            progress_send_xfer(ep, send_xfer);
            scount = 1;
        }
    }

    // This should be needed only in case of opcodes READ and ATOMIC
    // that we currently do not have => MAYBE for fi_rma
    // scount += respond_next_read_atomic(ep);

    if (ep->remote_ep.trp_flags & trp_ack_update) {
        if (unlikely(ep->remote_ep.trp_flags & trp_recv_missing)) {
            send_trp_sack(ep);
        } else {
            send_trp_ack(ep);
        }
    }

    flush_tx_queue(ep);

} /* progress_ep */

static void ep_shutdown(struct dpdk_ep *ep) {
    printf("[ep_shutdown] UNIMPLEMENTED\n");
    return;
} /* qp_shutdown */

// ================ Main Progress Functions =================
struct progress_arg {
    struct dpdk_progress *progress;
    bool                  clear_signal;
};

/* This function initializes the progress */
int dpdk_init_progress(struct dpdk_progress *progress, struct fi_info *info) {
    int ret;

    // TODO: this should become a parameter in some way
    progress->lcore_id = 1;
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
        FI_WARN(&dpdk_prov, FI_LOG_DOMAIN, "unable to start progress lcore thread\n");
        ret = -ret;
    }

    return ret;
}

// This is the main DPDK lcore loop => one polling thread PER DEVICE (= per domain)
int dpdk_run_progress(void *arg) {

    // Arguments
    struct progress_arg  *arguments    = (struct progress_arg *)arg;
    struct dpdk_progress *progress     = arguments->progress;
    bool                  clear_signal = arguments->clear_signal;

    struct slist_entry *prev, *cur;
    struct dpdk_domain *domain = container_of(progress, struct dpdk_domain, progress);
    struct dpdk_ep     *ep;

    while (likely(!atomic_load(&progress->stop_progress))) {

        ofi_genlock_lock(&domain->ep_mutex);
        slist_foreach(&domain->endpoint_list, cur, prev) {
            ep = container_of(cur, struct dpdk_ep, entry);
            switch (atomic_load(&ep->conn_state)) {
            case ep_conn_state_unbound:
                /* code */
                break;
            case ep_conn_state_connected:
                FI_DBG(&dpdk_prov, FI_LOG_DOMAIN, "Progress loop: progress EP %p\n", ep);
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

        // Receive action
        do_receive(domain);
    }

    return -1;
}

void dpdk_close_progress(struct dpdk_progress *progress) {
    printf("dpdk_close_progress: UNIMPLEMENTED\n");
    atomic_store(&progress->stop_progress, true);
}
