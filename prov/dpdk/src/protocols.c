#include "protocols.h"

/* Ethernet */

/* Prepends an Ethernet header to the frame and enqueues it on the given port.
 * The ether_type should be in host byte order. */
void enqueue_ether_frame(struct rte_mbuf *sendmsg, unsigned int ether_type, struct dpdk_ep *ep,
                         struct rte_ether_addr *dst_addr) {

    struct dpdk_domain *domain = container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);
    struct rte_ether_hdr *eth =
        (struct rte_ether_hdr *)rte_pktmbuf_prepend(sendmsg, sizeof(struct rte_ether_hdr));

    rte_ether_addr_copy(dst_addr, &eth->dst_addr);
    rte_ether_addr_copy(&domain->eth_addr, &eth->src_addr);
    eth->ether_type  = rte_cpu_to_be_16(ether_type);
    sendmsg->l2_len  = sizeof(*eth);
    *(ep->txq_end++) = sendmsg;

    // This is an optimization, but it breaks the separation between pure protocol processinf and
    // DPDK progress logic. I would prefer leaving it out, for the moment.
    if (ep->txq_end == ep->txq + dpdk_default_tx_burst_size) {
        printf("[DEBUG] TX queue filled; early flush could be forced]");
        //     RTE_LOG(DEBUG, USER1, "TX queue filled; early flush forced\n");
        //     flush_tx_queue(ep);
    }
} /* enqueue_ether_frame */

// Converts a string representing an eth address into a byte representation of the address itself
int eth_parse(char *string, unsigned char *eth_addr) {
    if (string == NULL || eth_addr == NULL) {
        return -1;
    }

    sscanf(string, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx", &eth_addr[0], &eth_addr[1], &eth_addr[2],
           &eth_addr[3], &eth_addr[4], &eth_addr[5]);
    return 0;
}

/* IPv4 */

uint16_t ip_checksum(struct rte_ipv4_hdr *ih, size_t len) {
    const void *buf = ih;
    uint32_t    sum = 0;

    /* extend strict-aliasing rules */
    typedef uint16_t __attribute__((__may_alias__)) uint16_t_p;
    const uint16_t_p *uint16_t_buf = (const uint16_t_p *)buf;
    const uint16_t_p *end          = uint16_t_buf + len / sizeof(*uint16_t_buf);

    for (; uint16_t_buf != end; ++uint16_t_buf)
        sum += *uint16_t_buf;

    /* if length is odd, keeping it byte order independent */
    if (likely(len % 2)) {
        uint16_t left           = 0;
        *(unsigned char *)&left = *(const unsigned char *)end;
        sum += left;
    }

    sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
    sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);

    uint16_t cksum = (uint16_t)sum;

    return (uint16_t)~cksum;
}

int32_t ip_parse(char *addr, uint32_t *dst) {
    if (inet_pton(AF_INET, addr, dst) != 1)
        return -1;

    return 0;
}

/* Appends a skeleton IPv4 header to the packet. Assume that src_addr and dst_addr are in
 * network byte order. */
struct rte_ipv4_hdr *prepend_ipv4_header(struct rte_mbuf *sendmsg, int next_proto_id,
                                         uint32_t src_addr, uint32_t dst_addr) {
    struct rte_ipv4_hdr *ip;
    size_t               payload_length;

    payload_length      = rte_pktmbuf_pkt_len(sendmsg);
    ip                  = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(sendmsg, sizeof(*ip));
    ip->version_ihl     = 0x45;
    ip->type_of_service = 0;
    ip->total_length    = rte_cpu_to_be_16(sizeof(*ip) + payload_length);
    ip->packet_id       = 0;
    ip->fragment_offset = 0;
    ip->time_to_live    = 64;
    ip->next_proto_id   = next_proto_id;
    ip->hdr_checksum    = 0;
    ip->src_addr        = src_addr;
    ip->dst_addr        = dst_addr;
    sendmsg->l3_len     = sizeof(*ip);

    if (!(sendmsg->ol_flags & RTE_MBUF_F_TX_IP_CKSUM)) {
        ip->hdr_checksum = rte_ipv4_cksum(ip);
    }

    return ip;
} /* prepend_ipv4_header */

/* UDP */

/* Appends a skeleton IPv4 header to the packet.  Note that this sets the
 * checksum to 0, which must either be computed in full or offloaded (in which
 * case the IP psuedo-header checksum must be pre-computed by the caller).
 * src_port and dst_port should be in network byte order. */
struct rte_udp_hdr *prepend_udp_header(struct rte_mbuf *sendmsg, unsigned int src_port,
                                       unsigned int dst_port) {
    struct rte_udp_hdr *udp;
    size_t              payload_length;

    payload_length   = rte_pktmbuf_pkt_len(sendmsg);
    udp              = (struct rte_udp_hdr *)rte_pktmbuf_prepend(sendmsg, sizeof(*udp));
    udp->src_port    = src_port;
    udp->dst_port    = dst_port;
    udp->dgram_cksum = 0;
    udp->dgram_len   = rte_cpu_to_be_16(sizeof(*udp) + payload_length);
    sendmsg->l4_len  = sizeof(*udp);

    return udp;
} /* prepend_udp_header */

/** Adds a UDP datagram to our packet TX queue to be transmitted when the queue
 * is next flushed.
 *
 * @param ep
 *   The endpoint that is sending this datagram.
 * @param sendmsg
 *   The mbuf containing the datagram to send.
 * @param dest
 *   The address handle of the destination for this datagram.
 * @param payload_checksum
 *   The non-complemented checksum of the packet payload.  Ignored if
 *   checksum_offload is enabled.
 */
void send_udp_dgram(struct dpdk_ep *ep, struct rte_mbuf *sendmsg, uint32_t raw_cksum) {
    struct rte_udp_hdr  *udp;
    struct rte_ipv4_hdr *ip;
    struct dpdk_domain  *domain = container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);

    if (domain->dev_flags & port_checksum_offload) {
        sendmsg->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM | RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
    }

    udp = prepend_udp_header(sendmsg, rte_cpu_to_be_16(ep->udp_port),
                             rte_cpu_to_be_16(ep->remote_udp_port));
    ip  = prepend_ipv4_header(sendmsg, IP_UDP, rte_cpu_to_be_32(domain->address >> 32),
                              rte_cpu_to_be_32(ep->remote_ipv4_addr));

    udp->dgram_cksum = rte_ipv4_phdr_cksum(ip, sendmsg->ol_flags);
    if (!(sendmsg->ol_flags & RTE_MBUF_F_TX_UDP_CKSUM)) {
        raw_cksum += udp->dgram_cksum + udp->src_port + udp->dst_port + udp->dgram_len;
        /* Add any carry bits into the checksum. */
        while (raw_cksum > UINT16_MAX) {
            raw_cksum = (raw_cksum >> 16) + (raw_cksum & 0xffff);
        }
        udp->dgram_cksum = (raw_cksum == UINT16_MAX) ? UINT16_MAX : ~raw_cksum;
    }

    enqueue_ether_frame(sendmsg, RTE_ETHER_TYPE_IPV4, ep, &ep->remote_eth_addr);
} /* send_udp_dgram */

/* TRP */
void send_trp_ack(struct dpdk_ep *ep) {
    struct dpdk_domain *domain = container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);
    struct ee_state    *ee     = &ep->remote_ep;
    struct rte_mbuf    *sendmsg;
    struct trp_hdr     *trp;

    assert(!(ee->trp_flags & trp_recv_missing));
    sendmsg      = rte_pktmbuf_alloc(ep->tx_hdr_mempool);
    trp          = (struct trp_hdr *)rte_pktmbuf_append(sendmsg, sizeof(*trp));
    trp->psn     = rte_cpu_to_be_32(ee->send_next_psn);
    trp->ack_psn = rte_cpu_to_be_32(ee->recv_ack_psn);
    trp->opcode  = rte_cpu_to_be_16(0);
    ee->trp_flags &= ~trp_ack_update;

    send_udp_dgram(ep, sendmsg,
                   (domain->dev_flags & port_checksum_offload) ? 0
                                                               : rte_raw_cksum(trp, sizeof(*trp)));
} /* send_trp_ack */

void send_trp_sack(struct dpdk_ep *ep) {
    struct rte_mbuf    *sendmsg;
    struct ee_state    *ee = &ep->remote_ep;
    struct trp_hdr     *trp;
    struct dpdk_domain *domain = container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);

    assert(ee->trp_flags & trp_recv_missing);
    sendmsg      = rte_pktmbuf_alloc(ep->tx_hdr_mempool);
    trp          = (struct trp_hdr *)rte_pktmbuf_append(sendmsg, sizeof(*trp));
    trp->psn     = rte_cpu_to_be_32(ee->recv_sack_psn.min);
    trp->ack_psn = rte_cpu_to_be_32(ee->recv_sack_psn.max);
    trp->opcode  = rte_cpu_to_be_16(trp_sack);

    ee->trp_flags &= ~trp_ack_update;

    send_udp_dgram(ep, sendmsg,
                   (domain->dev_flags & port_checksum_offload) ? 0
                                                               : rte_raw_cksum(trp, sizeof(*trp)));
} /* send_trp_sack */

void process_trp_sack(struct ee_state *ep, uint32_t psn_min, uint32_t psn_max) {
    struct pending_datagram_info *info;
    struct rte_mbuf             **sendmsg, **start, **end;

    sendmsg = start = ep->tx_head;
    end             = ep->tx_pending + ep->tx_pending_size;
    if (!*sendmsg) {
        return;
    }

    do {
        info = (struct pending_datagram_info *)(sendmsg + 1);
        maybe_sack_pending(info, psn_min, psn_max);

        if (++sendmsg == end) {
            sendmsg = ep->tx_pending;
        }
    } while (sendmsg != start && *sendmsg);
}

void maybe_sack_pending(struct pending_datagram_info *pending, uint32_t psn_min, uint32_t psn_max) {
    if ((psn_min == pending->psn || serial_less_32(psn_min, pending->psn)) &&
        serial_less_32(pending->psn, psn_max))
    {
        pending->next_retransmit = UINT64_MAX;
    }
}

/* DDP */
static inline struct rte_mbuf **tx_pending_entry(struct ee_state *ee, uint32_t psn) {
    int index = psn & (ee->tx_pending_size - 1);
    return &ee->tx_pending[index];

} /* tx_pending_entry */

static struct rdmap_terminate_payload *terminate_append_ddp_header(
    struct rdmap_packet *orig, struct rte_mbuf *sendmsg, struct rdmap_terminate_packet *term) {
    struct rdmap_terminate_payload *p;
    size_t                          hdr_size;

    term->hdrct = rdmap_hdrct_m | rdmap_hdrct_d;
    if (DDP_GET_T(orig->ddp_flags)) {
        hdr_size = sizeof(struct rdmap_tagged_packet);
    } else {
        hdr_size = sizeof(struct rdmap_untagged_packet);
    }
    p = (struct rdmap_terminate_payload *)rte_pktmbuf_append(sendmsg, hdr_size);
    memcpy(&p->payload, orig, hdr_size);
    return p;
} /* terminate_append_ddp_header */

int resend_ddp_segment(struct dpdk_ep *ep, struct rte_mbuf *sendmsg, struct ee_state *ee) {
    struct pending_datagram_info *info;
    struct rte_mbuf              *hdr;
    struct trp_hdr               *trp;
    uint32_t                      payload_raw_cksum = 0;
    struct dpdk_domain *domain = container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);

    info                  = (struct pending_datagram_info *)(sendmsg + 1);
    info->next_retransmit = rte_get_timer_cycles() + rte_get_timer_hz() / 100;
    if (info->transmit_count++ > RETRANSMIT_MAX) {
        return -EIO;
    }

    hdr = rte_pktmbuf_alloc(ep->tx_hdr_mempool);
    if (!hdr) {
        return -ENOMEM;
    }

    sendmsg = rte_pktmbuf_clone(sendmsg, sendmsg->pool);

    trp          = (struct trp_hdr *)rte_pktmbuf_append(hdr, sizeof(*trp));
    trp->psn     = rte_cpu_to_be_32(info->psn);
    trp->ack_psn = rte_cpu_to_be_32(ee->recv_ack_psn);
    trp->opcode  = rte_cpu_to_be_16(0);
    if (!(ee->trp_flags & trp_recv_missing)) {
        ee->trp_flags &= ~trp_ack_update;
    }

    rte_pktmbuf_chain(hdr, sendmsg);
    if (!domain->dev_flags & port_checksum_offload) {
        payload_raw_cksum = info->ddp_raw_cksum + rte_raw_cksum(trp, sizeof(*trp));
    }
    send_udp_dgram(ep, hdr, payload_raw_cksum);

    return 0;
} /* resend_ddp_segment */

int send_ddp_segment(struct dpdk_ep *ep, struct rte_mbuf *sendmsg,
                     struct read_atomic_response_state *readresp, struct dpdk_xfer_entry *wqe,
                     size_t payload_length) {
    struct dpdk_domain *domain = container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);

    struct pending_datagram_info *pending;
    uint32_t                      psn = ep->remote_ep.send_next_psn++;

    pending                 = (struct pending_datagram_info *)(sendmsg + 1);
    pending->wqe            = wqe;
    pending->readresp       = readresp;
    pending->transmit_count = 0;
    pending->ddp_length     = payload_length;
    if (!domain->dev_flags & port_checksum_offload) {
        pending->ddp_raw_cksum =
            rte_raw_cksum(rte_pktmbuf_mtod(sendmsg, void *), rte_pktmbuf_data_len(sendmsg));
    }
    pending->psn = psn;

    assert(*tx_pending_entry(&ep->remote_ep, psn) == NULL);
    *tx_pending_entry(&ep->remote_ep, psn) = sendmsg;

    resend_ddp_segment(ep, sendmsg, &ep->remote_ep);
    return psn;
} /* send_ddp_segment */

/* RDMAP */

void free_extbuf_cb(void *addr, void *opaque) {
    return;
}

static inline void rte_pktmbuf_ext_shinfo_init_helper_custom(
    struct rte_mbuf_ext_shared_info *ret_shinfo, rte_mbuf_extbuf_free_callback_t free_cb,
    void *fcb_opaque) {

    struct rte_mbuf_ext_shared_info *shinfo = ret_shinfo;
    shinfo->free_cb                         = free_cb;
    shinfo->fcb_opaque                      = fcb_opaque;
    rte_mbuf_ext_refcnt_set(shinfo, 1);
    return;
}

static void put_iov_in_chain(struct rte_mempool *pool, struct rte_mbuf *head_pkt, size_t dest_size,
                             const struct iovec *restrict src, size_t iov_count, size_t offset) {
    unsigned         y;
    size_t           prev, pos, cur;
    char            *src_iov_base;
    struct rte_mbuf *prev_pkt = head_pkt;

    pos = 0;
    for (y = 0, prev = 0; pos < dest_size && y < iov_count; ++y) {
        if (prev <= offset && offset < prev + src[y].iov_len) {
            cur          = RTE_MIN(prev + src[y].iov_len - offset, dest_size - pos);
            src_iov_base = src[y].iov_base;

            // Prepare an mbuf to point at the relevant payload
            // TODO: where do we de-allocate this?
            struct rte_mbuf                *payload_mbuf = rte_pktmbuf_alloc(pool);
            char                           *data         = src_iov_base + offset - prev;
            rte_iova_t                      iova         = rte_mem_virt2iova(data);
            struct rte_mbuf_ext_shared_info ret_shinfo;
            rte_pktmbuf_ext_shinfo_init_helper_custom(&ret_shinfo, &free_extbuf_cb, NULL);
            // Attach the memory buffer to the mbuf
            rte_pktmbuf_attach_extbuf(payload_mbuf, data, iova, cur, &ret_shinfo);
            payload_mbuf->data_len = cur;
            // Put packets in chain
            head_pkt->pkt_len = head_pkt->pkt_len + payload_mbuf->data_len;
            head_pkt->nb_segs += 1;
            prev_pkt->next = payload_mbuf;
            prev_pkt       = payload_mbuf;

            pos += cur;
            offset += cur;
        }
        prev += src[y].iov_len;
    }
} /* put_iov_in_chain */

void memcpy_from_iov(char *restrict dest, size_t dest_size, const struct iovec *restrict src,
                     size_t iov_count, size_t offset) {
    unsigned y;
    size_t   prev, pos, cur;
    char    *src_iov_base;

    pos = 0;
    for (y = 0, prev = 0; pos < dest_size && y < iov_count; ++y) {
        if (prev <= offset && offset < prev + src[y].iov_len) {
            cur          = RTE_MIN(prev + src[y].iov_len - offset, dest_size - pos);
            src_iov_base = src[y].iov_base;
            rte_memcpy(dest + pos, src_iov_base + offset - prev, cur);
            pos += cur;
            offset += cur;
        }
        prev += src[y].iov_len;
    }
}

void do_rdmap_send(struct dpdk_ep *ep, struct dpdk_xfer_entry *wqe) {
    struct dpdk_domain *domain = container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);
    struct rdmap_untagged_packet *new_rdmap;
    struct rte_mbuf              *sendmsg;
    unsigned int                  packet_length;
    size_t                        payload_length;
    uint16_t                      mtu = domain->mtu;

    if (wqe->state != SEND_XFER_TRANSFER) {
        return;
    }

    while (
        (wqe->bytes_sent < wqe->total_length || (wqe->bytes_sent == 0 && wqe->total_length == 0)) &&
        serial_less_32(wqe->remote_ep->send_next_psn, wqe->remote_ep->send_max_psn))
    {
        sendmsg = rte_pktmbuf_alloc(ep->tx_ddp_mempool);

        payload_length = RTE_MIN(mtu, wqe->total_length - wqe->bytes_sent);
        packet_length  = RDMAP_UNTAGGED_ALLOC_SIZE(payload_length);
        new_rdmap      = (struct rdmap_untagged_packet *)rte_pktmbuf_append(sendmsg, packet_length);
        new_rdmap->head.ddp_flags = (wqe->total_length - wqe->bytes_sent <= mtu)
                                        ? DDP_V1_UNTAGGED_LAST_DF
                                        : DDP_V1_UNTAGGED_DF;
        if (wqe->opcode == xfer_send_with_imm) {
            new_rdmap->head.rdmap_info = rdmap_opcode_send_with_imm | RDMAP_V1;
            new_rdmap->head.immediate  = wqe->imm_data;
        } else {
            new_rdmap->head.rdmap_info = rdmap_opcode_send | RDMAP_V1;
            new_rdmap->head.immediate  = 0;
        }
        new_rdmap->head.sink_stag = rte_cpu_to_be_32(0);
        new_rdmap->qn             = rte_cpu_to_be_32(0);
        new_rdmap->msn            = rte_cpu_to_be_32(wqe->msn);
        new_rdmap->mo             = rte_cpu_to_be_32(wqe->bytes_sent);
        if (payload_length > 0) {
            if (wqe->flags & xfer_send_inline) {
                memcpy(PAYLOAD_OF(new_rdmap), (char *)wqe->iov + wqe->bytes_sent, payload_length);
            } else {
                // Do not copy: zero-copy send
                put_iov_in_chain(ep->tx_ddp_mempool, sendmsg, payload_length, wqe->iov,
                                 wqe->iov_count, wqe->bytes_sent);
                // memcpy_from_iov(PAYLOAD_OF(new_rdmap), payload_length, wqe->iov, wqe->iov_count,
                //                 wqe->bytes_sent);
            }
        }

        send_ddp_segment(ep, sendmsg, NULL, wqe, payload_length);
        RTE_LOG(DEBUG, USER1, "<ep=%" PRIx16 "> SEND transmit msn=%" PRIu32 " [%zu-%zu]\n",
                ep->udp_port, wqe->msn, wqe->bytes_sent, wqe->bytes_sent + payload_length);

        wqe->bytes_sent += payload_length;

        if (wqe->total_length == 0) {
            break;
        }
    }

    if (wqe->bytes_sent == wqe->total_length) {
        wqe->state = SEND_XFER_WAIT;
    }
}

void do_rdmap_terminate(struct dpdk_ep *ep, struct packet_context *orig, enum rdmap_errno errcode) {
    {
        struct rte_mbuf                *sendmsg = rte_pktmbuf_alloc(ep->tx_ddp_mempool);
        struct rdmap_terminate_packet  *new_rdmap;
        struct rdmap_terminate_payload *payload;

        new_rdmap =
            (struct rdmap_terminate_packet *)rte_pktmbuf_append(sendmsg, sizeof(*new_rdmap));
        new_rdmap->untagged.head.ddp_flags  = DDP_V1_UNTAGGED_LAST_DF;
        new_rdmap->untagged.head.rdmap_info = rdmap_opcode_terminate | RDMAP_V1;
        new_rdmap->untagged.head.sink_stag  = 0;
        new_rdmap->untagged.qn              = rte_cpu_to_be_32(2);
        new_rdmap->untagged.msn             = rte_cpu_to_be_32(1);
        new_rdmap->untagged.mo              = rte_cpu_to_be_32(0);
        new_rdmap->error_code               = rte_cpu_to_be_16(errcode);
        new_rdmap->reserved                 = 0;
        switch (errcode & 0xff00) {
        case 0x0100:
            /* Error caused by RDMA Read Request */
            new_rdmap->hdrct = rdmap_hdrct_m | rdmap_hdrct_d | rdmap_hdrct_r;

            payload = (struct rdmap_terminate_payload *)rte_pktmbuf_append(
                sendmsg, 2 + sizeof(struct rdmap_readreq_packet));
            memcpy(&payload->payload, orig->rdmap, sizeof(struct rdmap_readreq_packet));
            break;
        case 0x0200:
        case 0x1200:
            /* Error caused by DDP or RDMAP untagged message other than
             * Read Request */
            if (orig) {
                payload = terminate_append_ddp_header(orig->rdmap, sendmsg, new_rdmap);
            } else {
                new_rdmap->hdrct = 0;
                payload          = NULL;
            }
            break;
        case 0x1000:
        case 0x1100:
            /* DDP layer error */
            payload = terminate_append_ddp_header(orig->rdmap, sendmsg, new_rdmap);
            break;
        case 0x0000:
        default:
            new_rdmap->hdrct = 0;
            payload          = NULL;
            break;
        }

        if (payload) {
            payload->ddp_seg_len = rte_cpu_to_be_16(orig->ddp_seg_length);
        }
        (void)send_ddp_segment(ep, sendmsg, NULL, NULL, 0);
    } /* do_rdmap_terminate */
}