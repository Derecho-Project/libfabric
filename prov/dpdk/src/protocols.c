#include "protocols.h"

/* Ethernet */

/* Prepends an Ethernet header to the frame and enqueues it on the given port.
 * It performs fragmentation if sendmsg is greater than the Ethernet MTU.
 * The ether_type should be in host byte order. */
void enqueue_ether_frame(struct rte_mbuf *sendmsg, unsigned int ether_type, struct dpdk_ep *ep,
                         struct rte_ether_addr *dst_addr) {

    struct dpdk_domain *domain = container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);

    struct rte_ether_hdr *eth =
        rte_pktmbuf_mtod_offset(sendmsg, struct rte_ether_hdr *, ETHERNET_HDR_OFFSET);

    rte_ether_addr_copy(dst_addr, &eth->dst_addr);
    rte_ether_addr_copy(&domain->eth_addr, &eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(ether_type);
    sendmsg->l2_len = RTE_ETHER_HDR_LEN;

    // Now, if necessary, fragment the packet
    if (sendmsg->pkt_len > (domain->mtu + RTE_ETHER_HDR_LEN)) {
        /* Mbufs for the fragmentation */
        struct rte_mbuf *pkts_out[MAX_FRAG_NUM];
        int              used_mbufs = 0;

        rte_pktmbuf_adj(sendmsg, RTE_ETHER_HDR_LEN);
        if ((used_mbufs =
                 rte_ipv4_fragment_packet(sendmsg, (struct rte_mbuf **)pkts_out, MAX_FRAG_NUM,
                                          domain->mtu, ep->tx_hdr_mempool, ep->tx_ddp_mempool)) < 0)
        {
            RTE_LOG(ERR, USER1, "Error while fragmenting packets: %s\n", rte_strerror(-used_mbufs));
            return;
        }

        // Prepend a new Ethernet header to each fragment
        struct rte_mbuf      *m;
        struct rte_ether_hdr *hdr_frag;
        for (int j = 0; j < used_mbufs; j++) {
            m = pkts_out[j];

            hdr_frag = (struct rte_ether_hdr *)rte_pktmbuf_prepend(m, RTE_ETHER_HDR_LEN);
            if (!hdr_frag) {
                printf("Error: no headroom in mbuf!\n");
                RTE_LOG(ERR, USER1, "Error while fragmenting packets: %s\n",
                        rte_strerror(rte_errno));
                return;
            }

            rte_ether_addr_copy(dst_addr, &hdr_frag->dst_addr);
            rte_ether_addr_copy(&domain->eth_addr, &hdr_frag->src_addr);
            hdr_frag->ether_type = rte_cpu_to_be_16(ether_type);
            m->l2_len            = sizeof(*hdr_frag);

            // Append the fragment to the transmission queue
            *(ep->txq_end++) = m;

            if (ep->txq_end == ep->txq + dpdk_default_tx_burst_size) {
                RTE_LOG(DEBUG, USER1, "TX queue filled; early flush forced\n");
                flush_tx_queue(ep);
            }
        }

        // Free the clone of the original packet: we will send the fragments, not this one
        rte_pktmbuf_free(sendmsg);

    } else {
        // Append the mbuf chain to the transmission queue
        *(ep->txq_end++) = sendmsg;
        if (ep->txq_end == ep->txq + dpdk_default_tx_burst_size) {
            RTE_LOG(DEBUG, USER1, "TX queue filled; early flush forced\n");
            flush_tx_queue(ep);
        }
    }
} /* enqueue_ether_frame */

// Converts a string representing an eth address into a byte representation of the address
// itself
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

    // Back to host byte order
    *dst = rte_be_to_cpu_32(*dst);

    return 0;
}

/* Appends a skeleton IPv4 header to the packet. Assume that src_addr and dst_addr are in
 * host byte order. The PAYLOAD must be the payload of the IP packet, including higher-level headers
 */
struct rte_ipv4_hdr *prepend_ipv4_header(struct rte_mbuf *sendmsg, int next_proto_id,
                                         uint32_t src_addr, uint32_t dst_addr,
                                         uint16_t ddp_length) {
    struct rte_ipv4_hdr *ip;

    // Get payload length
    size_t total_length = ddp_length + IP_HDR_LEN;

    ip              = rte_pktmbuf_mtod_offset(sendmsg, struct rte_ipv4_hdr *, IP_HDR_OFFSET);
    sendmsg->l3_len = IP_HDR_LEN;

    ip->src_addr        = rte_cpu_to_be_32(src_addr);
    ip->dst_addr        = rte_cpu_to_be_32(dst_addr);
    ip->version         = IPV4;
    ip->version_ihl     = 0x45;
    ip->type_of_service = 0;
    ip->total_length    = rte_cpu_to_be_16(total_length);
    ip->packet_id       = rte_cpu_to_be_16(ip->packet_id);
    ip->fragment_offset = 0;
    ip->time_to_live    = 64;
    ip->next_proto_id   = next_proto_id;
    ip->hdr_checksum    = 0x0000;

    if (!(sendmsg->ol_flags & RTE_MBUF_F_TX_IP_CKSUM)) {
        ip->hdr_checksum = rte_ipv4_cksum(ip);
    }

    return ip;
} /* prepend_ipv4_header */

// Reassemble IP packet from fragments
struct rte_mbuf *reassemble(struct rte_mbuf *m, struct lcore_queue_conf *qconf, uint16_t vlan_id,
                            uint64_t tms) {
    uint16_t ether_type = 0;

    // Ethernet and IP headers
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr  *ip_hdr;

    struct rte_ip_frag_tbl       *tbl;
    struct rte_ip_frag_death_row *dr;
    struct rx_queue              *rxq;

    eth_hdr    = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

    ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

    // TODO: We do not support VLAN or VXLAN yet. See dpdk-playground for an example
    if (ether_type == ETHERNET_P_IP) {
        if (ip_hdr->version != IPV4) {
            printf("Unsupported IP version\n");
            return NULL;
        }

        dr  = &qconf->death_row;
        rxq = &qconf->rx_queue_list[0];

        /* if it is a fragmented packet, then try to reassemble. */
        if (rte_ipv4_frag_pkt_is_fragmented((struct rte_ipv4_hdr *)ip_hdr)) {
            struct rte_mbuf *mo;

            tbl = rxq->frag_tbl;

            /* prepare mbuf: setup l2_len/l3_len. */
            m->l2_len = RTE_ETHER_HDR_LEN;
            m->l3_len = IP_HDR_LEN;

            /* process this fragment. */
            mo = rte_ipv4_frag_reassemble_packet(tbl, dr, m, tms, (struct rte_ipv4_hdr *)ip_hdr);
            if (mo == NULL) {
                /* no packet to return. */
                return NULL;
            }
            /* we have our packet reassembled. */
            if (mo != m) {
                m = mo;
            }
        }
        return m;
    }
    return NULL;
}

/* Setup per-queue fragment table at receiver side. Modified from DPDK ip_fragmentation example*/
int setup_queue_tbl(struct rx_queue *rxq, uint32_t lcore, uint32_t queue, uint16_t port_mtu) {
    int      socket;
    uint32_t nb_mbuf;
    uint64_t frag_cycles;
    char     buf[RTE_MEMPOOL_NAMESIZE];
    socket = rte_lcore_to_socket_id(lcore);
    if (socket == SOCKET_ID_ANY)
        socket = 0;

    uint32_t max_flow_num = (uint32_t)0x100;
    uint32_t max_flow_ttl = DEF_FLOW_TTL;
    uint32_t max_entries  = IP_FRAG_TBL_BUCKET_ENTRIES;
    // TODO: Not sure about the following...
    uint16_t nb_rxd = dpdk_default_rx_size;
    uint16_t nb_txd = dpdk_default_tx_size;

    /* Each table entry holds information about packet fragmentation. 8< */
    frag_cycles = (rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S * max_flow_ttl;
    // frag_cycles *= 100;

    if ((rxq->frag_tbl = rte_ip_frag_table_create(max_flow_num, IP_FRAG_TBL_BUCKET_ENTRIES,
                                                  max_entries, frag_cycles, socket)) == NULL)
    {
        printf("ip_frag_tbl_create(%u) on lcore: %u for queue: %u failed\n", max_flow_num, lcore,
               queue);
        return -1;
    }
    /* >8 End of holding packet fragmentation. */

    /*
     * At any given moment up to <max_flow_num * (MAX_FRAG_NUM)>
     * mbufs could be stored int the fragment table.
     * Plus, each TX queue can hold up to <max_flow_num> packets.
     */

    /* mbufs stored int the fragment table. 8< */
    nb_mbuf = RTE_MAX(max_flow_num, 2UL * dpdk_default_rx_burst_size) * MAX_FRAG_NUM;
    nb_mbuf *= (port_mtu + RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN + RTE_MBUF_DEFAULT_DATAROOM - 1) /
               RTE_MBUF_DEFAULT_DATAROOM;
    // nb_mbuf *= 2; /* ipv4 and ipv6 */
    nb_mbuf += nb_rxd + nb_txd;
    nb_mbuf = RTE_MAX(nb_mbuf, (uint32_t)RTE_MBUF_DEFAULT_DATAROOM);

    snprintf(buf, sizeof(buf), "mbuf_pool_%u_%u", lcore, queue);
    rxq->pool = rte_pktmbuf_pool_create(buf, nb_mbuf, 64, 0,
                                        port_mtu + RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN, socket);
    if (rxq->pool == NULL) {
        printf("rte_pktmbuf_pool_create(%s) failed\n", buf);
        return -1;
    }
    /* >8 End of mbufs stored int the fragmentation table. */

    return 0;
}

/* UDP */

/* Appends a UDP header to the packet.  Note that this sets the
 * checksum to 0, which must either be computed in full or offloaded (in which
 * case the IP psuedo-header checksum must be pre-computed by the caller).
 * The PAYLOAD must be the payload for the UDP packet, including higher-level headers.
 */
struct rte_udp_hdr *prepend_udp_header(struct rte_mbuf *sendmsg, unsigned int src_port,
                                       unsigned int dst_port, uint16_t ddp_length) {
    struct rte_udp_hdr *udp;

    // Get payload length
    size_t total_length = UDP_HDR_LEN + ddp_length;

    // Get and fill the UDP header
    udp             = rte_pktmbuf_mtod_offset(sendmsg, struct rte_udp_hdr *, UDP_HDR_OFFSET);
    sendmsg->l4_len = UDP_HDR_LEN;

    udp->src_port    = rte_cpu_to_be_16(src_port);
    udp->dst_port    = rte_cpu_to_be_16(dst_port);
    udp->dgram_cksum = 0;
    udp->dgram_len   = rte_cpu_to_be_16(total_length);

    return udp;
} /* prepend_udp_header */

// The DDP length must include the higher-level headers and the payload length
void send_udp_dgram(struct dpdk_ep *ep, struct rte_mbuf *sendmsg, uint32_t raw_cksum,
                    uint16_t ddp_length) {
    struct rte_udp_hdr  *udp;
    struct rte_ipv4_hdr *ip;
    struct dpdk_domain  *domain = container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);

    if (domain->dev_flags & port_checksum_offload) {
        sendmsg->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM | RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
    }

    // udp              = prepend_udp_header(sendmsg, ep->udp_port, ep->remote_udp_port,
    // ddp_length); ip               = prepend_ipv4_header(sendmsg, IP_UDP, domain->ipv4_addr,
    // ep->remote_ipv4_addr,
    //                                        ddp_length + UDP_HDR_LEN);
    udp = prepend_udp_header(sendmsg, ep->udp_port, ep->remote_udp_port, ddp_length);
    ip  = prepend_ipv4_header(sendmsg, IP_UDP, rte_be_to_cpu_16(domain->local_addr.sin_addr.s_addr),
                              ep->remote_ipv4_addr, ddp_length + UDP_HDR_LEN);
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
    sendmsg = rte_pktmbuf_alloc(ep->tx_hdr_mempool);
    RTE_LOG(DEBUG, USER1, "Sending TRP ACK\n");

    trp = rte_pktmbuf_mtod_offset(sendmsg, struct trp_hdr *, TRP_HDR_OFFSET);
    sendmsg->data_len += TRP_HDR_LEN + UDP_HDR_LEN + IP_HDR_LEN + RTE_ETHER_HDR_LEN;
    sendmsg->pkt_len += TRP_HDR_LEN + UDP_HDR_LEN + IP_HDR_LEN + RTE_ETHER_HDR_LEN;

    trp->psn     = rte_cpu_to_be_32(ee->send_next_psn);
    trp->ack_psn = rte_cpu_to_be_32(ee->recv_ack_psn);
    trp->opcode  = rte_cpu_to_be_16(0);
    ee->trp_flags &= ~trp_ack_update;

    send_udp_dgram(ep, sendmsg,
                   (domain->dev_flags & port_checksum_offload) ? 0
                                                               : rte_raw_cksum(trp, sizeof(*trp)),
                   TRP_HDR_LEN);
} /* send_trp_ack */

void send_trp_sack(struct dpdk_ep *ep) {
    struct dpdk_domain *domain = container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);
    struct ee_state    *ee     = &ep->remote_ep;
    struct rte_mbuf    *sendmsg;
    struct trp_hdr     *trp;

    assert(ee->trp_flags & trp_recv_missing);
    sendmsg = rte_pktmbuf_alloc(ep->tx_hdr_mempool);
    RTE_LOG(DEBUG, USER1, "Sending TRP SACK\n");

    trp = rte_pktmbuf_mtod_offset(sendmsg, struct trp_hdr *, TRP_HDR_OFFSET);
    sendmsg->data_len += TRP_HDR_LEN + UDP_HDR_LEN + IP_HDR_LEN + RTE_ETHER_HDR_LEN;
    sendmsg->pkt_len += TRP_HDR_LEN + UDP_HDR_LEN + IP_HDR_LEN + RTE_ETHER_HDR_LEN;

    trp->psn     = rte_cpu_to_be_32(ee->recv_sack_psn.min);
    trp->ack_psn = rte_cpu_to_be_32(ee->recv_sack_psn.max);
    trp->opcode  = rte_cpu_to_be_16(trp_sack);
    ee->trp_flags &= ~trp_ack_update;

    send_udp_dgram(ep, sendmsg,
                   (domain->dev_flags & port_checksum_offload) ? 0
                                                               : rte_raw_cksum(trp, sizeof(*trp)),
                   TRP_HDR_LEN);
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

// This is executed multiple times in case of packet retransmission
int resend_ddp_segment(struct dpdk_ep *ep, struct rte_mbuf *sendmsg, struct ee_state *ee) {
    struct pending_datagram_info *info;
    struct trp_hdr               *trp;
    uint32_t                      payload_raw_cksum = 0;
    struct dpdk_domain *domain = container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);

    info = (struct pending_datagram_info *)(sendmsg + 1);
    // TODO: [Lorenzo] We should make this timeout a configurable parameter
    info->next_retransmit = rte_get_timer_cycles() + rte_get_timer_hz() / 1000;
    if (info->transmit_count++ > RETRANSMIT_MAX) {
        return -EIO;
    }

    // Clone. The clone is necessary because the rte_eth_tx_burst function will free the mbufs,
    // but we need to keep them until they have been acknowledged
    sendmsg = rte_pktmbuf_clone(sendmsg, sendmsg->pool);

    // Prepare the TRP header
    // TODO: Should this be a sort of "prepend TRP header" as well? Why in a function called DDP?
    trp = rte_pktmbuf_mtod_offset(sendmsg, struct trp_hdr *, TRP_HDR_OFFSET);

    trp->psn     = rte_cpu_to_be_32(info->psn);
    trp->ack_psn = rte_cpu_to_be_32(ee->recv_ack_psn);
    trp->opcode  = rte_cpu_to_be_16(0);
    if (!(ee->trp_flags & trp_recv_missing)) {
        ee->trp_flags &= ~trp_ack_update;
    }

    if (!domain->dev_flags & port_checksum_offload) {
        payload_raw_cksum = info->ddp_raw_cksum + rte_raw_cksum(trp, sizeof(*trp));
    }

    send_udp_dgram(ep, sendmsg, payload_raw_cksum, TRP_HDR_LEN + info->ddp_length);

    return 0;
} /* resend_ddp_segment */

// This is executed only once per RDMAP packet.
// The payload side must include the RDMAP header length and the payload length.
// The pkt_len of the "sendmsg" mbuf must be set to the total HEADER + PAYLOAD length.
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

    // Insert this message into the list of messages sent but unacked
    assert(*tx_pending_entry(&ep->remote_ep, psn) == NULL);
    *tx_pending_entry(&ep->remote_ep, psn) = sendmsg;

    resend_ddp_segment(ep, sendmsg, &ep->remote_ep);
    return psn;
} /* send_ddp_segment */

/* RDMAP */

void free_extbuf_cb(void *addr, void *opaque) {
}

// This function is similar to the rte_pktmbuf_ext_shinfo_init_helper. However, the "original" one
// would allocate the rte_mbuf_ext_shared_info structure at the end of the external buffer. We
// can't, because the buffer is user-managed memory. So this function stores the struct in the
// area the user passes as first argument. Generally, and specifically for this case, the caller
// will pass a private area of the mbuf as first argument. DO NOT PASS a NULL callback pointer: it
// will be called by DPDK causing a segfault. Just pass a function that does nothing, if you do not
// need this feature.
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
    size_t prev, pos, cur;
    char  *src_iov_base;

    pos = 0;
    for (uint32_t y = 0, prev = 0; pos < dest_size && y < iov_count; ++y) {
        if (prev <= offset && offset < prev + src[y].iov_len) {
            cur          = RTE_MIN(prev + src[y].iov_len - offset, dest_size - pos);
            src_iov_base = src[y].iov_base;

            // Prepare an mbuf to point at the relevant payload
            struct rte_mbuf                 *payload_mbuf = rte_pktmbuf_alloc(pool);
            char                            *data         = src_iov_base + offset - prev;
            rte_iova_t                       iova         = rte_mem_virt2iova(data);
            struct rte_mbuf_ext_shared_info *ret_shinfo =
                (struct rte_mbuf_ext_shared_info *)(payload_mbuf + 1);
            rte_pktmbuf_ext_shinfo_init_helper_custom(ret_shinfo, free_extbuf_cb, NULL);
            // Attach the memory buffer to the mbuf
            rte_pktmbuf_attach_extbuf(payload_mbuf, data, iova, cur, ret_shinfo);
            payload_mbuf->pkt_len = payload_mbuf->data_len = cur;

            // Put packets in chain
            rte_pktmbuf_chain(head_pkt, payload_mbuf);

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
    struct rdmap_untagged_packet *new_rdmap;
    struct rte_mbuf              *sendmsg;
    size_t                        payload_length;

    uint16_t mtu = MAX_RDMAP_PAYLOAD_SIZE;

    if (wqe->state != SEND_XFER_TRANSFER) {
        return;
    }

    while (
        (wqe->bytes_sent < wqe->total_length || (wqe->bytes_sent == 0 && wqe->total_length == 0)) &&
        serial_less_32(wqe->remote_ep->send_next_psn, wqe->remote_ep->send_max_psn))
    {
        sendmsg = rte_pktmbuf_alloc(ep->tx_hdr_mempool);
        if (!sendmsg) {
            // TODO: Should we create an "error" state?
            wqe->state = SEND_XFER_COMPLETE;
            RTE_LOG(ERR, USER1, "Failed to allocate mbuf from pool %s\n", ep->tx_hdr_mempool->name);
            return;
        }

        // Header len. Add now the LEN of the packet. Now, because from now on, all the functions
        // will be potentially executed more than once in case of retransmission
        // TODO: Dos this make sense? In case of re-transmission to re-traverse the whole stack?
        sendmsg->data_len += RTE_ETHER_HDR_LEN + INNER_HDR_LEN;
        sendmsg->pkt_len += RTE_ETHER_HDR_LEN + INNER_HDR_LEN;

        // Data payload length. Not part of the pktmbuf, as sendmsg refers only to the headers
        payload_length = RTE_MIN(mtu, wqe->total_length - wqe->bytes_sent);

        // Prepare the RDMAP header
        new_rdmap =
            rte_pktmbuf_mtod_offset(sendmsg, struct rdmap_untagged_packet *, RDMAP_HDR_OFFSET);
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
            // TODO: Do we support inline data?
            // if (wqe->flags & xfer_send_inline) {
            //     memcpy(PAYLOAD_OF(new_rdmap), (char *)wqe->iov + wqe->bytes_sent,
            //     payload_length);
            // } else {

            // This is zero-copy send. But what about small sizes?
            // We could enable a mechanism that if total_size is <threshold, we copy the data
            // Attach the header buffer to the mbuf(s) that describe the payload
            put_iov_in_chain(ep->tx_ddp_mempool, sendmsg, payload_length, wqe->iov, wqe->iov_count,
                             wqe->bytes_sent);
        }

        send_ddp_segment(ep, sendmsg, NULL, wqe, RDMAP_HDR_LEN + payload_length);
        RTE_LOG(DEBUG, USER1, "<ep=%" PRIx16 "> SEND transmit msn=%" PRIu32 " [%zu-%zu]\n",
                ep->udp_port, wqe->msn, wqe->bytes_sent, wqe->bytes_sent + payload_length);

        wqe->bytes_sent += payload_length;
    }

    if (wqe->bytes_sent == wqe->total_length) {
        wqe->state = SEND_XFER_WAIT;
    }
} /* do_rdmap_send */

void do_rdmap_terminate(struct dpdk_ep *ep, struct packet_context *orig, enum rdmap_errno errcode) {

    /* Note 1. This uses 16 bytes more that regular data transfer headers.
     * To handle this, we made hdr_mbufs larger of 16 bytes to accomodate for this case.
     * A different design would be to allocate a new mbuf for the terminate packet, and a header
     * one for all the other, lower-layer headers. It seems to me that it is simpler to go with
     * the first option.
     */

    /* Note 2. In this case of termination, the regular RDMAP header is "augmented" with
     * additional info, represented by the structure  struct rdmap_terminate_packet (26 bytes
     * instead of 22). The packet should also contain a description of the packet that caused
     * the error (rdmap_packet) and the original ddp_size. Both these fields are stored in the
     * struct rdmap_terminate_payload (12 bytes, 2 + 10). Hence, the RDMAP part accounts for 38
     * bytes, to which we have to add the lower-level headers (ethernet, ip, udp, trp), for a
     * total size of 90 bytes.
     */

    struct rte_mbuf                *sendmsg = rte_pktmbuf_alloc(ep->tx_hdr_mempool);
    struct rdmap_terminate_packet  *new_rdmap;
    struct rdmap_terminate_payload *payload;

    new_rdmap = rte_pktmbuf_mtod_offset(sendmsg, struct rdmap_terminate_packet *, RDMAP_HDR_OFFSET);
    sendmsg->data_len = sizeof(struct rdmap_terminate_packet);

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

        payload = rte_pktmbuf_mtod_offset(sendmsg, struct rdmap_terminate_payload *,
                                          RDMAP_HDR_OFFSET + sizeof(struct rdmap_terminate_packet));
        sendmsg->data_len += sizeof(struct rdmap_terminate_payload);
        memcpy(&payload->payload, orig->rdmap, sizeof(struct rdmap_packet));
        break;
    case 0x0200:
    case 0x1200:
        /* Error caused by DDP or RDMAP untagged message other than
         * Read Request */
        if (orig) {
            new_rdmap->hdrct = rdmap_hdrct_m | rdmap_hdrct_d;

            payload =
                rte_pktmbuf_mtod_offset(sendmsg, struct rdmap_terminate_payload *,
                                        RDMAP_HDR_OFFSET + sizeof(struct rdmap_terminate_packet));
            sendmsg->data_len += sizeof(struct rdmap_terminate_payload);
            memcpy(&payload->payload, orig->rdmap, RDMAP_HDR_OFFSET + sizeof(struct rdmap_packet));
        } else {
            new_rdmap->hdrct = 0;
            payload          = NULL;
        }
        break;
    case 0x1000:
    case 0x1100:
        /* DDP layer error */
        new_rdmap->hdrct = rdmap_hdrct_m | rdmap_hdrct_d;

        payload = rte_pktmbuf_mtod_offset(sendmsg, struct rdmap_terminate_payload *,
                                          sizeof(struct rdmap_terminate_packet));
        sendmsg->data_len += sizeof(struct rdmap_terminate_payload);
        memcpy(&payload->payload, orig->rdmap, sizeof(struct rdmap_packet));
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

    // Add the length of the lower-level headers
    sendmsg->data_len += TRP_HDR_LEN + UDP_HDR_LEN + IP_HDR_LEN + RTE_ETHER_HDR_LEN;
    sendmsg->pkt_len = sendmsg->data_len;
    printf("Sending RDMAP terminate packet of size: %u\n", sendmsg->pkt_len);

    size_t total_size =
        (payload) ? sizeof(struct rdmap_terminate_packet) + sizeof(struct rdmap_terminate_payload)
                  : sizeof(struct rdmap_terminate_packet);
    (void)send_ddp_segment(ep, sendmsg, NULL, NULL, total_size);
} /* do_rdmap_terminate */
