#include "protocols.h"

//======================== HELPER FUNCTIONS ========================//
void free_extbuf_cb(void *addr, void *opaque) {
    return;
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

/* Checks if an mbuf crosses page boundary */
static inline int mbuf_crosses_page_boundary(struct rte_mbuf *m, size_t pg_sz) {
    uint64_t start = (uint64_t)m->buf_addr + m->data_off;
    uint64_t end   = start + m->data_len;
    return (start / pg_sz) != ((end - 1) / pg_sz);
}

static inline int set_iova_mapping(struct rte_mbuf *sendmsg, size_t page_size) {
    int ret = 0;
    // Get the mbuf pointing to external memory: the last of the chain.
    // IOVA mapping of DPDK-managed memory is already set by DPDK
    struct rte_mbuf *ext_mbuf = rte_pktmbuf_lastseg(sendmsg);
    if (!RTE_MBUF_HAS_EXTBUF(ext_mbuf)) {
        return ret;
    }

    // Set the IOVA mapping for the external memory.
    void *start_address = ext_mbuf->buf_addr + ext_mbuf->data_off;
    // The IOVA of the memseg is the IOVA of the start of the segment. Hence we need to add to that
    // value the offset between the segment start and the desired address.
    struct rte_memseg *ms =
        rte_mem_virt2memseg(start_address, rte_mem_virt2memseg_list(start_address));
    ext_mbuf->buf_iova = ms->iova + (start_address - ms->addr);
    // ext_mbuf->buf_iova = rte_mem_virt2iova(start_address);

    // If IOVA as PA, the mbuf may span two pages that correspond to two different
    // physical addresses. In this case, we need to split in two parts the mbuf containing the
    // user data (as it is allocated on external memory).
    if (rte_eal_iova_mode() != RTE_IOVA_VA) {
        // Reset the data offset: it causes errors in the driver with IOVA
        // TODO: Maybe this can be avoided by implementing the IP fragmentation
        // manually (copy from the original DPDK version).
        ext_mbuf->buf_addr = start_address;
        ext_mbuf->data_off = 0;

        // If mbuf crosses a page boundary, split it in two parts, one per page
        if (mbuf_crosses_page_boundary(ext_mbuf, page_size)) {

            FI_DBG(&dpdk_prov, FI_LOG_EP_DATA, "%s():%i: splitting mbuf crossing page boundary\n",
                   __func__, __LINE__);
            // 1. Get page boundary starting from last_mbuf->buf_addr (+ data_off)
            uint64_t start         = (uint64_t)start_address;
            uint64_t end           = start + ext_mbuf->data_len;
            uint64_t page_boundary = ((start / page_size) + 1) * page_size;

            // 3. Compute the length of the ext_mbuf and the second mbuf
            uint64_t second_len = end - page_boundary;

            // 4. Allocate a new mbuf for the second part
            struct rte_mbuf *second_mbuf = rte_pktmbuf_alloc(ext_mbuf->pool);
            if (!second_mbuf) {
                FI_WARN(&dpdk_prov, FI_LOG_EP_DATA, "%s():%i: Failed to allocate mbuf\n", __func__,
                        __LINE__);
                return rte_errno;
            }

            // 5. Attach the second mbuf to the external memory in the second page, with the correct
            // IOVA.
            ms = rte_mem_virt2memseg(page_boundary, rte_mem_virt2memseg_list(page_boundary));
            rte_iova_t second_iova = ms->iova + ((void *)page_boundary - ms->addr);
            // rte_iova_t second_iova = rte_mem_virt2iova(page_boundary);

            struct rte_mbuf_ext_shared_info *ret_shinfo =
                (struct rte_mbuf_ext_shared_info *)(second_mbuf + 1);
            rte_pktmbuf_ext_shinfo_init_helper_custom(ret_shinfo, free_extbuf_cb, NULL);
            rte_pktmbuf_attach_extbuf(second_mbuf, (void *)page_boundary, second_iova, second_len,
                                      ret_shinfo);
            second_mbuf->data_len = second_len;
            second_mbuf->data_off = 0;

            // 6. Chain this mbuf to the last one
            ext_mbuf->next = second_mbuf;
            ext_mbuf->data_len -= second_len;

            // 7. Increase the nsegs of the overall chain
            sendmsg->nb_segs++;
        }
    }
    return ret;
}

//======================== PROTOCOL-RELATED FUNCTIONS ========================//
/* Ethernet */
/* Prepends an Ethernet header to the frame and enqueues it on the given port.
 * It performs fragmentation if sendmsg is greater than the Ethernet MTU.
 * The ether_type should be in host byte order. */
void enqueue_ether_frame(struct rte_mbuf *sendmsg, unsigned int ether_type, struct dpdk_ep *ep,
                         struct rte_ether_addr *dst_addr) {

    struct dpdk_domain *domain = container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);
    assert(domain->res);
    // TODO: retrieve this from the domain!
    size_t pg_sz = sysconf(_SC_PAGESIZE);

    struct rte_ether_hdr *eth =
        rte_pktmbuf_mtod_offset(sendmsg, struct rte_ether_hdr *, ETHERNET_HDR_OFFSET);

    rte_ether_addr_copy(dst_addr, &eth->dst_addr);
    rte_ether_addr_copy(&domain->res->local_eth_addr, &eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(ether_type);
    sendmsg->l2_len = RTE_ETHER_HDR_LEN;

    // Now, if necessary, fragment the packet
    if (sendmsg->pkt_len > (domain->res->mtu + RTE_ETHER_HDR_LEN)) {
        /* Mbufs for the fragmentation */
        struct rte_mbuf *pkts_out[MAX_FRAG_NUM];
        int              used_mbufs = 0;

        rte_pktmbuf_adj(sendmsg, RTE_ETHER_HDR_LEN);
        if ((used_mbufs = rte_ipv4_fragment_packet(sendmsg, (struct rte_mbuf **)pkts_out,
                                                   MAX_FRAG_NUM, domain->res->mtu,
                                                   ep->tx_hdr_mempool, ep->tx_ddp_mempool)) < 0)
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
            rte_ether_addr_copy(&domain->res->local_eth_addr, &hdr_frag->src_addr);
            hdr_frag->ether_type = rte_cpu_to_be_16(ether_type);
            m->l2_len            = sizeof(*hdr_frag);

            // Set IOVA mapping for the fragment
            set_iova_mapping(m, pg_sz);

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
        // Set IOVA mapping
        set_iova_mapping(sendmsg, pg_sz);

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

/* ARP */
// Cache entries
static struct dlist_entry s_arp_cache = {.next = &s_arp_cache, .prev = &s_arp_cache};
// Broadcast Ethernet address in bytes
static uint8_t broadcast_hw[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

uint8_t *arp_get_hwaddr(uint32_t saddr) {
    struct dlist_entry *item;
    arp_cache_entry_t  *entry;

    dlist_foreach_container(&s_arp_cache, arp_cache_entry_t, entry, list) {
        if (entry->state == ARP_RESOLVED && entry->sip == saddr) {
            uint8_t *copy = entry->src_mac;
            return copy;
        }
    }

    return NULL;
}

uint8_t *arp_get_hwaddr_or_lookup(struct dpdk_domain_resources *domain_res, uint32_t saddr) {
    uint8_t *dst_mac = arp_get_hwaddr(saddr);
    if (dst_mac == NULL) {
        DPDK_INFO(FI_LOG_EP_CTRL,
                  "Failed to get dst MAC address from cache. Sending ARP request.\n");

        sleep(3);

        if ((arp_request(domain_res, domain_res->local_cm_addr.sin_addr.s_addr, saddr)) < 0) {
            DPDK_WARN(FI_LOG_EP_CTRL, "Failed to send ARP request\n");
            return NULL;
        }

        // TODO: Not ideal: but is there a better solution?
        while (!dst_mac) {
            usleep(100);
            dst_mac = arp_get_hwaddr(saddr);
        }
    }
    return dst_mac;
}

static int32_t _arp_update_translation_table(arp_hdr_t *hdr) {
    struct dlist_entry *item;
    arp_cache_entry_t  *entry;

    dlist_foreach_container(&s_arp_cache, arp_cache_entry_t, entry, list) {

        if (entry->hwtype == hdr->arp_htype && entry->sip == hdr->arp_data.arp_sip) {
            memcpy(entry->src_mac, hdr->arp_data.arp_sha, RTE_ETHER_ADDR_LEN);

            return ARP_TRASL_TABLE_UPDATE_OK;
        }
    }

    return ARP_TRASL_TABLE_UPDATE_NO_ENTRY;
}

static arp_cache_entry_t *__arp_cache_entry__alloc(arp_hdr_t *hdr) {
    arp_cache_entry_t *entry = (arp_cache_entry_t *)malloc(sizeof(arp_cache_entry_t));

    entry->state  = ARP_RESOLVED;
    entry->hwtype = hdr->arp_htype;
    entry->sip    = hdr->arp_data.arp_sip;
    memcpy(entry->src_mac, hdr->arp_data.arp_sha, RTE_ETHER_ADDR_LEN);

    dlist_init(&entry->list);
    return entry;
}

static int32_t _arp_insert_translation_table(arp_hdr_t *hdr) {
    arp_cache_entry_t *entry = __arp_cache_entry__alloc(hdr);
    dlist_insert_tail(&entry->list, &s_arp_cache);
    DPDK_DBG(FI_LOG_EP_CTRL, "ARP: Inserted new entry in ARP translation table\n");
    return ARP_TRASL_TABLE_INSERT_OK;
}

static void _do_arp_reply(struct dpdk_domain_resources *domain_res, arp_ipv4_t *req_data) {

    struct rte_mbuf *rte_mbuf = rte_pktmbuf_alloc(domain_res->cm_pool);

    // 1. Ethernet Header
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(rte_mbuf, struct rte_ether_hdr *);
    memcpy(&eth_hdr->src_addr, &domain_res->local_eth_addr, RTE_ETHER_ADDR_LEN);
    memcpy(&eth_hdr->dst_addr, req_data->arp_sha, RTE_ETHER_ADDR_LEN);
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHERNET_P_ARP);

    // 2. ARP Data
    arp_hdr_t  *arp_hdr = (arp_hdr_t *)(eth_hdr + 1);
    arp_ipv4_t *data    = (arp_ipv4_t *)(&arp_hdr->arp_data);
    memcpy(data->arp_tha, req_data->arp_sha, RTE_ETHER_ADDR_LEN);
    memcpy(data->arp_sha, &domain_res->local_eth_addr, RTE_ETHER_ADDR_LEN);

    data->arp_tip = req_data->arp_sip;
    data->arp_sip = domain_res->local_cm_addr.sin_addr.s_addr;

    arp_hdr->arp_opcode = rte_cpu_to_be_16(ARP_REPLY);
    arp_hdr->arp_htype  = rte_cpu_to_be_16(ARP_ETHERNET);
    arp_hdr->arp_hlen   = RTE_ETHER_ADDR_LEN;
    arp_hdr->arp_ptype  = rte_cpu_to_be_16(ETHERNET_P_IP);
    arp_hdr->arp_plen   = 4;

    rte_mbuf->next     = NULL;
    rte_mbuf->nb_segs  = 1;
    rte_mbuf->pkt_len  = sizeof(arp_hdr_t) + RTE_ETHER_HDR_LEN;
    rte_mbuf->data_len = rte_mbuf->pkt_len;

    // 3. Append the fragment to the transmission queue of the control DP
    rte_ring_enqueue(domain_res->cm_tx_ring, rte_mbuf);
}

void arp_receive(struct dpdk_domain_resources *domain_res, struct rte_mbuf *arp_mbuf) {
    arp_hdr_t *ahdr = rte_pktmbuf_mtod_offset(arp_mbuf, arp_hdr_t *, RTE_ETHER_HDR_LEN);

    if (domain_res->local_cm_addr.sin_addr.s_addr != ahdr->arp_data.arp_tip) {
        DPDK_DBG(FI_LOG_EP_CTRL, "ARP: was not for us - %d is not %d\n",
                 domain_res->local_cm_addr.sin_addr.s_addr, ahdr->arp_data.arp_tip);
        return;
    }

    uint32_t merge = _arp_update_translation_table(ahdr);
    if (merge == ARP_TRASL_TABLE_UPDATE_NO_ENTRY &&
        _arp_insert_translation_table(ahdr) == ARP_TRASL_TABLE_INSERT_FAILED)
    {
        DPDK_DBG(FI_LOG_EP_CTRL, "No free space in ARP translation table\n");
        return;
    }

    uint16_t opcode = rte_be_to_cpu_16(ahdr->arp_opcode);
    switch (opcode) {
    case ARP_REQUEST:
        DPDK_DBG(FI_LOG_EP_CTRL, "ARP: Seding reply\n");
        _do_arp_reply(domain_res, &ahdr->arp_data);
        break;
    case ARP_REPLY:
        DPDK_DBG(FI_LOG_EP_CTRL, "ARP: Received reply\n");
        break;
    default:
        DPDK_WARN(FI_LOG_EP_CTRL, "ARP: Opcode not supported: %04x!\n", opcode);
        break;
    }

    // TODO: Here we could notify the EP, but we should loop on the EP of the domain
    // So we could just let the EP poll on the HW cache
    // if (ep->remote_ipv4_addr == ahdr->arp_data.arp_sip) {
    //     DPDK_INFO(FI_LOG_EP_CTRL, "dst_dev ARP_REPLY\n");
    //     memcpy(&ep->remote_eth_addr, ahdr->arp_data.arp_sha, RTE_ETHER_ADDR_LEN);
    // }
}

int32_t arp_request(struct dpdk_domain_resources *domain_res, uint32_t saddr, uint32_t daddr) {
    DPDK_INFO(FI_LOG_EP_CTRL, "ARP Request\n");

    // 0. Allocate an mbuf
    struct rte_mbuf *rte_mbuf = rte_pktmbuf_alloc(domain_res->cm_pool);
    if (!rte_mbuf) {
        DPDK_WARN(FI_LOG_EP_CTRL, "Failed to allocate mbuf from pool %s: %s\n",
                  domain_res->cm_pool->name, rte_strerror(rte_errno));
        return -rte_errno;
    }

    // 1. Ethernet Header
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(rte_mbuf, struct rte_ether_hdr *);
    memcpy(&eth_hdr->src_addr, &domain_res->local_eth_addr, RTE_ETHER_ADDR_LEN);
    memcpy(&eth_hdr->dst_addr, broadcast_hw, RTE_ETHER_ADDR_LEN);
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHERNET_P_ARP);

    // 2. ARP data
    arp_hdr_t  *ahdr  = (arp_hdr_t *)(eth_hdr + 1);
    arp_ipv4_t *adata = (arp_ipv4_t *)(&ahdr->arp_data);

    memcpy(adata->arp_sha, &domain_res->local_eth_addr, RTE_ETHER_ADDR_LEN);
    memcpy(adata->arp_tha, broadcast_hw, RTE_ETHER_ADDR_LEN);
    adata->arp_sip = saddr;
    adata->arp_tip = daddr;

    ahdr->arp_opcode = rte_cpu_to_be_16(ARP_REQUEST);
    ahdr->arp_htype  = rte_cpu_to_be_16(ARP_ETHERNET);
    ahdr->arp_ptype  = rte_cpu_to_be_16(ETHERNET_P_IP);
    ahdr->arp_hlen   = RTE_ETHER_ADDR_LEN;
    ahdr->arp_plen   = 4;

    // 3. Append the fragment to the transmission queue of the control DP
    rte_mbuf->next    = NULL;
    rte_mbuf->nb_segs = 1;
    rte_mbuf->pkt_len = rte_mbuf->data_len = RTE_ETHER_HDR_LEN + sizeof(arp_hdr_t);
    return rte_ring_enqueue(domain_res->cm_tx_ring, rte_mbuf);
}

/* IPv4 */
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

// Reassemble IP packet from fragments. Assumes the ethertype is IPV4.
struct rte_mbuf *reassemble(struct rte_mbuf *m, struct lcore_queue_conf *qconf, uint16_t vlan_id,
                            uint64_t tms) {
    uint16_t ether_type = 0;

    // Ethernet and IP headers
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr  *ip_hdr;

    struct rte_ip_frag_tbl       *tbl;
    struct rte_ip_frag_death_row *dr;
    struct rx_queue              *rxq;

    eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    ip_hdr  = (struct rte_ipv4_hdr *)(eth_hdr + 1);
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
                                        RTE_MBUF_DEFAULT_DATAROOM + RTE_PKTMBUF_HEADROOM, socket);
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
    assert(domain->res);

    if (domain->dev_flags & port_checksum_offload) {
        sendmsg->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM | RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
    }

    udp = prepend_udp_header(sendmsg, ep->udp_port, ep->remote_udp_port, ddp_length);
    ip  = prepend_ipv4_header(sendmsg, IP_UDP,
                              rte_be_to_cpu_32(domain->res->local_cm_addr.sin_addr.s_addr),
                              ep->remote_ipv4_addr, ddp_length + UDP_HDR_LEN);

    if (!(sendmsg->ol_flags & RTE_MBUF_F_TX_UDP_CKSUM)) {
        // TODO: There appears to be an error with this computation of UDP checsum.
        // For now, leaving it to 0.
        udp->dgram_cksum = 0;
        // raw_cksum += udp->dgram_cksum + udp->src_port + udp->dst_port + udp->dgram_len;
        // /* Add any carry bits into the checksum. */
        // while (raw_cksum > UINT16_MAX) {
        //     raw_cksum = (raw_cksum >> 16) + (raw_cksum & 0xffff);
        // }
        // udp->dgram_cksum = (raw_cksum == UINT16_MAX) ? UINT16_MAX : ~raw_cksum;
    }

    enqueue_ether_frame(sendmsg, RTE_ETHER_TYPE_IPV4, ep, &ep->remote_eth_addr);

} /* send_udp_dgram */

/* TRP */
void send_trp_ack(struct dpdk_ep *ep) {
    struct dpdk_domain *domain = container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);
    assert(domain->res);
    struct ee_state *ee = &ep->remote_ep;
    struct rte_mbuf *sendmsg;
    struct trp_hdr  *trp;

    assert(!(ee->trp_flags & trp_recv_missing));
    sendmsg = rte_pktmbuf_alloc(ep->tx_hdr_mempool);

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
    info->next_retransmit = rte_get_timer_cycles() + rte_get_timer_hz() * 10; // / 1000;
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

    // TODO: this is wrong. This must be only the actual payload size
    // while now payload lenght includes also the headers and I have no
    // way now to know the actual payload size
    pending->ddp_length = payload_length;

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
            struct rte_mbuf_ext_shared_info *ret_shinfo =
                (struct rte_mbuf_ext_shared_info *)(payload_mbuf + 1);
            rte_pktmbuf_ext_shinfo_init_helper_custom(ret_shinfo, free_extbuf_cb, NULL);
            // Attach the memory buffer to the mbuf
            // We do not set the iova here. We will do that later, in the network stack
            rte_pktmbuf_attach_extbuf(payload_mbuf, data, 0, cur, ret_shinfo);
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
        FI_DBG(&dpdk_prov, FI_LOG_EP_DATA, "<ep=%u> SEND transmit msn=%" PRIu32 " [%zu-%zu]\n",
               ep->udp_port, wqe->msn, wqe->bytes_sent, wqe->bytes_sent + payload_length);

        wqe->bytes_sent += payload_length;
    }

    if (wqe->bytes_sent == wqe->total_length) {
        wqe->state = SEND_XFER_WAIT;
    }
} /* do_rdmap_send */

void do_rdmap_write(struct dpdk_ep *ep, struct dpdk_xfer_entry *wqe) {
    struct rdmap_tagged_packet *new_rdmap;
    struct rte_mbuf            *sendmsg;
    size_t                      payload_length, header_length;

    uint16_t mtu = 1440; // MAX_RDMAP_PAYLOAD_SIZE;

    if (wqe->state != SEND_XFER_TRANSFER) {
        return;
    }

    while (wqe->bytes_sent < wqe->total_length &&
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
        header_length = RTE_ETHER_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + TRP_HDR_LEN +
                        sizeof(struct rdmap_tagged_packet);
        sendmsg->data_len += header_length;
        sendmsg->pkt_len += header_length;

        payload_length = RTE_MIN(mtu, wqe->total_length - wqe->bytes_sent);
        new_rdmap =
            rte_pktmbuf_mtod_offset(sendmsg, struct rdmap_tagged_packet *, RDMAP_HDR_OFFSET);
        new_rdmap->head.ddp_flags =
            (wqe->total_length - wqe->bytes_sent <= mtu) ? DDP_V1_TAGGED_LAST_DF : DDP_V1_TAGGED_DF;

        if (wqe->opcode == xfer_write_with_imm) {
            new_rdmap->head.rdmap_info = rdmap_opcode_rdma_write_with_imm | RDMAP_V1;
            new_rdmap->head.immediate  = wqe->imm_data;
        } else {
            new_rdmap->head.rdmap_info = rdmap_opcode_rdma_write | RDMAP_V1;
            new_rdmap->head.immediate  = 0;
        }
        // TODO: We are currently only supporting a SINGLE IO for the write operation.
        // In the short-term, this should be checked earlier. In the long term, we should
        // support multiple IOs
        new_rdmap->head.sink_stag = rte_cpu_to_be_32((uint32_t)wqe->rma_iov[0].key);
        new_rdmap->offset         = rte_cpu_to_be_64(wqe->rma_iov[0].addr + wqe->bytes_sent);

        // Copy inline data, which are small
        if (payload_length > 0) {
            // TODO: Do we support inline data?
            // if (wqe->flags & usiw_send_inline) {
            //     payload = rte_pktmbuf_append(sendmsg, payload_length);
            //     memcpy(payload, (char *)wqe->iov + wqe->bytes_sent, payload_length);
            // } else {

            // This is zero-copy send. But what about small sizes?
            // We could enable a mechanism that if total_size is <threshold, we copy the data
            put_iov_in_chain(ep->tx_ddp_mempool, sendmsg, payload_length, wqe->iov, wqe->iov_count,
                             wqe->bytes_sent);
        }

        FI_DBG(&dpdk_prov, FI_LOG_EP_DATA, "Write of size %d\n", payload_length);
        send_ddp_segment(ep, sendmsg, NULL, wqe,
                         sizeof(struct rdmap_tagged_packet) + payload_length);

        wqe->bytes_sent += payload_length;
    }

    if (wqe->bytes_sent == wqe->total_length) {
        wqe->state = SEND_XFER_WAIT;
    }
} /* do_rdmap_write */

void do_rdmap_read_request(struct dpdk_ep *ep, struct dpdk_xfer_entry *wqe) {
    struct rdmap_readreq_packet *new_rdmap;
    struct rte_mbuf             *sendmsg;
    unsigned int                 packet_length, header_length;

    if (wqe->state != SEND_XFER_TRANSFER) {
        return;
    }

    if (ep->ord_active >= dpdk_max_ord) {
        /* Cannot issue more than ord_max simultaneous RDMA READ
         * Requests. */
        return;
    } else if (wqe->remote_ep->send_next_psn == wqe->remote_ep->send_max_psn ||
               serial_greater_32(wqe->remote_ep->send_next_psn, wqe->remote_ep->send_max_psn))
    {
        /* We have reached the maximum number of credits we are allowed
         * to send. */
        return;
    }
    ep->ord_active++;

    sendmsg = rte_pktmbuf_alloc(ep->tx_hdr_mempool);
    if (!sendmsg) {
        // TODO: Should we create an "error" state?
        wqe->state = SEND_XFER_COMPLETE;
        FI_DBG(&dpdk_prov, FI_LOG_EP_DATA, "Failed to allocate mbuf from pool %s\n",
               ep->tx_hdr_mempool->name);
        return;
    }

    // Header len. Add now the LEN of the packet. Now, because from now on, all the functions
    // will be potentially executed more than once in case of retransmission
    header_length = RTE_ETHER_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + TRP_HDR_LEN +
                    sizeof(struct rdmap_readreq_packet);
    sendmsg->data_len += header_length;
    sendmsg->pkt_len += header_length;

    // This is a header only, as it is a read request
    new_rdmap = rte_pktmbuf_mtod_offset(sendmsg, struct rdmap_readreq_packet *, RDMAP_HDR_OFFSET);
    packet_length = sizeof(*new_rdmap);
    sendmsg->data_len += packet_length;
    sendmsg->pkt_len += packet_length;

    if (!new_rdmap) {
        // TODO: Should we create an "error" state?
        wqe->state = SEND_XFER_COMPLETE;
        FI_DBG(&dpdk_prov, FI_LOG_EP_DATA, "Failed to append RDMAP header to empty mbuf %s\n",
               ep->tx_hdr_mempool->name);
        return;
    }

    new_rdmap->untagged.head.ddp_flags  = DDP_V1_UNTAGGED_LAST_DF;
    new_rdmap->untagged.head.rdmap_info = rdmap_opcode_rdma_read_request | RDMAP_V1;
    new_rdmap->untagged.head.sink_stag  = rte_cpu_to_be_32(wqe->local_stag);
    new_rdmap->untagged.qn              = rte_cpu_to_be_32(1);
    new_rdmap->untagged.msn             = rte_cpu_to_be_32(wqe->msn);
    new_rdmap->untagged.mo              = rte_cpu_to_be_32(0);
    new_rdmap->sink_offset              = rte_cpu_to_be_64((uintptr_t)wqe->iov[0].iov_base);
    new_rdmap->read_msg_size            = rte_cpu_to_be_32(wqe->iov[0].iov_len);
    // TODO: We are currently only supporting a SINGLE IO for the write operation.
    // In the short-term, this should be checked earlier. In the long term, we should
    // support multiple IOs
    new_rdmap->source_stag   = rte_cpu_to_be_64(wqe->rma_iov[0].key);
    new_rdmap->source_offset = rte_cpu_to_be_64(wqe->rma_iov[0].addr);

    send_ddp_segment(ep, sendmsg, NULL, wqe, sizeof(struct rdmap_readreq_packet) + packet_length);
    FI_DBG(&dpdk_prov, FI_LOG_EP_DATA, "<ep=%u> RDMA READ transmit msn=%u\n", ep->udp_port,
           wqe->msn);

    wqe->state = SEND_XFER_WAIT;
} /* do_rdmap_read_request */

int do_rdmap_read_response(struct dpdk_ep *ep, struct read_atomic_response_state *readresp) {
    struct rdmap_tagged_packet *new_rdmap;
    struct rte_mbuf            *sendmsg;
    size_t                      dgram_length;
    size_t                      payload_length, header_length;
    int                         count = 0;

    // Todo: see comment in ddp_place_tagged_data
    uint16_t mtu = 1440; // MAX_RDMAP_PAYLOAD_SIZE;

    while (readresp->read.msg_size > 0 &&
           serial_less_32(readresp->sink_ep->send_next_psn, readresp->sink_ep->send_max_psn))
    {
        sendmsg = rte_pktmbuf_alloc(ep->tx_hdr_mempool);
        if (!sendmsg) {
            RTE_LOG(ERR, USER1, "Failed to allocate mbuf from pool %s\n", ep->tx_hdr_mempool->name);
            return;
        }

        // Header len. Add now the LEN of the packet. Now, because from now on, all the functions
        // will be potentially executed more than once in case of retransmission
        // TODO: Dos this make sense? In case of re-transmission to re-traverse the whole stack?
        header_length = RTE_ETHER_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + TRP_HDR_LEN +
                        sizeof(struct rdmap_tagged_packet);
        sendmsg->data_len += header_length;
        sendmsg->pkt_len += header_length;

        // Fill the header
        new_rdmap =
            rte_pktmbuf_mtod_offset(sendmsg, struct rdmap_tagged_packet *, RDMAP_HDR_OFFSET);
        new_rdmap->head.ddp_flags =
            (readresp->read.msg_size <= mtu) ? DDP_V1_TAGGED_LAST_DF : DDP_V1_TAGGED_DF;
        new_rdmap->head.rdmap_info = RDMAP_V1 | rdmap_opcode_rdma_read_response;
        new_rdmap->head.sink_stag  = readresp->sink_stag;
        new_rdmap->offset          = rte_cpu_to_be_64(readresp->read.sink_offset);

        // Compute the payload
        payload_length = RTE_MIN(mtu, readresp->read.msg_size);
        if (payload_length > 0) {
            // memcpy(PAYLOAD_OF(new_rdmap), readresp->vaddr, payload_length);
            struct iovec iov = {
                .iov_base = readresp->vaddr,
                .iov_len  = payload_length,
            };
            // This is zero-copy send. But what about small sizes?
            // We could enable a mechanism that if total_size is <threshold, we copy the data
            // Attach the header buffer to the mbuf(s) that describe the payload
            put_iov_in_chain(ep->tx_ddp_mempool, sendmsg, payload_length, &iov, 1, 0);
        }

        send_ddp_segment(ep, sendmsg, readresp, NULL,
                         sizeof(struct rdmap_tagged_packet) + payload_length);
        readresp->vaddr += payload_length;
        readresp->read.msg_size -= payload_length;
        readresp->read.sink_offset += payload_length;
        count++;
    }

    if (readresp->read.msg_size == 0) {
        /* Signal that this is done */
        readresp->active = false;
        ep->readresp_head_msn++;
    }

    return count;
} /* respond_rdma_read */

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
    DPDK_WARN(FI_LOG_EP_DATA, "Sending RDMAP terminate packet of size: %u\n", sendmsg->pkt_len);

    size_t total_size =
        (payload) ? sizeof(struct rdmap_terminate_packet) + sizeof(struct rdmap_terminate_payload)
                  : sizeof(struct rdmap_terminate_packet);
    (void)send_ddp_segment(ep, sendmsg, NULL, NULL, total_size);
} /* do_rdmap_terminate */
