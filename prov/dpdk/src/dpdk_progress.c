#include "fi_dpdk.h"
#include "protocols.h"

// ================ Helper functions =================
extern void free_extbuf_cb(void *addr, void *opaque);

/* Fill a memory area with Ethernet, IP, and UDP headers */
static void prepare_headers(struct rte_mbuf *hdr_mbuf, int payload_size) {
    uint32_t src_addr;
    uint32_t dst_addr;

    /* Ethernet */
    struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(hdr_mbuf, struct rte_ether_hdr *);
    eth_parse("00:00:00:00:00:00", (unsigned char *)&ehdr->src_addr);
    eth_parse("ff:ff:ff:ff:ff:ff", (unsigned char *)&ehdr->dst_addr);
    ehdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    /* IP */
    struct rte_ipv4_hdr *ih = (struct rte_ipv4_hdr *)(ehdr + 1);
    ip_parse("10.0.0.211", &src_addr);
    ip_parse("10.0.0.212", &dst_addr);
    ih->version         = IPV4;
    ih->ihl             = 0x05;
    ih->type_of_service = 0;
    ih->total_length    = payload_size + IP_HEADER_LEN + UDP_HEADER_LEN;
    ih->packet_id       = ih->packet_id;
    ih->fragment_offset = 0x0000;
    ih->time_to_live    = 64;
    ih->next_proto_id   = IP_UDP;
    ih->hdr_checksum    = 0x0000;

    ih->src_addr     = ntohl(src_addr);
    ih->dst_addr     = ntohl(dst_addr);
    ih->total_length = htons(ih->total_length);
    ih->packet_id    = htons(ih->packet_id);
    ih->dst_addr     = htonl(ih->dst_addr);
    ih->src_addr     = htonl(ih->src_addr);
    ih->hdr_checksum = ip_checksum(ih, ih->ihl * 4);

    /* UDP */
    struct rte_udp_hdr *uh = (struct rte_udp_hdr *)(ih + 1);
    uh->dst_port           = htons(UDP_PORT);
    uh->src_port           = htons(UDP_PORT);
    uh->dgram_len          = htons(sizeof(struct rte_udp_hdr) + payload_size);
    uh->dgram_cksum        = 0;

    hdr_mbuf->data_len = RTE_ETHER_HDR_LEN + IP_HEADER_LEN + UDP_HEADER_LEN;
    hdr_mbuf->pkt_len  = hdr_mbuf->data_len;
}

static void tx_ep(struct dpdk_ep *ep, struct slist *tx_list) {

    struct dpdk_domain *domain = container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);
    struct dpdk_xfer_entry *entry;
    size_t                  count = 0;

    size_t           pkts_out_len = 32;
    struct rte_mbuf *pkts_out[pkts_out_len];

    // For each message: userspace protocol stack
    // TODO: this is a vey basic implementation, simplest case only
    // Does not take IOVA, UDP and lower-level fragmentation into account
    struct rte_mbuf *packet_mbuf, *header_mbuf;
    while (!slist_empty(tx_list)) {
        slist_remove_head_container(tx_list, struct dpdk_xfer_entry, entry, entry);
        if (entry->msg_data_len <= 0) {
            continue;
        }
        packet_mbuf           = (struct rte_mbuf *)entry->msg_data;
        uint64_t payload_size = packet_mbuf->data_len;

        // Prepare an header
        header_mbuf = rte_pktmbuf_alloc(ep->hdr_pool);
        prepare_headers(header_mbuf, payload_size);
        rte_pktmbuf_chain(header_mbuf, packet_mbuf);

        // printf("Prepared a packet of total length of %d bytes\n", header_mbuf->pkt_len);

        pkts_out[count] = header_mbuf;
        count++;
    }

    // Send packets
    int ret = rte_eth_tx_burst(domain->port_id, 0, pkts_out, count);
    if (ret < count) {
        FI_WARN(&dpdk_prov, FI_LOG_DOMAIN, "Could not send all packets");
    }
}

static void rx_ep(struct dpdk_ep *ep, struct slist *rx_list) {
    struct dpdk_domain *domain = container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);
    struct dpdk_xfer_entry *entry;

    size_t           pkts_in_len = 8;
    struct rte_mbuf *pkts_in[pkts_in_len];

    // Receive packets
    int ret = rte_eth_rx_burst(domain->port_id, 0, pkts_in, pkts_in_len);
    if (unlikely(ret < 0)) {
        FI_WARN(&dpdk_prov, FI_LOG_DOMAIN, "Could not receive packets: %s",
                rte_strerror(rte_errno));
        return;
    } else if (unlikely(ret == 0)) {
        return;
    }

    for (int i = 0; i < ret; i++) {
        struct rte_mbuf *mbuf = pkts_in[i];

        // Protocol processing
        // Get pointer to the content, that will start with an Ethernet header
        struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
        // Go on by sizeof(struct rte_ether_hdr) to get the IP header
        struct rte_ipv4_hdr *ip_hdp = (struct rte_ipv4_hdr *)(eth_hdr + 1);
        // Go on by sizeof(struct rte_ipv4_hdr) to get the UDP header
        struct rte_udp_hdr *udp_hdp = (struct rte_udp_hdr *)(ip_hdp + 1);

        // Check whether this packet is for us
        if (ntohs(udp_hdp->dst_port) == UDP_PORT) {
            // This is a packet for us, move the pointer to the payload
            // so the application can retrieve it easily
            rte_pktmbuf_adj(mbuf, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
                                      sizeof(struct rte_udp_hdr));
        } else {
            // Free the buffer
            rte_pktmbuf_free(mbuf);
            continue;
        }

        // Create an entry for the received packet
        // TODO: This would become unnecessary with rte_rings!
        // Just append the mbuf to the rx_list and go, lockless!
        entry = ofi_buf_alloc(domain->progress.xfer_pool);
        if (!entry) {
            FI_WARN(&dpdk_prov, FI_LOG_DOMAIN, "Could not allocate xfer entry. Discarding packet");
            continue;
        }
        entry->context  = 0;
        entry->cq_flags = 0;
        entry->cq       = container_of(ep->util_ep.tx_cq, struct dpdk_cq, util_cq);
        entry->cntr     = ep->util_ep.tx_cntr;

        entry->msg_data     = (void *)mbuf;
        entry->msg_data_len = sizeof(struct rte_mbuf *);

        slist_insert_tail(&entry->entry, rx_list);
    }
}

struct progress_arg {
    struct dpdk_progress *progress;
    bool                  clear_signal;
};

// ================ Progress functions =================
/* This function initializes the progress */
int dpdk_init_progress(struct dpdk_progress *progress, struct fi_info *info) {
    int ret;

    // TODO: this should become a parameter in some way
    progress->lcore_id      = 1;
    progress->stop_progress = 0;
    progress->fid.fclass    = DPDK_CLASS_PROGRESS;
    slist_init(&progress->event_list);

    // Mutex to access EP list
    ret = ofi_genlock_init(&progress->lock, OFI_LOCK_MUTEX);
    if (ret) {
        goto err;
    }

    ret = ofi_bufpool_create(&progress->xfer_pool, sizeof(struct dpdk_xfer_entry) + dpdk_max_inject,
                             16, 0, 1024, 0);
    if (ret) {
        goto err;
    }

    return 0;

err:
    ofi_bufpool_destroy(progress->xfer_pool);
    return ret;
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

// This is the main DPDK loop => one polling thread per device (= per domain)
int dpdk_run_progress(void *arg) {

    struct progress_arg *arguments = (struct progress_arg *)arg;

    struct dpdk_progress *progress     = arguments->progress;
    bool                  clear_signal = arguments->clear_signal;

    struct dpdk_domain *domain = container_of(progress, struct dpdk_domain, progress);
    struct slist_entry *cur, *prev, *rx_head;
    struct dpdk_ep     *ep;
    struct slist_entry *entry_cur;

    struct slist tx_list, rx_list;
    slist_init(&tx_list);
    slist_init(&rx_list);

    while (!progress->stop_progress) {

        // TODO: Careful! Nested locks: no good...
        // External mutex to guarantee no conflict with insertion of new EPs
        // Internal mutex to guarantee no conflict on RX/TX queues of each EP
        ofi_genlock_lock(&domain->ep_mutex);
        slist_foreach(&domain->endpoint_list, cur, prev) {
            ep = container_of(cur, struct dpdk_ep, endpoint_list);

            // Swap the tx queue of this endpoint with a local copy
            // and leave the tx empty
            ofi_genlock_lock(&ep->tx_mutex);
            slist_swap(&tx_list, &ep->tx_queue);
            ofi_genlock_unlock(&ep->tx_mutex);

            // Now I have a copy of the tx list of this endpoint
            tx_ep(ep, &tx_list);

            // Of course this is WRONG because here I receive anything, not only
            // the packets for this EP. The rx must be outside this loop and use
            // a table (port, ep) to dispatch the packets to the right EP.
            // Receive
            rx_ep(ep, &rx_list);

            // Append the rx list to the endpoint rx queue
            ofi_genlock_lock(&ep->rx_mutex);
            slist_splice_tail(&ep->rx_queue, &rx_list);
            ofi_genlock_unlock(&ep->rx_mutex);
        }
        ofi_genlock_unlock(&domain->ep_mutex);
    }

    void dpdk_close_progress(struct dpdk_progress * progress) {
        printf("dpdk_close_progress: UNIMPLEMENTED\n");
    }
}