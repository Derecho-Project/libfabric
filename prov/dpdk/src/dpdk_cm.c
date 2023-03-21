#include "fi_dpdk.h"
#include "protocols.h"

#include <ifaddrs.h>
#include <net/if.h>
#include <poll.h>
#include <sys/types.h>

#include <ofi_util.h>

static int dpdk_ep_getname(fid_t fid, void *addr, size_t *addrlen) {
    // TODO: return useful per-EP info
    printf("[dpdk_ep_connect] UNIMPLEMENTED\n");
    return 0;
}

static int dpdk_ep_connect(struct fid_ep *ep_fid, const void *addr, const void *param,
                           size_t paramlen) {
    int ret = FI_SUCCESS;

    // STEP 0 - validate the arguments
    if (paramlen > DPDK_MAX_CM_DATA_SIZE) {
        DPDK_WARN(FI_LOG_EP_CTRL, "Size of connection parameter(%d) is greater than %d.\n",
                  paramlen, DPDK_MAX_CM_DATA_SIZE);
        return -FI_EINVAL;
    }

    // STEP 1 - validate and setup the address 
    struct sockaddr* paddr = (struct sockaddr*) addr;
    switch (paddr->sa_family) {
    case AF_INET:
    case AF_INET6: // TODO: [Weijia] IPv6 support to be implemented.
    default:
        DPDK_WARN(FI_LOG_EP_CTRL, "Unsupported address family:%d. Only IPv4(%d) is currently supported.\n",
                  paddr->sa_family, AF_INET);
        return -FI_EINVAL;
    }
    struct sockaddr_in* paddrin = (struct sockaddr_in*) addr;

    // STEP 2 - local endpoint shifting to connecting state
    struct dpdk_ep *ep = container_of(ep_fid, struct dpdk_ep, util_ep.ep_fid);
    eth_parse("ff:ff:ff:ff:ff:ff", &ep->remote_eth_addr);
    ep->remote_ipv4_addr = rte_be_to_cpu32(paddrin->sin_addr.s_addr);
    ep->remote_udp_port = 0;
    atomic_store(&ep->conn_state, ep_conn_state_connecting);

    // STEP 3 - send connection request
    struct dpdk_domain* domain = container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);
    struct rte_mbuf* connreq_mbuf = rte_pktmbuf_alloc(domain->cm_pool);
    if (!connreq_mbuf) {
        ret = -FI_EIO;
        DPDK_WARN(FI_LOG_EP_CTRL, "Failed to allocate mbuf with rte_pktmbuf_alloc(): %s",
                  rte_strerror(rte_errno));
        goto error;
    }
    //// connreq_mbuf
    size_t                  ofst    = 0;
    struct rte_ether_hdr*   eth     = rte_pktmbuf_mtod_offset(connreq_mbuf,
                                                              struct rte_ether_hdr*,
                                                              ofst);
    ofst += sizeof(struct rte_ether_hdr);
    struct rte_ipv4_hdr*    ipv4    = rte_pktmbuf_mtod_offset(connreq_mbuf,
                                                              struct rte_ipv4_hdr*,
                                                              ofst);
    ofst += sizeof(struct rte_ipv4_hdr);
    struct rte_udp_hdr*     udp     = rte_pktmbuf_mtod_offset(connreq_mbuf, 
                                                              struct rte_udp_hdr*,
                                                              ofst);
    ofst += sizeof(struct rte_udp_hdr);
    struct dpdk_cm_msg_hdr* connreq = rte_pktmbuf_mtod_offset(connreq_mbuf,
                                                              struct dpdk_cm_msg_hdr*,
                                                              ofst);
    //// fill mbuf
    if (domain->dev_flags & port_checksum_offload) {
        connreq_mbuf->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM | RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
    }
    //// fill ether header
    rte_ether_addr_copy(&domain->eth_addr,&eth->src_addr);
    eth_parse("ff:ff:ff:ff:ff:ff",&eth->dst_addr);
    eth->ether_type = rte_cpu_to_be_16(ETHERNET_P_IP);
    //// fill ipv4 header in big endian
    ipv4->src_addr          = domain->local_addr.sin_addr.s_addr;
    ipv4->dst_addr          = paddrin->sin_addr.s_addr;
    ipv4->version           = IPV4;
    ipv4->ihl               = 0x5;
    ipv4->type_of_service   = 0;
    ipv4->total_length      = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) +
                                               sizeof(struct rte_udp_hdr) +
                                               sizeof(struct dpdk_cm_msg_hdr) +
                                               DPDK_MAX_CM_DATA_SIZE);
    ipv4->packet_id         = 0;
    ipv4->fragment_offset   = 0;
    ipv4->time_to_live      = 64;
    ipv4->next_proto_id     = IP_UDP;
    ipv4->hdr_checksum      = 0x0000;
    if (connreq_mbuf->ol_flags & RTE_MBUF_F_TX_IP_CKSUM) {
        ipv4->hdr_checksum = rte_ipv4_cksum(ipv4);
    }
    //// fill udp header
    udp->src_port       = domain->local_addr.sin_port;
    udp->dst_port       = paddrin->sin_port;
    udp->dgram_cksum    = 0;
    udp->dgram_len      = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr) +
                                           sizeof(struct dpdk_cm_msg_hdr) +
                                           DPDK_MAX_CM_DATA_SIZE);
    //// fill cm message
    connreq->type       = DPDK_CM_MSG_CONNECTION_REQUEST;
    connreq->session_id = ++ domain->cm_session_counter;
    connreq->payload.connection_request.client_data_udp_port    = ep->udp_port;
    connreq->payload.connection_request.paramlen                = paramlen;
    //// before sending
    connreq_mbuf->data_len  = RTE_ETHER_HDR_LEN + 
                              sizeof(struct rte_ipv4_hdr) +
                              sizeof(struct rte_udp_hdr) +
                              sizeof(struct dpdk_cm_msg_hdr) +
                              DPDK_MAX_CM_DATA_SIZE;
    connreq_mbuf->pkt_len   = connreq_mbuf->data_len;
    connreq_mbuf->l2_len    = RTE_ETHER_HDR_LEN;
    connreq_mbuf->l3_len    = sizeof(struct rte_ipv4_hdr);
    connreq_mbuf->l4_len    = sizeof(struct rte_udp_hdr);

    //// fill it to the ring
    if(rte_ring_enqueue(domain->cm_ring,connreq_mbuf)) {
        DPDK_WARN(FI_LOG_EP_CTRL, "CM ring is full. Please try again.\n");
        ret = -FI_EAGAIN;
        goto error;
    }

error:
    if (connreq_mbuf) {
        rte_pktmbuf_free(connreq_mbuf);
    }
    atomic_store(&ep->conn_state, ep_conn_state_unbound);
    return ret;
} /* dpdk_ep_connect */

static int dpdk_ep_accept(struct fid_ep *ep, const void *param, size_t paramlen) {

    printf("[dpdk_ep_accept] UNIMPLEMENTED\n");
    return 0;
}

struct fi_ops_cm dpdk_cm_ops = {
    .size     = sizeof(struct fi_ops_cm),
    .setname  = fi_no_setname,
    .getname  = dpdk_ep_getname,
    .getpeer  = fi_no_getpeer, // TODO: Provide an implementation!
    .connect  = dpdk_ep_connect,
    .listen   = fi_no_listen,
    .accept   = dpdk_ep_accept,
    .reject   = fi_no_reject,
    .shutdown = fi_no_shutdown, // TODO: Provide shutdown!
    .join     = fi_no_join,
};

/**
 * Note: this is a little messy: in the fi_setname() implementation in include/rdma/fi_cm.h, 
 * cm->setname() is called with fid pointing to a <struct fid_ep> object obtained using
 * container_of(fid, struct fid_ep, fid), where fid is of type <fid_t>, or a pointer to fid
 * object <struct fid>. Although the address is correct since the fid is always the first 
 * member of either fid_ep or fid_pep, such an implementation is ... messy. Here we follow
 * tcp provider's design by treating fid as a pointer to a <struct fid_pep> object. I hope
 * fi_cm(3) should fix this by enforce the meaning of fid preferably to be to a pointer to 
 * a <struct fid> object, which can be either a <struct fid_ep> or a <struct fid_pep> obj.
 */
static int dpdk_pep_setname(fid_t fid, void *addr, size_t addrlen) {

    struct dpdk_pep *pep;

    // TODO: although we allow IPv6 address here, dpdk provider's IPv6 support needs
    // to be validated elsewhere.
    if ((addrlen != sizeof(struct sockaddr_in)) &&
        (addrlen != sizeof(struct sockaddr_in6))) {
        return -FI_EINVAL;
    }

    pep = container_of(fid, struct dpdk_pep, util_pep.pep_fid);

    if (pep->info->src_addr) {
        free(pep->info->src_addr);
        pep->info->src_addrlen = 0;
    }

    pep->info->src_addr = mem_dup(addr, addrlen);
    if (!pep->info->src_addr) {
        return -FI_ENOMEM;
    }
    pep->info->src_addrlen = addrlen;

    return FI_SUCCESS;
}

/**
 * Similar to dpdk_pep_setname, the fid is again being treated as a pointer to a <struct fid_pep>
 * object, following the tcp provider design (xnet_pep_getname)
 */
static int dpdk_pep_getname(fid_t fid, void *addr, size_t *addrlen) {
    struct dpdk_pep    *pep;
    size_t addrlen_in = *addrlen;
    int    ret;

    pep = container_of(fid, struct dpdk_pep, util_pep.pep_fid);
    
    // here we use pep->info->src_addr
    if (*addrlen < pep->info->src_addrlen) {
        return -FI_ETOOSMALL;
    }

    memcpy(addr,pep->info->src_addr,pep->info->src_addrlen);

    return FI_SUCCESS;
}

static int dpdk_pep_listen(struct fid_pep *pep_fid) {

    printf("[dpdk_pep_listen] UNIMPLEMENTED\n");
    return 0;
}

static int dpdk_pep_reject(struct fid_pep *pep, fid_t fid_handle, const void *param,
                           size_t paramlen) {
    printf("[dpdk_pep_reject] UNIMPLEMENTED\n");
    return 0;
}

struct fi_ops_cm dpdk_pep_cm_ops = {
    .size     = sizeof(struct fi_ops_cm),
    .setname  = dpdk_pep_setname,
    .getname  = dpdk_pep_getname,
    .getpeer  = fi_no_getpeer,
    .connect  = fi_no_connect,
    .listen   = dpdk_pep_listen,
    .accept   = fi_no_accept,
    .reject   = dpdk_pep_reject,
    .shutdown = fi_no_shutdown,
    .join     = fi_no_join,
};

// ====== Internals ======
/**
 * This function must only be called from the dpdk_run_progress function from the domain PMD thread.
 */
int dpdk_cm_send(struct dpdk_domain* domain) {
    int ret = FI_SUCCESS;

    struct rte_mbuf* cm_mbuf;

    while (rte_ring_sc_dequeue(domain->cm_ring,&cm_mbuf) == 0) {
        while(rte_eth_tx_burst(domain->port_id,domain->queue_id,&cm_mbuf,1) < 1);
        rte_pktmbuf_free(cm_mbuf);
    }

    return ret;
}

/**
 Parse CM buf
        struct rte_ether_hdr*   eth_hdr = rte_pktmbuf_mtod_offset(cm_mbuf,
                                                                  struct rte_ether_hdr*,
                                                                  0);
        struct rte_ipv4_hdr*    ip_hdr  = rte_pktmbuf_mtod_offset(cm_mbuf,
                                                                  struct rte_ipv4_hdr*,
                                                                  RTE_ETHER_HDR_LEN);
        struct rte_udp_hdr*     udp_hdr = rte_pktmbuf_mtod_offset(cm_mbuf,
                                                                  struct rte_udp_hdr*,
                                                                  RTE_ETHER_HDR_LEN + sizeof(struct rte_ipv4_hdr));
        struct dpdk_cm_msg_hdr* cm_hdr  = rte_pktmbuf_mtod_offset(cm_mbuf,
                                                                  struct dpdk_cm_msg_hdr*,
                                                                  RTE_ETHER_HDR_LEN + sizeof(struct rte_ipv4_hdr) +
                                                                  sizeof(struct rte_udp_hdr));
        switch (cm_hdr->type) {
        case DPDK_CM_MSG
        }
 **/
