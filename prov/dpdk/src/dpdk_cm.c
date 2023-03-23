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
        DPDK_WARN(FI_LOG_EP_CTRL, "Size of connection parameter(%lu) is greater than %d.\n",
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
    eth_parse("ff:ff:ff:ff:ff:ff", ep->remote_eth_addr.addr_bytes);
    ep->remote_ipv4_addr = rte_be_to_cpu_32(paddrin->sin_addr.s_addr);
    ep->remote_cm_udp_port  = rte_be_to_cpu_16(paddrin->sin_port);
    ep->remote_udp_port = 0; // this will be assigned later
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
    eth_parse("ff:ff:ff:ff:ff:ff",eth->dst_addr.addr_bytes);
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
    connreq->type       = rte_cpu_to_be_32(DPDK_CM_MSG_CONNECTION_REQUEST);
    connreq->session_id = rte_cpu_to_be_32(++domain->cm_session_counter);
    connreq->payload.connection_request.client_data_udp_port    = rte_cpu_to_be_16(ep->udp_port);
    connreq->payload.connection_request.paramlen                = rte_cpu_to_be_16(paramlen);
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

    pep = container_of(fid, struct dpdk_pep, util_pep.pep_fid);
    
    // here we use pep->info->src_addr
    if (*addrlen < pep->info->src_addrlen) {
        return -FI_ETOOSMALL;
    }

    memcpy(addr,pep->info->src_addr,pep->info->src_addrlen);
    *addrlen = pep->info->src_addrlen;

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
 * This function must only be called from a PMD thread. 
 */
int dpdk_cm_send(struct dpdk_domain* domain) {
    int ret = FI_SUCCESS;

    struct rte_mbuf* cm_mbuf;

    while (rte_ring_sc_dequeue(domain->cm_ring,(void**)&cm_mbuf) == 0) {
        while(rte_eth_tx_burst(domain->port_id,domain->queue_id,&cm_mbuf,1) < 1);
        rte_pktmbuf_free(cm_mbuf);
    }

    return ret;
}

struct dpdk_cm_entry {
    fid_t           fid;
    struct fi_info* info;
    uint8_t         data[DPDK_MAX_CM_DATA_SIZE];
} ;

/* processing connection request */
static int process_cm_connreq(struct dpdk_domain*       domain,
                              struct rte_ether_hdr*     eth_hdr,
                              struct rte_ipv4_hdr*      ip_hdr,
                              struct rte_udp_hdr*       udp_hdr,
                              struct dpdk_cm_msg_hdr*   cm_hdr,
                              void*                     cm_data) {
    int ret = FI_SUCCESS;
    struct dpdk_eq* eq = container_of(domain->util_domain.eq, struct dpdk_eq, util_eq);

    // 1 - validate request
    if (rte_be_to_cpu_32(cm_hdr->type) != DPDK_CM_MSG_CONNECTION_REQUEST) {
        DPDK_WARN(FI_LOG_EP_CTRL,"%s got invalid message type:%d, expecting CONNREQ(%d).",
                  __func__,rte_be_to_cpu_32(cm_hdr->type),DPDK_CM_MSG_CONNECTION_REQUEST);
        return -FI_EINVAL;
    }

    // 2 - create connection handle and then the fi_info object
    struct dpdk_conn_handle* handle = (struct dpdk_conn_handle*)calloc(1, sizeof(struct dpdk_conn_handle));
    handle->fid.fclass          = FI_CLASS_CONNREQ;
    handle->domain              = domain;
    handle->session_id          = rte_be_to_cpu_32(cm_hdr->session_id);
    handle->remote_ip_addr      = rte_be_to_cpu_32(ip_hdr->src_addr);
    handle->remote_ctrl_port    = rte_be_to_cpu_16(udp_hdr->src_port);
    handle->remote_data_port    = rte_be_to_cpu_16(cm_hdr->payload.connection_request.client_data_udp_port);

    struct fi_info* info = fi_dupinfo(domain->info);
    if (!info) {
        DPDK_WARN(FI_LOG_EP_CTRL,"%s failed to duplicate the fi_info object from domain.",__func__);
        ret = -FI_ENOMEM;
        goto err1;
    }

    // info->src_addr is irrelavent because fi_endpoint() does not need it.
    struct sockaddr_in *dest_addr   = (struct sockaddr_in*)calloc(1,sizeof(struct sockaddr));
    if (!dest_addr) {
        DPDK_WARN(FI_LOG_EP_CTRL,"%s failed to create destination address.",__func__);
        ret = -FI_ENOMEM;
        goto err2;
    }
    dest_addr->sin_family           = AF_INET;
    dest_addr->sin_port             = udp_hdr->src_port;    // remote data port
    dest_addr->sin_addr.s_addr      = ip_hdr->src_addr;     // remote ip address
    info->addr_format               = FI_SOCKADDR_IN;
    info->dest_addrlen              = sizeof(struct sockaddr);
    info->dest_addr                 = dest_addr;
    info->handle                    = &handle->fid;

    // 3 - insert an event to event queue
    struct dpdk_cm_entry    cm_entry;
    /* [Weijia]: Generally, cm_entry.fid should point to the passive endpoint. But in DPDK design,
     * we didn't track the pep point in the domain or fabric (the passive endpoint and domain is
     * 1-1 though). Therefore we leave it a null pointer.
     */
    cm_entry.fid    = NULL;
    cm_entry.info   = info;
    uint16_t paramlen = rte_be_to_cpu_16(cm_hdr->payload.connection_request.paramlen);
    if ( paramlen > DPDK_MAX_CM_DATA_SIZE) {
        DPDK_WARN(FI_LOG_EP_CTRL,"%s failed to create connreq event because the peer's user data size (%d)"
                                 "is too big. Truncated to %d bytes.", __func__, paramlen, DPDK_MAX_CM_DATA_SIZE);
        paramlen = DPDK_MAX_CM_DATA_SIZE;
    }
    memcpy(&cm_entry.data, cm_data, paramlen);
    ret = fi_eq_write(&eq->util_eq.eq_fid,FI_CONNREQ,(void*)&cm_entry,
                       sizeof(struct fi_eq_cm_entry) + paramlen, 0);
    if (ret < 0) {
        DPDK_WARN(FI_LOG_EP_CTRL,"%s failed to insert connreq event to event queue with error code: %d.",
                  __func__,ret);
        goto err3;
    }

    return FI_SUCCESS;
err3:
    free(dest_addr);
err2:
    fi_freeinfo(info);
err1:
    return ret;
}

/* processing connection request acknowledgement */
static int process_cm_connreq_ack(struct dpdk_domain*       domain,
                                  struct rte_ether_hdr*     eth_hdr,
                                  struct rte_ipv4_hdr*      ip_hdr,
                                  struct rte_udp_hdr*       udp_hdr,
                                  struct dpdk_cm_msg_hdr*   cm_hdr,
                                  void*                     cm_data) {
    //TODO:
    return -FI_EPERM;
}

/* processing connection request rejection */
static int process_cm_connreq_rej(struct dpdk_domain*       domain,
                                  struct rte_ether_hdr*     eth_hdr,
                                  struct rte_ipv4_hdr*      ip_hdr,
                                  struct rte_udp_hdr*       udp_hdr,
                                  struct dpdk_cm_msg_hdr*   cm_hdr,
                                  void*                     cm_data) {
    //TODO:
    return -FI_EPERM;
}

/* processing disconnection request */
static int process_cm_disconnect(struct dpdk_domain*       domain,
                                 struct rte_ether_hdr*     eth_hdr,
                                 struct rte_ipv4_hdr*      ip_hdr,
                                 struct rte_udp_hdr*       udp_hdr,
                                 struct dpdk_cm_msg_hdr*   cm_hdr,
                                 void*                     cm_data) {
    //TODO:
    return -FI_EPERM;
}

/* processing disconnection acknowledgement */
static int process_cm_disconnect_ack(struct dpdk_domain*       domain,
                                     struct rte_ether_hdr*     eth_hdr,
                                     struct rte_ipv4_hdr*      ip_hdr,
                                     struct rte_udp_hdr*       udp_hdr,
                                     struct dpdk_cm_msg_hdr*   cm_hdr,
                                     void*                     cm_data) {
    //TODO:
    return -FI_EPERM;
}

/**
 * This function must only be called from a PMD thread.
 */
int dpdk_cm_recv(struct dpdk_domain* domain, struct rte_mbuf* cm_mbuf) {
    int ret = FI_SUCCESS;

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
    void*                   cm_data = rte_pktmbuf_mtod_offset(cm_mbuf, void*,
                                                              RTE_ETHER_HDR_LEN + sizeof(struct rte_ipv4_hdr) +
                                                              sizeof(struct rte_udp_hdr) + 
                                                              sizeof(struct dpdk_cm_msg_hdr));

    DPDK_TRACE(FI_LOG_EP_CTRL,"Receiving CM Message with type:%d.", cm_hdr->type);

    switch (cm_hdr->type) {
    case DPDK_CM_MSG_CONNECTION_REQUEST:
        ret = process_cm_connreq(domain,eth_hdr,ip_hdr,udp_hdr,cm_hdr,cm_data);
        break;
    case DPDK_CM_MSG_CONNECTION_ACKNOWLEDGEMENT:
        ret = process_cm_connreq_ack(domain,eth_hdr,ip_hdr,udp_hdr,cm_hdr,cm_data);
        break;
    case DPDK_CM_MSG_CONNECTION_REJECTION:
        ret = process_cm_connreq_rej(domain,eth_hdr,ip_hdr,udp_hdr,cm_hdr,cm_data);
        break;
    case DPDK_CM_MSG_DISCONNECTION_REQUEST:
        ret = process_cm_disconnect(domain,eth_hdr,ip_hdr,udp_hdr,cm_hdr,cm_data);
        break;
    case DPDK_CM_MSG_DISCONNECTION_ACKNOWLEDGEMENT:
        ret = process_cm_disconnect_ack(domain,eth_hdr,ip_hdr,udp_hdr,cm_hdr,cm_data);
        break;
    default:
        DPDK_WARN(FI_LOG_EP_CTRL,"Skipping unknown type:%d.", cm_hdr->type);
        ret = FI_EINVAL;
    }

    return ret;
}
