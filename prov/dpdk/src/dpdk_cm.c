#include "fi_dpdk.h"
#include "protocols.h"

#include <ifaddrs.h>
#include <net/if.h>
#include <poll.h>
#include <sys/types.h>

#include <ofi_util.h>

/*
 * internal data structures
 */
struct dpdk_cm_entry {
    fid_t           fid;
    struct fi_info *info;
    uint8_t         data[DPDK_MAX_CM_DATA_SIZE];
};

static int dpdk_ep_getname(fid_t fid, void *addr, size_t *addrlen) {
    int ret = FI_SUCCESS;
    switch (fid->fclass) {
    case FI_CLASS_EP: {
        struct dpdk_ep     *ep = container_of(fid, struct dpdk_ep, util_ep.ep_fid);
        struct dpdk_domain *domain =
            container_of(ep->util_ep.domain, struct dpdk_domain, util_domain.domain_fid);
        // TODO: IPv6 support needs special care.
        if (*addrlen < domain->info->src_addrlen) {
            DPDK_WARN(FI_LOG_EP_CTRL,
                      "%s failed because address buffer len(%lu) is smaller than the endpoint "
                      "address size(%lu).",
                      __func__, *addrlen, domain->info->src_addrlen);
            ret      = -FI_ETOOSMALL;
            *addrlen = domain->info->src_addrlen;
            goto error_group_1;
        }
        memcpy(addr, domain->info->src_addr, domain->info->src_addrlen);
        struct sockaddr_in *paddrin = (struct sockaddr_in *)addr;
        paddrin->sin_port           = rte_cpu_to_be_16(ep->udp_port);
        *addrlen                    = domain->info->src_addrlen;
    } break;
    case FI_CLASS_PEP: {
        struct dpdk_pep *pep = container_of(fid, struct dpdk_pep, util_pep.pep_fid);
        // TODO: IPv6 support needs special care.
        if (*addrlen < pep->info->src_addrlen) {
            DPDK_WARN(FI_LOG_EP_CTRL,
                      "%s failed because address buffer len(%lu) is smaller than the pep "
                      "address size(%lu).",
                      __func__, *addrlen, pep->info->src_addrlen);
            ret = -FI_EINVAL;
            goto error_group_1;
        }
        memcpy(addr, pep->info->src_addr, pep->info->src_addrlen);
        *addrlen = pep->info->src_addrlen;
    } break;
    default:
        DPDK_WARN(FI_LOG_EP_CTRL, "%s see invalid fid type:%lu, expecting EP(%d) or PEP(%d).",
                  __func__, fid->fclass, FI_CLASS_EP, FI_CLASS_PEP);
        ret = -FI_ENODATA;
        goto error_group_1;
    }
    return FI_SUCCESS;
error_group_1: // nothing changed.
    return ret;
}

static int dpdk_ep_getpeer(struct fid_ep *ep, void *addr, size_t *addrlen) {
    int                ret      = FI_SUCCESS;
    struct dpdk_ep    *dep      = container_of(ep, struct dpdk_ep, util_ep.ep_fid);
    enum ep_conn_state ep_state = atomic_load(&dep->conn_state);
    switch (ep_state) {
    case ep_conn_state_connected:
        // TODO:IPv6 support needs special care.
        if (*addrlen < sizeof(struct sockaddr_in)) {
            DPDK_WARN(FI_LOG_EP_CTRL,
                      "%s failed because address buffer len(%lu) is smaller than the pep "
                      "address size(%lu).",
                      __func__, *addrlen, sizeof(struct sockaddr_in));
            ret = -FI_EINVAL;
            goto error_group_1;
        }
        struct sockaddr_in *paddrin = (struct sockaddr_in *)addr;
        paddrin->sin_family         = AF_INET;
        paddrin->sin_port           = rte_cpu_to_be_16(dep->remote_udp_port);
        paddrin->sin_addr.s_addr    = rte_cpu_to_be_32(dep->remote_ipv4_addr);
        *addrlen                    = sizeof(struct sockaddr_in);
        break;
    case ep_conn_state_unbound:
    case ep_conn_state_connecting:
    case ep_conn_state_shutdown:
    case ep_conn_state_error:
    default:
        DPDK_WARN(FI_LOG_EP_CTRL, "%s cannot retrieve peer info in %d state.", __func__, ep_state);
        ret = -FI_ENODATA;
        goto error_group_1;
    }
    return FI_SUCCESS;
error_group_1: // nothing changed.
    return ret;
}

/*
 * Create a connection manager message buffer.
 * @param domain            DPDK domain
 * @param remote_ip_addr    The remote connection manager ip address in cpu order
 * @param remote_cm_port    The remote connection manager control udp port in cpu order
 * @param out_cm_mbuf       The output parameter
 *
 * @return FI_SUCCESS or error code.
 */
#define get_cm_header(m)                                                                           \
    rte_pktmbuf_mtod_offset(m, struct dpdk_cm_msg_hdr *,                                           \
                            sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +           \
                                sizeof(struct rte_udp_hdr))

static int create_cm_mbuf(struct dpdk_domain_resources *res, uint32_t remote_ip_addr,
                          uint16_t remote_cm_port, struct rte_mbuf **out_cm_mbuf) {
    int              ret     = FI_SUCCESS;
    struct rte_mbuf *cm_mbuf = rte_pktmbuf_alloc(res->cm_pool);
    if (!cm_mbuf) {
        ret = -FI_EIO;
        DPDK_WARN(FI_LOG_EP_CTRL, "Failed to allocate mbuf with rte_pktmbuf_alloc(): %s",
                  rte_strerror(rte_errno));
        goto error_group_1;
    }
    size_t                ofst = 0;
    struct rte_ether_hdr *eth  = rte_pktmbuf_mtod_offset(cm_mbuf, struct rte_ether_hdr *, ofst);
    ofst += sizeof(struct rte_ether_hdr);
    struct rte_ipv4_hdr *ipv4 = rte_pktmbuf_mtod_offset(cm_mbuf, struct rte_ipv4_hdr *, ofst);
    ofst += sizeof(struct rte_ipv4_hdr);
    struct rte_udp_hdr *udp = rte_pktmbuf_mtod_offset(cm_mbuf, struct rte_udp_hdr *, ofst);
    //// fill mbuf
    if (res->domain->dev_flags & port_checksum_offload) {
        cm_mbuf->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM | RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
    }
    //// fill ether header
    rte_ether_addr_copy(&res->local_eth_addr, &eth->src_addr);
    uint8_t *dst_mac = arp_get_hwaddr(remote_ip_addr);
    while (dst_mac == NULL) {
        DPDK_WARN(FI_LOG_EP_CTRL,
                  "Failed to get dst MAC address from cache. Sending ARP request.\n");
        arp_request(res->domain, res->local_cm_addr.sin_addr.s_addr, remote_ip_addr);
        usleep(100); // TODO: Not ideal: but is there a better solution?
        dst_mac = arp_get_hwaddr(remote_ip_addr);
    }
    rte_ether_addr_copy(dst_mac, &eth->dst_addr.addr_bytes);
    eth->ether_type = rte_cpu_to_be_16(ETHERNET_P_IP);
    //// fill ipv4 header in big endian
    ipv4->src_addr        = res->local_cm_addr.sin_addr.s_addr;
    ipv4->dst_addr        = rte_cpu_to_be_32(remote_ip_addr);
    ipv4->version         = IPV4;
    ipv4->ihl             = 0x5;
    ipv4->type_of_service = 0;
    ipv4->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) +
                                          sizeof(struct dpdk_cm_msg_hdr) + DPDK_MAX_CM_DATA_SIZE);
    ipv4->packet_id    = 0;
    ipv4->fragment_offset = 0;
    ipv4->time_to_live    = 64;
    ipv4->next_proto_id   = IP_UDP;
    ipv4->hdr_checksum    = 0x0000;
    if (cm_mbuf->ol_flags & RTE_MBUF_F_TX_IP_CKSUM) {
        ipv4->hdr_checksum = rte_ipv4_cksum(ipv4);
    }
    //// fill udp header
    udp->src_port    = res->local_cm_addr.sin_port;
    udp->dst_port    = rte_cpu_to_be_16(remote_cm_port);
    udp->dgram_cksum = 0;
    udp->dgram_len = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr) + sizeof(struct dpdk_cm_msg_hdr) +
                                      DPDK_MAX_CM_DATA_SIZE);
    //// before sending
    cm_mbuf->data_len = RTE_ETHER_HDR_LEN + sizeof(struct rte_ipv4_hdr) +
                        sizeof(struct rte_udp_hdr) + sizeof(struct dpdk_cm_msg_hdr) +
                        DPDK_MAX_CM_DATA_SIZE;
    cm_mbuf->pkt_len = cm_mbuf->data_len;
    cm_mbuf->l2_len  = RTE_ETHER_HDR_LEN;
    cm_mbuf->l3_len  = sizeof(struct rte_ipv4_hdr);
    cm_mbuf->l4_len  = sizeof(struct rte_udp_hdr);

    *out_cm_mbuf = cm_mbuf;
    return FI_SUCCESS;
error_group_1:
    *out_cm_mbuf = NULL;
    return ret;
} /* create_cm_buf */

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
    struct sockaddr *paddr = (struct sockaddr *)addr;
    switch (paddr->sa_family) {
    case AF_INET:
        break;
    case AF_INET6: // TODO: [Weijia] IPv6 support to be implemented.
    default:
        DPDK_WARN(FI_LOG_EP_CTRL,
                  "Unsupported address family:%d. Only IPv4(%d) is currently supported.\n",
                  paddr->sa_family, AF_INET);
        return -FI_EINVAL;
    }
    struct sockaddr_in *paddrin = (struct sockaddr_in *)addr;

    // STEP 2 - local endpoint shifting to connecting state
    struct dpdk_ep     *ep     = container_of(ep_fid, struct dpdk_ep, util_ep.ep_fid);
    struct dpdk_domain *domain = container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);
    assert(domain->res);
    eth_parse("ff:ff:ff:ff:ff:ff", ep->remote_eth_addr.addr_bytes);
    ep->remote_ipv4_addr   = rte_be_to_cpu_32(paddrin->sin_addr.s_addr);
    ep->remote_cm_udp_port = rte_be_to_cpu_16(paddrin->sin_port);
    ep->remote_udp_port    = 0; // this will be assigned later
    atomic_store(&ep->conn_state, ep_conn_state_connecting);
    atomic_store(&ep->session_id, ++domain->res->cm_session_counter);

    // STEP 2.5 - Get the dst MAC address from the ARP cache
    uint8_t *dst_mac = arp_get_hwaddr(paddrin->sin_addr.s_addr);
    if (dst_mac == NULL) {
        DPDK_INFO(FI_LOG_EP_CTRL,
                  "Failed to get dst MAC address from cache. Sending ARP request.\n");
        ret = arp_request(domain, domain->res->local_cm_addr.sin_addr.s_addr,
                          paddrin->sin_addr.s_addr);
        if (ret < 0) {
            DPDK_WARN(FI_LOG_EP_CTRL, "Failed to send ARP request: %s\n", rte_strerror(-ret));
            goto error;
        }

        // TODO: Not ideal: but is there a better solution?
        while (!dst_mac) {
            usleep(100);
            dst_mac = arp_get_hwaddr(paddrin->sin_addr.s_addr);
        }
    }
    memcpy(ep->remote_eth_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

    // STEP 3 - send connection request
    struct rte_mbuf *connreq_mbuf;
    ret = create_cm_mbuf(domain->res, ep->remote_ipv4_addr, ep->remote_cm_udp_port, &connreq_mbuf);
    if (ret) {
        goto error;
    }
    //// fill cm message
    struct dpdk_cm_msg_hdr *connreq = get_cm_header(connreq_mbuf);
    connreq->type                   = rte_cpu_to_be_32(DPDK_CM_MSG_CONNECTION_REQUEST);
    connreq->session_id             = rte_cpu_to_be_32(ep->session_id);
    connreq->typed_header.connection_request.client_data_udp_port = rte_cpu_to_be_16(ep->udp_port);
    connreq->typed_header.connection_request.paramlen             = rte_cpu_to_be_16(paramlen);
    memcpy(connreq->payload, param, paramlen);
    //// fill it to the ring
    DPDK_DBG(FI_LOG_EP_CTRL, "adding connreq to cm ring.\n");
    if (rte_ring_mp_enqueue(domain->res->cm_tx_ring, connreq_mbuf)) {
        DPDK_WARN(FI_LOG_EP_CTRL, "CM ring is full. Please try again.\n");
        ret = -FI_EAGAIN;
        goto error;
    }
    DPDK_DBG(FI_LOG_EP_CTRL, "connreq msg added to cm ring.\n");

    return FI_SUCCESS;

error:
    if (connreq_mbuf) {
        rte_pktmbuf_free(connreq_mbuf);
    }
    atomic_store(&ep->conn_state, ep_conn_state_unbound);
    return ret;
} /* dpdk_ep_connect */

static int dpdk_ep_accept(struct fid_ep *ep, const void *param, size_t paramlen) {
    int                      ret         = FI_SUCCESS;
    struct dpdk_ep          *dep         = container_of(ep, struct dpdk_ep, util_ep.ep_fid);
    struct dpdk_conn_handle *conn_handle = NULL;

    // 0 - validate the arguments
    if (paramlen > DPDK_MAX_CM_DATA_SIZE) {
        ret = -FI_EINVAL;
        DPDK_WARN(FI_LOG_EP_CTRL, "Size of connection parameter(%lu) is greater than %d.\n",
                  paramlen, DPDK_MAX_CM_DATA_SIZE);
        goto error_group_1;
    }

    // 1 - test if ep is ready for fi_accept()
    if (dep->conn_state != ep_conn_state_connecting) {
        ret = -FI_EINVAL;
        DPDK_WARN(FI_LOG_EP_CTRL, "%p failed because of invalid endpoint state(%u). Expecting %d.",
                  __func__, dep->conn_state, ep_conn_state_connecting);
        goto error_group_1;
    }
    if (!dep->conn_handle) {
        ret = -FI_EINVAL;
        DPDK_WARN(FI_LOG_EP_CTRL, "%p failed because of the absence of a connection handle.",
                  __func__);
        goto error_group_1;
    }
    if (dep->conn_handle->fclass != FI_CLASS_CONNREQ) {
        ret = -FI_EINVAL;
        DPDK_WARN(FI_LOG_EP_CTRL,
                  "%p failed because of unexpected connection handle class (%lu). Excepting %d.",
                  __func__, dep->conn_handle->fclass, FI_CLASS_CONNREQ);
        goto error_group_1;
    }

    // 2 - set up endpoint for connection ready.
    conn_handle = container_of(dep->conn_handle, struct dpdk_conn_handle, fid);
    eth_parse("ff:ff:ff:ff:ff:ff", dep->remote_eth_addr.addr_bytes);
    dep->remote_ipv4_addr   = conn_handle->remote_ip_addr;
    dep->remote_cm_udp_port = conn_handle->remote_ctrl_port;
    dep->remote_udp_port    = conn_handle->remote_data_port;

    // 2.5 - Get the dst MAC address from the ARP cache
    uint8_t *dst_mac = arp_get_hwaddr(dep->remote_ipv4_addr);
    while (dst_mac == NULL) {
        DPDK_WARN(FI_LOG_EP_CTRL,
                  "Failed to get dst MAC address from cache. Sending ARP request.\n");
        arp_request(conn_handle->res->domain, conn_handle->res->local_cm_addr.sin_addr.s_addr,
                    dep->remote_ipv4_addr);
        usleep(100); // TODO: Not ideal: but is there a better solution?
        dst_mac = arp_get_hwaddr(dep->remote_ipv4_addr);
    }
    memcpy(dep->remote_eth_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

    // 3 - set endpoint to connected state
    atomic_store(&dep->conn_state, ep_conn_state_connected);

    // 4 - generate a FI_CONNECTED event locally, and
    struct dpdk_cm_entry cm_entry;
    cm_entry.fid  = &ep->fid;
    cm_entry.info = NULL;
    memcpy(&cm_entry.data, param, paramlen);
    struct dpdk_eq *eq = container_of(dep->util_ep.eq, struct dpdk_eq, util_eq);
    ret                = fi_eq_write(&eq->util_eq.eq_fid, FI_CONNECTED, (void *)&cm_entry,
                                     sizeof(struct fi_eq_cm_entry) + paramlen, 0);
    if (ret < 0) {
        DPDK_WARN(FI_LOG_EP_CTRL,
                  "%s failed to insert connreq event to event queue with error code: %d.", __func__,
                  ret);
        goto error_group_1;
    }

    // 5 - notify the peer node with CONNECTED
    struct rte_mbuf    *connack_mbuf = NULL;
    struct dpdk_domain *domain = container_of(dep->util_ep.domain, struct dpdk_domain, util_domain);
    assert(domain->res);
    ret = create_cm_mbuf(domain->res, conn_handle->remote_ip_addr, conn_handle->remote_ctrl_port,
                         &connack_mbuf);
    if (ret) {
        goto error_group_1;
    }
    //// fill cm message
    struct dpdk_cm_msg_hdr *connack = get_cm_header(connack_mbuf);
    connack->type                   = rte_cpu_to_be_32(DPDK_CM_MSG_CONNECTION_ACKNOWLEDGEMENT);
    connack->session_id             = rte_cpu_to_be_32(conn_handle->session_id);
    connack->typed_header.connection_acknowledgement.client_data_udp_port =
        rte_cpu_to_be_16(dep->remote_udp_port);
    connack->typed_header.connection_acknowledgement.server_data_udp_port =
        rte_cpu_to_be_16(dep->udp_port);
    connack->typed_header.connection_acknowledgement.paramlen = rte_cpu_to_be_16(paramlen);
    memcpy(connack->payload, param, paramlen);
    //// fill it to the ring
    DPDK_DBG(FI_LOG_EP_CTRL, "adding connack to cm ring.\n");
    if (rte_ring_mp_enqueue(domain->res->cm_tx_ring, connack_mbuf)) {
        DPDK_WARN(FI_LOG_EP_CTRL, "CM ring is full. Please try again.\n");
        ret = -FI_EAGAIN;
        goto error_group_1;
    }
    DPDK_DBG(FI_LOG_EP_CTRL, "connack msg added to cm ring.\n");

    return FI_SUCCESS;
    // error handling
error_group_1:
    return ret;
} /* dpdk_ep_accept */

static int dpdk_pep_reject(struct fid_pep *pep, fid_t handle, const void *param, size_t paramlen) {
    int ret = FI_SUCCESS;
    // 0 - validate the arguments
    if (!pep) {
        ret = -FI_EINVAL;
        DPDK_WARN(FI_LOG_EP_CTRL, "%s: passive endpoint is invalid.\n", __func__);
        goto error_group_1;
    }
    if (!handle) {
        ret = -FI_EINVAL;
        DPDK_WARN(FI_LOG_EP_CTRL, "%s: connection handle is invalid.\n", __func__);
        goto error_group_1;
    }
    if (paramlen > DPDK_MAX_CM_DATA_SIZE) {
        ret = -FI_EINVAL;
        DPDK_WARN(FI_LOG_EP_CTRL, "Size of connection parameter(%lu) is greater than %d.\n",
                  paramlen, DPDK_MAX_CM_DATA_SIZE);
        goto error_group_1;
    }

    // 1 - notify the peer node with rejection
    struct rte_mbuf         *connrej_mbuf = NULL;
    struct dpdk_conn_handle *conn_handle  = container_of(handle, struct dpdk_conn_handle, fid);
    ret = create_cm_mbuf(conn_handle->res, conn_handle->remote_ip_addr,
                         conn_handle->remote_ctrl_port, &connrej_mbuf);
    if (ret) {
        goto error_group_1;
    }
    //// fill cm message
    struct dpdk_cm_msg_hdr *connrej = get_cm_header(connrej_mbuf);
    connrej->type                   = rte_cpu_to_be_32(DPDK_CM_MSG_CONNECTION_REJECTION);
    connrej->session_id             = rte_cpu_to_be_32(conn_handle->session_id);
    connrej->typed_header.connection_rejection.client_data_udp_port =
        rte_cpu_to_be_16(conn_handle->remote_data_port);
    connrej->typed_header.connection_rejection.paramlen = rte_cpu_to_be_16(paramlen);
    memcpy(connrej->payload, param, paramlen);
    //// fill it to the ring
    DPDK_DBG(FI_LOG_EP_CTRL, "adding connrej to cm ring.\n");
    if (rte_ring_mp_enqueue(conn_handle->res->cm_tx_ring, connrej_mbuf)) {
        DPDK_WARN(FI_LOG_EP_CTRL, "CM ring is full. Please try again.\n");
        ret = -FI_EAGAIN;
        goto error_group_1;
    }
    DPDK_DBG(FI_LOG_EP_CTRL, "connrej msg added to cm ring.\n");
    return FI_SUCCESS;
error_group_1:
    return ret;
} /* dpdk_ep_reject */

static int dpdk_ep_shutdown(struct fid_ep *ep, uint64_t flags) {
    int                 ret    = FI_SUCCESS;
    struct dpdk_ep     *dep    = container_of(ep, struct dpdk_ep, util_ep.ep_fid);
    struct dpdk_domain *domain = container_of(dep->util_ep.domain, struct dpdk_domain, util_domain);
    assert(domain->res);
    struct rte_mbuf *disconnreq_mbuf = NULL;
    // 0 - handle shutdown for states
    switch (dep->conn_state) {
    case ep_conn_state_connected:
        // send a DPDK_CM_MSG_DISCONNECTION_REQUEST message to peer.
        {
            ret = create_cm_mbuf(domain->res, dep->remote_ipv4_addr, dep->remote_cm_udp_port,
                                 &disconnreq_mbuf);
            if (ret) {
                goto error_group_1;
            }
            atomic_store(&dep->session_id, ++domain->res->cm_session_counter);
            struct dpdk_cm_msg_hdr *disconnreq = get_cm_header(disconnreq_mbuf);
            disconnreq->type       = rte_cpu_to_be_32(DPDK_CM_MSG_DISCONNECTION_REQUEST);
            disconnreq->session_id = rte_cpu_to_be_32(dep->session_id);
            disconnreq->typed_header.disconnection_request.local_data_udp_port =
                rte_cpu_to_be_16(dep->udp_port);
            disconnreq->typed_header.disconnection_request.remote_data_udp_port =
                rte_cpu_to_be_16(dep->remote_udp_port);
            //// fill it to the ring
            DPDK_DBG(FI_LOG_EP_CTRL, "adding disconnreq to cm ring.\n");
            if (rte_ring_mp_enqueue(domain->res->cm_tx_ring, disconnreq_mbuf)) {
                DPDK_WARN(FI_LOG_EP_CTRL, "CM ring is full. Please try again.\n");
                ret = -FI_EAGAIN;
                goto error_group_2;
            }
            DPDK_DBG(FI_LOG_EP_CTRL, "disconnreq msg added to cm ring.\n");
            //// then, change to shutdown state
            atomic_store(&dep->conn_state, ep_conn_state_shutdown);
        }
        break;
    case ep_conn_state_unbound:
    case ep_conn_state_connecting:
        /* TODO:
         * Shutting down an endpoint in ep_conn_state_connecting state needs more care.
         * Currently, we assume the peer relies on the data path failure handling.
         */
        atomic_store(&dep->conn_state, ep_conn_state_shutdown);
        break;
    case ep_conn_state_shutdown:
    case ep_conn_state_error:
    default:
        // nothing to do.
        break;
    }
    return FI_SUCCESS;
error_group_2: // disconnreq_mbuf may need to be freed.
    if (disconnreq_mbuf) {
        rte_pktmbuf_free(disconnreq_mbuf);
    }
error_group_1: // nothing changed
    return ret;
} /* dpdk_ep_shutdown */

struct fi_ops_cm dpdk_cm_ops = {
    .size     = sizeof(struct fi_ops_cm),
    .setname  = fi_no_setname,
    .getname  = dpdk_ep_getname,
    .getpeer  = dpdk_ep_getpeer,
    .connect  = dpdk_ep_connect,
    .listen   = fi_no_listen,
    .accept   = dpdk_ep_accept,
    .reject   = fi_no_reject,
    .shutdown = dpdk_ep_shutdown,
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
    if ((addrlen != sizeof(struct sockaddr_in)) && (addrlen != sizeof(struct sockaddr_in6))) {
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
    struct dpdk_pep *pep;

    pep = container_of(fid, struct dpdk_pep, util_pep.pep_fid);

    // here we use pep->info->src_addr
    if (*addrlen < pep->info->src_addrlen) {
        *addrlen = pep->info->src_addrlen;
        return -FI_ETOOSMALL;
    }

    memcpy(addr, pep->info->src_addr, pep->info->src_addrlen);
    *addrlen = pep->info->src_addrlen;

    return FI_SUCCESS;
}

static int dpdk_pep_listen(struct fid_pep *pep_fid) {
    // change the state
    struct dpdk_pep *pep = container_of(pep_fid, struct dpdk_pep, util_pep.pep_fid);
    pep->state           = DPDK_PEP_LISTENING;
    return FI_SUCCESS;
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
/* processing connection request */
static int process_cm_connreq(struct dpdk_domain_resources *res, struct rte_ether_hdr *eth_hdr,
                              struct rte_ipv4_hdr *ip_hdr, struct rte_udp_hdr *udp_hdr,
                              struct dpdk_cm_msg_hdr *cm_hdr, void *cm_data) {
    int ret = FI_SUCCESS;

    assert(res);
    ofi_mutex_lock(&res->pep_lock);
    // skip when passive endpoint does not exist or is not active.
    if (!res->pep || (res->pep->state != DPDK_PEP_LISTENING)) {
        DPDK_WARN(FI_LOG_EP_CTRL,
                  "Received CONNREQ message without active passive endpoint on domain:%s.\n",
                  res->domain_name);
        ofi_mutex_unlock(&res->pep_lock);
        return ret;
    }
    // handle connection request.
    struct dpdk_eq *eq = container_of(res->pep->util_pep.eq, struct dpdk_eq, util_eq);

    // 1 - validate request
    if (rte_be_to_cpu_32(cm_hdr->type) != DPDK_CM_MSG_CONNECTION_REQUEST) {
        DPDK_WARN(FI_LOG_EP_CTRL, "%s got invalid message type:%d, expecting CONNREQ(%d).",
                  __func__, rte_be_to_cpu_32(cm_hdr->type), DPDK_CM_MSG_CONNECTION_REQUEST);
        ret = -FI_EINVAL;
        goto error_group_1;
    }

    // 2 - create connection handle and then the fi_info object
    struct dpdk_conn_handle *handle =
        (struct dpdk_conn_handle *)calloc(1, sizeof(struct dpdk_conn_handle));
    handle->fid.fclass       = FI_CLASS_CONNREQ;
    handle->res              = res;
    handle->session_id       = rte_be_to_cpu_32(cm_hdr->session_id);
    handle->remote_ip_addr   = rte_be_to_cpu_32(ip_hdr->src_addr);
    handle->remote_ctrl_port = rte_be_to_cpu_16(udp_hdr->src_port);
    handle->remote_data_port =
        rte_be_to_cpu_16(cm_hdr->typed_header.connection_request.client_data_udp_port);

    struct fi_info *info = fi_dupinfo(res->pep->info);
    if (!info) {
        DPDK_WARN(FI_LOG_EP_CTRL, "%s failed to duplicate a struct fi_info object.\n", __func__);
        ret = -FI_ENOMEM;
        goto error_group_1;
    }
    info->handle = &handle->fid;

    // 3 - insert an event to event queue
    struct dpdk_cm_entry cm_entry;
    cm_entry.fid      = &res->pep->util_pep.pep_fid.fid;
    cm_entry.info     = info;
    uint16_t paramlen = rte_be_to_cpu_16(cm_hdr->typed_header.connection_request.paramlen);
    if (paramlen > DPDK_MAX_CM_DATA_SIZE) {
        DPDK_WARN(FI_LOG_EP_CTRL,
                  "%s failed to create connreq event because the peer's user data size (%d)"
                  "is too big. Truncated to %d bytes.",
                  __func__, paramlen, DPDK_MAX_CM_DATA_SIZE);
        paramlen = DPDK_MAX_CM_DATA_SIZE;
    }
    memcpy(&cm_entry.data, cm_data, paramlen);
    ret = fi_eq_write(&eq->util_eq.eq_fid, FI_CONNREQ, (void *)&cm_entry,
                      sizeof(struct fi_eq_cm_entry) + paramlen, 0);
    if (ret < 0) {
        DPDK_WARN(FI_LOG_EP_CTRL,
                  "%s failed to insert connreq event to event queue with error code: %d.", __func__,
                  ret);
        goto error_group_2;
    }

    ofi_mutex_unlock(&res->pep_lock);

    return FI_SUCCESS;

error_group_2:
    fi_freeinfo(info);
error_group_1:
    ofi_mutex_unlock(&res->pep_lock);
    return ret;
}

/* processing connection request acknowledgement or rejection
 * on the connecting client side.
 */
static int process_cm_conn_ack_or_rej(struct dpdk_domain_resources *res,
                                      struct rte_ether_hdr *eth_hdr, struct rte_ipv4_hdr *ip_hdr,
                                      struct rte_udp_hdr *udp_hdr, struct dpdk_cm_msg_hdr *cm_hdr,
                                      void *cm_data) {
    int             ret = FI_SUCCESS;
    struct dpdk_ep *ep  = NULL;
    ofi_mutex_lock(&res->domain_lock);
    if (!res->domain) {
        DPDK_WARN(FI_LOG_EP_CTRL,
                  "Unexpected CONNACK/CONNREJ message received on domain:%s. drop it\n",
                  res->domain_name);
        ofi_mutex_unlock(&res->domain_lock);
        ret = -FI_EINVAL;
        goto error_group_1;
    }
    // 0 - validate parameters
    int ep_idx =
        rte_be_to_cpu_16(cm_hdr->typed_header.connection_acknowledgement.client_data_udp_port) -
        (rte_be_to_cpu_16(res->local_cm_addr.sin_port) + 1);
    if (ep_idx < 0 || ep_idx > MAX_ENDPOINTS_PER_APP) {
        DPDK_WARN(FI_LOG_DOMAIN, "%s failed because endpoint is invalid: %d.", __func__, ep_idx);
        ret = -FI_EINVAL;
        goto error_group_1;
    }
    // TODO: [Weijia] the endpoint list might be implemented in a lockless approach?
    ofi_genlock_lock(&res->domain->ep_mutex);
    ep = res->domain->udp_port_to_ep[ep_idx];
    ofi_genlock_unlock(&res->domain->ep_mutex);
    // 1 - check local status
    if (atomic_load(&ep->conn_state) != ep_conn_state_connecting) {
        DPDK_WARN(FI_LOG_EP_CTRL,
                  "%s failed because endpoint is in state(%d). Excepting connecting state(%d)",
                  __func__, ep->conn_state, ep_conn_state_connecting);
        ret = -FI_ENOENT;
        goto error_group_1;
    }
    if (atomic_load(&ep->session_id) != rte_be_to_cpu_32(cm_hdr->session_id)) {
        DPDK_WARN(FI_LOG_EP_CTRL,
                  "%s failed because session_id (%d) in connack does not match session_id (%d)"
                  "in the connecting endpoint.",
                  __func__, rte_be_to_cpu_32(cm_hdr->session_id), atomic_load(&ep->session_id));
        ret = -FI_ENOENT;
        goto error_group_1;
    }
    // 2 - collect information from the header
    ep->remote_udp_port =
        rte_be_to_cpu_16(cm_hdr->typed_header.connection_acknowledgement.server_data_udp_port);

    // 3 - change state: connecting --> connected.
    switch (rte_be_to_cpu_32(cm_hdr->type)) {
    case DPDK_CM_MSG_CONNECTION_ACKNOWLEDGEMENT:
        atomic_store(&ep->conn_state, ep_conn_state_connected);
        break;
    case DPDK_CM_MSG_CONNECTION_REJECTION:
        atomic_store(&ep->conn_state, ep_conn_state_shutdown);
        break;
    default:
        DPDK_WARN(FI_LOG_EP_CTRL,
                  "%s failed because the connection message(%d) is neither CONNACK nor CONNREJ.",
                  __func__, rte_be_to_cpu_32(cm_hdr->type));
        ret = -FI_EINVAL;
        goto error_group_1;
    }

    // 4 - generate an event
    struct dpdk_cm_entry cm_entry;
    cm_entry.fid      = &ep->util_ep.ep_fid.fid;
    cm_entry.info     = NULL;
    uint16_t paramlen = rte_be_to_cpu_16(cm_hdr->typed_header.connection_acknowledgement.paramlen);
    if (paramlen > DPDK_MAX_CM_DATA_SIZE) {
        DPDK_WARN(FI_LOG_EP_CTRL,
                  "%s creating an event: because the peer's user data size (%d)"
                  "is too big. Truncated to %d bytes.",
                  __func__, paramlen, DPDK_MAX_CM_DATA_SIZE);
        paramlen = DPDK_MAX_CM_DATA_SIZE;
    }
    memcpy(&cm_entry.data, cm_data, paramlen);
    struct dpdk_eq *deq = container_of(ep->util_ep.eq, struct dpdk_eq, util_eq);
    uint32_t event      = (rte_be_to_cpu_32(cm_hdr->type) == DPDK_CM_MSG_CONNECTION_ACKNOWLEDGEMENT)
                              ? FI_CONNECTED
                              : FI_SHUTDOWN;
    ret                 = fi_eq_write(&deq->util_eq.eq_fid, event, (void *)&cm_entry,
                                      sizeof(struct fi_eq_cm_entry) + paramlen, 0);
    if (ret < 0) {
        DPDK_WARN(FI_LOG_EP_CTRL,
                  "%s failed to insert 'connected' event to event queue with error code: %d.",
                  __func__, ret);
        goto error_group_2;
    }

    ofi_mutex_unlock(&res->domain_lock);
    return FI_SUCCESS;

error_group_2: // endpoint has changed.
error_group_1: // endpoint is still connecting
    ofi_mutex_unlock(&res->domain_lock);
    return ret;
}

// TODO: check process_cm_conn_ack_or_rej and process_cm_disconnect
/* processing disconnection request */
static int process_cm_disconnect(struct dpdk_domain_resources *res, struct rte_ether_hdr *eth_hdr,
                                 struct rte_ipv4_hdr *ip_hdr, struct rte_udp_hdr *udp_hdr,
                                 struct dpdk_cm_msg_hdr *cm_hdr, void *cm_data) {
    int             ret = FI_SUCCESS;
    struct dpdk_ep *ep  = NULL;
    // 0 - validate parameters
    ofi_mutex_lock(&res->domain_lock);
    if (!res->domain) {
        DPDK_WARN(FI_LOG_EP_CTRL,
                  "Unexpected CONNACK/CONNREJ message received on domain:%s. drop it\n",
                  cfg_title(res->domain_config));
        ofi_mutex_unlock(&res->domain_lock);
        ret = -FI_EINVAL;
        goto error_group_1;
    }
    int ep_idx = rte_be_to_cpu_16(cm_hdr->typed_header.disconnection_request.remote_data_udp_port) -
                 (rte_be_to_cpu_16(res->local_cm_addr.sin_port) + 1);
    if (ep_idx < 0 || ep_idx > MAX_ENDPOINTS_PER_APP) {
        DPDK_WARN(FI_LOG_DOMAIN, "%s failed because endpoint is invalid: %d.", __func__, ep_idx);
        ret = -FI_EINVAL;
        goto error_group_1;
    }
    ofi_genlock_lock(&res->domain->ep_mutex);
    ep = res->domain->udp_port_to_ep[ep_idx];
    ofi_genlock_unlock(&res->domain->ep_mutex);
    // 1 - check local status
    uint32_t ep_state = atomic_load(&ep->conn_state);
    switch (ep_state) {
    case ep_conn_state_connected: {
        // change state
        atomic_store(&ep->conn_state, ep_conn_state_shutdown);
        // generate a shutdown event
        struct dpdk_cm_entry cm_entry;
        cm_entry.fid        = &ep->util_ep.ep_fid.fid;
        cm_entry.info       = NULL;
        struct dpdk_eq *deq = container_of(ep->util_ep.eq, struct dpdk_eq, util_eq);
        ret                 = fi_eq_write(&deq->util_eq.eq_fid, FI_SHUTDOWN, (void *)&cm_entry,
                                          sizeof(struct fi_eq_cm_entry), 0);
        if (ret < 0) {
            DPDK_WARN(FI_LOG_EP_CTRL,
                      "%s failed to insert 'connected' event to event queue with error code: %d.",
                      __func__, ret);
            goto error_group_2;
        }
    } break;
    case ep_conn_state_connecting:
    case ep_conn_state_unbound:
    case ep_conn_state_shutdown:
    case ep_conn_state_error:
    default:
        DPDK_WARN(FI_LOG_EP_CTRL,
                  "%s ignores unexpected disconnection message because endpoint is in %d state.\n",
                  __func__, ep_state);
        goto error_group_1;
    }

    ofi_mutex_unlock(&res->domain_lock);
    return FI_SUCCESS;
    // 1 -
error_group_2: // state chagned.
error_group_1: // nothing changed.
    ofi_mutex_unlock(&res->domain_lock);
    return ret;
} /* process_cm_disconnect */

/**
 * This function must only be called from the connection management ctrl thread
 * Here, we hold the res->pep_lock.
 */
int dpdk_cm_recv(struct rte_mbuf *m, struct dpdk_domain_resources *res) {
    int ret = FI_SUCCESS;

    uint32_t              offset  = 0;
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ether_hdr *, offset);
    offset += sizeof(*eth_hdr);
    struct rte_ipv4_hdr *ip_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, offset);
    offset += sizeof(*ip_hdr);
    struct rte_udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *, offset);
    offset += sizeof(*udp_hdr);
    struct dpdk_cm_msg_hdr *cm_hdr = rte_pktmbuf_mtod_offset(m, struct dpdk_cm_msg_hdr *, offset);
    offset += sizeof(*cm_hdr);
    void *cm_data = rte_pktmbuf_mtod_offset(m, void *, offset);

    DPDK_TRACE(FI_LOG_EP_CTRL, "Receiving CM Message with type:%d.\n", cm_hdr->type);

    switch (rte_be_to_cpu_32(cm_hdr->type)) {
    case DPDK_CM_MSG_CONNECTION_REQUEST:
        DPDK_DBG(FI_LOG_EP_CTRL, "received CONNREQ message, calling process_cm_connreq().\n");
        ret = process_cm_connreq(res, eth_hdr, ip_hdr, udp_hdr, cm_hdr, cm_data);
        DPDK_DBG(FI_LOG_EP_CTRL, "returned from process_cm_connreq(). retcode=%d\n", ret);
        break;
    case DPDK_CM_MSG_CONNECTION_ACKNOWLEDGEMENT:
    case DPDK_CM_MSG_CONNECTION_REJECTION:
        DPDK_DBG(FI_LOG_EP_CTRL,
                 "received CONNACK/CONNREJ message, calling process_cm_conn_ack_or_rej().\n");
        ret = process_cm_conn_ack_or_rej(res, eth_hdr, ip_hdr, udp_hdr, cm_hdr, cm_data);
        DPDK_DBG(FI_LOG_EP_CTRL, "returned from process_cm_conn_ack_or_rej(). retcode=%d\n", ret);
        break;
    case DPDK_CM_MSG_DISCONNECTION_REQUEST:
        DPDK_DBG(FI_LOG_EP_CTRL, "received DISCONNREQ message, calling process_cm_disconnect().\n");
        ret = process_cm_disconnect(res, eth_hdr, ip_hdr, udp_hdr, cm_hdr, cm_data);
        DPDK_DBG(FI_LOG_EP_CTRL, "returned from process_cm_disconnect(). retcode=%d\n", ret);
        break;
    default:
        DPDK_WARN(FI_LOG_EP_CTRL, "Skipping unknown type:%d.\n", cm_hdr->type);
        ret = FI_EINVAL;
    }

    return ret;
}
