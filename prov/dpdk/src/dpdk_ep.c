#include "fi_dpdk.h"
#include "protocols.h"

#include <ifaddrs.h>
#include <net/if.h>
#include <poll.h>
#include <sys/types.h>

#include <ofi_util.h>

// ================== HELPER FUNCTIONS ========
static int ep_queue_init(struct dpdk_ep *ep, struct dpdk_xfer_queue *q, uint32_t q_size,
                         uint32_t max_recv_sge, char *q_name) {
    size_t wqe_size;
    char   name[RTE_RING_NAMESIZE];
    int    i, ret;

    snprintf(name, RTE_RING_NAMESIZE, "ep%" PRIu16 "_ring", ep->udp_port);
    q->ring = rte_malloc(NULL, rte_ring_get_memsize(q_size + 1), RTE_CACHE_LINE_SIZE, q_name);
    if (!q->ring) {
        return -rte_errno;
    }
    ret = rte_ring_init(q->ring, name, q_size + 1, RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (ret) {
        return ret;
    }

    snprintf(name, RTE_RING_NAMESIZE, "ep%" PRIu16 "_free", ep->udp_port);
    q->free_ring = rte_malloc(NULL, rte_ring_get_memsize(q_size + 1), RTE_CACHE_LINE_SIZE, q_name);
    if (!q->free_ring) {
        return -rte_errno;
    }
    ret = rte_ring_init(q->free_ring, name, q_size + 1, RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (ret) {
        return ret;
    }
    wqe_size   = sizeof(struct dpdk_xfer_entry) + max_recv_sge * sizeof(struct iovec);
    q->storage = calloc(q_size + 1, wqe_size);
    if (!q->storage)
        return -errno;

    for (i = 0; i < q_size; ++i) {
        rte_ring_enqueue(q->free_ring, q->storage + i * wqe_size);
    }

    dlist_init(&q->active_head);
    rte_spinlock_init(&q->lock);
    q->max_wr   = q_size;
    q->max_sge  = max_recv_sge;
    q->next_msn = 1;
    return 0;
} /* usiw_recv_wqe_queue_init */

// ============== ACTIVE ENDPOINT ==============
// === EP FI_OPS ===

static int dpdk_ep_bind(struct fid *fid, struct fid *bfid, uint64_t flags) {
    struct dpdk_ep *ep;
    struct dpdk_cq *cq = container_of(bfid, struct dpdk_cq, util_cq.cq_fid.fid);
    int             ret;

    ep  = container_of(fid, struct dpdk_ep, util_ep.ep_fid.fid);
    ret = ofi_ep_bind_valid(&dpdk_prov, bfid, flags);
    if (ret) {
        return ret;
    }

    switch (bfid->fclass) {
    case FI_CLASS_CQ:
        ret = ofi_ep_bind_cq(&ep->util_ep, &cq->util_cq, flags);
        if (flags & FI_RECV) {
            ep->recv_cq = cq;
        } else if (flags & FI_SEND) {
            ep->send_cq = cq;
        } else {
            FI_WARN(&dpdk_prov, FI_LOG_EP_CTRL, "invalid flags for CQ binding");
            return -FI_EINVAL;
        }
        // TODO: Not ideal... see cq readfrom
        cq->ep = ep;
        break;

    // TODO: for the moment, just associate the CQ.
    // The rest of the function is unimplemented

    // case FI_CLASS_EQ:
    //     if (ep->util_ep.type != FI_EP_MSG)
    //         return -FI_EINVAL;

    //     ep->eq = container_of(bfid, struct dpdk_eq, eq_fid.fid);

    //     /* Make sure EQ channel is not polled during migrate */
    //     ofi_mutex_lock(&ep->eq->lock);
    //     if (vrb_is_xrc_ep(ep))
    //         ret = vrb_ep_xrc_set_tgt_chan(ep);
    //     else
    //         ret = rdma_migrate_id(ep->id, ep->eq->channel);
    //     ofi_mutex_unlock(&ep->eq->lock);
    //     if (ret) {
    //         VRB_WARN_ERRNO(FI_LOG_EP_CTRL, "rdma_migrate_id");
    //         return -errno;
    //     }
    //     break;
    // case FI_CLASS_SRX_CTX:
    //     if (ep->util_ep.type != FI_EP_MSG)
    //         return -FI_EINVAL;

    //     ep->srq_ep = container_of(bfid, struct vrb_srq_ep, ep_fid.fid);
    //     break;
    // case FI_CLASS_AV:
    //     if (ep->util_ep.type != FI_EP_DGRAM)
    //         return -FI_EINVAL;

    //     av = container_of(bfid, struct vrb_dgram_av, util_av.av_fid.fid);
    //     return ofi_ep_bind_av(&ep->util_ep, &av->util_av);
    default:
        return -FI_EINVAL;
    }

    return 0;
}

static int dpdk_ep_close(struct fid *fid) {
    struct dpdk_progress *progress;
    struct dpdk_ep       *ep;

    printf("[dpdk_ep_close] UNIMPLEMENTED\n");
    // ep = container_of(fid, struct dpdk_ep, util_ep.ep_fid.fid);

    // TODO: Remove the ep descriptor from the DOMAIN list
    // Need a lock!

    // progress = dpdk_ep2_progress(ep);
    // ofi_genlock_lock(&progress->lock);
    // dlist_remove_init(&ep->unexp_entry);
    // dpdk_halt_sock(progress, ep->bsock.sock);
    // dpdk_ep_flush_all_queues(ep);
    // ofi_genlock_unlock(&progress->lock);

    // free(ep->cm_msg);
    // ofi_close_socket(ep->bsock.sock);

    // ofi_endpoint_close(&ep->util_ep);
    free(ep);
    return 0;
}

static int dpdk_ep_ctrl(struct fid *fid, int command, void *arg) {
    struct dpdk_ep     *ep;
    struct dpdk_domain *domain;

    ep = container_of(fid, struct dpdk_ep, util_ep.ep_fid.fid);
    switch (command) {
    case FI_ENABLE:
        if ((ofi_needs_rx(ep->util_ep.caps) && !ep->util_ep.rx_cq) ||
            (ofi_needs_tx(ep->util_ep.caps) && !ep->util_ep.tx_cq))
        {
            FI_WARN(&dpdk_prov, FI_LOG_EP_CTRL, "missing needed CQ binding\n");
            return -FI_ENOCQ;
        }

        // Now we must associate the EP with the progress thread
        domain = container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);
        ofi_genlock_lock(&domain->ep_mutex);
        slist_insert_tail(&ep->entry, &domain->endpoint_list);
        ofi_genlock_unlock(&domain->ep_mutex);

        break;
    default:
        FI_WARN(&dpdk_prov, FI_LOG_EP_CTRL, "unsupported command\n");
        return -FI_ENOSYS;
    }
    return FI_SUCCESS;
}

static int dpdk_ep_getname(fid_t fid, void *addr, size_t *addrlen) {
    // TODO: return useful per-EP info
    printf("[dpdk_ep_connect] UNIMPLEMENTED\n");
    return 0;
}

static int dpdk_ep_connect(struct fid_ep *ep_fid, const void *addr, const void *param,
                           size_t paramlen) {

    // TODO: This is a placeholder to have the EP work
    // This is for Weijia to provide the actual implementation
    struct dpdk_ep *ep = container_of(ep_fid, struct dpdk_ep, util_ep.ep_fid);
    eth_parse("ff:ff:ff:ff:ff:ff", &ep->remote_eth_addr);
    ip_parse("192.168.56.212", &ep->remote_ipv4_addr);
    ep->remote_udp_port = 2510;

    atomic_store(&ep->conn_state, ep_conn_state_connected);

    // TODO: IMPLEMENT THIS FUNCTION
    printf("[dpdk_ep_connect] UNIMPLEMENTED\n");

    return 0;
}

static int dpdk_ep_accept(struct fid_ep *ep, const void *param, size_t paramlen) {

    printf("[dpdk_ep_accept] UNIMPLEMENTED\n");
    return 0;
}

// === EP MSG functions ===
// Defined in a separate file for clarity
extern struct fi_ops_msg dpdk_msg_ops;

static struct fi_ops dpdk_ep_fi_ops = {
    .size     = sizeof(struct fi_ops),
    .close    = dpdk_ep_close,
    .bind     = dpdk_ep_bind,
    .control  = dpdk_ep_ctrl,
    .ops_open = fi_no_ops_open,
};

static struct fi_ops_cm dpdk_cm_ops = {
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

/* Create an endpoint. Not active until explicitly enabled */
int dpdk_endpoint(struct fid_domain *domain, struct fi_info *info, struct fid_ep **ep_fid,
                  void *context) {
    struct dpdk_ep          *ep;
    struct dpdk_pep         *pep;
    struct dpdk_conn_handle *handle;
    int                      ret = 0;

    ep = calloc(1, sizeof(*ep));
    if (!ep) {
        return -FI_ENOMEM;
    }

    /* 1. libfabric-specific initialization */
    ret = ofi_endpoint_init(domain, &dpdk_util_prov, info, &ep->util_ep, context, NULL);
    if (ret) {
        goto err1;
    }
    // TODO: Complete the OPS definition
    *ep_fid            = &ep->util_ep.ep_fid;
    (*ep_fid)->fid.ops = &dpdk_ep_fi_ops;
    // (*ep_fid)->ops     = &dpdk_ep_ops;
    (*ep_fid)->cm  = &dpdk_cm_ops;
    (*ep_fid)->msg = &dpdk_msg_ops;
    //     (*ep_fid)->rma     = &dpdk_rma_ops;
    //     (*ep_fid)->tagged  = &dpdk_tagged_ops;

    /* 2. DPDK-specific initialization */
    struct dpdk_domain *dpdk_domain =
        container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);

    // Initialize TX and RX queues //TODO: Cleanup and memory free in case of failure
    ep_queue_init(ep, &ep->sq, dpdk_default_tx_size, DPDK_IOV_LIMIT, "send");
    ep_queue_init(ep, &ep->rq, dpdk_default_rx_size, DPDK_IOV_LIMIT, "recv");

    // TODO: Cleanup and memory free in case of failure
    RTE_LOG(DEBUG, USER1, "Initializing the QP TXQ to contain %u structs of size %u\n",
            dpdk_default_tx_size, sizeof(*ep->txq));
    ep->txq     = calloc(dpdk_default_tx_size, sizeof(*ep->txq));
    ep->txq_end = ep->txq;

    // Completion Queues are not initialized here, but in the fi_ep_bind function, as they are
    // created independently by the end user

    // Initialize the remote endpoint state
    // TODO: [uRDMA comment] Get this from the remote peer
    ep->remote_ep.send_max_psn    = dpdk_default_tx_size / 2;
    ep->remote_ep.tx_pending_size = dpdk_default_tx_size / 2;
    ep->remote_ep.tx_pending =
        calloc(ep->remote_ep.tx_pending_size, sizeof(*ep->remote_ep.tx_pending));
    if (!ep->remote_ep.tx_pending) {
        RTE_LOG(DEBUG, USER1, "<ep=%" PRIx16 "> Set up tx_pending failed: %s\n", ep->udp_port,
                strerror(errno));
        goto err4;
    }
    ep->remote_ep.tx_head             = ep->remote_ep.tx_pending;
    ep->remote_ep.recv_rresp_last_psn = binheap_new(dpdk_max_ord);
    if (!ep->remote_ep.recv_rresp_last_psn) {
        goto err4;
    }

    // Set the state of the endpoint to unbound
    atomic_store(&ep->conn_state, ep_conn_state_unbound);

    // Initialize the acknowledgement management system
    ep->readresp_store = calloc(dpdk_max_ird, sizeof(*ep->readresp_store));
    if (!ep->readresp_store) {
        RTE_LOG(DEBUG, USER1, "<ep=%" PRIx16 "> Set up readresp_store failed: %s\n", ep->udp_port,
                strerror(errno));
        goto err5;
    }
    ep->readresp_head_msn = 1;
    ep->ord_active        = 0;

    // Initialize header memory pool. TODO: handle memory cleanup
    /* We must allocate an mbuf large enough to hold the maximum possible
     * received packet. Note that the 64-byte headroom does *not* count for
     * incoming packets. Note that the MTU as set by urdma and DPDK does
     * *not* include the Ethernet header, CRC, or VLAN tag, but the drivers
     * require space for these in the receive buffer.
     * The other headers (IP and upper) are taken into account by the priv_size
     * of the mempool, which is PENDING_DATAGRAM_INFO_SIZE.
     */
    size_t mbuf_size = RTE_PKTMBUF_HEADROOM + MTU + RTE_ETHER_VXLAN_HLEN + RTE_ETHER_CRC_LEN;

    ep->tx_hdr_mempool_name = malloc(64);
    sprintf(ep->tx_hdr_mempool_name, "hdr_pool_%s", ep->util_ep.domain->name);
    ep->tx_hdr_mempool = rte_pktmbuf_pool_create(
        ep->tx_hdr_mempool_name, 2 * MAX_ENDPOINTS_PER_APP * dpdk_default_tx_size, 0,
        PENDING_DATAGRAM_INFO_SIZE, mbuf_size, rte_socket_id());
    if (!ep->tx_hdr_mempool) {
        rte_exit(EXIT_FAILURE, "Cannot create hdr tx mempool for domain %s: %s\n",
                 ep->util_ep.domain->name, rte_strerror(rte_errno));
    }

    // Same for the DDP mempool. uRDMA did not allocate the DDP header mempool, leaving it as a TODO
    // and re-using the hdr mempool. Let's try to actually separate them.
    // TODO: cleanup!!
    ep->tx_ddp_mempool_name = malloc(64);
    sprintf(ep->tx_ddp_mempool_name, "hdr_pool_%s", ep->util_ep.domain->name);
    ep->tx_ddp_mempool = rte_pktmbuf_pool_create(
        ep->tx_ddp_mempool_name, 2 * MAX_ENDPOINTS_PER_APP * dpdk_default_tx_size, 0,
        PENDING_DATAGRAM_INFO_SIZE, mbuf_size, rte_socket_id());
    if (!ep->tx_ddp_mempool) {
        rte_exit(EXIT_FAILURE, "Cannot create hdr tx mempool for domain %s: %s\n",
                 ep->util_ep.domain->name, rte_strerror(rte_errno));
    }

    // Add this EP to EP list of the domain, and increase the associated values
    // MUST be done while holding the EP MUTEX.
    ofi_genlock_lock(&dpdk_domain->ep_mutex);
    slist_insert_tail(&ep->entry, &dpdk_domain->endpoint_list);
    dpdk_domain->num_endpoints++;
    u_int16_t base_udp_port                   = *((u_int16_t *)dpdk_domain->address);
    ep->udp_port                              = base_udp_port + (dpdk_domain->num_endpoints - 1);
    dpdk_domain->udp_port_to_ep[ep->udp_port] = ep;
    ofi_genlock_unlock(&dpdk_domain->ep_mutex);

    return 0;

// TODO: complete error handling
err5:
err4:
err3:
err2:
    ofi_endpoint_close(&ep->util_ep);
err1:
    free(ep);
    return ret;
}

// ============== PASSIVE ENDPOINT ==============
// === Helper functions ===
static int dpdk_pep_close(struct fid *fid) {

    printf("[dpdk_pep_close] UNIMPLEMENTED\n");
    return 0;
}

static int dpdk_pep_bind(struct fid *fid, struct fid *bfid, uint64_t flags) {

    printf("[dpdk_pep_bind] UNIMPLEMENTED\n");
    return 0;
}

static int dpdk_pep_setname(fid_t fid, void *addr, size_t addrlen) {

    printf("[dpdk_pep_setname] UNIMPLEMENTED\n");
    strncpy(addr, "dummy_address", 14);
    return 0;
}

static int dpdk_pep_getname(fid_t fid, void *addr, size_t *addrlen) {
    struct dpdk_ep     *ep;
    struct dpdk_domain *domain;

    ep     = container_of(fid, struct dpdk_ep, util_ep.ep_fid);
    domain = container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);

    size_t addrlen_in = domain->addrlen;
    if (addrlen_in < *addrlen) {
        memcpy(addr, domain->address, addrlen_in);
    }
    return (addrlen_in < *addrlen) ? -FI_ETOOSMALL : FI_SUCCESS;
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

// === PEP functions ===
static struct fi_ops dpdk_pep_fi_ops = {
    .size     = sizeof(struct fi_ops),
    .close    = dpdk_pep_close,
    .bind     = dpdk_pep_bind,
    .control  = fi_no_control,
    .ops_open = fi_no_ops_open,
};

static struct fi_ops_cm dpdk_pep_cm_ops = {
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

static struct fi_ops_ep dpdk_pep_ops = {
    .size         = sizeof(struct fi_ops_ep),
    .getopt       = fi_no_getopt, // TODO: implement: dpdk_pep_getopt,
    .setopt       = fi_no_setopt,
    .tx_ctx       = fi_no_tx_ctx,
    .rx_ctx       = fi_no_rx_ctx,
    .rx_size_left = fi_no_rx_size_left,
    .tx_size_left = fi_no_tx_size_left,
};

int dpdk_passive_ep(struct fid_fabric *fabric, struct fi_info *info, struct fid_pep **pep_fid,
                    void *context) {
    struct dpdk_pep *pep;
    int              ret;

    if (!info) {
        FI_WARN(&dpdk_prov, FI_LOG_EP_CTRL, "invalid info\n");
        return -FI_EINVAL;
    }

    ret = ofi_prov_check_info(&dpdk_util_prov, fabric->api_version, info);
    if (ret) {
        return ret;
    }

    pep = calloc(1, sizeof(*pep));
    if (!pep) {
        return -FI_ENOMEM;
    }

    ret = ofi_pep_init(fabric, info, &pep->util_pep, context);
    if (ret) {
        goto err1;
    }

    // TODO: finish to implement!
    printf("[dpdk_passive_ep ] PARTIALLY UNIMPLEMENTED\n");

    pep->util_pep.pep_fid.fid.ops = &dpdk_pep_fi_ops;
    pep->util_pep.pep_fid.cm      = &dpdk_pep_cm_ops;
    pep->util_pep.pep_fid.ops     = &dpdk_pep_ops;

    pep->info = fi_dupinfo(info);
    if (!pep->info) {
        ret = -FI_ENOMEM;
        goto err2;
    }

    //     pep->cm_ctx.fid.fclass = DPDK_CLASS_CM;
    //     pep->cm_ctx.hfid       = &pep->util_pep.pep_fid.fid;
    //     pep->cm_ctx.state      = DPDK_CM_LISTENING;
    //     pep->cm_ctx.cm_data_sz = 0;
    //     pep->sock              = INVALID_SOCKET;

    //     if (info->src_addr) {
    //         ret = dpdk_pep_sock_create(pep);
    //         if (ret)
    //             goto err3;
    //     }

    // TODO: Here we first set the ops to pep->util_pep, then we pass the pointer to the caller.
    // Instead, in the dpdk_endpoint(), we first pass the pointer to the caller, then we set the
    // ops to the caller. We should be consistent and choose one of the two approaches!
    *pep_fid = &pep->util_pep.pep_fid;
    return FI_SUCCESS;
err3:
    fi_freeinfo(pep->info);
err2:
    ofi_pep_close(&pep->util_pep);
err1:
    free(pep);
    return ret;
}
