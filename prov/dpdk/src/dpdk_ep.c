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

    // Compute the ring size (=elements) and byte size. Elements must be a power of 2.
    size_t ring_size       = rte_align32pow2(q_size + 1);
    size_t ring_size_bytes = rte_ring_get_memsize(ring_size);

    // 1. Create the active descriptor ring
    snprintf(name, RTE_RING_NAMESIZE, "ep%" PRIu16 "_%s_ring", ep->udp_port, q_name);
    q->ring = rte_malloc(NULL, ring_size_bytes, RTE_CACHE_LINE_SIZE);
    if (!q->ring) {
        FI_WARN(&dpdk_prov, FI_LOG_EP_CTRL, "Failed to allocate memory for ring %s", name);
        return -rte_errno;
    }
    ret = rte_ring_init(q->ring, name, ring_size, RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (ret) {
        FI_WARN(&dpdk_prov, FI_LOG_EP_CTRL, "Failed to initialize ring %s", name);
        return ret;
    }

    // 2. Create the free descriptor ring
    snprintf(name, RTE_RING_NAMESIZE, "ep%" PRIu16 "_%s_free", ep->udp_port, q_name);
    q->free_ring = rte_malloc(NULL, ring_size_bytes, RTE_CACHE_LINE_SIZE);
    if (!q->free_ring) {
        FI_WARN(&dpdk_prov, FI_LOG_EP_CTRL, "Failed to allocate memory for ring %s", name);
        return -rte_errno;
    }
    ret = rte_ring_init(q->free_ring, name, ring_size, RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (ret) {
        FI_WARN(&dpdk_prov, FI_LOG_EP_CTRL, "Failed to initialize ring %s", name);
        return ret;
    }

    // 3. Allocate the storage for the descriptors
    wqe_size   = sizeof(struct dpdk_xfer_entry) + max_recv_sge * sizeof(struct iovec);
    q->storage = calloc(ring_size, wqe_size);
    if (!q->storage)
        return -errno;

    // 4. Enqueue all the descriptors in the free ring
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

    int ret;
    ep  = container_of(fid, struct dpdk_ep, util_ep.ep_fid.fid);
    ret = ofi_ep_bind_valid(&dpdk_prov, bfid, flags);
    if (ret) {
        FI_WARN(&dpdk_prov, FI_LOG_EP_CTRL, "invalid bfid");
        return ret;
    }

    switch (bfid->fclass) {
    case FI_CLASS_CQ:
        struct dpdk_cq *cq = container_of(bfid, struct dpdk_cq, util_cq.cq_fid.fid);
        ret                = ofi_ep_bind_cq(&ep->util_ep, &cq->util_cq, flags);
        if (ret < 0) {
            printf("ofi_ep_bind_cq failed\n");
            FI_WARN(&dpdk_prov, FI_LOG_EP_CTRL, "ofi_ep_bind_cq failed");
            return ret;
        }
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

    case FI_CLASS_EQ:
        struct dpdk_eq *eq = container_of(bfid, struct dpdk_eq, util_eq.eq_fid.fid);
        ret                = ofi_ep_bind_eq(&ep->util_ep, &eq->util_eq);
        if (ret < 0) {
            printf("ofi_ep_bind_eq failed\n");
            FI_WARN(&dpdk_prov, FI_LOG_EP_CTRL, "ofi_ep_bind_eq failed");
            return ret;
        }
        break;
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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
static int dpdk_ep_close(struct fid *fid) {
    struct dpdk_progress *progress;
    struct dpdk_ep       *ep = NULL;

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
    // free(ep);
    return 0;
}
#pragma GCC diagnostic pop

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

static struct fi_ops dpdk_ep_fi_ops = {
    .size     = sizeof(struct fi_ops),
    .close    = dpdk_ep_close,
    .bind     = dpdk_ep_bind,
    .control  = dpdk_ep_ctrl,
    .ops_open = fi_no_ops_open,
};

/* Create an endpoint. Not active until explicitly enabled */
int dpdk_endpoint(struct fid_domain *domain, struct fi_info *info, struct fid_ep **ep_fid,
                  void *context) {
    struct dpdk_ep          *ep;
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

    *ep_fid            = &ep->util_ep.ep_fid;
    (*ep_fid)->fid.ops = &dpdk_ep_fi_ops;
    (*ep_fid)->cm      = &dpdk_cm_ops;
    (*ep_fid)->msg     = &dpdk_msg_ops;
    // TODO: Complete the OPS definition
    // (*ep_fid)->rma     = &dpdk_rma_ops;
    // (*ep_fid)->tagged  = &dpdk_tagged_ops;
    // (*ep_fid)->atomic  = &dpdk_atomic_ops;
    // (*ep_fid)->ops_collective    = &dpdk_collective_ops;

    /* 2. DPDK-specific initialization */
    struct dpdk_domain *dpdk_domain =
        container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);

    // Initialize TX and RX queues
    // TODO: Cleanup and memory free in case of failure
    ret = ep_queue_init(ep, &ep->sq, dpdk_default_tx_size, DPDK_IOV_LIMIT, "send");
    if (ret) {
        // [Weijia] ep->udp_port hasn't been initialized here, right?
        FI_WARN(&dpdk_prov, FI_LOG_EP_CTRL, "Failed to init send queue of ep%d", ep->udp_port);
        goto err6;
    }
    ret = ep_queue_init(ep, &ep->rq, dpdk_default_rx_size, DPDK_IOV_LIMIT, "recv");
    if (ret) {
        // [Weijia] ep->udp_port hasn't been initialized here, right?
        FI_WARN(&dpdk_prov, FI_LOG_EP_CTRL, "Failed to init recv queue of ep%d", ep->udp_port);
        goto err7;
    }

    // TODO: Cleanup and memory free in case of failure
    RTE_LOG(DEBUG, USER1, "Initializing the QP TXQ to contain %lu structs of size %lu\n",
            dpdk_default_tx_size, sizeof(*ep->txq));
    ep->txq     = calloc(dpdk_default_tx_size, sizeof(*ep->txq));
    if (!ep->txq) {
        FI_WARN(&dpdk_prov, FI_LOG_EP_CTRL, "Failed to create txq table.");
        ret = -FI_ENOMEM;
        goto err7;
    }
    ep->txq_end = ep->txq;

    // Completion Queues are not initialized here, but in the fi_ep_bind function, as they are
    // created independently by the end user

    // Initialize the remote endpoint state
    // TODO: [uRDMA comment] Get this from the remote peer
    ep->remote_ep.expected_read_msn = 1;
    ep->remote_ep.expected_ack_msn  = 1;
    ep->remote_ep.next_send_msn     = 1;
    ep->remote_ep.next_read_msn     = 1;
    ep->remote_ep.next_ack_msn      = 1;
    ep->remote_ep.send_max_psn      = dpdk_default_tx_size / 2;
    ep->remote_ep.tx_pending_size   = dpdk_default_tx_size / 2;
    ep->remote_ep.tx_pending =
        calloc(ep->remote_ep.tx_pending_size, sizeof(*ep->remote_ep.tx_pending));
    if (!ep->remote_ep.tx_pending) {
        // [Weijia] ep->udp_port hasn't been initialized here, right?
        RTE_LOG(DEBUG, USER1, "<ep=%" PRIx16 "> Set up tx_pending failed: %s\n", ep->udp_port,
                strerror(errno));
        ret = -FI_ENOMEM;
        goto err4;
    }
    ep->remote_ep.tx_head             = ep->remote_ep.tx_pending;
    ep->remote_ep.recv_rresp_last_psn = binheap_new(dpdk_max_ord);
    if (!ep->remote_ep.recv_rresp_last_psn) {
        goto err4;
    }

    // Set the state of the endpoint
    if (info->handle) {
        switch (info->handle->fclass) {
        case FI_CLASS_CONNREQ:
            // In case of FI_CLASS_CONNREQ, we pass the handle to ep for fi_accept().
            ep->conn_handle = info->handle;
            atomic_store(&ep->conn_state, ep_conn_state_connecting);
            break;
        default:
            DPDK_WARN(FI_LOG_EP_CTRL,"%s get unexpected type:%lu from fi_info::handle.",
                      __func__, info->handle->fclass);
            ret = -FI_EINVAL;
            goto err5;
        }
    } else {
        atomic_store(&ep->conn_state, ep_conn_state_unbound);
    }

    // Initialize the acknowledgement management system
    ep->readresp_store = calloc(dpdk_max_ird, sizeof(*ep->readresp_store));
    if (!ep->readresp_store) {
        // [Weijia] ep->udp_port hasn't been initialized here, right?
        RTE_LOG(DEBUG, USER1, "<ep=%" PRIx16 "> Set up readresp_store failed: %s\n", ep->udp_port,
                strerror(errno));
        goto err6;
    }
    ep->readresp_head_msn = 1;
    ep->ord_active        = 0;

    // Dimension of the TX mempools (must be power of 2)
    size_t pool_size = rte_align32pow2(2 * MAX_ENDPOINTS_PER_APP * dpdk_default_tx_size);

    // Initialize header memory pool. TODO: handle memory cleanup
    // We keep the original idea to reserve a private size to store local TX info
    // represented by the pending_datagram_info struct
    // TODO: Maybe add some space after the header to store "small" data that can be copied?
    size_t mbuf_size    = RTE_ETHER_HDR_LEN + INNER_HDR_LEN + RTE_ETHER_CRC_LEN;
    size_t cache_size   = 64;
    size_t private_size = PENDING_DATAGRAM_INFO_SIZE;
    char   tx_hdr_mempool_name[20];
    sprintf(tx_hdr_mempool_name, "hdr_pool_%u", ep->udp_port);
    ep->tx_hdr_mempool = rte_pktmbuf_pool_create(tx_hdr_mempool_name, pool_size, cache_size,
                                                 private_size, mbuf_size, rte_socket_id());
    if (!ep->tx_hdr_mempool) {
        rte_exit(EXIT_FAILURE, "Cannot create hdr tx mempool for EP %u: %s\n", ep->udp_port,
                 rte_strerror(rte_errno));
    }

    // Initialize "external buffers" memory pool. TODO: handle memory cleanup
    // These will reference user memory (provided that it was previously registered)
    // and will be put in chain with the headers
    mbuf_size    = 0; // Will reference external memory!
    cache_size   = 64;
    private_size = 0;
    char tx_ddp_mempool_name[20];
    sprintf(tx_ddp_mempool_name, "ddp_pool_%u", ep->udp_port);
    ep->tx_ddp_mempool = rte_pktmbuf_pool_create(tx_ddp_mempool_name, pool_size, cache_size,
                                                 private_size, mbuf_size, rte_socket_id());
    if (!ep->tx_ddp_mempool) {
        rte_exit(EXIT_FAILURE, "Cannot create hdr tx mempool for EP %u: %s\n", ep->udp_port,
                 rte_strerror(rte_errno));
    }

    // Add this EP to EP list of the domain, and increase the associated values
    // MUST be done while holding the EP MUTEX.
    // [Weijia] Is it possible that num_endpoints being growing beyond MAX_ENDPOINTS_PER_APP,
    //          leaving released udp ports unused?
    ofi_genlock_lock(&dpdk_domain->ep_mutex);
    slist_insert_tail(&ep->entry, &dpdk_domain->endpoint_list);
    dpdk_domain->udp_port_to_ep[dpdk_domain->num_endpoints] = ep;
    dpdk_domain->num_endpoints++;
    ep->udp_port = rte_be_to_cpu_16(dpdk_domain->local_addr.sin_port) +
                   dpdk_domain->num_endpoints;
    ofi_genlock_unlock(&dpdk_domain->ep_mutex);

    FI_INFO(&dpdk_prov, FI_LOG_EP_CTRL, "Created EP %u", ep->udp_port);

    return 0;

// TODO: complete error handling
err7:
err6:
err5:
err4:
// err3:
// err2:
    ofi_endpoint_close(&ep->util_ep);
err1:
    free(ep);
    return ret;
}

// ============== PASSIVE ENDPOINT ==============
static int dpdk_pep_bind(struct fid* fid, struct fid *bfid, uint64_t flags) {
    struct dpdk_pep* pep_l3 = container_of(fid, struct dpdk_pep, util_pep.pep_fid.fid);

    int ret = FI_SUCCESS;
    switch(bfid->fclass) {
    case FI_CLASS_EQ:
        struct util_eq* eq_l2 = container_of(bfid,struct util_eq,eq_fid.fid);
        ret = ofi_pep_bind_eq(&pep_l3->util_pep, eq_l2, flags);
        if (ret == FI_SUCCESS) {
            struct dpdk_fabric* fabric_l3 = container_of(pep_l3->util_pep.fabric,struct dpdk_fabric,util_eq);
            fabric_l3->util_eq = eq_l2;
        }
        break;
    default:
        DPDK_WARN(FI_LOG_EP_CTRL,
            "%s: invalid FID class %lu. Expecting FI_CLASS_EQ(%d) only.\n",
            __func__, bfid->fclass, FI_CLASS_EQ);
        ret = -FI_EINVAL;
    }
    return ret;
}

// === PEP functions ===
static struct fi_ops dpdk_pep_fi_ops = {
    .size     = sizeof(struct fi_ops),
    .close    = fi_no_close,
    .bind     = dpdk_pep_bind,
    .control  = fi_no_control,
    .ops_open = fi_no_ops_open,
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

    pep->util_pep.pep_fid.fid.ops = &dpdk_pep_fi_ops;
    pep->util_pep.pep_fid.cm      = &dpdk_pep_cm_ops;
    pep->util_pep.pep_fid.ops     = &dpdk_pep_ops;

    pep->state = DPDK_PEP_INIT;
    pep->info  = fi_dupinfo(info);
    if (!pep->info) {
        ret = -FI_ENOMEM;
        goto err2;
    }

    // TODO: Here we first set the ops to pep->util_pep, then we pass the pointer to the caller.
    // Instead, in the dpdk_endpoint(), we first pass the pointer to the caller, then we set the
    // ops to the caller. We should be consistent and choose one of the two approaches!
    *pep_fid = &pep->util_pep.pep_fid;
    return FI_SUCCESS;
err2:
    ofi_pep_close(&pep->util_pep);
err1:
    free(pep);
    return ret;
}
