#include "fi_dpdk.h"

#include <ifaddrs.h>
#include <net/if.h>
#include <poll.h>
#include <sys/types.h>

#include <ofi_util.h>

// ============== ACTIVE ENDPOINT ==============
// === Helper functions ===

static int dpdk_ep_bind(struct fid *fid, struct fid *bfid, uint64_t flags) {
    struct dpdk_ep *ep;
    struct dpdk_cq *cq = container_of(bfid, struct dpdk_cq, util_cq.cq_fid.fid);
    int             ret;

    ep  = container_of(fid, struct dpdk_ep, util_ep.ep_fid.fid);
    ret = ofi_ep_bind_valid(&dpdk_prov, bfid, flags);
    if (ret)
        return ret;

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

    // TODO: IMPLEMENT THIS FUNCTION
    printf("[dpdk_ep_connect] UNIMPLEMENTED\n");

    return 0;
}

static int dpdk_ep_accept(struct fid_ep *ep, const void *param, size_t paramlen) {

    printf("[dpdk_ep_accept] UNIMPLEMENTED\n");
    return 0;
}

// === EP functions ===
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

    ret = ofi_endpoint_init(domain, &dpdk_util_prov, info, &ep->util_ep, context, NULL);
    if (ret) {
        goto err1;
    }

    printf("[dpdk_endpoint] EP creation only partially implemented\n");

    // TODO: Initialize the structures
    ep->hdr_pool_name = malloc(64);
    sprintf(ep->hdr_pool_name, "hdr_pool_%s", ep->util_ep.domain->name);
    ep->hdr_pool = rte_pktmbuf_pool_create(ep->hdr_pool_name, 10240, 64, 0,
                                           RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    *ep_fid            = &ep->util_ep.ep_fid;
    (*ep_fid)->fid.ops = &dpdk_ep_fi_ops;
    // (*ep_fid)->ops     = &dpdk_ep_ops;
    (*ep_fid)->cm  = &dpdk_cm_ops;
    (*ep_fid)->msg = &dpdk_msg_ops;
    //     (*ep_fid)->rma     = &dpdk_rma_ops;
    //     (*ep_fid)->tagged  = &dpdk_tagged_ops;

    // Add this EP to EP list of the domain, and increase the associated values
    // MUST be done while holding the lock on the list.
    struct dpdk_domain *dpdk_domain =
        container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);
    ofi_genlock_lock(&dpdk_domain->ep_mutex);
    slist_insert_tail(&ep->entry, &dpdk_domain->endpoint_list);
    dpdk_domain->num_endpoints++;
    u_int16_t base_udp_port                   = *((u_int16_t *)dpdk_domain->address);
    ep->udp_port                              = base_udp_port + (dpdk_domain->num_endpoints - 1);
    dpdk_domain->udp_port_to_ep[ep->udp_port] = ep;
    ofi_genlock_unlock(&dpdk_domain->ep_mutex);

    return 0;

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
