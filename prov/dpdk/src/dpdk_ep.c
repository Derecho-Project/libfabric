#include "fi_dpdk.h"

#include <ifaddrs.h>
#include <net/if.h>
#include <poll.h>
#include <sys/types.h>

#include <ofi_util.h>

static struct fi_ops_eq dpdk_eq_ops = {
    // TODO: Implement these functions
    // .size = sizeof(struct fi_ops_eq),
    // .read = dpdk_eq_read,
    // .readerr = ofi_eq_readerr,
    // .sread = ofi_eq_sread,
    // .write = ofi_eq_write,
    // .strerror = ofi_eq_strerror,
};

static struct fi_ops dpdk_eq_fi_ops = {
    // TODO: Implement these functions
    // .size = sizeof(struct fi_ops),
    // .close = dpdk_eq_close,
    // .bind = fi_no_bind,
    // .control = ofi_eq_control,
    // .ops_open = fi_no_ops_open,
};

int dpdk_endpoint(struct fid_domain *domain, struct fi_info *info, struct fid_ep **ep_fid,
                  void *context) {
    //     struct dpdk_ep          *ep;
    //     struct dpdk_pep         *pep;
    //     struct dpdk_conn_handle *handle;
    int ret = 0;

    printf("[dpdk_endpoint] UNIMPLEMENTED\n");

    //     ep = calloc(1, sizeof(*ep));
    //     if (!ep)
    //         return -FI_ENOMEM;

    //     ret = ofi_endpoint_init(domain, &dpdk_util_prov, info, &ep->util_ep, context, NULL);
    //     if (ret)
    //         goto err1;

    //     ofi_bsock_init(&ep->bsock, dpdk_staging_sbuf_size, dpdk_prefetch_rbuf_size);
    //     if (info->handle) {
    //         if (((fid_t)info->handle)->fclass == FI_CLASS_PEP) {
    //             pep = container_of(info->handle, struct dpdk_pep, util_pep.pep_fid.fid);

    //             ep->bsock.sock = pep->sock;
    //             pep->sock      = INVALID_SOCKET;
    //         } else {
    //             ep->state = DPDK_RCVD_REQ;
    //             handle    = container_of(info->handle, struct dpdk_conn_handle, fid);
    //             /* EP now owns socket */
    //             ep->bsock.sock = handle->sock;
    //             handle->sock   = INVALID_SOCKET;
    //             ep->hdr_bswap  = handle->endian_match ? dpdk_hdr_none : dpdk_hdr_bswap;
    //             /* Save handle, but we only free if user calls accept.
    //              * Otherwise, user will call reject, which will free it.
    //              */
    //             ep->handle = handle;

    //             ret = dpdk_setup_socket(ep->bsock.sock, info);
    //             if (ret)
    //                 goto err3;
    //         }
    //     } else {
    //         ep->bsock.sock = ofi_socket(ofi_get_sa_family(info), SOCK_STREAM, 0);
    //         if (ep->bsock.sock == INVALID_SOCKET) {
    //             ret = -ofi_sockerr();
    //             goto err2;
    //         }

    //         ret = dpdk_setup_socket(ep->bsock.sock, info);
    //         if (ret)
    //             goto err3;

    //         dpdk_set_zerocopy(ep->bsock.sock);

    //         if (info->src_addr &&
    //             (!ofi_is_any_addr(info->src_addr) || ofi_addr_get_port(info->src_addr)))
    //         {

    //             if (!ofi_addr_get_port(info->src_addr)) {
    //                 dpdk_set_no_port(ep->bsock.sock);
    //             }

    //             ret = bind(ep->bsock.sock, info->src_addr, (socklen_t)info->src_addrlen);
    //             if (ret) {
    //                 FI_WARN(&dpdk_prov, FI_LOG_EP_CTRL, "bind failed\n");
    //                 ret = -ofi_sockerr();
    //                 goto err3;
    //             }
    //         }
    //     }

    //     ret = ofi_mutex_init(&ep->lock);
    //     if (ret)
    //         goto err3;

    //     slist_init(&ep->rx_queue);
    //     slist_init(&ep->tx_queue);
    //     slist_init(&ep->priority_queue);
    //     slist_init(&ep->rma_read_queue);
    //     slist_init(&ep->need_ack_queue);
    //     slist_init(&ep->async_queue);

    //     if (info->ep_attr->rx_ctx_cnt != FI_SHARED_CONTEXT)
    //         ep->rx_avail = (int)info->rx_attr->size;

    //     ep->cur_rx.hdr_done     = 0;
    //     ep->cur_rx.hdr_len      = sizeof(ep->cur_rx.hdr.base_hdr);
    //     ep->min_multi_recv_size = DPDK_MIN_MULTI_RECV;
    //     dpdk_config_bsock(&ep->bsock);
    //     ep->report_success = dpdk_report_success;

    //     *ep_fid            = &ep->util_ep.ep_fid;
    //     (*ep_fid)->fid.ops = &dpdk_ep_fi_ops;
    //     (*ep_fid)->ops     = &dpdk_ep_ops;
    //     (*ep_fid)->cm      = &dpdk_cm_ops;
    //     (*ep_fid)->msg     = &dpdk_msg_ops;
    //     (*ep_fid)->rma     = &dpdk_rma_ops;
    //     (*ep_fid)->tagged  = &dpdk_tagged_ops;

    //     return 0;
    // err3:
    //     ofi_close_socket(ep->bsock.sock);
    // err2:
    //     ofi_endpoint_close(&ep->util_ep);
    // err1:
    //     free(ep);
    return ret;
}

int dpdk_passive_ep(struct fid_fabric *fabric, struct fi_info *info, struct fid_pep **pep_fid,
                    void *context) {
    struct dpdk_pep *pep;
    int              ret = 0;

    printf("[dpdk_passive_ep] UNIMPLEMENTED\n");

    //     if (!info) {
    //         FI_WARN(&dpdk_prov, FI_LOG_EP_CTRL, "invalid info\n");
    //         return -FI_EINVAL;
    //     }

    //     ret = ofi_prov_check_info(&dpdk_util_prov, fabric->api_version, info);
    //     if (ret)
    //         return ret;

    //     pep = calloc(1, sizeof(*pep));
    //     if (!pep)
    //         return -FI_ENOMEM;

    //     ret = ofi_pep_init(fabric, info, &pep->util_pep, context);
    //     if (ret)
    //         goto err1;

    //     pep->util_pep.pep_fid.fid.ops = &dpdk_pep_fi_ops;
    //     pep->util_pep.pep_fid.cm      = &dpdk_pep_cm_ops;
    //     pep->util_pep.pep_fid.ops     = &dpdk_pep_ops;

    //     pep->info = fi_dupinfo(info);
    //     if (!pep->info) {
    //         ret = -FI_ENOMEM;
    //         goto err2;
    //     }

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

    //     *pep_fid = &pep->util_pep.pep_fid;
    //     return FI_SUCCESS;
    // err3:
    //     fi_freeinfo(pep->info);
    // err2:
    //     ofi_pep_close(&pep->util_pep);
    // err1:
    //     free(pep);
    return ret;
}
