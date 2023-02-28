#include "fi_dpdk.h"

int dpdk_srx_context(struct fid_domain *domain, struct fi_rx_attr *attr, struct fid_ep **rx_ep,
                     void *context) {
    // struct dpdk_rx_ctx *srx;
    int ret = FI_SUCCESS;

    printf("[dpdk_srx_context] UNIMPLEMENTED\n");

    //     srx = calloc(1, sizeof(*srx));
    //     if (!srx)
    //         return -FI_ENOMEM;

    //     srx->rx_fid.fid.fclass  = FI_CLASS_SRX_CTX;
    //     srx->rx_fid.fid.context = context;
    //     srx->rx_fid.fid.ops     = &dpdk_srx_fid_ops;
    //     srx->rx_fid.ops         = &dpdk_srx_ops;

    //     srx->rx_fid.msg    = &dpdk_srx_msg_ops;
    //     srx->rx_fid.tagged = &dpdk_srx_tag_ops;
    //     slist_init(&srx->rx_queue);
    //     slist_init(&srx->tag_queue);

    //     ret = ofi_mutex_init(&srx->lock);
    //     if (ret)
    //         goto err1;

    //     ret =
    //         ofi_bufpool_create(&srx->buf_pool, sizeof(struct dpdk_xfer_entry), 16, attr->size,
    //         1024, 0);
    //     if (ret)
    //         goto err2;

    //     srx->match_tag_rx = (attr->caps & FI_DIRECTED_RECV) ? dpdk_match_tag_addr :
    //     dpdk_match_tag; srx->op_flags     = attr->op_flags; *rx_ep            = &srx->rx_fid;
    //     return FI_SUCCESS;
    // err2:
    //     ofi_mutex_destroy(&srx->lock);
    // err1:
    //     free(srx);
    return ret;
}