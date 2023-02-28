#include "fi_dpdk.h"

int dpdk_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr, struct fid_cq **cq_fid,
                 void *context) {
    // struct dpdk_cq   *cq;
    // struct fi_cq_attr cq_attr;
    int ret;

    // TODO: Implementation of the completion queue
    printf("[dpdk_cq_open] UNIMPLEMENTED\n");

    //     cq = calloc(1, sizeof(*cq));
    //     if (!cq) {
    //         return -FI_ENOMEM;
    //     }

    //     if (!attr->size) {
    //         attr->size = DPDK_DEF_CQ_SIZE;
    //     }

    //     ret = ofi_bufpool_create(&cq->xfer_pool, sizeof(struct dpdk_xfer_entry), 16, 0, 1024, 0);
    //     if (ret) {
    //         goto free_cq;
    //     }

    //     if (attr->wait_obj == FI_WAIT_NONE || attr->wait_obj == FI_WAIT_UNSPEC) {
    //         cq_attr          = *attr;
    //         cq_attr.wait_obj = FI_WAIT_POLLFD;
    //         attr             = &cq_attr;
    //     }

    //     ret = ofi_cq_init(&dpdk_prov, domain, attr, &cq->util_cq, &dpdk_cq_progress, context);
    //     if (ret) {
    //         goto destroy_pool;
    //     }

    //     *cq_fid            = &cq->util_cq.cq_fid;
    //     (*cq_fid)->fid.ops = &dpdk_cq_fi_ops;
    //     return 0;

    // destroy_pool:
    //     ofi_bufpool_destroy(cq->xfer_pool);
    // free_cq:
    //     free(cq);
    return ret;
}

int dpdk_cntr_open(struct fid_domain *fid_domain, struct fi_cntr_attr *attr,
                   struct fid_cntr **cntr_fid, void *context) {
    // struct util_cntr   *cntr;
    // struct fi_cntr_attr cntr_attr;
    int ret = 0;

    printf("[dpdk_cntr_open] UNIMPLEMENTED\n");

    //     cntr = calloc(1, sizeof(*cntr));
    //     if (!cntr)
    //         return -FI_ENOMEM;

    //     if (attr->wait_obj == FI_WAIT_NONE || attr->wait_obj == FI_WAIT_UNSPEC) {
    //         cntr_attr          = *attr;
    //         cntr_attr.wait_obj = FI_WAIT_POLLFD;
    //         attr               = &cntr_attr;
    //     }

    //     ret = ofi_cntr_init(&dpdk_prov, fid_domain, attr, cntr, &dpdk_cntr_progress, context);
    //     if (ret)
    //         goto free;

    //     *cntr_fid = &cntr->cntr_fid;
    //     return FI_SUCCESS;

    // free:
    //     free(cntr);
    return ret;
}
