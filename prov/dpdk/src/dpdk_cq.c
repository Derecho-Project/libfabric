#include "fi_dpdk.h"

static ssize_t dpdk_cq_readfrom(struct fid_cq *cq_fid, void *buf, size_t count,
                                fi_addr_t *src_addr) {
    struct dpdk_cq     *cq;
    ssize_t             ret;
    struct dpdk_domain *domain;
    domain = container_of(cq->util_cq.domain, struct dpdk_domain, util_domain);

    cq = container_of(cq_fid, struct dpdk_cq, util_cq.cq_fid);
    ofi_genlock_lock(&domain->progress.lock);
    ret = ofi_cq_readfrom(cq_fid, buf, count, src_addr);
    ofi_genlock_unlock(&domain->progress.lock);
    return ret;
}

static ssize_t dpdk_cq_readerr(struct fid_cq *cq_fid, struct fi_cq_err_entry *buf, uint64_t flags) {
    struct dpdk_cq     *cq;
    ssize_t             ret;
    struct dpdk_domain *domain;
    domain = container_of(cq->util_cq.domain, struct dpdk_domain, util_domain);

    cq = container_of(cq_fid, struct dpdk_cq, util_cq.cq_fid);
    ofi_genlock_lock(&domain->progress.lock);
    ret = ofi_cq_readerr(cq_fid, buf, flags);
    ofi_genlock_unlock(&domain->progress.lock);
    return ret;
}

static int dpdk_cq_close(struct fid *fid) {
    int             ret;
    struct dpdk_cq *cq;

    cq  = container_of(fid, struct dpdk_cq, util_cq.cq_fid.fid);
    ret = ofi_cq_cleanup(&cq->util_cq);
    if (ret)
        return ret;

    free(cq);
    return 0;
}

static int dpdk_cq_control(struct fid *fid, int command, void *arg) {
    struct util_cq *cq;
    int             ret;

    cq = container_of(fid, struct util_cq, cq_fid.fid);

    switch (command) {
    case FI_GETWAIT:
    case FI_GETWAITOBJ:
        if (!cq->wait)
            return -FI_ENODATA;

        ret = fi_control(&cq->wait->wait_fid.fid, command, arg);
        break;
    default:
        return -FI_ENOSYS;
    }

    return ret;
}

static struct fi_ops dpdk_cq_fi_ops = {
    .size     = sizeof(struct fi_ops),
    .close    = dpdk_cq_close,
    .bind     = fi_no_bind,
    .control  = dpdk_cq_control,
    .ops_open = fi_no_ops_open,
};

static struct fi_ops_cq dpdk_cq_ops = {
    .size      = sizeof(struct fi_ops_cq),
    .read      = ofi_cq_read,
    .readfrom  = dpdk_cq_readfrom,
    .readerr   = dpdk_cq_readerr,
    .sread     = ofi_cq_sread,
    .sreadfrom = ofi_cq_sreadfrom,
    .signal    = ofi_cq_signal,
    .strerror  = ofi_cq_strerror,
};

static void dpdk_cq_progress(struct util_cq *util_cq) {
    struct dpdk_cq *cq;
    cq = container_of(util_cq, struct dpdk_cq, util_cq);
    printf("[dpdk_cq_progress] UNIMPLEMENTED\n");

    // TODO: What am I supposed to put here?
    // dpdk_run_progress(dpdk_cq2_progress(cq), false);
}

static int dpdk_cq_wait_try_func(void *arg) {
    OFI_UNUSED(arg);
    return FI_SUCCESS;
}

int dpdk_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr, struct fid_cq **cq_fid,
                 void *context) {
    struct dpdk_fabric *fabric;
    struct dpdk_cq     *cq;
    struct fi_cq_attr   cq_attr;
    int                 ret;

    cq = calloc(1, sizeof(*cq));
    if (!cq)
        return -FI_ENOMEM;

    if (!attr->size)
        attr->size = DPDK_DEF_CQ_SIZE;

    if (attr->wait_obj == FI_WAIT_UNSPEC) {
        cq_attr          = *attr;
        cq_attr.wait_obj = FI_WAIT_POLLFD;
        attr             = &cq_attr;
    }

    ret = ofi_cq_init(&dpdk_prov, domain, attr, &cq->util_cq, &dpdk_cq_progress, context);
    if (ret)
        goto free_cq;

    *cq_fid            = &cq->util_cq.cq_fid;
    (*cq_fid)->fid.ops = &dpdk_cq_fi_ops;
    (*cq_fid)->ops     = &dpdk_cq_ops;
    return 0;

cleanup:
    ofi_cq_cleanup(&cq->util_cq);
free_cq:
    free(cq);
    return ret;
}
