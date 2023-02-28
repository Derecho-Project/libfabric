#include "fi_dpdk.h"

#include <ifaddrs.h>
#include <net/if.h>
#include <poll.h>
#include <sys/types.h>

static struct fi_ops_domain dpdk_domain_ops = {
    .size             = sizeof(struct fi_ops_domain),
    .av_open          = ofi_ip_av_create,
    .cq_open          = dpdk_cq_open,
    .endpoint         = dpdk_endpoint,
    .scalable_ep      = fi_no_scalable_ep,
    .cntr_open        = dpdk_cntr_open,
    .poll_open        = fi_poll_create,
    .stx_ctx          = fi_no_stx_context,
    .srx_ctx          = dpdk_srx_context,
    .query_atomic     = fi_no_query_atomic,
    .query_collective = fi_no_query_collective,
};

static int dpdk_set_ops(struct fid *fid, const char *name, uint64_t flags, void *ops,
                        void *context) {
    struct dpdk_domain *domain;

    domain = container_of(fid, struct dpdk_domain, util_domain.domain_fid.fid);
    if (flags)
        return -FI_EBADFLAGS;

    if (!strcasecmp(name, OFI_OPS_DYNAMIC_RBUF)) {
        domain->dynamic_rbuf = ops;
        if (domain->dynamic_rbuf->size != sizeof(*domain->dynamic_rbuf)) {
            domain->dynamic_rbuf = NULL;
            return -FI_ENOSYS;
        }

        return 0;
    }

    return -FI_ENOSYS;
}

static int dpdk_domain_close(fid_t fid) {
    struct dpdk_domain *domain;
    int                 ret;

    domain = container_of(fid, struct dpdk_domain, util_domain.domain_fid.fid);

    ret = ofi_domain_close(&domain->util_domain);
    if (ret)
        return ret;

    free(domain);
    return FI_SUCCESS;
}

static struct fi_ops dpdk_domain_fi_ops = {
    .size     = sizeof(struct fi_ops),
    .close    = dpdk_domain_close,
    .bind     = ofi_domain_bind,
    .control  = fi_no_control,
    .ops_open = fi_no_ops_open,
    .tostr    = NULL,
    .ops_set  = dpdk_set_ops,
};

static struct fi_ops_mr dpdk_domain_fi_ops_mr = {
    .size    = sizeof(struct fi_ops_mr),
    .reg     = ofi_mr_reg,
    .regv    = ofi_mr_regv,
    .regattr = ofi_mr_regattr,
};

int dpdk_domain_open(struct fid_fabric *fabric, struct fi_info *info,
                     struct fid_domain **domain_fid, void *context) {
    struct dpdk_domain *domain;
    int                 ret;

    ret = ofi_prov_check_info(&dpdk_util_prov, fabric->api_version, info);
    if (ret) {
        return ret;
    }

    domain = calloc(1, sizeof(*domain));
    if (!domain) {
        return -FI_ENOMEM;
    }

    ret = ofi_domain_init(fabric, info, &domain->util_domain, context, OFI_LOCK_MUTEX);
    if (ret) {
        goto err;
    }

    domain->util_domain.domain_fid.fid.ops = &dpdk_domain_fi_ops;
    domain->util_domain.domain_fid.ops     = &dpdk_domain_ops;
    domain->util_domain.domain_fid.mr      = &dpdk_domain_fi_ops_mr;
    *domain_fid                            = &domain->util_domain.domain_fid;

    return FI_SUCCESS;
err:
    free(domain);
    return ret;
}
