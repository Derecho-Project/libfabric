#include "fi_dpdk.h"

static int dpdk_fabric_close(fid_t fid) {
    int                 ret;
    struct dpdk_fabric *fabric;

    fabric = container_of(fid, struct dpdk_fabric, util_fabric.fabric_fid.fid);

    ret = ofi_fabric_close(&fabric->util_fabric);
    if (ret)
        return ret;

    free(fabric);
    return 0;
}

struct fi_ops_fabric dpdk_fabric_ops = {
    .size       = sizeof(struct fi_ops_fabric),
    .domain     = dpdk_domain_open,
    .passive_ep = dpdk_passive_ep,
    .eq_open    = dpdk_eq_open,
    .wait_open  = ofi_wait_fd_open,
    .trywait    = ofi_trywait,
    .domain2    = fi_no_domain2
};

struct fi_ops dpdk_fabric_fi_ops = {
    .size     = sizeof(struct fi_ops),
    .close    = dpdk_fabric_close,
    .bind     = fi_no_bind,
    .control  = fi_no_control,
    .ops_open = fi_no_ops_open,
    .ops_set  = fi_no_ops_set
};

int dpdk_create_fabric(struct fi_fabric_attr *attr, struct fid_fabric **fabric_fid, void *context) {
    struct dpdk_fabric *fabric;
    int                 ret;

    fabric = calloc(1, sizeof(*fabric));
    if (!fabric)
        return -FI_ENOMEM;

    ret = ofi_fabric_init(&dpdk_prov, dpdk_util_prov.info->fabric_attr, attr, &fabric->util_fabric,
                          context);
    if (ret)
        goto free;

    fabric->util_fabric.fabric_fid.fid.ops = &dpdk_fabric_fi_ops;
    fabric->util_fabric.fabric_fid.ops     = &dpdk_fabric_ops;
    *fabric_fid                            = &fabric->util_fabric.fabric_fid;

    return 0;

close:
    (void)ofi_fabric_close(&fabric->util_fabric);
free:
    free(fabric);
    return ret;
}
