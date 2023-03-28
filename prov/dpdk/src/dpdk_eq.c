#include "fi_dpdk.h"

/* If we don't have an EQ, then we're writing an event for an rdm ep.
 * That goes directly on the rdm event list.
 *
int dpdk_eq_write(struct util_eq *eq, uint32_t event, const void *buf, size_t len, uint64_t flags) {
    return (int)fi_eq_write(&eq->eq_fid, event, buf, len, flags);
}

static ssize_t dpdk_eq_read(struct fid_eq *eq_fid, uint32_t *event, void *buf, size_t len,
                            uint64_t flags) {
    return ofi_eq_read(eq_fid, event, buf, len, flags);
}
*/

static int dpdk_eq_close(struct fid *fid) {
    struct dpdk_eq *eq;
    int             ret;

    ret = ofi_eq_cleanup(fid);
    if (ret)
        return ret;

    eq = container_of(fid, struct dpdk_eq, util_eq.eq_fid.fid);

    ofi_mutex_destroy(&eq->close_lock);
    free(eq);
    return 0;
}

static struct fi_ops_eq dpdk_eq_ops = {
    .size     = sizeof(struct fi_ops_eq),
    .read     = ofi_eq_read,
    .readerr  = ofi_eq_readerr,
    .sread    = ofi_eq_sread,
    .write    = ofi_eq_write,
    .strerror = ofi_eq_strerror,
};

static struct fi_ops dpdk_eq_fi_ops = {
    .size     = sizeof(struct fi_ops),
    .close    = dpdk_eq_close,
    .bind     = fi_no_bind,
    .control  = ofi_eq_control,
    .ops_open = fi_no_ops_open,
};

int dpdk_eq_open(struct fid_fabric *fabric_fid, struct fi_eq_attr *attr, struct fid_eq **eq_fid,
                 void *context) {
    struct dpdk_eq *eq;
    int             ret;

    eq = calloc(1, sizeof(*eq));
    if (!eq)
        return -FI_ENOMEM;

    ret = ofi_eq_init(fabric_fid, attr, &eq->util_eq.eq_fid, context);
    if (ret) {
        FI_WARN(&dpdk_prov, FI_LOG_EQ, "EQ creation failed\n");
        goto err1;
    }

    ret = ofi_mutex_init(&eq->close_lock);
    if (ret)
        goto err2;

    eq->util_eq.eq_fid.ops     = &dpdk_eq_ops;
    eq->util_eq.eq_fid.fid.ops = &dpdk_eq_fi_ops;

    *eq_fid = &eq->util_eq.eq_fid;
    return 0;

err2:
    ofi_mutex_destroy(&eq->close_lock);
err1:
    ofi_eq_cleanup(&eq->util_eq.eq_fid.fid);
    free(eq);
    return ret;
}
