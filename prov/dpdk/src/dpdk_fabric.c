#include "fi_dpdk.h"

#include <ifaddrs.h>
#include <net/if.h>
#include <poll.h>
#include <sys/types.h>

#include <ofi_util.h>

// Declared in fi_dpdk.c
extern struct fi_provider dpdk_prov;

struct fi_ops_fabric dpdk_fabric_ops = {.size       = sizeof(struct fi_ops_fabric),
                                        .domain     = dpdk_domain_open,
                                        .passive_ep = dpdk_passive_ep,
                                        .eq_open    = dpdk_eq_create,
                                        .wait_open  = ofi_wait_fd_open,
                                        .trywait    = ofi_trywait};

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
struct fi_ops dpdk_fabric_fi_ops = {
    .size     = sizeof(struct fi_ops),
    .close    = dpdk_fabric_close,
    .bind     = fi_no_bind,
    .control  = fi_no_control,
    .ops_open = fi_no_ops_open,
};

int dpdk_create_fabric(struct fi_fabric_attr *attr, struct fid_fabric **fabric_fid, void *context) {
    struct dpdk_fabric *fabric;
    int                 ret;

    fabric = calloc(1, sizeof(struct dpdk_fabric));
    if (!fabric) {
        return -FI_ENOMEM;
    }

    ret = ofi_fabric_init(&dpdk_prov, dpdk_util_prov.info->fabric_attr, attr, &fabric->util_fabric,
                          context);
    if (ret) {
        printf("ofi_fabric_init failed: %s\n", fi_strerror(-ret));
        free(fabric);
        return ret;
    }

    fabric->util_fabric.fabric_fid.fid.ops = &dpdk_fabric_fi_ops;
    fabric->util_fabric.fabric_fid.ops     = &dpdk_fabric_ops;
    *fabric_fid                            = &fabric->util_fabric.fabric_fid;

    printf("dpdk_create_fabric successful\n");

    return 0;
}