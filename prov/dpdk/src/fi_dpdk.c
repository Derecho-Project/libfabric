#include "fi_dpdk.h"

// ================ Provider Initialization Functions =================
static void fi_dpdk_fini(void) {

    rte_eal_cleanup();
}

// This function is implemented in dpdk_info.c
extern int dpdk_getinfo(uint32_t version, const char *node, const char *service, uint64_t flags,
                        const struct fi_info *hints, struct fi_info **info);
struct fi_provider dpdk_prov = {
    .name       = "dpdk",
    .version    = OFI_VERSION_DEF_PROV,
    .fi_version = OFI_VERSION_LATEST,
    .getinfo    = dpdk_getinfo,
    .fabric     = dpdk_create_fabric,
    .cleanup    = fi_dpdk_fini,
};

// Entry point for the libfabric provider
DPDK_INI {
    // TODO: These arguments should be received as parameters from the caller
    int   argc   = 3;
    char *argv[] = {"libfabric", "-b", "0000:05:00.0"};

    // TODO: Limit the number of cores to dedicate to DPDK!

    // Initialize the EAL
    if (rte_eal_init(argc, argv) < 0) {
        FI_WARN(&dpdk_prov, FI_LOG_CORE, "Error with EAL initialization\n");
        return NULL;
    }

    return &dpdk_prov;
}
