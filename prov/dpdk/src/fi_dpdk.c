#include "fi_dpdk.h"

// ================ The global variables ================
struct dpdk_params_t dpdk_params  = {
    .base_port      = DEFAULT_DPDK_BASE_PORT,           // FI_DPDK_BASE_PORT
    .cm_ring_size   = DEFAULT_DPDK_CM_RING_SIZE,        // FI_DPDK_CM_RING_SIZE
};

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

static void dpdk_init_env(void) {

    /* set the dpdk base port */
    fi_param_define(&dpdk_prov, "base_port", FI_PARAM_INT, "define dpdk base port");
    fi_param_get_int(&dpdk_prov, "base_port", &dpdk_params.base_port);
    if (dpdk_params.base_port < 0 && dpdk_params.base_port > 65535) {
        DPDK_WARN(FI_LOG_FABRIC, "User provided base_port %d is invalid."
            " Falling back to default base_port:%d instead. \n",
            dpdk_params.base_port, DEFAULT_DPDK_BASE_PORT);
        dpdk_params.base_port = DEFAULT_DPDK_BASE_PORT;
    }

    /* set the dpdk cm ring size */
    fi_param_define(&dpdk_prov, "cm_ring_size", FI_PARAM_SIZE_T, "define dpdk cm ring size");
    fi_param_get_size_t(&dpdk_prov, "cm_ring_size", &dpdk_params.cm_ring_size);
}

// Entry point for the libfabric provider
DPDK_INI {
    // set up the environment
    dpdk_init_env();

    int   argc   = 1;
    char *argv[] = {"libfabric"};

    // TODO: Limit the number of cores to dedicate to DPDK!

    // Initialize the EAL
    if (rte_eal_init(argc, argv) < 0) {
        FI_WARN(&dpdk_prov, FI_LOG_CORE, "Error with EAL initialization\n");
        return NULL;
    }

    // initialize dpdk info
    dpdk_init_info(&(dpdk_util_prov.info));

    return &dpdk_prov;
}
