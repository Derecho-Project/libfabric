#include "fi_dpdk.h"

// declared in dpdk_attr.c, contains provider-spec attributes and default config
static int dpdk_getinfo(uint32_t version, const char *node, const char *service, uint64_t flags,
                        const struct fi_info *hints, struct fi_info **info) {

    // TODO: Consider the hints and flags, as well as the version, node, and service parameters
    // TODO:: For the moment, I have inserted here some default values, but we should really just
    // take them from those listed in dpdk_attr.c, which we shoud also check for correctness! E.g.,
    // we should find the correct correspondence between the DPDK device and the OFI device.

    // Iterate over the avilable DPDK devices. For each device, create a new fi_info struct and add
    // it to the info list. => We should filter this list based on the hints, but for now we just
    // ignore that
    uint16_t port_id;
    RTE_ETH_FOREACH_DEV(port_id) {

        // get DPDK device info
        struct rte_eth_dev_info dev_info;
        rte_eth_dev_info_get(port_id, &dev_info);

        // Create a new fi_info struct. Who frees this memory?
        struct fi_info *new_info = ofi_allocinfo_internal();
        if (!new_info) {
            return -FI_ENOMEM;
        }

        // Capabilities from dpdk_attr.c => check if they are correct!
        new_info->caps = dpdk_util_prov.info->caps;
        new_info->mode = dpdk_util_prov.info->mode;

        // Fabric info from dpdk_attr.c
        new_info->fabric_attr->name =
            (char *)malloc(strlen(dpdk_util_prov.info->fabric_attr->name) + 1);
        bzero(new_info->fabric_attr->name, strlen(dpdk_util_prov.info->fabric_attr->name) + 1);
        strcpy(new_info->fabric_attr->name, dpdk_util_prov.info->fabric_attr->name);
        new_info->fabric_attr->api_version = dpdk_util_prov.info->fabric_attr->api_version;

        // Domain info //TODO: check the correspondence with the values in dpdk_attr.c
        new_info->domain_attr->name = (char *)malloc(strlen(dev_info.device->name) + 1);
        bzero(new_info->domain_attr->name, strlen(dev_info.device->name) + 1);
        // if_indextoname(dev_info.if_index, new_info->domain_attr->name);
        strcpy(new_info->domain_attr->name, dev_info.device->name);
        new_info->domain_attr->av_type = dpdk_util_prov.info->domain_attr->av_type;

        // Endpoint type can be:
        // FI_EP_MSG Reliable-connected => Assuming our impl!
        // FI_EP_DGRAM Unreliable datagram => Should we also enable this?
        // FI_EP_RDM Reliable-unconnected
        new_info->ep_attr->protocol = dpdk_util_prov.info->ep_attr->protocol;
        new_info->ep_attr->type     = dpdk_util_prov.info->ep_attr->type;

        // Add the new fi_info to the list
        new_info->next = *info;
        *info          = new_info;
    }

    return 0;
}

static void fi_dpdk_fini(void) {

    rte_eal_cleanup();
}

struct fi_provider dpdk_prov = {
    .name       = "dpdk",
    .version    = OFI_VERSION_DEF_PROV,
    .fi_version = OFI_VERSION_LATEST,
    .getinfo    = dpdk_getinfo,
    .fabric     = dpdk_create_fabric,
    .cleanup    = fi_dpdk_fini,
};

DPDK_INI {
    // TODO: These arguments should be received as parameters from the caller, to enable for a more
    // flexible use of DPDK
    int   argc   = 1;
    char *argv[] = {"libfabric"};

    // TODO: Limit the number of cores to dedicate to DPDK!

    // Initialize the EAL
    if (rte_eal_init(argc, argv) < 0) {
        FI_WARN(&dpdk_prov, FI_LOG_CORE, "Error with EAL initialization\n");
        return NULL;
    }

    return &dpdk_prov;
}
