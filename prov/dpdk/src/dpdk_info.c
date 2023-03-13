
#include "fi_dpdk.h"

#include <ifaddrs.h>
#include <net/if.h>
#include <poll.h>
#include <sys/types.h>

#include <ofi_util.h>

// TODO: This file is copied from the TCP provider. It seems to define the capabilities of the
// provider in a single place. Plus, it contains the declaration of the default values for the
// attributes of the provider. We MUST check if these values are correct for the DPDK provider. E.g.
// the format of the domain name which should be the PCI address instead of the kernel interface
// name.

// TODO: This address must be passed by the application
#define LF_IP_ADDR_DEFAULT "192.168.56.211"

// TODO: This is the base UDP port of the Libfabric DPDK provider. It is used as a base to assign
// UDP ports to different EPs. This might become a parameter of the provider.
#define LF_PORT_DEFAULT 2509

#define DPDK_DOMAIN_CAPS (FI_REMOTE_COMM)
#define DPDK_EP_CAPS     (FI_MSG | FI_RMA)
#define DPDK_TX_CAPS     (FI_SEND | FI_WRITE | FI_READ | FI_ATOMIC)
#define DPDK_RX_CAPS     (FI_RECV | FI_REMOTE_READ | FI_REMOTE_WRITE | FI_RMA_EVENT | FI_ATOMIC)

#define DPDK_MSG_ORDER                                                                             \
    (OFI_ORDER_RAR_SET | OFI_ORDER_RAW_SET | FI_ORDER_RAS | OFI_ORDER_WAW_SET | FI_ORDER_WAS |     \
     FI_ORDER_SAW | FI_ORDER_SAS)

#define DPDK_TX_OP_FLAGS                                                                           \
    (FI_INJECT | FI_INJECT_COMPLETE | FI_TRANSMIT_COMPLETE | FI_DELIVERY_COMPLETE |                \
     FI_COMMIT_COMPLETE | FI_COMPLETION)

#define DPDK_RX_OP_FLAGS (FI_COMPLETION)

#define DPDK_MAX_INJECT 128

static struct fi_tx_attr dpdk_tx_attr = {
    .caps          = DPDK_EP_CAPS | DPDK_TX_CAPS,
    .op_flags      = DPDK_TX_OP_FLAGS,
    .comp_order    = FI_ORDER_STRICT,
    .msg_order     = DPDK_MSG_ORDER,
    .inject_size   = DPDK_MAX_INJECT,
    .size          = 1024,
    .iov_limit     = DPDK_IOV_LIMIT,
    .rma_iov_limit = DPDK_IOV_LIMIT,
};

static struct fi_rx_attr dpdk_rx_attr = {.caps                = DPDK_EP_CAPS | DPDK_RX_CAPS,
                                         .op_flags            = DPDK_RX_OP_FLAGS,
                                         .comp_order          = FI_ORDER_STRICT,
                                         .msg_order           = DPDK_MSG_ORDER,
                                         .total_buffered_recv = 0,
                                         .size                = 65536,
                                         .iov_limit           = DPDK_IOV_LIMIT};

static struct fi_ep_attr dpdk_ep_attr = {
    .type               = FI_EP_MSG,
    .protocol           = FI_PROTO_IWARP, // TODO: that is important! Changed to iWARP
    .protocol_version   = 0,
    .max_msg_size       = SIZE_MAX,
    .tx_ctx_cnt         = 1,
    .rx_ctx_cnt         = 1,
    .max_order_raw_size = SIZE_MAX,
    .max_order_waw_size = SIZE_MAX,
};

// TODO: What are these values? What is the name here? Why not an interface/PCI address?
static struct fi_domain_attr dpdk_domain_attr = {
    .name             = "dpdk",
    .caps             = DPDK_DOMAIN_CAPS,
    .threading        = FI_THREAD_SAFE,
    .control_progress = FI_PROGRESS_AUTO,
    .data_progress    = FI_PROGRESS_AUTO,
    .resource_mgmt    = FI_RM_ENABLED,
    .mr_mode          = FI_MR_BASIC,
    .mr_key_size      = sizeof(uint64_t),
    .av_type          = FI_AV_MAP, // Changed this. Not sure, though.
    .cq_data_size     = sizeof(uint64_t),
    .cq_cnt           = 256,
    .ep_cnt           = 8192,
    .tx_ctx_cnt       = 8192,
    .rx_ctx_cnt       = 8192,
    .max_ep_srx_ctx   = 8192,
    .max_ep_tx_ctx    = 1,
    .max_ep_rx_ctx    = 1,
    .mr_iov_limit     = 1,
};

static struct fi_fabric_attr dpdk_fabric_attr = {
    .name         = "DPDK",
    .prov_version = OFI_VERSION_DEF_PROV,
    .api_version  = OFI_VERSION_LATEST,
};

struct fi_info dpdk_info = {.next = NULL,
                            .caps = DPDK_DOMAIN_CAPS | DPDK_EP_CAPS | DPDK_TX_CAPS | DPDK_RX_CAPS,
                            .tx_attr     = &dpdk_tx_attr,
                            .rx_attr     = &dpdk_rx_attr,
                            .ep_attr     = &dpdk_ep_attr,
                            .domain_attr = &dpdk_domain_attr,
                            .fabric_attr = &dpdk_fabric_attr,
                            .addr_format = FI_FORMAT_UNSPEC,
                            .src_addrlen = sizeof(uint64_t)};

size_t dpdk_default_tx_size       = 256; // TODO: What is this?
size_t dpdk_default_rx_size       = 256; // TODO: What is this?
size_t dpdk_max_inject            = 128; // TODO: What is this?
size_t dpdk_default_tx_burst_size = 32;  // TODO: Why here? Should be a configurable parameter...
size_t dpdk_default_rx_burst_size = 32;  // TODO: Why here? Should be a configurable parameter...

/* User hints will still override the modified dest_info attributes
 * through ofi_alter_info
 */
static void dpdk_alter_defaults(uint32_t version, const struct fi_info *hints,
                                const struct fi_info *base_info, struct fi_info *dest_info) {
    dest_info->tx_attr->size = dpdk_default_tx_size;
    if ((base_info->ep_attr->rx_ctx_cnt != FI_SHARED_CONTEXT) && hints && hints->ep_attr &&
        (hints->ep_attr->rx_ctx_cnt != FI_SHARED_CONTEXT))
        dest_info->rx_attr->size = dpdk_default_rx_size;
}

struct util_prov dpdk_util_prov = {
    .prov           = &dpdk_prov,
    .info           = &dpdk_info,
    .alter_defaults = &dpdk_alter_defaults,
    .flags          = 0,
};

int dpdk_getinfo(uint32_t version, const char *node, const char *service, uint64_t flags,
                 const struct fi_info *hints, struct fi_info **info) {

    // TODO: Consider the hints and flags, as well as the version, node, and service parameters
    // TODO:: For the moment, I have inserted here some default values, but we should really just
    // take them from those listed in dpdk_info.c, which we shoud also check for correctness! E.g.,
    // we should find the correct correspondence between the DPDK device and the OFI device.

    // TODO: The Node parameter is the IP address the application is passing to the provider

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

        // Capabilities from dpdk_info.c => check if they are correct!
        new_info->caps = dpdk_util_prov.info->caps;
        new_info->mode = dpdk_util_prov.info->mode;

        // Fabric info from dpdk_info.c
        new_info->fabric_attr->name =
            (char *)malloc(strlen(dpdk_util_prov.info->fabric_attr->name) + 1);
        bzero(new_info->fabric_attr->name, strlen(dpdk_util_prov.info->fabric_attr->name) + 1);
        strcpy(new_info->fabric_attr->name, dpdk_util_prov.info->fabric_attr->name);
        new_info->fabric_attr->api_version = dpdk_util_prov.info->fabric_attr->api_version;

        // Domain info //TODO: check the correspondence with the values in dpdk_info.c
        new_info->domain_attr->name = (char *)malloc(strlen(rte_dev_name(dev_info.device)) + 1);
        bzero(new_info->domain_attr->name, strlen(rte_dev_name(dev_info.device)) + 1);
        // if_indextoname(dev_info.if_index, new_info->domain_attr->name);
        strcpy(new_info->domain_attr->name, rte_dev_name(dev_info.device));
        new_info->domain_attr->av_type = dpdk_util_prov.info->domain_attr->av_type;

        new_info->addr_format = dpdk_util_prov.info->addr_format;
        new_info->src_addrlen = dpdk_util_prov.info->src_addrlen;

        // TODO: Address info must become a parameter!!
        new_info->src_addr = (void *)malloc(dpdk_util_prov.info->src_addrlen);
        // The highest 32 bits of the src_addr are the IP address
        uint32_t ip_addr = inet_addr(LF_IP_ADDR_DEFAULT);
        // Now copy ip_addr in the most significant 32 bits of the src_addr
        memcpy(new_info->src_addr, &ip_addr, sizeof(uint32_t));
        // Now copy the port_id in the least significant 16 bits of the src_addr
        memcpy(new_info->src_addr + sizeof(uint32_t), LF_PORT_DEFAULT, sizeof(uint16_t));

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