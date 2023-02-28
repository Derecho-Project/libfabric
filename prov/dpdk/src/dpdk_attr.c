
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

#define DPDK_DOMAIN_CAPS (FI_LOCAL_COMM | FI_REMOTE_COMM)
#define DPDK_EP_CAPS     (FI_MSG | FI_RMA | FI_READ | FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE)
#define DPDK_EP_SRX_CAPS (DPDK_EP_CAPS | FI_TAGGED)
#define DPDK_TX_CAPS     (FI_SEND | FI_WRITE | FI_READ)
#define DPDK_RX_CAPS     (FI_RECV | FI_REMOTE_READ | FI_REMOTE_WRITE | FI_RMA_EVENT)

#define DPDK_MSG_ORDER                                                                             \
    (OFI_ORDER_RAR_SET | OFI_ORDER_RAW_SET | FI_ORDER_RAS | OFI_ORDER_WAW_SET | FI_ORDER_WAS |     \
     FI_ORDER_SAW | FI_ORDER_SAS)

#define DPDK_TX_OP_FLAGS                                                                           \
    (FI_INJECT | FI_INJECT_COMPLETE | FI_TRANSMIT_COMPLETE | FI_DELIVERY_COMPLETE |                \
     FI_COMMIT_COMPLETE | FI_COMPLETION)

#define DPDK_RX_OP_FLAGS (FI_COMPLETION)

#define DPDK_MAX_INJECT 128
#define DPDK_IOV_LIMIT  8

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

static struct fi_tx_attr dpdk_tx_srx_attr = {
    .caps          = DPDK_EP_SRX_CAPS | DPDK_TX_CAPS,
    .op_flags      = DPDK_TX_OP_FLAGS,
    .comp_order    = FI_ORDER_STRICT,
    .msg_order     = DPDK_MSG_ORDER,
    .inject_size   = DPDK_MAX_INJECT,
    .size          = 1024,
    .iov_limit     = DPDK_IOV_LIMIT,
    .rma_iov_limit = DPDK_IOV_LIMIT,
};

static struct fi_rx_attr dpdk_rx_srx_attr = {.caps                = DPDK_EP_SRX_CAPS | DPDK_RX_CAPS,
                                             .op_flags            = DPDK_RX_OP_FLAGS,
                                             .comp_order          = FI_ORDER_STRICT,
                                             .msg_order           = DPDK_MSG_ORDER,
                                             .total_buffered_recv = 0,
                                             .size                = 65536,
                                             .iov_limit           = DPDK_IOV_LIMIT};

static struct fi_ep_attr dpdk_ep_srx_attr = {
    .type               = FI_EP_MSG,
    .protocol           = FI_PROTO_SOCK_TCP,
    .protocol_version   = 0,
    .max_msg_size       = SIZE_MAX,
    .tx_ctx_cnt         = 1,
    .rx_ctx_cnt         = FI_SHARED_CONTEXT,
    .max_order_raw_size = SIZE_MAX,
    .max_order_waw_size = SIZE_MAX,
    .mem_tag_format     = FI_TAG_GENERIC,
};

// TODO: What are these values? What is the name here? Why not an interface/PCI address?
static struct fi_domain_attr dpdk_domain_attr = {
    .name             = "dpdk",
    .caps             = DPDK_DOMAIN_CAPS,
    .threading        = FI_THREAD_SAFE,
    .control_progress = FI_PROGRESS_AUTO,
    .data_progress    = FI_PROGRESS_AUTO,
    .resource_mgmt    = FI_RM_ENABLED,
    .mr_mode          = FI_MR_SCALABLE | FI_MR_BASIC,
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

struct fi_info dpdk_srx_info = {.caps = DPDK_DOMAIN_CAPS | DPDK_EP_SRX_CAPS | DPDK_TX_CAPS |
                                        DPDK_RX_CAPS,
                                .addr_format = FI_SOCKADDR,
                                .tx_attr     = &dpdk_tx_srx_attr,
                                .rx_attr     = &dpdk_rx_srx_attr,
                                .ep_attr     = &dpdk_ep_srx_attr,
                                .domain_attr = &dpdk_domain_attr,
                                .fabric_attr = &dpdk_fabric_attr};

struct fi_info dpdk_info = {.next = &dpdk_srx_info,
                            .caps = DPDK_DOMAIN_CAPS | DPDK_EP_CAPS | DPDK_TX_CAPS | DPDK_RX_CAPS,
                            .addr_format = FI_SOCKADDR,
                            .tx_attr     = &dpdk_tx_attr,
                            .rx_attr     = &dpdk_rx_attr,
                            .ep_attr     = &dpdk_ep_attr,
                            .domain_attr = &dpdk_domain_attr,
                            .fabric_attr = &dpdk_fabric_attr};

/* User hints will still override the modified dest_info attributes
 * through ofi_alter_info
 */

size_t dpdk_default_tx_size = 256;
size_t dpdk_default_rx_size = 256;

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
