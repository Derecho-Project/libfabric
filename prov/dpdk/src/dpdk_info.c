
#include "fi_dpdk.h"

#include <ifaddrs.h>
#include <net/if.h>
#include <poll.h>
#include <sys/types.h>

#include <ofi_util.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

// TODO: This file is copied from the TCP provider. It seems to define the capabilities of the
// provider in a single place. Plus, it contains the declaration of the default values for the
// attributes of the provider. We MUST check if these values are correct for the DPDK provider. E.g.
// the format of the domain name which should be the PCI address instead of the kernel interface
// name.

#define DPDK_DOMAIN_CAPS (FI_REMOTE_COMM)
#define DPDK_EP_CAPS     (FI_MSG)       // For the moment we only support MSG endpoints
#define DPDK_TX_CAPS     (DPDK_EP_CAPS | OFI_TX_RMA_CAPS | OFI_RX_RMA_CAPS | FI_ATOMICS)
#define DPDK_RX_CAPS     (DPDK_EP_CAPS | OFI_RX_MSG_CAPS | OFI_RX_RMA_CAPS | FI_ATOMICS)

#define DPDK_MSG_ORDER                                                                             \
    (OFI_ORDER_RAR_SET | OFI_ORDER_RAW_SET | FI_ORDER_RAS | OFI_ORDER_WAW_SET | FI_ORDER_WAS |     \
     FI_ORDER_SAW | FI_ORDER_SAS)

#define DPDK_TX_OP_FLAGS                                                                           \
    (FI_INJECT | FI_INJECT_COMPLETE | FI_TRANSMIT_COMPLETE | FI_DELIVERY_COMPLETE |                \
     FI_COMMIT_COMPLETE | FI_COMPLETION)

#define DPDK_RX_OP_FLAGS (FI_COMPLETION)

#define DPDK_MAX_INJECT 128

#define DPDK_BASE_PORT 2509

static struct fi_tx_attr dpdk_tx_attr = {
    .caps          = DPDK_EP_CAPS | DPDK_TX_CAPS,
    .op_flags      = DPDK_TX_OP_FLAGS,
    .comp_order    = FI_ORDER_STRICT,
    .msg_order     = DPDK_MSG_ORDER,
    .inject_size   = DPDK_MAX_INJECT,
    .size          = 1024,
    .iov_limit     = DPDK_IOV_LIMIT,
    .rma_iov_limit = DPDK_IOV_LIMIT
};

static struct fi_rx_attr dpdk_rx_attr = {
    .caps                = DPDK_EP_CAPS | DPDK_RX_CAPS,
    .op_flags            = DPDK_RX_OP_FLAGS,
    .comp_order          = FI_ORDER_STRICT,
    .msg_order           = DPDK_MSG_ORDER,
    .total_buffered_recv = 0,
    .size                = 65536,
    .iov_limit           = DPDK_IOV_LIMIT
};

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
    // .name             = "PCI address",
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

size_t dpdk_default_tx_size = 256; // TODO: What is this?
size_t dpdk_default_rx_size = 256; // TODO: What is this?
size_t dpdk_max_inject      = 128; // TODO: What is this?

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
    .info           = NULL,
    .alter_defaults = &dpdk_alter_defaults,
    .flags          = 0,
};

int dpdk_init_info(const struct fi_info **all_infos) {
    *all_infos = NULL;

    uint16_t port_id;
    struct fi_info* tail = NULL;
    RTE_ETH_FOREACH_DEV(port_id) {
        // get DPDK device info
        struct rte_eth_dev_info dev_info;
        rte_eth_dev_info_get(port_id, &dev_info);

        struct fi_info *new_info = ofi_allocinfo_internal();
        if (!new_info) {
            return -FI_ENOMEM;
        }

        // 1 - initialize struct fi_info
        new_info->caps = DPDK_DOMAIN_CAPS | DPDK_EP_CAPS | DPDK_TX_CAPS | DPDK_RX_CAPS;
        // mode is unset.
        new_info->addr_format = FI_SOCKADDR,
        // src_addrlen is unset.
        // dest_addrlen is unset.
        // src_addr is unset.
        // dest_addr is unset.
        // handle is unset.
        *new_info->tx_attr = dpdk_tx_attr;
        *new_info->rx_attr = dpdk_rx_attr;
        *new_info->ep_attr = dpdk_ep_attr;
        *new_info->domain_attr = dpdk_domain_attr;
        *new_info->fabric_attr = dpdk_fabric_attr;
        new_info->fabric_attr->name = (char*)malloc(strlen(dpdk_fabric_attr.name)+1);
        strcpy(new_info->fabric_attr->name,dpdk_fabric_attr.name);
        // nic is unset.

        // 2 - fill the port name information
        new_info->domain_attr->name = (char*)malloc(strlen(rte_dev_name(dev_info.device)) + 1);
        strcpy(new_info->domain_attr->name, rte_dev_name(dev_info.device));

        // 3 - link it to the global info list
        new_info->next = tail;
        tail = new_info;
    }

    *all_infos = tail;
    return 0;
}

static int dpdk_check_hints(uint32_t version,
                            const struct fi_info* hints,
                            const struct fi_info* info) {
    int ret;
    uint64_t prov_mode;

    if (hints->caps & ~(info->caps)) {
        DPDK_INFO(FI_LOG_CORE, "Unsupported capabilities\n");
        return -FI_ENODATA;
    }

    if (!ofi_valid_addr_format(info->addr_format, hints->addr_format)) {
        return -FI_ENODATA;
    }

    prov_mode = ofi_mr_get_prov_mode(version, hints, info);

    if ((hints->mode & prov_mode) != prov_mode) {
        DPDK_INFO(FI_LOG_CORE, "needed mode not set\n");
        return -FI_ENODATA;
    }

    if (hints->fabric_attr) {
        ret = ofi_check_fabric_attr(&dpdk_prov, info->fabric_attr, hints->fabric_attr);
        if (ret) {
            return ret;
        }
    }

    if (hints->domain_attr) {
        if (hints->domain_attr->name &&
            strcasecmp(hints->domain_attr->name, info->domain_attr->name)) {
            DPDK_INFO(FI_LOG_CORE, "skipping device %s (want %s)\n",
                      info->domain_attr->name, hints->domain_attr->name);
            return -FI_ENODATA;
        }

        ret = ofi_check_domain_attr(&dpdk_prov, version, info->domain_attr, hints);

        if (ret) {
            return ret;
        }
    }

    if (hints->ep_attr) {
        ret = ofi_check_ep_attr(&dpdk_util_prov,info->fabric_attr->api_version,info,hints);
        if (ret) {
            return ret;
        }
    }

    if (hints->rx_attr) {
        ret = ofi_check_rx_attr(&dpdk_prov, info, hints->rx_attr, hints->mode);
        if (ret) {
            return ret;
        }
    }

    if (hints->tx_attr) {
        ret = ofi_check_tx_attr(&dpdk_prov, info->tx_attr, hints->tx_attr, hints->mode);
        if (ret) {
            return ret;
        }
    }

    return FI_SUCCESS;
}

int dpdk_getinfo(uint32_t version, const char *node, const char *service, uint64_t flags,
                 const struct fi_info *hints, struct fi_info **info) {
    struct fi_info* generated_info = NULL;
    const struct fi_info* check_info = dpdk_util_prov.info;

    for (;check_info;check_info=check_info->next) {
        // 1) match the hints, flags, info
        if (hints) {
            if (hints->ep_attr) {
                if (ofi_check_ep_type(&dpdk_prov, check_info->ep_attr, hints->ep_attr)) {
                    continue;
                }
            }

            if (dpdk_check_hints(version, hints, check_info)) {
                continue;
            }
        }

        // 2) generate info
        // node:service --> dest addr
        // hints.src    --> src addr
        struct fi_info* cur_info = fi_dupinfo(check_info);
        if (!cur_info) {
            return -FI_ENOMEM;
        }

        if (hints && hints->src_addr) {
            cur_info->src_addr = malloc(hints->src_addrlen);
            if (!cur_info->src_addr) {
                return -FI_ENOMEM;
            }
            memcpy(cur_info->src_addr,hints->src_addr,hints->src_addrlen);
            cur_info->src_addrlen = hints->src_addrlen;
        }

        if (hints && hints->dest_addr) {
            cur_info->dest_addr = malloc(hints->dest_addrlen);
            if (!cur_info->dest_addr) {
                return -FI_ENOMEM;
            }
            memcpy(cur_info->dest_addr,hints->dest_addr,hints->dest_addrlen);
            cur_info->dest_addrlen = hints->dest_addrlen;
        } else if (node) {
            struct addrinfo *dest_addr;
            if(getaddrinfo(node,service,NULL,&dest_addr)) {
                return -FI_ENODATA;
            }
            cur_info->dest_addrlen = dest_addr->ai_addrlen;
            memcpy(cur_info->dest_addr,dest_addr->ai_addr,dest_addr->ai_addrlen);
            freeaddrinfo(dest_addr);
        }

        // 3) link it up
        cur_info->next = generated_info;
        generated_info = cur_info;
    }

    *info = generated_info;

    return 0;
}
