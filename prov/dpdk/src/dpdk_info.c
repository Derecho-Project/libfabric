
#include "fi_dpdk.h"
#include "protocols.h"

#include <ifaddrs.h>
#include <net/if.h>
#include <poll.h>
#include <sys/types.h>

#include <netdb.h>
#include <ofi_util.h>
#include <sys/socket.h>
#include <sys/types.h>

// TODO: This file is copied from the TCP provider. It seems to define the capabilities of the
// provider in a single place. Plus, it contains the declaration of the default values for the
// attributes of the provider. We MUST check if these values are correct for the DPDK provider. E.g.
// the format of the domain name which should be the PCI address instead of the kernel interface
// name.

#define DPDK_DOMAIN_CAPS (FI_REMOTE_COMM)
#define DPDK_EP_CAPS     (FI_MSG) // For the moment we only support MSG endpoints
#define DPDK_TX_CAPS     (DPDK_EP_CAPS | OFI_TX_RMA_CAPS | OFI_RX_RMA_CAPS | FI_ATOMICS)
#define DPDK_RX_CAPS     (DPDK_EP_CAPS | OFI_RX_MSG_CAPS | OFI_RX_RMA_CAPS | FI_ATOMICS)

#define DPDK_MSG_ORDER                                                                             \
    (OFI_ORDER_RAR_SET | OFI_ORDER_RAW_SET | FI_ORDER_RAS | OFI_ORDER_WAW_SET | FI_ORDER_WAS |     \
     FI_ORDER_SAW | FI_ORDER_SAS)

#define DPDK_TX_OP_FLAGS                                                                           \
    (FI_INJECT | FI_INJECT_COMPLETE | FI_TRANSMIT_COMPLETE | FI_DELIVERY_COMPLETE |                \
     FI_COMMIT_COMPLETE | FI_COMPLETION)

#define DPDK_RX_OP_FLAGS (FI_COMPLETION)

// #define DPDK_MAX_INJECT 128
// disable inject temporarily
#define DPDK_MAX_INJECT 0 

static struct fi_tx_attr dpdk_tx_attr = {.caps          = DPDK_EP_CAPS | DPDK_TX_CAPS,
                                         .op_flags      = DPDK_TX_OP_FLAGS,
                                         .comp_order    = FI_ORDER_STRICT,
                                         .msg_order     = DPDK_MSG_ORDER,
                                         .inject_size   = DPDK_MAX_INJECT,
                                         .size          = 1024,
                                         .iov_limit     = DPDK_IOV_LIMIT,
                                         .rma_iov_limit = DPDK_IOV_LIMIT};

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
    // .name             = "PCI address",
    .caps             = DPDK_DOMAIN_CAPS,
    .threading        = FI_THREAD_SAFE,
    .control_progress = FI_PROGRESS_AUTO,
    .data_progress    = FI_PROGRESS_AUTO,
    .resource_mgmt    = FI_RM_ENABLED,
    .mr_mode          = FI_MR_LOCAL,
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

// All these parameters should be a per-device configuration, with default values but potentially
// overridable from users, that should be resident in the dpdk_domain structure (maybe
// dpdk_domain->dev).
size_t dpdk_default_tx_size       = 256; // TODO: What is this?
size_t dpdk_default_rx_size       = 256; // TODO: What is this?
size_t dpdk_max_inject            = 128; // TODO: What is this?
size_t dpdk_default_tx_burst_size = 32;  // TODO: Why here? Should be a configurable parameter...
size_t dpdk_default_rx_burst_size = 32;  // TODO: Why here? Should be a configurable parameter...
// Max simultaneous RDMA READ and Atomic Requests
size_t dpdk_max_ord = 128; // TODO: Why here? Should be a configurable parameter...
// Max simultaneous pending operations? Not sure...
size_t dpdk_max_ird = 128; // TODO: Why here? Should be a configurable parameter...

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

    // TODO: Consider the hints and flags, as well as the version, node, and service parameters
    // TODO:: For the moment, I have inserted here some default values, but we should really just
    // take them from those listed in dpdk_info.c, which we shoud also check for correctness! E.g.,
    // we should find the correct correspondence between the DPDK device and the OFI device.

    // TODO: The Node parameter is the IP address the application is passing to the provider

    // Iterate over the avilable DPDK devices. For each device, create a new fi_info struct and add
    // it to the info list. => We should filter this list based on the hints, but for now we just
    // ignore that
    uint16_t        port_id;
    struct fi_info *tail = NULL;
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
        *new_info->tx_attr          = dpdk_tx_attr;
        *new_info->rx_attr          = dpdk_rx_attr;
        *new_info->ep_attr          = dpdk_ep_attr;
        *new_info->domain_attr      = dpdk_domain_attr;
        *new_info->fabric_attr      = dpdk_fabric_attr;
        new_info->fabric_attr->name = (char *)malloc(strlen(dpdk_fabric_attr.name) + 1);
        strcpy(new_info->fabric_attr->name, dpdk_fabric_attr.name);
        // nic is unset.

        // 2 - fill the port name information
        new_info->domain_attr->name = (char *)malloc(strlen(rte_dev_name(dev_info.device)) + 1);
        strcpy(new_info->domain_attr->name, rte_dev_name(dev_info.device));

        // 3 - link it to the global info list
        new_info->next = tail;
        tail           = new_info;
    }

    *all_infos = tail;
    return 0;
}

static int dpdk_check_hints(uint32_t version, const struct fi_info *hints,
                            const struct fi_info *info) {
    int      ret;
    uint64_t prov_mode;

    if (hints->caps & ~(info->caps)) {
        DPDK_INFO(FI_LOG_CORE, "Unsupported capabilities\n");
        return -FI_ENODATA;
    }

    if (!ofi_valid_addr_format(info->addr_format, hints->addr_format)) {
        DPDK_INFO(FI_LOG_CORE, "address format unmatch.\n");
        return -FI_ENODATA;
    }

    prov_mode = ofi_mr_get_prov_mode(version, hints, info);

    if ((hints->mode & prov_mode) != prov_mode) {
        DPDK_INFO(FI_LOG_CORE, "needed mode not set\n");
        return -FI_ENODATA;
    }

    /** [Weijia] I doubt ofi_check_fabric_attr()'s using of FI_VERSION_LT. The comparison should be
    reversed? if (hints->fabric_attr) { ret = ofi_check_fabric_attr(&dpdk_prov, info->fabric_attr,
    hints->fabric_attr); if (ret) { DPDK_INFO(FI_LOG_CORE, "fabric_attr check failed.\n"); return
    ret;
        }
    }
    **/

    if (hints->domain_attr) {
        if (hints->domain_attr->name &&
            strcasecmp(hints->domain_attr->name, info->domain_attr->name))
        {
            DPDK_INFO(FI_LOG_CORE, "skipping device %s (want %s)\n", info->domain_attr->name,
                      hints->domain_attr->name);
            return -FI_ENODATA;
        }

        ret = ofi_check_domain_attr(&dpdk_prov, version, info->domain_attr, hints);

        if (ret) {
            DPDK_INFO(FI_LOG_CORE, "domain_attr check failed.\n");
            return ret;
        }
    }

    if (hints->ep_attr) {
        ret = ofi_check_ep_attr(&dpdk_util_prov, info->fabric_attr->api_version, info, hints);
        if (ret) {
            DPDK_INFO(FI_LOG_CORE, "ep_attr check failed.\n");
            return ret;
        }
    }

    if (hints->rx_attr) {
        ret = ofi_check_rx_attr(&dpdk_prov, info, hints->rx_attr, hints->mode);
        if (ret) {
            DPDK_INFO(FI_LOG_CORE, "rx_attr check failed.\n");
            return ret;
        }
    }

    if (hints->tx_attr) {
        ret = ofi_check_tx_attr(&dpdk_prov, info->tx_attr, hints->tx_attr, hints->mode);
        if (ret) {
            DPDK_INFO(FI_LOG_CORE, "tx_attr check failed.\n");
            return ret;
        }
    }

    return FI_SUCCESS;
}

int dpdk_getinfo(uint32_t version, const char *node, const char *service, uint64_t flags,
                 const struct fi_info *hints, struct fi_info **info) {
    struct fi_info       *generated_info = NULL;
    const struct fi_info *check_info     = dpdk_util_prov.info;

    for (; check_info; check_info = check_info->next) {
        // 1) match the hints, flags, info
        if (hints) {
            if (hints->ep_attr) {
                if (ofi_check_ep_type(&dpdk_prov, check_info->ep_attr, hints->ep_attr)) {
                    DPDK_TRACE(FI_LOG_FABRIC, "ofi_check_ep_type: unmatch.\n");
                    continue;
                }
            }

            if (dpdk_check_hints(version, hints, check_info)) {
                DPDK_TRACE(FI_LOG_FABRIC, "dpdk_check_hints: unmatch.\n");
                continue;
            }
        }

        // 2) generate info
        // node:service --> dest addr
        // hints.src    --> src addr
        struct fi_info *cur_info = fi_dupinfo(check_info);
        if (!cur_info) {
            return -FI_ENOMEM;
        }

        if (hints && hints->src_addr) {
            cur_info->src_addr = malloc(hints->src_addrlen);
            if (!cur_info->src_addr) {
                DPDK_WARN(FI_LOG_FABRIC, "%s: failed to allocate %lu bytes for src_addr.\n",
                          __func__, hints->src_addrlen);
                return -FI_ENOMEM;
            }
            memcpy(cur_info->src_addr, hints->src_addr, hints->src_addrlen);
            cur_info->src_addrlen = hints->src_addrlen;
        }

        // test domain configuration
        if (!cur_info->src_addr) {
            cfg_t *domain_config = dpdk_domain_config(cur_info->domain_attr->name);
            if (domain_config) {
                struct sockaddr_in addr;
                addr.sin_family = AF_INET;
                ssize_t cm_port = cfg_getint(domain_config, CFG_OPT_DOMAIN_CM_PORT);
                if (cm_port < 0 || cm_port > 65535) {
                    DPDK_WARN(FI_LOG_DOMAIN, "Invalid CM port(%ld) configured for domain:%s\n",
                              cm_port, cur_info->domain_attr->name);
                    fi_freeinfo(cur_info);
                    return -FI_EINVAL;
                }
                addr.sin_port = htons((uint16_t)cm_port);
                char *ip      = cfg_getstr(domain_config, CFG_OPT_DOMAIN_IP);
                if (!inet_pton(AF_INET, ip, &addr.sin_addr)) {
                    DPDK_WARN(FI_LOG_DOMAIN, "Invalid ip address(%s) configured for domain:%s\n",
                              ip, cur_info->domain_attr->name);
                    fi_freeinfo(cur_info);
                    return -FI_EINVAL;
                }
                cur_info->src_addr = malloc(sizeof(addr));
                if (!cur_info->src_addr) {
                    DPDK_WARN(FI_LOG_DOMAIN, "%s: failed to allocate %lu bytes for src_addr.\n",
                              __func__, sizeof(addr));
                    fi_freeinfo(cur_info);
                    return -FI_ENOMEM;
                }
                memcpy(cur_info->src_addr, &addr, sizeof(addr));
                cur_info->src_addrlen = sizeof(addr);
            }
        }

        if (hints && hints->dest_addr) {
            cur_info->dest_addr = malloc(hints->dest_addrlen);
            if (!cur_info->dest_addr) {
                DPDK_WARN(FI_LOG_FABRIC, "%s: failed to allocate %lu bytes for dest_addr.\n",
                          __func__, hints->dest_addrlen);
                return -FI_ENOMEM;
            }
            memcpy(cur_info->dest_addr, hints->dest_addr, hints->dest_addrlen);
            cur_info->dest_addrlen = hints->dest_addrlen;
        } else if (node) {
            struct addrinfo *dest_addr;
            if (getaddrinfo(node, service, NULL, &dest_addr)) {
                DPDK_WARN(FI_LOG_FABRIC, "%s: cannot find destination address for node:%s.\n",
                          __func__, node);
                return -FI_ENODATA;
            }
            cur_info->dest_addrlen = dest_addr->ai_addrlen;
            memcpy(cur_info->dest_addr, dest_addr->ai_addr, dest_addr->ai_addrlen);
            freeaddrinfo(dest_addr);
        }

        // 3) link it up
        cur_info->next = generated_info;
        generated_info = cur_info;
    }

    *info = generated_info;

    return 0;
}
