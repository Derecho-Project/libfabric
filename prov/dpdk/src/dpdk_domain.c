#include "fi_dpdk.h"
#include "protocols.h"

#include <ifaddrs.h>
#include <net/if.h>
#include <poll.h>
#include <sys/types.h>

/// Helper functions

/* Many configuration parameters required to startup DPDK */
static inline int port_init(struct rte_mempool *mempool, uint16_t port_id, uint16_t queue_id,
                            uint16_t mtu, uint64_t *dev_flags) {
    int valid_port = rte_eth_dev_is_valid_port(port_id);
    if (!valid_port)
        return -1;

    struct rte_eth_dev_info dev_info;
    int                     retval = rte_eth_dev_info_get(port_id, &dev_info);
    if (retval != 0) {
        fprintf(stderr, "[error] cannot get device (port %u) info: %s\n", 0, strerror(-retval));
        return retval;
    }

    // Derive the actual MTU we can use based on device capabilities and user request
    uint16_t actual_mtu = RTE_MIN(mtu, dev_info.max_mtu);

    // Configure the device
    struct rte_eth_conf port_conf;
    memset(&port_conf, 0, sizeof(port_conf));
    port_conf.rxmode.mtu = actual_mtu;
    port_conf.rxmode.offloads |= (RTE_ETH_RX_OFFLOAD_CHECKSUM | RTE_ETH_RX_OFFLOAD_SCATTER);
    port_conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;
    port_conf.txmode.offloads |= (RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_MULTI_SEGS);
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
    const uint16_t rx_rings = 1, tx_rings = 1;
    retval = rte_eth_dev_configure(port_id, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    // TODO: Here I should retrieve a set of device flags for each function and make it available
    // in the dpdk_domain struct in order to retrieve it when needed (in the progress thread).
    // In particular the current code would need to know: port_checksum_offload, port_fdir
    *dev_flags = 0;

    // Set the MTU explicitly
    retval = rte_eth_dev_set_mtu(port_id, actual_mtu);
    if (retval != 0) {
        printf("Error setting up the MTU (%d)\n", retval);
        return retval;
    }

    uint16_t nb_rxd = 1024;
    uint16_t nb_txd = 1024;
    retval          = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    int socket_id = rte_eth_dev_socket_id(port_id);

    for (uint16_t q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port_id, q, nb_rxd, socket_id, NULL, mempool);
        if (retval != 0)
            return retval;
    }

    struct rte_eth_txconf txconf = dev_info.default_txconf;
    txconf.offloads              = port_conf.txmode.offloads;
    for (uint16_t q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port_id, q, nb_txd, socket_id, &txconf);
        if (retval != 0)
            return retval;
    }

    retval = rte_eth_dev_start(port_id);
    if (retval != 0) {
        return retval;
    }

    retval = rte_eth_promiscuous_enable(port_id);
    if (retval != 0)
        return retval;

    return 0;
}

/// Domain creation functions

static int dpdk_domain_close(fid_t fid) {
    struct dpdk_domain *domain;
    int                 ret;

    domain = container_of(fid, struct dpdk_domain, util_domain.domain_fid.fid);

    if (domain->rx_pool) {
        rte_mempool_free(domain->rx_pool);
    }

    if (domain->cm_pool) {
        rte_mempool_free(domain->cm_pool);
    }

    if (domain->cm_ring) {
        rte_ring_free(domain->cm_ring);
    }

    if (domain->info) {
        fi_freeinfo(domain->info);
    }

    ret = ofi_domain_close(&domain->util_domain);
    if (ret)
        return ret;

    free(domain);
    return FI_SUCCESS;
}

static struct fi_ops_domain dpdk_domain_ops = {
    .size             = sizeof(struct fi_ops_domain),
    .av_open          = ofi_ip_av_create,
    .cq_open          = dpdk_cq_open,
    .endpoint         = dpdk_endpoint,
    .scalable_ep      = fi_no_scalable_ep,
    .cntr_open        = fi_no_cntr_open,
    .poll_open        = fi_poll_create,
    .stx_ctx          = fi_no_stx_context,
    .srx_ctx          = fi_no_srx_context,
    .query_atomic     = fi_no_query_atomic,
    .query_collective = fi_no_query_collective,
};
static struct fi_ops dpdk_domain_fi_ops = {
    .size     = sizeof(struct fi_ops),
    .close    = dpdk_domain_close,
    .bind     = ofi_domain_bind,
    .control  = fi_no_control,
    .ops_open = fi_no_ops_open,
    .tostr    = fi_no_tostr,
    .ops_set  = fi_no_ops_set,
};

// MR API defined in dpdk_mr.c
extern struct fi_ops_mr dpdk_domain_fi_ops_mr;

// Create a new dpdk domain. The creation follows three steps:
// 1. libfabric-specific initialization
// 2. dpdk-specific initialization
// 3. start the DPDK progress thread (as a DPDK lcore)
int dpdk_domain_open(struct fid_fabric *fabric_fid, struct fi_info *info,
                     struct fid_domain **domain_fid, void *context) {
    struct dpdk_fabric *fabric;
    struct dpdk_domain *domain;
    int                 ret;

    /* 1. libfabric-specific initialization */
    fabric = container_of(fabric_fid, struct dpdk_fabric, util_fabric.fabric_fid);
    ret    = ofi_prov_check_info(&dpdk_util_prov, fabric_fid->api_version, info);
    if (ret) {
        return ret;
    }

    if (info->addr_format != FI_SOCKADDR &&
        info->addr_format != FI_SOCKADDR_IN &&
        info->addr_format != FI_SOCKADDR_IN6) {
        DPDK_WARN(FI_LOG_DOMAIN, "Unsupported address format:(%d). "
                                 "Only FI_SOCKADDR(%d), FI_SOCKADDR_IN(%d), FI_SOCK_ADDR_IN6(%d) are supported.",
                  info->addr_format,FI_SOCKADDR,FI_SOCKADDR_IN,FI_SOCKADDR_IN6);
        return -FI_EINVAL;
    }

    domain = calloc(1, sizeof(*domain));
    if (!domain) {
        return -FI_ENOMEM;
    }

    ret = ofi_domain_init(fabric_fid, info, &domain->util_domain, context, OFI_LOCK_NONE);
    if (ret) {
        goto free;
    }
    domain->util_domain.domain_fid.fid.ops = &dpdk_domain_fi_ops;
    domain->util_domain.domain_fid.ops     = &dpdk_domain_ops;
    domain->util_domain.domain_fid.mr      = &dpdk_domain_fi_ops_mr;
    *domain_fid                            = &domain->util_domain.domain_fid;

    // keep a copy of domain
    domain->info = fi_dupinfo(info);
    if (!domain->info) {
        DPDK_WARN(FI_LOG_DOMAIN, "Cannot");
        ret = -FI_ENOMEM;
        goto free;
    }
    /* 2. DPDK-specific initialization */

    // Ethernet MTU. This excludes the Ethernet header and the CRC.
    // TODO: Support for VLAN or VXLAN is not yet implemented
    domain->mtu = MTU;

    // Allocate the mempool for RX mbufs
    char rx_pool_name[32];
    sprintf(rx_pool_name, "rx_pool_%s", domain->util_domain.name);
    // Dimension of the TX mempools (must be power of 2)
    size_t pool_size = rte_align32pow2(2 * MAX_ENDPOINTS_PER_APP * dpdk_default_rx_size);
    // Dimension of the mbufs in the TX mempools. Must contain at least an Ethernet frame + private
    // DPDK data (see documentation)
    size_t mbuf_size = RTE_PKTMBUF_HEADROOM + RTE_ETHER_HDR_LEN + domain->mtu + RTE_ETHER_CRC_LEN;
    // Other parameters
    size_t cache_size   = 64;
    size_t private_size = RTE_PKTMBUF_HEADROOM;
    domain->rx_pool     = rte_pktmbuf_pool_create(rx_pool_name, pool_size, cache_size, private_size,
                                                  mbuf_size, rte_socket_id());
    if (domain->rx_pool == NULL) {
        DPDK_WARN(FI_LOG_CORE, "Cannot create RX mbuf pool for domain %s: %s",
                domain->util_domain.name, rte_strerror(rte_errno));
        goto close;
    }
    DPDK_TRACE(FI_LOG_CORE, "RX mempool created.");

    // Allocate the mempool for CM mbufs
    char cm_pool_name[32];
    sprintf(cm_pool_name, "rx_pool_%s", domain->util_domain.name);
    size_t cm_pool_size = rte_align32pow2(MAX_ENDPOINTS_PER_APP);
    domain->cm_pool = rte_pktmbuf_pool_create(cm_pool_name,                             // name
                                              rte_align32pow2(MAX_ENDPOINTS_PER_APP),   // n
                                              cache_size,                               // cache_size
                                              0,                                        // priv_size
                                              RTE_ETHER_HDR_LEN +
                                              sizeof(struct rte_ipv4_hdr) +
                                              sizeof(struct rte_udp_hdr) +
                                              sizeof(struct dpdk_cm_msg_hdr) + 
                                              DPDK_MAX_CM_DATA_SIZE + 
                                              RTE_ETHER_CRC_LEN,                        // data_room_size
                                              rte_socket_id());                         // socket_id
    if (!domain->cm_pool) {
        DPDK_WARN(FI_LOG_CORE, "Cannot create CM mbuf pool for domain %s: %s",
                  domain->util_domain.name, rte_strerror(rte_errno));
        goto close;
    }
    DPDK_TRACE(FI_LOG_CORE, "CM mempool created.");

    // Allocate CM ring buffer
    char cm_ring_name[32];
    sprintf(cm_ring_name, "cm_ring_%s", domain->util_domain.name);
    domain->cm_ring = rte_ring_create(cm_ring_name,
                                      rte_align32pow2(dpdk_params.cm_ring_size),
                                      rte_socket_id(),
                                      RING_F_MP_RTS_ENQ|RING_F_SC_DEQ);
    if (!domain->cm_ring) {
        DPDK_WARN(FI_LOG_CORE, "Fail to create CM ring for domain %s: %s",
                  domain->util_domain.name, rte_strerror(rte_errno));
        goto close;
    }
    DPDK_TRACE(FI_LOG_CORE, "CM ring created.");
    
    // Initialize the CM session counter
    atomic_init(&domain->cm_session_counter, 0);

    // Initialize the DPDK device
    // TODO: port_id, queue_id, lcore_id, dev_flags, and mtu MUST be configurable parameters!
    // More generally, I think many of the parameter passed to and retrieved from
    // the port_init function must be kept in a struct device_info that is part of
    // the dpdk_domain struct.
    domain->port_id  = 0;
    domain->queue_id = 0;
    domain->lcore_id = 1; // lcore 0 is the main thread, so this must be > 0
    if (port_init(domain->rx_pool, domain->port_id, domain->queue_id, domain->mtu,
                  &domain->dev_flags) < 0)
    {
        FI_WARN(&dpdk_prov, FI_LOG_CORE, "Port Init DPDK: error\n");
        goto free;
    };

    // Get the IP and UDP port info from the configuration
    domain->local_addr = *(struct sockaddr_in*)info->src_addr; 
    rte_eth_macaddr_get(domain->port_id, &domain->eth_addr);

    // Initialize the list of endpoints
    slist_init(&domain->endpoint_list);
    domain->num_endpoints = 0;
    // Initialize the mutex to access EP list and info
    ofi_genlock_init(&domain->ep_mutex, OFI_LOCK_MUTEX);

    // Initialize the progress thread structure for this domain
    ret = dpdk_init_progress(&domain->progress, info, domain->lcore_id);
    if (ret) {
        goto close;
    }

    // Allocate the mempool for descriptors of externally allocated data
    // domain->ext_pool_name = malloc(13);
    // sprintf(domain->ext_pool_name, "ext_pool_%s", domain->util_domain.name);
    // domain->ext_pool =
    //     rte_pktmbuf_pool_create(domain->ext_pool_name, 128, 64, 0, 0, rte_socket_id());
    // if (domain->ext_pool == NULL) {
    //     FI_WARN(&dpdk_prov, FI_LOG_CORE, "Cannot create external mbuf pool for domain %s: %s",
    //             domain->util_domain.name, rte_strerror(rte_errno));
    //     goto close;
    // }
    // printf("External mempool creation OK\n");

    // Initialize the rx TLB table
    domain->lcore_queue_conf.n_rx_queue = 1;
    setup_queue_tbl(&domain->lcore_queue_conf.rx_queue_list[0], 0, 0, domain->mtu); // pool and tbl
    domain->lcore_queue_conf.rx_queue_list[0].portid = domain->port_id;

    /* 3. Start the progress thread for this domain */
    ret = dpdk_start_progress(&domain->progress);
    if (ret) {
        goto close_prog;
    }

    return FI_SUCCESS;

close_prog:
    dpdk_close_progress(&domain->progress);
close:
    if (domain->rx_pool) {
        rte_mempool_free(domain->rx_pool);
    }
    if (domain->cm_pool) {
        rte_mempool_free(domain->cm_pool);
    }
    if (domain->cm_ring) {
        rte_ring_free(domain->cm_ring);
    }
    if (domain->info) {
        fi_freeinfo(domain->info);
    }
    (void)ofi_domain_close(&domain->util_domain);
free:
    free(domain);
    return ret;
}
