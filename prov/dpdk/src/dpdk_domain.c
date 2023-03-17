#include "fi_dpdk.h"

#include <ifaddrs.h>
#include <net/if.h>
#include <poll.h>
#include <sys/types.h>

/// Helper functions

/* Many configuration parameters required to startup DPDK */
static inline int port_init(struct rte_mempool *mempool, uint16_t port_id, uint16_t mtu) {
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

int dpdk_domain_open(struct fid_fabric *fabric_fid, struct fi_info *info,
                     struct fid_domain **domain_fid, void *context) {
    struct dpdk_fabric *fabric;
    struct dpdk_domain *domain;
    int                 ret;

    fabric = container_of(fabric_fid, struct dpdk_fabric, util_fabric.fabric_fid);
    ret    = ofi_prov_check_info(&dpdk_util_prov, fabric_fid->api_version, info);
    if (ret)
        return ret;

    domain = calloc(1, sizeof(*domain));
    if (!domain)
        return -FI_ENOMEM;

    ret = ofi_domain_init(fabric_fid, info, &domain->util_domain, context, OFI_LOCK_NONE);
    if (ret)
        goto free;

    slist_init(&domain->endpoint_list);
    ofi_genlock_init(&domain->ep_mutex, OFI_LOCK_MUTEX);

    // Allocate the mempool for RX mbufs
    domain->rx_pool_name = malloc(32);
    sprintf(domain->rx_pool_name, "rx_pool_%s", domain->util_domain.name);
    domain->rx_pool = rte_pktmbuf_pool_create(domain->rx_pool_name, 10240, 64, 0,
                                              RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (domain->rx_pool == NULL) {
        FI_WARN(&dpdk_prov, FI_LOG_CORE, "Cannot create RX mbuf pool for domain %s: %s",
                domain->util_domain.name, rte_strerror(rte_errno));
        goto free;
    }
    printf("RX mempool creation OK\n");

    // Allocate the mempool for descriptors of externally allocated data
    domain->ext_pool_name = malloc(13);
    sprintf(domain->ext_pool_name, "ext_pool_%s", domain->util_domain.name);
    domain->ext_pool =
        rte_pktmbuf_pool_create(domain->ext_pool_name, 128, 64, 0, 0, rte_socket_id());
    if (domain->ext_pool == NULL) {
        FI_WARN(&dpdk_prov, FI_LOG_CORE, "Cannot create external mbuf pool for domain %s: %s",
                domain->util_domain.name, rte_strerror(rte_errno));
        goto free;
    }
    printf("External mempool creation OK\n");

    // Initialize the DPDK device
    // TODO: port_id and mtu should be configurable parameters!
    domain->port_id = 0;
    if (port_init(domain->rx_pool, domain->port_id, 1500) < 0) {
        FI_WARN(&dpdk_prov, FI_LOG_CORE, "Port Init DPDK: error\n");
        goto free;
    };

    // Initialize the progress thread structure for this domain
    ret = dpdk_init_progress(&domain->progress, info);
    if (ret) {
        goto close;
    }

    // Start the progress thread for this domain
    ret = dpdk_start_progress(&domain->progress);
    if (ret) {
        goto close;
    }

    domain->util_domain.domain_fid.fid.ops = &dpdk_domain_fi_ops;
    domain->util_domain.domain_fid.ops     = &dpdk_domain_ops;
    domain->util_domain.domain_fid.mr      = &dpdk_domain_fi_ops_mr;
    *domain_fid                            = &domain->util_domain.domain_fid;

    return FI_SUCCESS;

close_prog:
    dpdk_close_progress(&domain->progress);
close:
    (void)ofi_domain_close(&domain->util_domain);
free:
    free(domain->rx_pool_name);
    free(domain->ext_pool_name);
    free(domain);
    return ret;
}
