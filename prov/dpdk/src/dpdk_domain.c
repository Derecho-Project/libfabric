#include "fi_dpdk.h"
#include "protocols.h"

#include <ifaddrs.h>
#include <net/if.h>
#include <poll.h>
#include <sys/types.h>

/// Helper functions

/// Domain creation functions

static int dpdk_domain_close(fid_t fid) {
    struct dpdk_domain *domain;
    int                 ret;

    domain = container_of(fid, struct dpdk_domain, util_domain.domain_fid.fid);

    if (domain->info) {
        fi_freeinfo(domain->info);
    }

    ret = ofi_domain_close(&domain->util_domain);
    if (ret)
        return ret;

    release_dpdk_domain_resources(domain->res);

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
    // struct dpdk_fabric *fabric;
    struct dpdk_domain *domain;
    int                 ret;

    /* 0. find the domain resources in the fabric */
    struct dpdk_fabric *fabric =
        container_of(fabric_fid, struct dpdk_fabric, util_fabric.fabric_fid);
    struct dpdk_domain_resources *res = NULL;
    ret                               = get_or_create_dpdk_domain_resources(fabric, info, &res);
    if (ret) {
        DPDK_WARN(FI_LOG_DOMAIN, "Failed to get domain resources.\n");
        return ret;
    }
    // if a domain for the requested name already exists, return it */
    if (res->domain) {
        *domain_fid = &res->domain->util_domain.domain_fid;
        return FI_SUCCESS;
    }

    /* 1. libfabric-specific initialization */
    ret = ofi_prov_check_info(&dpdk_util_prov, fabric_fid->api_version, info);
    if (ret) {
        return ret;
    }

    if (info->addr_format != FI_SOCKADDR && info->addr_format != FI_SOCKADDR_IN &&
        info->addr_format != FI_SOCKADDR_IN6)
    {
        DPDK_WARN(FI_LOG_DOMAIN,
                  "Unsupported address format:(%d). "
                  "Only FI_SOCKADDR(%d), FI_SOCKADDR_IN(%d), FI_SOCK_ADDR_IN6(%d) are supported.\n",
                  info->addr_format, FI_SOCKADDR, FI_SOCKADDR_IN, FI_SOCKADDR_IN6);
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
        DPDK_WARN(FI_LOG_DOMAIN, "Failed to allocated memory for domain->info\n");
        ret = -FI_ENOMEM;
        goto free;
    }

    /* 2. DPDK-specific initialization */
    ofi_mutex_lock(&res->domain_lock);
    if (res->domain) {
        ofi_mutex_unlock(&res->domain_lock);
        DPDK_WARN(FI_LOG_DOMAIN, "Failed to create domain on %s.\n", res->domain_name);
        ret = -FI_EBUSY;
        goto free;
    }

    // TODO: these should move to res.
    // TODO: Here I should retrieve a set of device flags for each function and make it available
    // in the dpdk_domain struct in order to retrieve it when needed (in the progress thread).
    // In particular the current code would need to know: port_checksum_offload, port_fdir
    domain->dev_flags = 0x0;
    domain->lcore_id  = 0x1;

    // Initialize the list of endpoints
    slist_init(&domain->endpoint_list);
    domain->num_endpoints = 0;
    // Initialize the mutex to access EP list and info
    ofi_genlock_init(&domain->ep_mutex, OFI_LOCK_MUTEX);

    // Initialize the packet_context ring for orphan send descriptors
    char name[46];
    sprintf(name, "pkt_ctx_ring_%s", res->domain_name);
    unsigned int ring_size = 65536 * MAX_ENDPOINTS_PER_APP;
    domain->free_ctx_ring =
        rte_ring_create(name, ring_size, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!domain->free_ctx_ring) {
        DPDK_WARN(FI_LOG_DOMAIN, "Failed to create free_ctx_ring\n");
        ret = -FI_ENOMEM;
        goto free;
    }
    for (int i = 0; i < ring_size; i++) {
        struct packet_context *ctx = malloc(sizeof(struct packet_context));
        rte_ring_enqueue(domain->free_ctx_ring, ctx);
    }
    // Initialize the list of orphan sends
    dlist_init(&domain->orphan_sends);

    // Initialize the progress thread structure for this domain
    ret = dpdk_init_progress(&domain->progress, info, domain->lcore_id);
    if (ret) {
        ofi_mutex_unlock(&res->domain_lock);
        goto close;
    }
    // Initialize the rx TLB table
    domain->lcore_queue_conf.n_rx_queue = 1;
    setup_queue_tbl(&domain->lcore_queue_conf.rx_queue_list[0], domain->lcore_id, res->data_rxq_id,
                    res->mtu); // pool and tbl
    domain->lcore_queue_conf.rx_queue_list[0].portid = res->port_id;
    ofi_genlock_init(&domain->mr_tbl_lock, OFI_LOCK_MUTEX);

    // Initialize the MR tbl
    domain->mr_tbl.capacity = MAX_MR_BUCKETS_PER_DOMAIN;
    domain->mr_tbl.mr_count = 0;

    // bind domain and res
    res->domain = domain;
    domain->res = res;

    ofi_mutex_unlock(&res->domain_lock);

    /* 3. Start the progress thread for this domain */
    ret = dpdk_start_progress(&domain->progress);
    if (ret) {
        goto close_prog;
    }

    return FI_SUCCESS;

close_prog:
    dpdk_close_progress(&domain->progress);
close:
    if (domain->info) {
        fi_freeinfo(domain->info);
    }
    (void)ofi_domain_close(&domain->util_domain);
free:
    free(domain);
    release_dpdk_domain_resources(res);
    return ret;
}
