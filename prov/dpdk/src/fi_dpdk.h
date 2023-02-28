#ifndef _DPDK_H
#define _DPDK_H

#include <net/if.h>
#include <stdlib.h>
#include <sys/types.h>

#include <ofi.h>
#include <ofi_enosys.h>
#include <ofi_list.h>
#include <ofi_net.h>
#include <ofi_proto.h>
#include <ofi_prov.h>
#include <ofi_rbuf.h>
#include <ofi_signal.h>
#include <ofi_util.h>

#include <rdma/fabric.h>

#include <rte_eal.h>
#include <rte_ethdev.h>

#define PROVIDER_NAME "dpdk"
#define DPDK_MAX_CM_DATA_SIZE 256
#define DPDK_DEF_CQ_SIZE 1024

// Global structures for the DPDK provider
extern struct fi_provider dpdk_prov;
extern struct util_prov dpdk_util_prov;

// Enumerations for the DPDK provider
enum dpdk_cm_state
{
    DPDK_CM_LISTENING,
    DPDK_CM_CONNECTING,
    DPDK_CM_WAIT_REQ,
    DPDK_CM_REQ_SENT,
    DPDK_CM_REQ_RVCD,
    DPDK_CM_RESP_READY,
    /* CM context is freed once connected */
};

// Structures for the DPDK provider
struct dpdk_fabric
{
    struct util_fabric util_fabric;
};

struct dpdk_domain
{
    struct util_domain util_domain;
    struct ofi_ops_dynamic_rbuf *dynamic_rbuf;
};

struct dpdk_endpoint
{
    char *pci_addr;
    uint32_t port;
};

struct dpdk_cm_msg
{
    struct ofi_ctrl_hdr hdr;
    char data[DPDK_MAX_CM_DATA_SIZE];
};

struct dpdk_cm_context
{
    struct fid fid;
    struct fid *hfid;
    enum dpdk_cm_state state;
    size_t cm_data_sz;
    struct dpdk_cm_msg msg;
};

struct dpdk_pep
{
    struct util_pep util_pep;
    struct fi_info *info;
    SOCKET sock;
    struct dpdk_cm_context cm_ctx;
};

struct dpdk_xfer_entry
{
    // TODO: Define the CQ entry structure
    char dummy_cnt[512];
};
struct dpdk_cq
{
    struct util_cq util_cq;
    struct ofi_bufpool *xfer_pool;
};

struct dpdk_eq
{
    struct util_eq util_eq;
    /*
      The following lock avoids race between ep close
      and connection management code.
     */
    ofi_mutex_t close_lock;
};

struct dpdk_device
{
    struct dpdk_device *next;
    struct rte_eth_dev_info *device;
};

// Fabric
int dpdk_create_fabric(struct fi_fabric_attr *attr, struct fid_fabric **fabric, void *context);

// Domain
int dpdk_domain_open(struct fid_fabric *fabric, struct fi_info *info, struct fid_domain **domain,
                     void *context);

// Endpoint
int dpdk_endpoint(struct fid_domain *domain, struct fi_info *info, struct fid_ep **ep_fid,
                  void *context);
void dpdk_ep_disable(struct dpdk_ep *ep, int cm_err, void *err_data, size_t err_data_size);
int dpdk_passive_ep(struct fid_fabric *fabric, struct fi_info *info, struct fid_pep **pep,
                    void *context);

// Event Queue
int dpdk_eq_create(struct fid_fabric *fabric_fid, struct fi_eq_attr *attr, struct fid_eq **eq_fid,
                   void *context);
int dpdk_cntr_open(struct fid_domain *fid_domain, struct fi_cntr_attr *attr,
                   struct fid_cntr **cntr_fid, void *context);

// Completion Queue
int dpdk_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr, struct fid_cq **cq_fid,
                 void *context);

// Shared
int dpdk_srx_context(struct fid_domain *domain, struct fi_rx_attr *attr, struct fid_ep **rx_ep,
                     void *context);

#endif /* _DPDK_H_ */
