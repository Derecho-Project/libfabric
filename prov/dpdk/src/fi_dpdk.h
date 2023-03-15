#ifndef _DPDK_H
#define _DPDK_H

#include <assert.h>
#include <ifaddrs.h>
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

#define PROVIDER_NAME         "dpdk"
#define DPDK_MAX_CM_DATA_SIZE 256
#define DPDK_DEF_CQ_SIZE      1024
#define DPDK_MAX_EVENTS       1024
#define DPDK_IOV_LIMIT        8

#define DPDK_NEED_RESP     BIT(1)
#define DPDK_NEED_ACK      BIT(2)
#define DPDK_INTERNAL_XFER BIT(3)
#define DPDK_NEED_DYN_RBUF BIT(4)
#define DPDK_ASYNC         BIT(5)
#define DPDK_INJECT_OP     BIT(6)
#define DPDK_FREE_BUF      BIT(7)
#define DPDK_SAVED_XFER    BIT(8)
#define DPDK_COPY_RECV     BIT(9)
#define DPDK_CLAIM_RECV    BIT(10)
#define DPDK_MULTI_RECV    FI_MULTI_RECV /* BIT(16) */

// ==================== Global variables ====================
// Global structures for the DPDK provider
extern struct fi_provider dpdk_prov;
extern struct util_prov   dpdk_util_prov;

// Global parameters => Can't we put them in dpdk_info.c?
extern size_t dpdk_max_inject;
extern size_t dpdk_default_tx_size;
extern size_t dpdk_default_rx_size;

// ==================== Enumerations ====================
// CM states
enum dpdk_cm_state {
    DPDK_CM_LISTENING,
    DPDK_CM_CONNECTING,
    DPDK_CM_WAIT_REQ,
    DPDK_CM_REQ_SENT,
    DPDK_CM_REQ_RVCD,
    DPDK_CM_RESP_READY,
    /* CM context is freed once connected */
};

// FID classes, specific for the DPDK provider
#define OFI_PROV_SPECIFIC_DPDK (0x888 << 16)
enum {
    DPDK_CLASS_CM = OFI_PROV_SPECIFIC_DPDK,
    DPDK_CLASS_PROGRESS,
};

// ==================== Memory Management ====================

struct dpdk_mr {
    // Libfabric memory region descriptor
    struct fid_mr mr_fid;
    // Memory Region references
    void  *buf;
    size_t len;
};

// ======= Fabric, Domain, Endpoint and Threads  =======
// Represents a DPDK fabric
struct dpdk_fabric {
    struct util_fabric util_fabric;
};

// Progress represents the data for the progress thread
struct dpdk_progress {
    // Fabric ID
    struct fid fid;
    // Mutex to access event list and CQ
    struct ofi_genlock lock;
    // List (and associated buffer pool) of events
    struct slist        event_list;
    struct ofi_bufpool *xfer_pool;
    // Spinning lcore id
    int lcore_id;
    // Signal to stop the progress thread
    int stop_progress;
};

// Represents a DPDK domain (=> a DPDK device)
struct dpdk_domain {
    // Utility domain
    struct util_domain util_domain;
    // List of EP associated with this domain
    struct slist endpoint_list;
    // Mutex to access the list of EP
    struct ofi_genlock ep_mutex;
    // Progress thread data
    struct dpdk_progress progress;
    // Port ID of the DPDK device
    uint16_t port_id;
    // Mempool for incoming packets
    struct rte_mempool *rx_pool;
    char               *rx_pool_name;
    // Memory pool to allocate packet descriptors for external buffers
    struct rte_mempool *ext_pool;
    char               *ext_pool_name;
};

// DPDK endpoint: represents an open connection
struct dpdk_ep {
    // Reference to the associated endpoint
    struct util_ep util_ep;
    // Receive and Transmit queues (= indeed, a "queue pair")
    struct slist rx_queue;
    struct slist tx_queue;
    // Mutex to access the queues
    struct ofi_genlock rx_mutex;
    struct ofi_genlock tx_mutex;
    // Memory pool for headers
    struct rte_mempool *hdr_pool;
    char               *hdr_pool_name;
    // This is necessary because we keep ep in a list
    struct slist_entry endpoint_list;
};

// Functions for objects creation
int  dpdk_init_info(const struct fi_info **all_infos);
int  dpdk_create_fabric(struct fi_fabric_attr *attr, struct fid_fabric **fabric, void *context);
int  dpdk_domain_open(struct fid_fabric *fabric, struct fi_info *info, struct fid_domain **domain,
                      void *context);
int  dpdk_endpoint(struct fid_domain *domain, struct fi_info *info, struct fid_ep **ep_fid,
                   void *context);
void dpdk_ep_disable(struct dpdk_ep *ep, int cm_err, void *err_data, size_t err_data_size);

// Functions for progress thread
int  dpdk_init_progress(struct dpdk_progress *progress, struct fi_info *info);
int  dpdk_start_progress(struct dpdk_progress *progress);
void dpdk_close_progress(struct dpdk_progress *progress);
int  dpdk_run_progress(void *args);
void dpdk_progress_rx(struct dpdk_ep *ep);

void dpdk_handle_event_list(struct dpdk_progress *progress);

// ======= Passive Endpoint and Connection Management (CM)  =======
struct dpdk_cm_msg {
    struct ofi_ctrl_hdr hdr;
    char                data[DPDK_MAX_CM_DATA_SIZE];
};

union dpdk_hdrs {};

struct dpdk_cm_context {
    struct fid         fid;
    struct fid        *hfid;
    enum dpdk_cm_state state;
    size_t             cm_data_sz;
    struct dpdk_cm_msg msg;
};

// Passive Endpoint
struct dpdk_pep {
    struct util_pep        util_pep;
    struct fi_info        *info;
    struct dpdk_cm_context cm_ctx;
};

int dpdk_passive_ep(struct fid_fabric *fabric, struct fi_info *info, struct fid_pep **pep,
                    void *context);

// ==================== Event Descriptor ====================
// Packet descriptor to be exchanged across queues. Used in various queues to
// point to recv/send message!
struct dpdk_xfer_entry {
    struct slist_entry entry;
    struct dpdk_ep    *saving_ep;
    struct dpdk_cq    *cq;
    struct util_cntr  *cntr;
    fi_addr_t          src_addr;
    uint64_t           cq_flags;
    void              *context;
    uint64_t           has_immediate_data;
    uint64_t           immediate_data;
    size_t             msg_data_len;
    void              *msg_data;
};

// ==================== Completion Queues ====================
struct dpdk_cq {
    struct util_cq util_cq;
};
int dpdk_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr, struct fid_cq **cq_fid,
                 void *context);

// ==================== Events Queues ====================
struct dpdk_event {
    struct slist_entry    list_entry;
    uint32_t              event;
    struct fi_eq_cm_entry cm_entry;
};

struct dpdk_eq {
    struct util_eq util_eq;
    /*
      The following lock avoids race between ep close
      and connection management code.
     */
    ofi_mutex_t        close_lock;
    struct dlist_entry wait_eq_entry;
};

int  dpdk_eq_open(struct fid_fabric *fabric_fid, struct fi_eq_attr *attr, struct fid_eq **eq_fid,
                  void *context);
void dpdk_tx_queue_insert(struct dpdk_ep *ep, struct dpdk_xfer_entry *tx_entry);

#endif /* _DPDK_H_ */
