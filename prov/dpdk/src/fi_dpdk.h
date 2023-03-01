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

#define PROVIDER_NAME         "dpdk"
#define DPDK_MAX_CM_DATA_SIZE 256
#define DPDK_DEF_CQ_SIZE      1024
#define DPDK_MAX_EVENTS       1024

// Global structures for the DPDK provider
extern struct fi_provider dpdk_prov;
extern struct util_prov   dpdk_util_prov;

// Global parameters => Can't we put them in dpdk_attr.c?
extern int    dpdk_disable_autoprog; // This seems a parameter
extern size_t dpdk_max_inject;
extern int    dpdk_io_uring;
extern size_t dpdk_default_tx_size;
extern size_t dpdk_default_rx_size;

// Enumerations for the DPDK provider
// TODO: make them specific for DPDK
enum dpdk_cm_state {
    DPDK_CM_LISTENING,
    DPDK_CM_CONNECTING,
    DPDK_CM_WAIT_REQ,
    DPDK_CM_REQ_SENT,
    DPDK_CM_REQ_RVCD,
    DPDK_CM_RESP_READY,
    /* CM context is freed once connected */
};

#define OFI_PROV_SPECIFIC_DPDK (0x8cb << 16)
enum {
    DPDK_CLASS_CM = OFI_PROV_SPECIFIC_DPDK,
    DPDK_CLASS_PROGRESS,
    DPDK_CLASS_URING,
};

// Structures for the DPDK provider
struct dpdk_uring {
    struct fid     fid;
    ofi_io_uring_t ring;
    // TODO: Define an uRING
    // struct ofi_sockapi_uring *sockapi;
};

/* Serialization is handled at the progress instance level, using the
 * progress locks.  A progress instance has 2 locks, only one of which is
 * enabled.  The other lock will be set to NONE, meaning it is fully disabled.
 * The active_lock field will reference the lock that's in use.
 *
 * There is a progress instance for each fabric and domain object.  The
 * progress instance associated with the domain is the most frequently
 * accessed, as that's where the opened sockets reside.  A single domain
 * exports either rdm or msg endpoints to the app, but not both.  If the
 * progress instance is associated with a domain that exports rdm endpoints,
 * then the rdm_lock is active and lock is set to NONE.  Otherwise, lock is
 * active, and rdm_lock is set to NONE.
 *
 * The reason for the separate locking is to handle nested locking issues
 * that can arise when using an rdm endpoint over a msg endpoint.  Because
 * the code supporting msg endpoints does not know if it is being used
 * by an rdm endpoint, it uses the lock field for serialization.  If the
 * domain is exporting msg endpoints, that lock will be valid, which gives
 * the proper serialization.  In this situation, the application is handling
 * CM events directly.  However, if the msg endpoint is being used
 * through an rdm domain, we need to handle CM events internally.  The rdm_lock
 * is used to serialize access to the rdm endpoint, and will have already been
 * acquired prior to accessing any msg endpoint.  In this case, the lock
 * field will be set to NONE, disabling lower-level locks as they are not
 * needed.
 *
 * This simplifies the number of locks needed to access various objects and
 * avoids complicated nested locking that would otherwise be needed to
 * handle event processing.
 */
struct dpdk_progress {
    struct fid          fid;
    struct ofi_genlock  lock;
    struct ofi_genlock  rdm_lock;
    struct ofi_genlock *active_lock;

    struct dlist_entry unexp_msg_list;
    struct dlist_entry unexp_tag_list;
    struct dlist_entry saved_tag_list;
    struct fd_signal   signal;

    struct slist        event_list;
    struct ofi_bufpool *xfer_pool;

    struct dpdk_uring  tx_uring;
    struct dpdk_uring  rx_uring;
    struct ofi_sockapi sockapi;

    struct ofi_dynpoll epoll_fd;

    bool      auto_progress;
    pthread_t thread;
};

struct dpdk_fabric {
    struct util_fabric   util_fabric;
    struct dpdk_progress progress;
    struct dlist_entry   wait_eq_list;
};

struct dpdk_domain {
    struct util_domain   util_domain;
    struct dpdk_progress progress;
};

struct dpdk_endpoint {
    char    *pci_addr;
    uint32_t port;
};

struct dpdk_cm_msg {
    struct ofi_ctrl_hdr hdr;
    char                data[DPDK_MAX_CM_DATA_SIZE];
};

struct dpdk_cm_context {
    struct fid         fid;
    struct fid        *hfid;
    enum dpdk_cm_state state;
    size_t             cm_data_sz;
    struct dpdk_cm_msg msg;
};

struct dpdk_pep {
    struct util_pep        util_pep;
    struct fi_info        *info;
    SOCKET                 sock;
    struct dpdk_cm_context cm_ctx;
};

struct dpdk_ep {
    struct util_ep   util_ep;
    struct dpdk_srx *srx;
};

struct dpdk_xfer_entry {
    // TODO: Define the CQ entry structure
    char dummy_cnt[512];
};

struct dpdk_srx {
    struct fid_ep       rx_fid;
    struct dpdk_domain *domain;
    struct slist        rx_queue;
    struct slist        tag_queue;
    struct ofi_dyn_arr  src_tag_queues;
    struct ofi_dyn_arr  saved_msgs;

    struct dpdk_xfer_entry *(*match_tag_rx)(struct dpdk_srx *srx, struct dpdk_ep *ep, uint64_t tag);

    uint64_t tag_seq_no;
    uint64_t op_flags;
    size_t   min_multi_recv_size;

    /* Internal use when srx is part of rdm endpoint */
    struct dpdk_rdm  *rdm;
    struct dpdk_cq   *cq;
    struct util_cntr *cntr;
};

struct dpdk_cq {
    struct util_cq util_cq;
};

static inline struct dpdk_progress *dpdk_cq2_progress(struct dpdk_cq *cq) {
    struct dpdk_domain *domain;
    domain = container_of(cq->util_cq.domain, struct dpdk_domain, util_domain);
    return &domain->progress;
}

struct dpdk_eq {
    struct util_eq util_eq;
    /*
      The following lock avoids race between ep close
      and connection management code.
     */
    ofi_mutex_t        close_lock;
    struct dlist_entry wait_eq_entry;
};

struct dpdk_device {
    struct dpdk_device      *next;
    struct rte_eth_dev_info *device;
};

// Fabric
int dpdk_create_fabric(struct fi_fabric_attr *attr, struct fid_fabric **fabric, void *context);

int dpdk_start_all(struct dpdk_fabric *fabric);

// Domain
int dpdk_domain_open(struct fid_fabric *fabric, struct fi_info *info, struct fid_domain **domain,
                     void *context);

// Endpoint
int  dpdk_endpoint(struct fid_domain *domain, struct fi_info *info, struct fid_ep **ep_fid,
                   void *context);
void dpdk_ep_disable(struct dpdk_ep *ep, int cm_err, void *err_data, size_t err_data_size);
int  dpdk_passive_ep(struct fid_fabric *fabric, struct fi_info *info, struct fid_pep **pep,
                     void *context);

// Event Queue
int dpdk_eq_create(struct fid_fabric *fabric_fid, struct fi_eq_attr *attr, struct fid_eq **eq_fid,
                   void *context);
int dpdk_eq_add_progress(struct dpdk_eq *eq, struct dpdk_progress *progress, void *context);
int dpdk_eq_del_progress(struct dpdk_eq *eq, struct dpdk_progress *progress);

int dpdk_cntr_open(struct fid_domain *fid_domain, struct fi_cntr_attr *attr,
                   struct fid_cntr **cntr_fid, void *context);

// Completion Queue and its progress
int dpdk_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr, struct fid_cq **cq_fid,
                 void *context);

int  dpdk_init_progress(struct dpdk_progress *progress, struct fi_info *info);
void dpdk_close_progress(struct dpdk_progress *progress);
int  dpdk_start_progress(struct dpdk_progress *progress);

void dpdk_run_progress(struct dpdk_progress *progress, bool clear_signal);

// Shared
int dpdk_srx_context(struct fid_domain *domain, struct fi_rx_attr *attr, struct fid_ep **rx_ep,
                     void *context);

#endif /* _DPDK_H_ */
