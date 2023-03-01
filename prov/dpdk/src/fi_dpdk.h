#ifndef _DPDK_H
#define _DPDK_H

#include <assert.h>
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

struct dpdk_cm_msg {
    struct ofi_ctrl_hdr hdr;
    char                data[DPDK_MAX_CM_DATA_SIZE];
};

/* Inject buffer space is included */
// TODO: SPECIALIZE FOR DPDK HDRS
union dpdk_hdrs {
    char dummy_hdrs[128];
};

struct dpdk_active_rx {
    union dpdk_hdrs         hdr;
    size_t                  hdr_len;
    size_t                  hdr_done;
    size_t                  data_left;
    struct dpdk_xfer_entry *entry;
    int (*handler)(struct dpdk_ep *ep);
    void *claim_ctx;
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

// TODO: SPECIALIZE FOR DPDK and clean the struct content
struct dpdk_ep {
    struct util_ep        util_ep;
    struct dpdk_active_rx cur_rx;

    struct dlist_entry unexp_entry;
    struct slist       rx_queue;
    struct slist       tx_queue;
    struct slist       priority_queue;
    struct slist       need_ack_queue;
    struct slist       async_queue;
    struct slist       rma_read_queue;
    int                rx_avail;
    struct dpdk_srx   *srx;
};

// This represents a PACKET DESCRIPTOR to be exchanged across queues. Used in various queues to
// point to recv/send message!
// TODO: Currently copy/pasted from TCP provider. Specialize for DPDK!
struct dpdk_xfer_entry {
    struct slist_entry entry;
    void              *user_buf;
    size_t             iov_cnt;
    struct iovec       iov[DPDK_IOV_LIMIT + 1];
    struct dpdk_ep    *saving_ep;
    struct dpdk_cq    *cq;
    struct util_cntr  *cntr;
    uint64_t           tag_seq_no;
    uint64_t           tag;
    uint64_t           ignore;
    fi_addr_t          src_addr;
    uint64_t           cq_flags;
    uint32_t           ctrl_flags;
    uint32_t           async_index;
    void              *context;
    /* For RMA read requests, we track the request response so that
     * we don't generate multiple completions for the same operation.
     */
    struct dpdk_xfer_entry *resp_entry;

    /* hdr must be second to last, followed by msg_data.  msg_data
     * is sized dynamically based on the max_inject size
     */
    union dpdk_hdrs hdr;
    char            msg_data[];
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

struct dpdk_rdm {
    struct util_ep    util_ep;
    struct dpdk_pep  *pep;
    struct dpdk_srx  *srx;
    struct index_map  conn_idx_map;
    struct dpdk_conn *rx_loopback;
    union ofi_sock_ip addr;
};

struct dpdk_conn {
    struct dpdk_ep        *ep;
    struct dpdk_rdm       *rdm;
    struct util_peer_addr *peer;
    uint32_t               remote_pid;
    int                    flags;
};

struct dpdk_event {
    struct slist_entry    list_entry;
    struct dpdk_rdm      *rdm;
    uint32_t              event;
    struct fi_eq_cm_entry cm_entry;
};

static inline struct dpdk_progress *dpdk_ep2_progress(struct dpdk_ep *ep) {
    struct dpdk_domain *domain;
    domain = container_of(ep->util_ep.domain, struct dpdk_domain, util_domain);
    return &domain->progress;
}

static inline struct dpdk_progress *dpdk_rdm2_progress(struct dpdk_rdm *rdm) {
    struct dpdk_domain *domain;
    domain = container_of(rdm->util_ep.domain, struct dpdk_domain, util_domain);
    return &domain->progress;
}
static inline int dpdk_progress_locked(struct dpdk_progress *progress) {
    return ofi_genlock_held(progress->active_lock);
}

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
int  dpdk_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr, struct fid_cq **cq_fid,
                  void *context);
void dpdk_progress_rx(struct dpdk_ep *ep);

static inline struct dpdk_cq *dpdk_ep_rx_cq(struct dpdk_ep *ep) {
    return container_of(ep->util_ep.rx_cq, struct dpdk_cq, util_cq);
}

static inline struct dpdk_cq *dpdk_ep_tx_cq(struct dpdk_ep *ep) {
    return container_of(ep->util_ep.tx_cq, struct dpdk_cq, util_cq);
}

// TODO: not sure which queue!
void dpdk_tx_queue_insert(struct dpdk_ep *ep, struct dpdk_xfer_entry *tx_entry);

int  dpdk_init_progress(struct dpdk_progress *progress, struct fi_info *info);
void dpdk_close_progress(struct dpdk_progress *progress);
int  dpdk_start_progress(struct dpdk_progress *progress);

void dpdk_run_progress(struct dpdk_progress *progress, bool clear_signal);
void dpdk_progress(struct dpdk_progress *progress, bool clear_signal);
void dpdk_progress_all(struct dpdk_fabric *fabric);
void dpdk_handle_event_list(struct dpdk_progress *progress);

// Shared
int dpdk_srx_context(struct fid_domain *domain, struct fi_rx_attr *attr, struct fid_ep **rx_ep,
                     void *context);

// WHY HERE???
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

static inline struct dpdk_xfer_entry *dpdk_alloc_xfer(struct dpdk_progress *progress) {
    struct dpdk_xfer_entry *xfer;

    assert(dpdk_progress_locked(progress));
    xfer = ofi_buf_alloc(progress->xfer_pool);
    if (!xfer)
        return NULL;

    // TODO: DPDK-specialize
    //  xfer->hdr.base_hdr.flags = 0;
    xfer->cq_flags   = 0;
    xfer->cntr       = NULL;
    xfer->cq         = NULL;
    xfer->ctrl_flags = 0;
    xfer->context    = 0;
    xfer->user_buf   = NULL;
    return xfer;
}

static inline void dpdk_free_xfer(struct dpdk_progress *progress, struct dpdk_xfer_entry *xfer) {
    assert(dpdk_progress_locked(progress));

    if (xfer->ctrl_flags & DPDK_FREE_BUF)
        free(xfer->user_buf);

    ofi_buf_free(xfer);
}

static inline struct dpdk_xfer_entry *dpdk_alloc_rx(struct dpdk_ep *ep) {
    struct dpdk_xfer_entry *xfer;

    assert(dpdk_progress_locked(dpdk_ep2_progress(ep)));
    xfer = dpdk_alloc_xfer(dpdk_ep2_progress(ep));
    if (xfer) {
        xfer->cntr = ep->util_ep.rx_cntr;
        xfer->cq   = dpdk_ep_rx_cq(ep);
    }

    return xfer;
}

static inline struct dpdk_xfer_entry *dpdk_alloc_tx(struct dpdk_ep *ep) {
    struct dpdk_xfer_entry *xfer;

    assert(dpdk_progress_locked(dpdk_ep2_progress(ep)));
    xfer = dpdk_alloc_xfer(dpdk_ep2_progress(ep));
    if (xfer) {
        // TODO: DPDK-specialize!
        // xfer->hdr.base_hdr.version = DPDK_HDR_VERSION;
        // xfer->hdr.base_hdr.op_data = 0;
        xfer->cq = dpdk_ep_tx_cq(ep);
    }

    return xfer;
}

/* We need to progress receives in the case where we're waiting
 * on the application to post a buffer to consume a receive
 * that we've already read from the kernel.  If the message is
 * of length 0, there's no additional data to read, so calling
 * poll without forcing progress can result in application hangs.
 */
static inline bool dpdk_has_unexp(struct dpdk_ep *ep) {
    assert(dpdk_progress_locked(dpdk_ep2_progress(ep)));
    return ep->cur_rx.handler && !ep->cur_rx.entry;
}

#endif /* _DPDK_H_ */
