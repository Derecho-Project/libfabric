#ifndef _DPDK_H
#define _DPDK_H

// TODOs
// 1)  pep getname() is important. It should return the LOCAL IP address, which in turn should be a
//      PARAMETER of the provider. Plus the UDP port number, which should be a PARAMETER of the
//      provider. The address returned could be IP_addr:UDP_port.

// 2)  The accept()/connect() must serve to exchange the remote IP address and UDP port number
//     between client and server.
//      => For uRDMA integration: it must start from the siw_connect() function. The
//      siw_device/usiw_device is the fi_domain equivalent. When you open a connection, you create a
//      CEQ associated to a QP (=> EP) and the device (=> domain) has a list of CEQs (or, each EP
//      has a ref to EQ).
//      => WQE == fi_msg
//      => BUT ACTUALLY we don't need to take anything from uRDMA except for the TRP protocol for
//      TCP-like guarantees. The rest is fine! We can easily implement it ourselves!

#include <assert.h>
#include <ifaddrs.h>
#include <math.h>
#include <net/if.h>
#include <stdatomic.h>
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
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_udp.h>

#include "util.h"

// TODO: This represents the maximum number of endpoints (EPs) that can be created by a single
// application. This value is used to keep an efficient mapping between UDP ports and EP. This must
// be placed in the fi_info file and become a provider parameter.
#define MAX_ENDPOINTS_PER_APP 128

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
extern size_t dpdk_default_tx_burst_size;
extern size_t dpdk_default_rx_burst_size;
extern size_t dpdk_max_ord;
extern size_t dpdk_max_ird;

// ==================== General utilities ====================
/** Compares two 32-bit unsigned integers using the rules in RFC 1982 with
 * SERIAL_BITS=32.  Returns true if and only if s1 < s2. */
bool serial_less_32(uint32_t s1, uint32_t s2);
/** Compares two 32-bit unsigned integers using the rules in RFC 1982 with
 * SERIAL_BITS=32.  Returns true if and only if s1 > s2. */
bool serial_greater_32(uint32_t s1, uint32_t s2);

// ==================== Memory Management ====================
struct dpdk_mr {
    // Libfabric memory region descriptor
    struct fid_mr mr_fid;
    // Memory Region references
    void  *buf;
    size_t len;
};

// ==================== Event Descriptor and DPDK Queues ====================
struct dpdk_xfer_queue {
    struct rte_ring *ring;
    struct rte_ring *free_ring;
    char            *storage;
    int              max_wr;
    int              max_sge;
    rte_spinlock_t   lock;
    // What is this?
    struct dlist_entry active_head;
    // TODO: maybe a union for the following?
    // Send-specific
    unsigned int max_inline;
    // Receive-specific
    uint32_t next_msn;
};

struct psn_range {
    uint32_t min;
    uint32_t max;
};
struct ee_state {
    uint32_t expected_read_msn;
    uint32_t expected_ack_msn;
    uint32_t next_send_msn;
    uint32_t next_read_msn;
    uint32_t next_ack_msn;

    /* TX TRP state */
    uint32_t send_last_acked_psn;
    uint32_t send_next_psn;
    uint32_t send_max_psn;

    /* RX TRP state */
    uint32_t recv_ack_psn;
    /* This tracks both READ and atomic responses. It is a memory area to keep unacked packets */
    // TODO: can we find a better way to do this?
    struct binheap *recv_rresp_last_psn;

    uint32_t         trp_flags;
    struct psn_range recv_sack_psn;

    struct rte_mbuf **tx_pending;
    struct rte_mbuf **tx_head;
    int               tx_pending_size;
    struct rte_ring  *rx_queue;
};

enum xfer_send_state {
    SEND_XFER_INIT = 0,
    SEND_XFER_TRANSFER,
    SEND_XFER_WAIT,
    SEND_XFER_COMPLETE,
};

enum xfer_send_opcode {
    xfer_send           = 0,
    xfer_write          = 1,
    xfer_read           = 2,
    xfer_atomic         = 3,
    xfer_send_with_imm  = 4,
    xfer_write_with_imm = 5,
};

enum {
    xfer_send_signaled = 1,
    xfer_send_inline   = 2,
};

// Datapath message descriptor to be exchanged across rings/queues/lists
// In uRDMA there are two distinct structures. I merged them. Is this a good idea?
// Should we keep them separate? Should we use a union?
struct dpdk_xfer_entry {
    struct dlist_entry    entry;
    void                 *context;
    enum xfer_send_opcode opcode;
    struct ee_state      *remote_ep;
    uint64_t              remote_addr;
    uint32_t              rkey;
    uint32_t              flags;
    uint32_t              index;
    enum xfer_send_state  state;
    uint32_t              msn;
    size_t                total_length;
    size_t                bytes_sent;
    size_t                bytes_acked;
    uint64_t              atomic_add_swap;
    uint64_t              atomic_compare;
    uint8_t               atomic_opcode;

    // For receive
    bool   complete;
    size_t recv_size;
    size_t input_size;

    // Immediate data
    uint32_t imm_data;
    // Pointers to IOV data
    size_t       iov_count;
    struct iovec iov[];
};

// ======= Fabric, Domain, Endpoint and Threads  =======

// Progress represents the data for the progress thread
struct dpdk_progress {
    // Fabric ID
    struct fid fid;
    // Mutex to access event list and CQ
    struct ofi_genlock lock;
    // List (and associated buffer pool) of events
    struct slist event_list;
    // Spinning lcore id
    int lcore_id;
    // Signal to stop the progress thread
    atomic_bool stop_progress;
};

enum dpdk_device_flags {
    port_checksum_offload = 1,
    port_fdir             = 2,
};

// Handle packet fragmentation
struct rx_queue {
    struct rte_ip_frag_tbl *frag_tbl;
    struct rte_mempool     *pool;
    uint16_t                portid;
};

/* Structure that handles per-lcore info.
 TODO: We assume only 1 receiving queue */
struct lcore_queue_conf {
    uint16_t                     n_rx_queue;
    struct rx_queue              rx_queue_list[1];
    struct rte_ip_frag_death_row death_row;
} __rte_cache_aligned;

// Represents a DPDK domain (=> a DPDK device)
struct dpdk_domain {
    // Utility domain
    struct util_domain util_domain;

    // TODO: The following fields could be grouped in a "dev" struct,
    // which could be passed also to the child EPs for faster access.
    // Port ID of the DPDK device
    uint16_t port_id;
    // Queue ID of the DPDK device
    uint16_t queue_id;
    // Device flags
    uint64_t dev_flags;
    // MTU
    uint32_t mtu;
    // DPDK core id
    uint16_t lcore_id;

    // Local Ethernet Address
    struct rte_ether_addr   eth_addr;
    // IPv4 Address and Port
    struct sockaddr_in      local_addr;

    // List of EP associated with this domain
    struct slist endpoint_list;
    // Number of EP in the list
    size_t num_endpoints;
    // Array of EP accessed by UDP port
    struct dpdk_ep *udp_port_to_ep[MAX_ENDPOINTS_PER_APP];
    // Mutex to access the list of EP
    struct ofi_genlock ep_mutex;

    // Progress thread data
    struct dpdk_progress progress;

    // Mempool for incoming packets
    struct rte_mempool *rx_pool;

    // Receive TLB to track incoming fragmented packet
    // TODO: Potentially, this could span multiple hardware queues.
    struct lcore_queue_conf lcore_queue_conf;

    // [Weijia] Connection management members
    struct rte_mempool* cm_pool;
    struct rte_ring*    cm_ring;
    atomic_uint         cm_session_counter;
};

#define DPDK_MAX_CM_DATA_SIZE   256

// DPDK endpoint connection state
enum ep_conn_state {
    ep_conn_state_unbound,
    ep_conn_state_connecting,
    ep_conn_state_connected,
    ep_conn_state_shutdown,
    ep_conn_state_error,
};

// DPDK endpoint: represents an open connection
struct dpdk_ep {
    // Reference to the associated endpoint
    struct util_ep util_ep;
    // UDP port => Used as unique identifier for the endpoint
    uint16_t udp_port;

    // Remote connection endpoint information
    // All are in host byte order
    struct rte_ether_addr remote_eth_addr;
    uint32_t              remote_ipv4_addr;
    uint16_t              remote_udp_port;

    // Receive and Transmit queues (= indeed, a "queue pair")
    struct dpdk_xfer_queue sq;
    struct dpdk_xfer_queue rq;
    // txq_end points one entry beyond the last entry in the table
    // the table is full when txq_end == txq + tx_burst_size
    // the burst should be flushed at that point
    struct rte_mbuf **txq_end;
    struct rte_mbuf **txq;
    // Receive and Transmit completion queues
    struct dpdk_cq *send_cq;
    struct dpdk_cq *recv_cq;

    // Connection information
    struct ee_state remote_ep;
    atomic_uint     conn_state;

    // Acknowledgement management
    struct read_atomic_response_state *readresp_store;
    uint32_t                           readresp_head_msn;
    uint8_t                            ord_active;

    // Memory pools for data buffers
    // 1. HDR pool:    contain the headers for the packets
    // 2. DDP mempool: pointers to external memory (zero-copy)
    struct rte_mempool *tx_hdr_mempool;
    struct rte_mempool *tx_ddp_mempool;

    // This is necessary because we keep EPs in a list
    struct slist_entry entry;
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
int  dpdk_init_progress(struct dpdk_progress *progress, struct fi_info *info, int lcore_id);
int  dpdk_start_progress(struct dpdk_progress *progress);
void dpdk_close_progress(struct dpdk_progress *progress);
int  dpdk_run_progress(void *args);
void dpdk_progress_rx(struct dpdk_ep *ep);
void flush_tx_queue(struct dpdk_ep *ep);

void dpdk_handle_event_list(struct dpdk_progress *progress);

// ======= Passive Endpoint and Connection Management (CM)  =======
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

// ======= Fabric, Domain, Endpoint and Threads  =======
// Represents a DPDK fabric
struct dpdk_fabric {
    struct util_fabric util_fabric;
};
 
// ======= Passive Endpoint and Connection Management (CM)  =======
enum dpdk_cm_msg_type {
    DPDK_CM_MSG_CONNECTION_REQUEST,
    DPDK_CM_MSG_CONNECTION_ACKNOWLEDGEMENT,
    DPDK_CM_MSG_CONNECTION_REJECTION,
    DPDK_CM_MSG_DISCONNECTION_REQUEST,
    DPDK_CM_MSG_DISCONNECTION_ACKNOWLEDGEMENT,
};

struct dpdk_cm_msg_hdr {
    uint32_t type;          // dpdk_cm_msg_type
    uint32_t session_id;    // a number picked by the connecting client to identify a session.
    union {
        // connection request
        struct {
            uint16_t                    client_data_udp_port;
            uint16_t                    paramlen;
        } __attribute__((__packed__))   connection_request;
        // connection acknowledgement
        struct {
            uint16_t                    server_data_udp_port;
        } __attribute__((__packed__))   connection_acknowledgement;
        // connection rejection
        struct {
            uint32_t                    rejection_code;
        } __attribute__((__packed__))   connection_rejection;
        // disconnection request
        struct {
            uint16_t                    local_data_udp_port;
            uint16_t                    remote_data_udp_port;
        } __attribute__((__packed__))   disconnection_request;
        // disconnection response
        struct {
            uint16_t                    local_data_udp_port;
            uint16_t                    remote_data_udp_port;
        } __attribute__((__packed__))   disconnection_response;
        // space padding
        struct {
            uint8_t                     bytes[56];
        } __attribute__((__packed__))   _padding;
    } __attribute__((__packed__))   payload;
};

/* We don't need this.
struct dpdk_cm_context {
    struct fid         fid;
    struct fid        *hfid;
    enum dpdk_cm_state state;
    size_t             cm_data_sz;
    struct dpdk_cm_msg msg;
};
*/

// Passive Endpoint
struct dpdk_pep {
    struct util_pep         util_pep;
    struct fi_info          *info;
    enum dpdk_cm_state      state;
};

int dpdk_passive_ep(struct fid_fabric *fabric, struct fi_info *info, struct fid_pep **pep,
                    void *context);

// ==================== Completion Queue ====================
enum fi_wc_status {
    FI_WC_SUCCESS,
    FI_WC_LOC_LEN_ERR,
    FI_WC_LOC_QP_OP_ERR,
    FI_WC_LOC_EEC_OP_ERR,
    FI_WC_LOC_PROT_ERR,
    FI_WC_WR_FLUSH_ERR,
    FI_WC_MW_BIND_ERR,
    FI_WC_BAD_RESP_ERR,
    FI_WC_LOC_ACCESS_ERR,
    FI_WC_REM_INV_REQ_ERR,
    FI_WC_REM_ACCESS_ERR,
    FI_WC_REM_OP_ERR,
    FI_WC_RETRY_EXC_ERR,
    FI_WC_RNR_RETRY_EXC_ERR,
    FI_WC_LOC_RDD_VIOL_ERR,
    FI_WC_REM_INV_RD_REQ_ERR,
    FI_WC_REM_ABORT_ERR,
    FI_WC_INV_EECN_ERR,
    FI_WC_INV_EEC_STATE_ERR,
    FI_WC_FATAL_ERR,
    FI_WC_RESP_TIMEOUT_ERR,
    FI_WC_GENERAL_ERR,
    FI_WC_TM_ERR,
    FI_WC_TM_RNDV_INCOMPLETE,
};

enum fi_wc_opcode {
    FI_WC_SEND,
    FI_WC_RDMA_WRITE,
    FI_WC_RDMA_READ,
    FI_WC_COMP_SWAP,
    FI_WC_FETCH_ADD,
    FI_WC_BIND_MW,
    FI_WC_LOCAL_INV,
    FI_WC_TSO,
    FI_WC_ATOMIC_WRITE = 9,
    /*
     * Set value of FI_WC_RECV so consumers can test if a completion is a
     * receive by testing (opcode & FI_WC_RECV).
     */
    FI_WC_RECV = 1 << 7,
    FI_WC_RECV_RDMA_WITH_IMM,

    FI_WC_TM_ADD,
    FI_WC_TM_DEL,
    FI_WC_TM_SYNC,
    FI_WC_TM_RECV,
    FI_WC_TM_NO_TAG,
    FI_WC_DRIVER1,
    FI_WC_DRIVER2,
    FI_WC_DRIVER3,
};

enum { FI_WC_IP_CSUM_OK_SHIFT = 2 };

enum fi_wc_flags {
    FI_WC_GRH           = 1 << 0,
    FI_WC_WITH_IMM      = 1 << 1,
    FI_WC_IP_CSUM_OK    = 1 << FI_WC_IP_CSUM_OK_SHIFT,
    FI_WC_WITH_INV      = 1 << 3,
    FI_WC_TM_SYNC_REQ   = 1 << 4,
    FI_WC_TM_MATCH      = 1 << 5,
    FI_WC_TM_DATA_VALID = 1 << 6,
};

struct fi_dpdk_wc {
    void             *wr_context;
    enum fi_wc_status status;
    enum fi_wc_opcode opcode;
    uint32_t          byte_len;
    uint32_t          ep_id;

    uint32_t wc_flags; // it can be 0 or FI_WC_WITH_IMM
    uint32_t imm_data; // valid when FI_WC_WITH_IMM is set.
};

struct fi_dpdk_cq_event {
    uint32_t event_type;
    uint32_t cq_id;
};

struct dpdk_cq {
    struct util_cq   util_cq;
    enum fi_wait_obj wait_obj;

    atomic_uint      refcnt;
    struct rte_ring *cqe_ring;
    struct rte_ring *free_ring;
    size_t           capacity;
    size_t           ep_count;
    uint32_t         cq_id;
    atomic_bool      notify_flag;
    // Vector of dpdk_wc
    struct fi_dpdk_wc *storage;
    // Associated EP // TODO: Not ideal...
    struct dpdk_ep *ep;
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


//===================== DPDK Parameters ================
struct dpdk_params_t {
    // dpdk base port
    #define DEFAULT_DPDK_BASE_PORT          (2509)
    int     base_port;
    // connection manager ring size
    #define DEFAULT_DPDK_CM_RING_SIZE       (16)
    size_t  cm_ring_size;
};

extern struct dpdk_params_t dpdk_params;

//===================== Log infrastructure ================
#define DPDK_TRACE(subsys, ...) FI_TRACE(&dpdk_prov, subsys, __VA_ARGS__)
#define DPDK_DBG(subsys, ...)   FI_DBG  (&dpdk_prov, subsys, __VA_ARGS__)
#define DPDK_INFO(subsys, ...)  FI_INFO (&dpdk_prov, subsys, __VA_ARGS__)
#define DPDK_WARN(subsys, ...)  FI_WARN (&dpdk_prov, subsys, __VA_ARGS__)


#endif /* _DPDK_H_ */
