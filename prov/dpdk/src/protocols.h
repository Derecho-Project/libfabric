#ifndef DPDK_DPDK_PROTOCOLS_H
#define DPDK_DPDK_PROTOCOLS_H

#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "fi_dpdk.h"
/* This file contains definitions and function prototypes for the userspace protocol processing.*/

struct packet_context {
    struct dlist_entry   entry;
    struct dpdk_ep      *dst_ep;
    struct ee_state     *src_ep;
    size_t               ddp_seg_length;
    struct rdmap_packet *rdmap;
    struct rte_mbuf     *mbuf_head;
    uint32_t             psn;
};

/* Size of headers */
#define IP_HDR_LEN    sizeof(struct rte_ipv4_hdr)
#define UDP_HDR_LEN   sizeof(struct rte_udp_hdr)
#define TRP_HDR_LEN   sizeof(struct trp_hdr)
#define RDMAP_HDR_LEN sizeof(struct rdmap_untagged_packet)

/* All the headers that are included in the MTU size */
#define MTU           1500
#define INNER_HDR_LEN (IP_HDR_LEN + UDP_HDR_LEN + TRP_HDR_LEN + RDMAP_HDR_LEN)
#define HDR_MBUF_EXTRA_SPACE                                                                       \
    (sizeof(struct rdmap_readreq_packet) - sizeof(struct rdmap_untagged_packet))

/* Offsets of headers in the hdr mbufs */
#define ETHERNET_HDR_OFFSET 0
#define IP_HDR_OFFSET       (ETHERNET_HDR_OFFSET + RTE_ETHER_HDR_LEN)
#define UDP_HDR_OFFSET      (IP_HDR_OFFSET + IP_HDR_LEN)
#define TRP_HDR_OFFSET      (UDP_HDR_OFFSET + UDP_HDR_LEN)
#define RDMAP_HDR_OFFSET    (TRP_HDR_OFFSET + TRP_HDR_LEN)

/* IP-level fragmentation macros */
#define IP_FRAG_TBL_BUCKET_ENTRIES 16 // Should be power of two.
#define MAX_FRAG_NUM               RTE_LIBRTE_IP_FRAG_MAX_FRAG
#define PREFETCH_OFFSET            3
#define DEF_FLOW_TTL               MS_PER_S
#define DEF_FLOW_NUM               0x1000

/* Ethernet */
#define ETHERNET_P_LOOP  0x0060 /* Ethernet Loopback packet	    */
#define ETHERNET_P_TSN   0x22F0 /* TSN (IEEE 1722) packet	    */
#define ETHERNET_P_IP    0x0800 /* Internet Protocol packet	    */
#define ETHERNET_P_ARP   0x0806 /* Address Resolution packet	*/
#define ETHERNET_P_8021Q 0x8100 /* 802.1Q VLAN Extended Header  */
#define ETHERNET_P_IPV6  0x86DD /* IPv6 over bluebook		    */

#define ETHERNET_ADDRESS_PRT_FMT "%02X:%02X:%02X:%02X:%02X:%02X"

#define ETHERNET_ADDRESS_BYTES(mac_addrs)                                                          \
    (mac_addrs)[0], (mac_addrs)[1], (mac_addrs)[2], (mac_addrs)[3], (mac_addrs)[4], (mac_addrs)[5]

// Converts a string representing an eth address into a byte representation of the address itself
int eth_parse(char *string, unsigned char *eth_addr);

void enqueue_ether_frame(struct rte_mbuf *sendmsg, unsigned int ether_type, struct dpdk_ep *ep,
                         struct rte_ether_addr *dst_addr);

/* ARP */
#define ARP_REQUEST    0x0001
#define ARP_REPLY      0x0002
#define ARP_HEADER_LEN sizeof(struct arp_hdr)
#define ARP_ETHERNET   0x0001
#define ARP_IPV4       0x0800
#define ARP_CACHE_LEN  32
#define ARP_FREE       0
#define ARP_WAITING    1
#define ARP_RESOLVED   2

typedef struct arp_ipv4 {
    uint8_t  arp_sha[RTE_ETHER_ADDR_LEN];
    uint32_t arp_sip;
    uint8_t  arp_tha[RTE_ETHER_ADDR_LEN];
    uint32_t arp_tip;
} __attribute__((packed)) arp_ipv4_t;

typedef struct arp_hdr {
    uint16_t arp_htype;
    uint16_t arp_ptype;
    uint8_t  arp_hlen;
    uint8_t  arp_plen;
    uint16_t arp_opcode;

    arp_ipv4_t arp_data;
} __attribute__((packed)) arp_hdr_t;

uint8_t *arp_get_hwaddr(uint32_t saddr);
uint8_t *arp_get_hwaddr_or_lookup(struct dpdk_domain_resources *domain_res, uint32_t saddr);
void     arp_receive(struct dpdk_domain_resources *domain_res, struct rte_mbuf *arp_mbuf);
int32_t  arp_request(struct dpdk_domain_resources *domain_res, uint32_t saddr, uint32_t daddr);

// ARP Table
#define ARP_TRASL_TABLE_INSERT_FAILED   0
#define ARP_TRASL_TABLE_INSERT_OK       1
#define ARP_TRASL_TABLE_UPDATE_NO_ENTRY 0
#define ARP_TRASL_TABLE_UPDATE_OK       1

typedef struct arp_cache_entry {
    struct dlist_entry list;

    uint16_t hwtype;
    uint32_t sip;
    uint8_t  src_mac[RTE_ETHER_ADDR_LEN];
    uint32_t state;
} arp_cache_entry_t;

/* IPv4 */
#define ICMPV4     1
#define IPV4       4
#define IP_TCP     6
#define IP_UDP     17
#define ip_len(ip) (ip->len - (ip->ihl * 4))

int32_t ip_parse(char *addr, uint32_t *dst);

struct rte_ipv4_hdr *prepend_ipv4_header(struct rte_mbuf *sendmsg, int next_proto_id,
                                         uint32_t src_addr, uint32_t dst_addr, uint16_t ddp_length);
struct rte_mbuf *reassemble(struct rte_mbuf *m, struct lcore_queue_conf *qconf, uint16_t vlan_id,
                            uint64_t tms);

int setup_queue_tbl(struct rx_queue *rxq, uint32_t lcore, uint32_t queue, uint16_t port_mtu);

/* UDP */

// UDP max payload size
// IMPORTANT: By default, DPDK limits the number of IP fragments per packet
// to RTE_LIBRTE_IP_FRAG_MAX_FRAG. In v22.11, this is 8. This is because generally production-grade
// networks do not allow loger IP fragment chains. So, either you increase that value in your DPDK
// installation, or you reduce the max UDP payload size to stay below that threashold. In this
// example, we adopt the latter approach as it does not require you to change, recompile, and
// reinstall DPDK.
#define MAX_UDP_PAYLOAD_SIZE 11808

void send_udp_dgram(struct dpdk_ep *ep, struct rte_mbuf *sendmsg, uint32_t raw_cksum,
                    uint16_t ddp_length);

struct rte_udp_hdr *prepend_udp_header(struct rte_mbuf *sendmsg, unsigned int src_port,
                                       unsigned int dst_port, uint16_t ddp_length);

/* TRP */
#define RETRANSMIT_MAX 0

enum {
    trp_req = 0x1000,
    /**< Initial request from the client.  Any data in the packet
     * is considered to be part of the RDMA CM private data
     * exchange. */
    trp_accept = 0x2000,
    /**< Accepting a connection request from the client.  Any data
     * in the packet is passed as private data to the client
     * application. */
    trp_reject = 0x3000,
    /**< Rejecting a connection request from the client.  Any data
     * in the packet is passed as private data to the client
     * application. */
    trp_fin = 0x4000,
    /**< Indicates that the sender wishes to close the connection.
     * The connection is destroyed as soon as this message is sent;
     * no response from the receiver is necessary nor expected. */
    trp_sack = 0x5000,
    /**< This packet is a selective acknowledgement that contains
     * no data.  Rather, the psn and ack_psn fields indicate the
     * minimum and (maximum + 1) sequence numbers, respectively, in
     * a contiguous range that have been received. */
    trp_opcode_mask = 0xf000,
    /**< Mask of all bits used for opcode. */
    trp_reserved_mask = 0x0fff,
    /**< Mask of all bits not currently used. */
    trp_opcode_shift = 12,
    /**< Number of bits that opcode is shifted by. */
};

enum {
    trp_recv_missing = 1,
    trp_ack_update   = 2,
};

struct trp_hdr {
    uint32_t psn;
    uint32_t ack_psn;
    uint16_t opcode;
} __attribute__((__packed__));

struct trp_rr_params {
    uint16_t pd_len;
    uint16_t ird;
    uint16_t ord;
} __attribute__((__packed__));

struct trp_rr {
    struct trp_hdr       hdr;
    struct trp_rr_params params;
} __attribute__((__packed__));

struct pending_datagram_info {
    uint64_t                           next_retransmit;
    struct dpdk_xfer_entry            *wqe;
    struct read_atomic_response_state *readresp;
    uint16_t                           transmit_count;
    uint16_t                           ddp_length;
    uint32_t                           ddp_raw_cksum;
    uint32_t                           psn;
};
#define PENDING_DATAGRAM_INFO_SIZE sizeof(struct pending_datagram_info)

void send_trp_ack(struct dpdk_ep *ep);
void send_trp_sack(struct dpdk_ep *ep);
void process_trp_sack(struct ee_state *ep, uint32_t psn_min, uint32_t psn_max);
void maybe_sack_pending(struct pending_datagram_info *pending, uint32_t psn_min, uint32_t psn_max);

/* DDP */
#define DDP_V1_UNTAGGED_DF      0x01
#define DDP_V1_TAGGED_DF        0x81
#define DDP_V1_UNTAGGED_LAST_DF 0x41
#define DDP_V1_TAGGED_LAST_DF   0xc1
#define DDP_GET_T(flags)        ((flags >> 7) & 0x1)
#define DDP_GET_L(flags)        ((flags >> 6) & 0x1)
#define DDP_GET_DV(flags)       ((flags) & 0x3)

struct read_atomic_response_state {
    char    *vaddr;
    uint32_t sink_stag; /* network byte order */
    bool     active;
    enum {
        read_response,
        atomic_response,
    } type;
    struct dlist_entry qp_entry;
    struct ee_state   *sink_ep;

    union {
        struct {
            uint32_t msg_size;
            uint64_t sink_offset; /* host byte order */
        } read;
        struct {
            unsigned int opcode;
            uint32_t     req_id;
            uint64_t     add_swap;
            uint64_t     add_swap_mask;
            uint64_t     compare;
            uint64_t     compare_mask;
            bool         done;
        } atomic;
    };
};

enum ddp_queue_number {
    ddp_queue_send            = 0,
    ddp_queue_read_request    = 1,
    ddp_queue_terminate       = 2,
    ddp_queue_atomic_response = 3,
    ddp_queue_ack             = 4,
};

int send_ddp_segment(struct dpdk_ep *ep, struct rte_mbuf *sendmsg,
                     struct read_atomic_response_state *readresp, struct dpdk_xfer_entry *wqe,
                     size_t payload_length);
int resend_ddp_segment(struct dpdk_ep *ep, struct rte_mbuf *sendmsg, struct ee_state *ee);

/* RDMAP */

#define MAX_RDMAP_PAYLOAD_SIZE (MAX_UDP_PAYLOAD_SIZE - TRP_HDR_LEN - RDMAP_HDR_LEN)

#define RDMAP_V1                0x40
#define RDMAP_GET_RV(flags)     ((flags >> 6) & 0x3)
#define RDMAP_GET_OPCODE(flags) ((flags) & 0xf)

/** Given a pointer to a structure representing a packet header, returns a
 * pointer to the payload (one byte immediately after the header) */
#define PAYLOAD_OF(x) ((char *)((x) + 1))

struct rdmap_packet {
    uint8_t  ddp_flags;  /* 0=Tagged 1=Last 7-6=DDP_Version */
    uint8_t  rdmap_info; /* 1-0=RDMAP_Version 7-4=Opcode */
    uint32_t sink_stag;
    uint32_t immediate; /* The immediate data */
} __attribute__((__packed__));
static_assert(sizeof(struct rdmap_packet) == 10, "unexpected sizeof(rdmap_packet)");

enum rdmap_atomic_opcodes {
    rdmap_atomic_fetchadd = 0,
    rdmap_atomic_cmpswap  = 1,
};

struct rdmap_tagged_packet {
    struct rdmap_packet head;
    uint64_t            offset;
} __attribute__((__packed__));
static_assert(sizeof(struct rdmap_tagged_packet) == 18, "unexpected sizeof(rdmap_tagged_packet)");

struct rdmap_untagged_packet {
    struct rdmap_packet head;
    uint32_t            qn;  /* Queue Number */
    uint32_t            msn; /* Message Sequence Number */
    uint32_t            mo;  /* Message Offset */
} __attribute__((__packed__));
static_assert(sizeof(struct rdmap_untagged_packet) == 22,
              "unexpected sizeof(rdmap_untagged_packet)");

#define RDMAP_TAGGED_ALLOC_SIZE(len) (sizeof(struct rdmap_tagged_packet) + (len))
struct rdmap_readreq_packet {
    struct rdmap_untagged_packet untagged;
    uint64_t                     sink_offset;
    uint32_t                     read_msg_size;
    uint32_t                     source_stag;
    uint64_t                     source_offset;
} __attribute__((__packed__));
static_assert(sizeof(struct rdmap_readreq_packet) == 46, "unexpected sizeof(rdmap_readreq_packet)");

struct rdmap_terminate_packet {
    struct rdmap_untagged_packet untagged;
    uint16_t                     error_code; /* 0-3 layer 4-7 etype 8-16 code */
    uint8_t                      hdrct;      /* bits: 0-M 1-D 2-R */
    uint8_t                      reserved;
} __attribute__((__packed__));
static_assert(sizeof(struct rdmap_terminate_packet) == 26,
              "unexpected sizeof(rdmap_terminate_packet)");

struct rdmap_terminate_payload {
    uint16_t            ddp_seg_len;
    struct rdmap_packet payload;
} __attribute__((__packed__));

struct rdmap_atomicreq_packet {
    struct rdmap_untagged_packet untagged;
    uint32_t                     opcode;
    uint32_t                     req_id;
    uint32_t                     remote_stag;
    uint64_t                     remote_offset;
    uint64_t                     add_swap_data;
    uint64_t                     add_swap_mask;
    uint64_t                     compare_data;
    uint64_t                     compare_mask;
} __attribute__((__packed__));
static_assert(sizeof(struct rdmap_atomicreq_packet) == 74,
              "unexpected sizeof(rdmap_atomicreq_packet)");

struct rdmap_atomicresp_packet {
    struct rdmap_untagged_packet untagged;
    uint32_t                     req_id;
    uint64_t                     orig_value;
} __attribute__((__packed__));
static_assert(sizeof(struct rdmap_atomicresp_packet) == 34,
              "unexpected sizeof(rdmap_atomicresp_packet)");

enum rdmap_packet_type {
    rdmap_opcode_rdma_write          = 0,
    rdmap_opcode_rdma_read_request   = 1,
    rdmap_opcode_rdma_read_response  = 2,
    rdmap_opcode_send                = 3,
    rdmap_opcode_send_inv            = 4,
    rdmap_opcode_send_se             = 5,
    rdmap_opcode_send_se_inv         = 6,
    rdmap_opcode_terminate           = 7,
    rdmap_opcode_imm_data            = 8,
    rdmap_opcode_imm_data_se         = 9,
    rdmap_opcode_atomic_request      = 10,
    rdmap_opcode_atomic_response     = 11,
    rdmap_opcode_rdma_write_with_imm = 12,
    rdmap_opcode_send_with_imm       = 13,
};

enum /*rdmap_hdrct*/ {
    rdmap_hdrct_m = 1,
    rdmap_hdrct_d = 2,
    rdmap_hdrct_r = 4,
};

enum rdmap_errno {
    rdmap_error_local_catastrophic              = 0x0000,
    rdmap_error_stag_invalid                    = 0x0100,
    rdmap_error_base_or_bounds_violation        = 0x0101,
    rdmap_error_access_violation                = 0x0102,
    rdmap_error_stag_wrong_stream               = 0x0103,
    rdmap_error_to_wrap                         = 0x0104,
    rdmap_error_protection_stag_not_invalidated = 0x0109,
    rdmap_error_remote_protection_unspecified   = 0x01ff,
    rdmap_error_version_invalid                 = 0x0205,
    rdmap_error_opcode_unexpected               = 0x0206,
    rdmap_error_remote_stream_catastrophic      = 0x0207,
    rdmap_error_remote_global_catastrophic      = 0x0208,
    rdmap_error_operation_stag_not_invalidated  = 0x0209,
    rdmap_error_remote_operation_unspecified    = 0x02ff,
    ddp_error_local_catastrophic                = 0x1000,
    ddp_error_tagged_stag_invalid               = 0x1100,
    ddp_error_tagged_base_or_bounds_violation   = 0x1101,
    ddp_error_tagged_stag_wrong_stream          = 0x1102,
    ddp_error_tagged_to_wrap                    = 0x1103,
    ddp_error_tagged_version_invalid            = 0x1104,
    ddp_error_untagged_invalid_qn               = 0x1201,
    ddp_error_untagged_no_buffer                = 0x1202,
    ddp_error_untagged_invalid_msn              = 0x1203,
    ddp_error_untagged_invalid_mo               = 0x1204,
    ddp_error_untagged_message_too_long         = 0x1205,
    ddp_error_untagged_version_invalid          = 0x1206,
};

void memcpy_from_iov(char *restrict dest, size_t dest_size, const struct iovec *restrict src,
                     size_t iov_count, size_t offset);
void do_rdmap_send(struct dpdk_ep *ep, struct dpdk_xfer_entry *entry);
void do_rdmap_write(struct dpdk_ep *ep, struct dpdk_xfer_entry *entry);
void do_rdmap_read_request(struct dpdk_ep *ep, struct dpdk_xfer_entry *entry);
int  do_rdmap_read_response(struct dpdk_ep *ep, struct read_atomic_response_state *readresp);
void do_rdmap_terminate(struct dpdk_ep *ep, struct packet_context *orig, enum rdmap_errno errcode);

int setup_queue_tbl(struct rx_queue *rxq, uint32_t lcore, uint32_t queue, uint16_t port_mtu);
#endif // DPDK_PROTOCOLS_H
