#ifndef DPDK_DPDK_PROTOCOLS_H
#define DPDK_DPDK_PROTOCOLS_H

#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "fi_dpdk.h"

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>

/* This file contains definitions and function prototypes for the userspace protocol processing.*/

struct packet_context {
    struct ee_state     *src_ep;
    size_t               ddp_seg_length;
    struct rdmap_packet *rdmap;
    uint32_t             psn;
};

/* Ethernet */
#define ETHERNET_ADDRESS_LEN 6
#define ETHERNET_HEADER_LEN  14
#define MTU                  1500

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

/* IPv4 */

#define ICMPV4        1
#define IPV4          4
#define IP_TCP        6
#define IP_UDP        17
#define IP_HEADER_LEN 20
#define ip_len(ip)    (ip->len - (ip->ihl * 4))

uint16_t ip_checksum(struct rte_ipv4_hdr *ih, size_t len);
int32_t  ip_parse(char *addr, uint32_t *dst);

/* UDP */
#define UDP_HEADER_LEN       8
#define UDP_PORT             2310
#define MAX_UDP_PAYLOAD_SIZE 11808

/* TRP */
#define RETRANSMIT_MAX 5

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

void send_trp_sack(struct dpdk_ep *ep);
void process_trp_sack(struct ee_state *ep, uint32_t psn_min, uint32_t psn_max);
void maybe_sack_pending(struct pending_datagram_info *pending, uint32_t psn_min, uint32_t psn_max);

/* DDP */
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

struct pending_datagram_info {
    uint64_t                           next_retransmit;
    struct dpdk_xfer_entry            *xfer_entry;
    struct read_atomic_response_state *readresp;
    uint16_t                           transmit_count;
    uint16_t                           ddp_length;
    uint32_t                           ddp_raw_cksum;
    uint32_t                           psn;
};

void ddp_place_tagged_data(struct dpdk_ep *ep, struct packet_context *orig);

/* RDMAP */
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
struct rdmap_packet {
    uint8_t  ddp_flags;  /* 0=Tagged 1=Last 7-6=DDP_Version */
    uint8_t  rdmap_info; /* 1-0=RDMAP_Version 7-4=Opcode */
    uint32_t sink_stag;
    uint32_t immediate; /* The immediate data */
} __attribute__((__packed__));
static_assert(sizeof(struct rdmap_packet) == 10, "unexpected sizeof(rdmap_packet)");

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

void do_rdmap_send(struct dpdk_ep *ep, struct dpdk_xfer_entry *entry);
void do_rdmap_terminate(struct dpdk_ep *ep, struct packet_context *orig, enum rdmap_errno errcode);
#endif // DPDK_PROTOCOLS_H
