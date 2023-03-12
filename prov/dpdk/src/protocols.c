#include "protocols.h"

/* Ethernet */

// Converts a string representing an eth address into a byte representation of the address itself
int eth_parse(char *string, unsigned char *eth_addr) {
    if (string == NULL || eth_addr == NULL) {
        return -1;
    }

    sscanf(string, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx", &eth_addr[0], &eth_addr[1], &eth_addr[2],
           &eth_addr[3], &eth_addr[4], &eth_addr[5]);
    return 0;
}

/* IPv4 */

uint16_t ip_checksum(struct rte_ipv4_hdr *ih, size_t len) {
    const void *buf = ih;
    uint32_t    sum = 0;

    /* extend strict-aliasing rules */
    typedef uint16_t __attribute__((__may_alias__)) uint16_t_p;
    const uint16_t_p *uint16_t_buf = (const uint16_t_p *)buf;
    const uint16_t_p *end          = uint16_t_buf + len / sizeof(*uint16_t_buf);

    for (; uint16_t_buf != end; ++uint16_t_buf)
        sum += *uint16_t_buf;

    /* if length is odd, keeping it byte order independent */
    if (likely(len % 2)) {
        uint16_t left           = 0;
        *(unsigned char *)&left = *(const unsigned char *)end;
        sum += left;
    }

    sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
    sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);

    uint16_t cksum = (uint16_t)sum;

    return (uint16_t)~cksum;
}

int32_t ip_parse(char *addr, uint32_t *dst) {
    if (inet_pton(AF_INET, addr, dst) != 1)
        return -1;

    return 0;
}

/* UDP */

/* TRP */
void send_trp_sack(struct dpdk_ep *ep) {
    struct rte_mbuf *sendmsg;
    struct ee_state *ee = &ep->remote_ep;
    struct trp_hdr  *trp;

    assert(ee->trp_flags & trp_recv_missing);
    sendmsg      = rte_pktmbuf_alloc(ep->tx_hdr_mempool);
    trp          = (struct trp_hdr *)rte_pktmbuf_append(sendmsg, sizeof(*trp));
    trp->psn     = rte_cpu_to_be_32(ee->recv_sack_psn.min);
    trp->ack_psn = rte_cpu_to_be_32(ee->recv_sack_psn.max);
    trp->opcode  = rte_cpu_to_be_16(trp_sack);

    ee->trp_flags &= ~trp_ack_update;

    send_udp_dgram(
        ep, sendmsg,
        /*(ep->dev->flags & port_checksum_offload) ? 0 :*/ rte_raw_cksum(trp, sizeof(*trp)));
} /* send_trp_sack */

/* DDP */

/* RDMAP */
