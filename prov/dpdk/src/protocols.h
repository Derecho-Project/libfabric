#ifndef ETHERNET_H
#define ETHERNET_H

#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <rte_ip.h>

#define MAX_UDP_PAYLOAD_SIZE 11808

#define ETHERNET_ADDRESS_LEN 6
#define ETHERNET_HEADER_LEN  14

#define ICMPV4 1
#define IPV4   4
#define IP_TCP 6
#define IP_UDP 17

#define IP_HEADER_LEN 20
#define ip_len(ip)    (ip->len - (ip->ihl * 4))

/* UDP header length*/
#define UDP_HEADER_LEN 8
#define UDP_PORT       2310

#define MTU 1500

#define ETHERNET_P_LOOP  0x0060 /* Ethernet Loopback packet	    */
#define ETHERNET_P_TSN   0x22F0 /* TSN (IEEE 1722) packet	    */
#define ETHERNET_P_IP    0x0800 /* Internet Protocol packet	    */
#define ETHERNET_P_ARP   0x0806 /* Address Resolution packet	*/
#define ETHERNET_P_8021Q 0x8100 /* 802.1Q VLAN Extended Header  */
#define ETHERNET_P_IPV6  0x86DD /* IPv6 over bluebook		    */

#define ETHERNET_ADDRESS_PRT_FMT "%02X:%02X:%02X:%02X:%02X:%02X"

#define ETHERNET_ADDRESS_BYTES(mac_addrs)                                                          \
    (mac_addrs)[0], (mac_addrs)[1], (mac_addrs)[2], (mac_addrs)[3], (mac_addrs)[4], (mac_addrs)[5]

#ifdef DEBUG_ETH
#define ETHERNET_DEBUG(msg, ehdr)                                                                  \
    do {                                                                                           \
        LOG_DEBUG("eth " msg " ("                                                                  \
                  "dst_mac: " ETHERNET_ADDRESS_PRT_FMT ", "                                        \
                  "src_mac: " ETHERNET_ADDRESS_PRT_FMT ", "                                        \
                  "ether_type: %.4hx",                                                             \
                  ETHERNET_ADDRESS_BYTES(ehdr->dst_mac), ETHERNET_ADDRESS_BYTES(ehdr->src_mac),    \
                  (ehdr)->ether_type);                                                             \
    } while (0)
#else
#define ETHERNET_DEBUG(msg, ehdr)
#endif

// Converts a string representing an eth address into a byte representation of the address itself
int eth_parse(char *string, unsigned char *eth_addr) {
    if (string == NULL || eth_addr == NULL) {
        return -1;
    }

    sscanf(string, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx", &eth_addr[0], &eth_addr[1], &eth_addr[2],
           &eth_addr[3], &eth_addr[4], &eth_addr[5]);
    return 0;
}

static uint16_t ip_checksum(struct rte_ipv4_hdr *ih, size_t len) {
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

static inline int32_t ip_parse(char *addr, uint32_t *dst) {
    if (inet_pton(AF_INET, addr, dst) != 1)
        return -1;

    return 0;
}

#endif // ETHERNET_H
