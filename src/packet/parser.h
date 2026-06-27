#ifndef SPIFAST_PARSER_H
#define SPIFAST_PARSER_H

#include <stdint.h>
#include <rte_mbuf.h>

/* ─────────────────────────────────────────────────────────────────────────────
 * Packet metadata — five-tuple plus optional VLAN tag  (SDD §3.1)
 * Allocated on the RX/classifier lcore stack per packet; never heap-allocated.
 * Total: 12 bytes — fits in one cache line alongside local variables.
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    uint32_t src_ip;      /* IPv4 source address, network byte order;
                             after flow normalisation: numerically smaller IP */
    uint32_t dst_ip;      /* IPv4 destination address, network byte order    */
    uint16_t src_port;    /* transport source port, host byte order           */
    uint16_t dst_port;    /* transport destination port, host byte order      */
    uint8_t  protocol;    /* IP protocol: IPPROTO_TCP (6) or IPPROTO_UDP (17)*/
    uint8_t  vlan_valid;  /* 1 if frame carried a VLAN tag, 0 otherwise       */
    uint16_t vlan_id;     /* 802.1Q VLAN ID [0..4095]; valid when vlan_valid */
} pkt_meta_t;

/* ─────────────────────────────────────────────────────────────────────────────
 * Public API  (SDD §2.3)
 * ───────────────────────────────────────────────────────────────────────────── */

/* Parse mbuf headers (Ethernet → VLAN → IPv4 → TCP/UDP).
 * Writes result into *meta on success.  Returns 0 on success, -1 on any
 * parse failure (unsupported EtherType, truncated header, non-TCP/UDP).
 * Zero-copy: operates directly on mbuf data; no allocation.  SDD §2.3 */
int parse_packet(struct rte_mbuf *mbuf, pkt_meta_t *meta);

/* Apply bidirectional flow normalisation in-place (SDD §2.3, DD-10).
 * Ensures forward and reverse packets of the same flow produce the same key.
 * Pure function, constant time, stateless — no allocation.  */
void normalize_flow(pkt_meta_t *meta);

#endif /* SPIFAST_PARSER_H */
