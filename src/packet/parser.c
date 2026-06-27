#include <stdint.h>

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_byteorder.h>

#include "parser.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * normalize_flow()  —  SDD §2.3, DD-10  (pure, constant-time, stateless)
 *
 * Canonical form: smaller src_ip in src fields.
 * Tie-break on equal IPs: smaller src_port in src_port.
 * Protocol and VLAN are never modified.
 * ───────────────────────────────────────────────────────────────────────────── */
void normalize_flow(pkt_meta_t *meta)
{
    if (meta->src_ip > meta->dst_ip) {
        uint32_t tmp_ip   = meta->src_ip;
        meta->src_ip      = meta->dst_ip;
        meta->dst_ip      = tmp_ip;
        uint16_t tmp_port = meta->src_port;
        meta->src_port    = meta->dst_port;
        meta->dst_port    = tmp_port;
    } else if (meta->src_ip == meta->dst_ip &&
               meta->src_port > meta->dst_port) {
        uint16_t tmp   = meta->src_port;
        meta->src_port = meta->dst_port;
        meta->dst_port = tmp;
    }
}

/* ─────────────────────────────────────────────────────────────────────────────
 * parse_packet()  —  SDD §2.3 (6-step zero-copy parsing chain)
 *
 * Operates directly on mbuf data pointer; no copies, no allocation.
 * Returns 0 on success (*meta fully populated).
 * Returns -1 for any unsupported or malformed packet (*meta undefined).
 * ───────────────────────────────────────────────────────────────────────────── */
int parse_packet(struct rte_mbuf *mbuf, pkt_meta_t *meta)
{
    const uint8_t *data     = rte_pktmbuf_mtod(mbuf, const uint8_t *);
    uint32_t       data_len = mbuf->data_len;
    uint32_t       offset   = 0;

    /* Step 1: Ethernet header */
    if (data_len < sizeof(struct rte_ether_hdr))
        return -1;
    const struct rte_ether_hdr *eth = (const struct rte_ether_hdr *)data;
    uint16_t etype = rte_be_to_cpu_16(eth->ether_type);
    offset = sizeof(struct rte_ether_hdr);

    /* Step 2: optional IEEE 802.1Q VLAN tag */
    meta->vlan_valid = 0;
    meta->vlan_id    = 0;
    if (etype == RTE_ETHER_TYPE_VLAN) {
        if (data_len < offset + sizeof(struct rte_vlan_hdr))
            return -1;
        const struct rte_vlan_hdr *vlan =
            (const struct rte_vlan_hdr *)(data + offset);
        meta->vlan_id    = rte_be_to_cpu_16(vlan->vlan_tci) & 0x0FFF;
        meta->vlan_valid = 1;
        etype  = rte_be_to_cpu_16(vlan->eth_proto);
        offset += sizeof(struct rte_vlan_hdr);
    }

    /* Step 3: IPv4 only — all other EtherTypes are dropped */
    if (etype != RTE_ETHER_TYPE_IPV4)
        return -1;
    if (data_len < offset + sizeof(struct rte_ipv4_hdr))
        return -1;
    const struct rte_ipv4_hdr *ip4 =
        (const struct rte_ipv4_hdr *)(data + offset);

    uint32_t ihl_bytes = ((uint32_t)(ip4->version_ihl & 0x0F)) * 4;
    if (ihl_bytes < 20)                         /* RFC 791: min IHL = 5 */
        return -1;
    if (data_len < offset + ihl_bytes)
        return -1;

    meta->src_ip   = ip4->src_addr;             /* preserved in network byte order */
    meta->dst_ip   = ip4->dst_addr;
    meta->protocol = ip4->next_proto_id;
    offset        += ihl_bytes;

    /* Step 4: TCP or UDP — ICMP and all other protocols are dropped */
    if (meta->protocol == IPPROTO_TCP) {
        if (data_len < offset + sizeof(struct rte_tcp_hdr))
            return -1;
        const struct rte_tcp_hdr *tcp =
            (const struct rte_tcp_hdr *)(data + offset);
        meta->src_port = rte_be_to_cpu_16(tcp->src_port);
        meta->dst_port = rte_be_to_cpu_16(tcp->dst_port);
    } else if (meta->protocol == IPPROTO_UDP) {
        if (data_len < offset + sizeof(struct rte_udp_hdr))
            return -1;
        const struct rte_udp_hdr *udp =
            (const struct rte_udp_hdr *)(data + offset);
        meta->src_port = rte_be_to_cpu_16(udp->src_port);
        meta->dst_port = rte_be_to_cpu_16(udp->dst_port);
    } else {
        return -1;
    }

    /* Steps 5–6: five-tuple is assembled; apply bidirectional normalisation */
    normalize_flow(meta);

    return 0;
}
