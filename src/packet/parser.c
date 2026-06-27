#include <string.h>
#include <arpa/inet.h>

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_byteorder.h>

#include "parser.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * parse_packet()  —  SDD §2.3 (6-step parsing chain)
 *
 * Operates zero-copy directly on mbuf data; no heap allocation.
 * Returns 0 on success (meta is filled), -1 on any parse failure.
 * ───────────────────────────────────────────────────────────────────────────── */
int parse_packet(struct rte_mbuf *mbuf, pkt_meta_t *meta)
{
    /* TODO: Step 1 — Ethernet header.
     *   data     = rte_pktmbuf_mtod(mbuf, uint8_t *);
     *   data_len = mbuf->data_len;
     *   if (data_len < sizeof(struct rte_ether_hdr)) return -1;
     *   eth   = (struct rte_ether_hdr *) data;
     *   etype = rte_be_to_cpu_16(eth->ether_type);
     *   offset = sizeof(struct rte_ether_hdr);   // 14 bytes  */

    /* TODO: Step 2 — VLAN tag strip (IEEE 802.1Q, EtherType 0x8100).
     *   meta->vlan_valid = 0; meta->vlan_id = 0;
     *   if (etype == RTE_ETHER_TYPE_VLAN):
     *     if (data_len < offset + 4) return -1;
     *     vlan_hdr = (struct rte_vlan_hdr *)(data + offset);
     *     meta->vlan_id    = rte_be_to_cpu_16(vlan_hdr->vlan_tci) & 0x0FFF;
     *     meta->vlan_valid = 1;
     *     etype  = rte_be_to_cpu_16(vlan_hdr->eth_proto);
     *     offset += 4;  */

    /* TODO: Step 3 — IPv4 only (EtherType 0x0800; drop all others).
     *   if (etype != RTE_ETHER_TYPE_IPV4) return -1;
     *   if (data_len < offset + sizeof(struct rte_ipv4_hdr)) return -1;
     *   ip4 = (struct rte_ipv4_hdr *)(data + offset);
     *   ihl_bytes = (ip4->version_ihl & 0x0F) * 4;
     *   if (ihl_bytes < 20) return -1;
     *   meta->src_ip   = ip4->src_addr;   // keep network byte order
     *   meta->dst_ip   = ip4->dst_addr;
     *   meta->protocol = ip4->next_proto_id;
     *   offset += ihl_bytes;  */

    /* TODO: Step 4 — TCP or UDP transport header.
     *   if (meta->protocol == IPPROTO_TCP):
     *     if (data_len < offset + sizeof(struct rte_tcp_hdr)) return -1;
     *     tcp = (struct rte_tcp_hdr *)(data + offset);
     *     meta->src_port = rte_be_to_cpu_16(tcp->src_port);
     *     meta->dst_port = rte_be_to_cpu_16(tcp->dst_port);
     *   elif (meta->protocol == IPPROTO_UDP):
     *     if (data_len < offset + sizeof(struct rte_udp_hdr)) return -1;
     *     udp = (struct rte_udp_hdr *)(data + offset);
     *     meta->src_port = rte_be_to_cpu_16(udp->src_port);
     *     meta->dst_port = rte_be_to_cpu_16(udp->dst_port);
     *   else: return -1;   // non-TCP/UDP protocol  */

    /* TODO: Step 5 — Five-tuple is now fully assembled in *meta. */

    /* TODO: Step 6 — Apply bidirectional flow normalisation.
     *   normalize_flow(meta);
     *   return 0;  */

    (void)mbuf; (void)meta;
    return -1;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * normalize_flow()  —  SDD §2.3, DD-10  (pure, constant-time, stateless)
 *
 * Canonical form: numerically smaller src_ip is placed in src fields.
 * If src_ip == dst_ip, smaller port goes to src_port.
 * This ensures forward and reverse packets of the same flow produce the
 * same five-tuple key without maintaining any per-flow state (FR-012, FR-013).
 * ───────────────────────────────────────────────────────────────────────────── */
void normalize_flow(pkt_meta_t *meta)
{
    /* TODO: if (meta->src_ip > meta->dst_ip):
     *         swap(meta->src_ip, meta->dst_ip);
     *         swap(meta->src_port, meta->dst_port);
     *       elif (meta->src_ip == meta->dst_ip && meta->src_port > meta->dst_port):
     *         swap(meta->src_port, meta->dst_port);
     *   protocol and vlan fields are never swapped.  */
    (void)meta;
}
