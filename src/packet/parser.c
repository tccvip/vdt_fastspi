#include <stdint.h>

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_byteorder.h>
#include <rte_ring.h>
#include <rte_prefetch.h>
#include <rte_hash_crc.h>

#include "parser.h"

/* Written by RX lcore; read by Parser, Worker, TX (SDD §6.8). */
extern volatile int g_shutdown_flag;

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

/* ─────────────────────────────────────────────────────────────────────────────
 * parser_lcore_func()  —  SDD §2.3 (Parser lcore hot loop)
 *
 * Dequeues bursts from parser_ring, prefetches packet data, calls parse_packet()
 * writing five-tuple metadata directly into each mbuf's headroom, then
 * hash-dispatches to the target worker_ring.
 *
 * Prefetch pattern (SDD §2.3, SPIFAST_PREFETCH_AHEAD = 4):
 *   Pre-prime the first PREFETCH_AHEAD entries before the main loop, then
 *   issue one rolling prefetch per iteration to keep packet data in L1 cache.
 *
 * Ownership (SDD §6.7):
 *   On successful parse + enqueue → ownership transfers to the Worker lcore.
 *   On parse failure or ring-full   → rte_pktmbuf_free() returns mbuf to pool.
 * ───────────────────────────────────────────────────────────────────────────── */
int parser_lcore_func(void *arg)
{
    parser_ctx_t         *ctx   = (parser_ctx_t *)arg;
    parser_lcore_stats_t *stats = ctx->stats;

    struct rte_mbuf *pkts[SPIFAST_BURST_SIZE];

    while (!g_shutdown_flag || !rte_ring_empty(ctx->parser_ring)) {
        unsigned int nb = rte_ring_dequeue_burst(ctx->parser_ring,
                                                  (void **)pkts,
                                                  SPIFAST_BURST_SIZE, NULL);
        if (nb == 0)
            continue;

        stats->received += nb;

        /* Pre-prime prefetch for the first PREFETCH_AHEAD packets so their
         * data is in-flight before the processing loop begins. */
        unsigned int pre = nb < SPIFAST_PREFETCH_AHEAD
                             ? nb : SPIFAST_PREFETCH_AHEAD;
        for (unsigned int j = 0; j < pre; j++)
            rte_prefetch0(rte_pktmbuf_mtod(pkts[j], void *));

        for (unsigned int i = 0; i < nb; i++) {
            /* Rolling prefetch: start fetching packet i+PREFETCH_AHEAD while
             * processing packet i to hide the L1 miss latency. */
            if (i + SPIFAST_PREFETCH_AHEAD < nb)
                rte_prefetch0(rte_pktmbuf_mtod(pkts[i + SPIFAST_PREFETCH_AHEAD],
                                                void *));

            /* Write parsed five-tuple directly into mbuf headroom (DD-17).
             * parse_packet() also calls normalize_flow() before returning. */
            pkt_meta_t *meta = pkt_meta_of(pkts[i]);
            if (parse_packet(pkts[i], meta) != 0) {
                rte_pktmbuf_free(pkts[i]);
                stats->invalid++;
                continue;
            }
            stats->parsed++;

            /* Hash dispatch: normalised five-tuple → deterministic worker slot.
             * Ensures all packets of the same flow reach the same Worker lcore,
             * keeping ACL Stage-2 context warm in its L1 cache (DD-14). */
            uint32_t worker_idx = rte_hash_crc(meta, sizeof(pkt_meta_t), 0)
                                  % ctx->num_workers;

            int rc = rte_ring_enqueue(ctx->worker_rings[worker_idx], pkts[i]);
            if (rc != 0) {
                /* worker_ring full: free mbuf, ownership returns to pool */
                rte_pktmbuf_free(pkts[i]);
                stats->ring_drop++;
                continue;
            }
            stats->dispatched++;
        }
    }

    return 0;
}
