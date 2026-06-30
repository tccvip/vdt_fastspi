#ifndef SPIFAST_PARSER_H
#define SPIFAST_PARSER_H

#include <stdint.h>
#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include "pkt_ctx.h"           /* pkt_meta_t, pkt_meta_of, pkt_meta_read */
#include "dpdk/dpdk_init.h"    /* SPIFAST_MAX_WORKERS, SPIFAST_BURST_SIZE,
                                   SPIFAST_PREFETCH_AHEAD, CACHE_LINE_SIZE */
#include "perf/perf_stats.h"   /* perf_stage_t                            */

/* ─────────────────────────────────────────────────────────────────────────────
 * Per-lcore statistics for the Parser lcore  (SDD §3.5)
 *
 * Written only by the Parser lcore; read by main/stats lcore without locking.
 * Cache-line padded to prevent false sharing with adjacent stats structs.
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    uint64_t received;    /* mbufs dequeued from parser_ring                   */
    uint64_t parsed;      /* mbufs successfully parsed (headers valid)         */
    uint64_t invalid;     /* mbufs freed due to parse failure                  */
    uint64_t dispatched;  /* mbufs successfully enqueued to a worker_ring      */
    uint64_t ring_drop;   /* mbufs freed because target worker_ring was full   */
    /* Per-worker dispatch breakdown — written by Parser, read by main/stats.
     * Used to detect hash-dispatch imbalance when debugging multi-worker perf. */
    uint64_t dispatched_to[SPIFAST_MAX_WORKERS];
    uint8_t  _pad[CACHE_LINE_SIZE
                  - ((5 + SPIFAST_MAX_WORKERS) * sizeof(uint64_t)) % CACHE_LINE_SIZE];
} __rte_cache_aligned parser_lcore_stats_t;

/* ─────────────────────────────────────────────────────────────────────────────
 * Context passed to parser_lcore_func() at lcore launch  (SDD §2.3)
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    struct rte_ring      *parser_ring;                       /* SPSC: dequeue source  */
    struct rte_ring      *worker_rings[SPIFAST_MAX_WORKERS]; /* SPSC: enqueue targets */
    uint32_t              num_workers;
    parser_lcore_stats_t *stats;
    perf_stage_t         *perf;   /* perf counters for this lcore (may be NULL) */
} parser_ctx_t;

/* ─────────────────────────────────────────────────────────────────────────────
 * Public API  (SDD §2.3)
 * ───────────────────────────────────────────────────────────────────────────── */

/* Parse mbuf headers (Ethernet → VLAN → IPv4 → TCP/UDP) and normalise flow.
 * Writes result into *meta on success.  Returns 0 on success, -1 on any
 * parse failure (unsupported EtherType, truncated header, non-TCP/UDP).
 * Zero-copy: operates directly on mbuf data; no allocation.  SDD §2.3 */
int parse_packet(struct rte_mbuf *mbuf, pkt_meta_t *meta);

/* Apply bidirectional flow normalisation in-place (SDD §2.3, DD-10).
 * Ensures forward and reverse packets of the same flow produce the same key.
 * Pure, constant-time, stateless — no allocation.  Exposed for unit tests. */
void normalize_flow(pkt_meta_t *meta);

/* Parser lcore entry point.  Launched via rte_eal_remote_launch().
 * Drains parser_ring burst-by-burst, writes five-tuple metadata into each
 * mbuf's headroom, and hash-dispatches to the appropriate worker_ring.
 * Runs until g_shutdown_flag is set AND parser_ring is empty.  SDD §2.3 */
int parser_lcore_func(void *arg);

#endif /* SPIFAST_PARSER_H */
