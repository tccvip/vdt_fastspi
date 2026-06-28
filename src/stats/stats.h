#ifndef SPIFAST_STATS_H
#define SPIFAST_STATS_H

#include <stdint.h>
#include "dpdk/dpdk_init.h"      /* SPIFAST_MAX_GROUPS     */
#include "packet/rx.h"           /* rx_lcore_stats_t       */
#include "worker/worker.h"       /* worker_lcore_stats_t   */

/* ─────────────────────────────────────────────────────────────────────────────
 * Statistics snapshot — produced each interval; consumed by log.c  (SDD §3.6)
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    /* Per-interval deltas (since the previous snapshot) */
    uint64_t interval_rx_pkts;
    uint64_t interval_fwd_pkts;
    uint64_t interval_fwd_bytes;
    double   interval_mbps;
    double   interval_pps;
    double   interval_sec;       /* actual wall-clock seconds in this interval */

    /* Session-wide cumulative totals */
    uint64_t total_rx_pkts;
    uint64_t total_fwd_pkts;
    uint64_t total_drop_pkts;
    uint64_t total_invalid_pkts;
    uint64_t total_ring_drop_pkts;
    uint64_t total_bytes;

    /* Per-group hit counts (snapshot copy) */
    uint64_t group_hits[SPIFAST_MAX_GROUPS];
    uint32_t num_groups;

    /* Session elapsed time */
    uint64_t elapsed_sec;        /* seconds since first packet received */
} stats_snapshot_t;

/* ─────────────────────────────────────────────────────────────────────────────
 * Context passed to stats_init() — references to all per-lcore counters.
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    const rx_lcore_stats_t      *rx_stats;
    const worker_lcore_stats_t  *worker_stats;   /* array [0..num_workers) */
    uint32_t                     num_workers;
    uint32_t                     num_groups;
} stats_ctx_t;

/* ─────────────────────────────────────────────────────────────────────────────
 * Public API  (SDD §2.7, §8.1)
 * ───────────────────────────────────────────────────────────────────────────── */

/* Initialise internal state; record the cycle counter of the first packet
 * as the session start time.  Must be called once before stats_collect().  */
void stats_init(const stats_ctx_t *ctx);

/* Aggregate per-lcore counters, compute interval Mbps/PPS, and return a
 * snapshot.  Intended to be called once per second from main lcore.  SDD §8.1 */
stats_snapshot_t stats_collect(void);

/* Verify at session end that total_rx == total_fwd + total_drop + total_invalid.
 * Logs PASS or FAIL with lost-packet count.  SDD §8.1, FR-032 */
void validate_packet_accounting(const stats_snapshot_t *final_snap);

#endif /* SPIFAST_STATS_H */
