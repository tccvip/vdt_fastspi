#ifndef SPIFAST_PERF_STATS_H
#define SPIFAST_PERF_STATS_H

#include <stdint.h>
#include <rte_common.h>
#include "dpdk/dpdk_init.h"   /* CACHE_LINE_SIZE, SPIFAST_MAX_WORKERS */

/* ─────────────────────────────────────────────────────────────────────────────
 * Sampling rate  (SDD perf extension)
 *
 * RX: measure 1 in SPIFAST_PERF_SAMPLE_RATE packets.
 * Parser / Worker / ACL / TX: measure 1 in SPIFAST_PERF_SAMPLE_RATE bursts.
 *
 * Default 1000 keeps the rte_rdtsc() call rate far below 0.1% overhead at
 * any realistic packet rate.  Override at build time: -DSPIFAST_PERF_SAMPLE_RATE=N
 * ───────────────────────────────────────────────────────────────────────────── */
#ifndef SPIFAST_PERF_SAMPLE_RATE
#define SPIFAST_PERF_SAMPLE_RATE  1000
#endif

/* ─────────────────────────────────────────────────────────────────────────────
 * perf_stage_t  —  per-pipeline-stage cycle accumulator
 *
 * Written exclusively by the owning lcore; read by the main lcore without
 * locks.  Torn 64-bit reads are acceptable for display-only use (same policy
 * as the existing lcore_stats structs — SDD §6.6).
 *
 * Cache-line sized to prevent false sharing with adjacent stage structs.
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    uint64_t total_cycles;   /* sum of rdtsc deltas across sampled measurements  */
    uint64_t total_packets;  /* packets accounted in those measurements           */
    uint64_t total_samples;  /* number of measurement points taken (debug aid)    */
    uint8_t  _pad[CACHE_LINE_SIZE - 3 * sizeof(uint64_t)];
} __rte_cache_aligned perf_stage_t;

_Static_assert(sizeof(perf_stage_t) == CACHE_LINE_SIZE,
               "perf_stage_t must occupy exactly one cache line");

/* ─────────────────────────────────────────────────────────────────────────────
 * perf_ctx_t  —  aggregate perf context for one application instance
 *
 * Owned by main.c (static global, zero-initialised at startup).
 * Pointers into worker[] and acl[] are distributed to each worker_ctx_t so
 * that each worker lcore writes only to its own slot (no false sharing).
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    perf_stage_t rx;
    perf_stage_t parser;
    perf_stage_t worker[SPIFAST_MAX_WORKERS];   /* one slot per worker lcore     */
    perf_stage_t acl[SPIFAST_MAX_WORKERS];      /* ACL-only subset of that time  */
    perf_stage_t tx;
    uint32_t     num_workers;
} perf_ctx_t;

/* ─────────────────────────────────────────────────────────────────────────────
 * perf_report()  —  print formatted performance report to stdout
 *
 * Called from the main lcore stats loop once per interval.  Converts raw
 * cycle counts to nanoseconds using tsc_hz = rte_get_tsc_hz().
 *
 * interval_pps / interval_mbps are taken from the most recent stats_collect()
 * snapshot so that the throughput section matches the existing log line.
 * ───────────────────────────────────────────────────────────────────────────── */
void perf_report(const perf_ctx_t *ctx,
                 uint64_t          tsc_hz,
                 double            interval_pps,
                 double            interval_mbps,
                 uint64_t          total_rx,
                 uint64_t          total_tx);

#endif /* SPIFAST_PERF_STATS_H */
