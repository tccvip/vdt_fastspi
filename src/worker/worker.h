#ifndef SPIFAST_WORKER_H
#define SPIFAST_WORKER_H

#include <stdint.h>
#include <rte_common.h>
#include <rte_ring.h>
#include "dpdk/dpdk_init.h"       /* CACHE_LINE_SIZE, SPIFAST_* constants */
#include "rule/rule_loader.h"     /* flat_rule_table_t                    */
#include "perf/perf_stats.h"      /* perf_stage_t                         */

/* ─────────────────────────────────────────────────────────────────────────────
 * Per-worker-lcore statistics  (SDD §2.6, §3.5)
 *
 * 4 × uint64_t = 32 bytes.  Padded to one cache line (64 B) to prevent
 * false sharing between worker stats structs in the stats array.
 * Written exclusively by the owning worker lcore; read by main/stats lcore.
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    uint64_t received;      /* mbufs dequeued from worker_ring                 */
    uint64_t forwarded;     /* mbufs with action=FORWARD (enqueued to tx_ring) */
    uint64_t dropped;       /* mbufs freed (action=DROP)                       */
    uint64_t tx_ring_drop;  /* FORWARD mbufs freed because tx_ring was full    */
    uint8_t  _pad[CACHE_LINE_SIZE - 4 * sizeof(uint64_t)];
} __rte_cache_aligned worker_lcore_stats_t;

_Static_assert(sizeof(worker_lcore_stats_t) == CACHE_LINE_SIZE,
               "worker_lcore_stats_t must occupy exactly one cache line");

/* ─────────────────────────────────────────────────────────────────────────────
 * Context passed to each worker lcore at launch  (SDD §2.6)
 *
 * All pointers are initialised once by main before rte_eal_remote_launch()
 * and are read-only by the worker thereafter (no locking needed).
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    struct rte_ring         *ring;            /* SPSC input ring (this worker only)    */
    struct rte_ring         *tx_ring;         /* MPSC output ring (shared by N workers)*/
    const flat_rule_table_t *flat_rule_table; /* flat rule table for flat_acl_match()  */
    uint32_t                 worker_idx;      /* index [0 .. num_workers)              */
    worker_lcore_stats_t    *stats;
    uint64_t                 group_hits[SPIFAST_MAX_GROUPS]; /* hit count per group_idx */
    perf_stage_t            *perf_worker; /* full-burst worker time (may be NULL) */
    perf_stage_t            *perf_acl;   /* ACL-only subset of worker time        */
} worker_ctx_t;

/* ─────────────────────────────────────────────────────────────────────────────
 * Public API  (SDD §2.6)
 * ───────────────────────────────────────────────────────────────────────────── */

/* Entry point for a worker lcore (launched via rte_eal_remote_launch).
 * Dequeues bursts → builds ACL keys → flat_acl_match_burst → FORWARD or DROP.
 * Exits when g_shutdown_flag is set AND ring is empty.  SDD §2.6 */
int worker_lcore_func(void *arg);

#endif /* SPIFAST_WORKER_H */
