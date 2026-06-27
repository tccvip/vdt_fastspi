#ifndef SPIFAST_WORKER_H
#define SPIFAST_WORKER_H

#include <stdint.h>
#include <rte_common.h>
#include <rte_ring.h>
#include "dpdk/dpdk_init.h"   /* CACHE_LINE_SIZE */

/* ─────────────────────────────────────────────────────────────────────────────
 * Per-worker-lcore statistics  (SDD §3.5)
 * Cache-line padded to avoid false sharing between workers.
 * Written only by the owning worker lcore; read by main/stats lcore.
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    uint64_t pkt_count;   /* packets dequeued from the ring              */
    uint64_t byte_count;  /* bytes of those packets (sum of pkt_len)     */
    uint8_t  _pad[CACHE_LINE_SIZE
                  - (2 * sizeof(uint64_t)) % CACHE_LINE_SIZE];
} __rte_cache_aligned worker_lcore_stats_t;

/* ─────────────────────────────────────────────────────────────────────────────
 * Context passed to each worker lcore at launch  (SDD §2.6)
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    struct rte_ring       *ring;         /* dedicated SPSC ring for this worker */
    uint32_t               worker_idx;   /* index [0 .. num_workers)            */
    worker_lcore_stats_t  *stats;        /* pointer to per-worker stat struct   */
} worker_ctx_t;

/* ─────────────────────────────────────────────────────────────────────────────
 * Public API  (SDD §2.6)
 * ───────────────────────────────────────────────────────────────────────────── */

/* Entry point for a worker lcore (launched via rte_eal_remote_launch).
 * Drains ring, increments counters, frees mbufs to mempool.
 * Continues until g_shutdown_flag is set AND ring is empty.  SDD §2.6 */
int worker_lcore_func(void *arg);

#endif /* SPIFAST_WORKER_H */
