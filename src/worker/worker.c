#include <stdint.h>

#include <rte_mbuf.h>
#include <rte_ring.h>

#include "worker.h"
#include "dpdk/dpdk_init.h"   /* SPIFAST_WORKER_BURST */

/* Shutdown flag set by RX lcore; workers poll it to know when to drain and exit. */
extern volatile int g_shutdown_flag;

/* ─────────────────────────────────────────────────────────────────────────────
 * worker_lcore_func()  —  SDD §2.6
 *
 * Entry point for each worker lcore (launched via rte_eal_remote_launch).
 *
 * Lifecycle:
 *   1. Dequeue a burst from the dedicated SPSC ring.
 *   2. For each mbuf: increment pkt_count and byte_count; free mbuf to mempool.
 *   3. Loop until shutdown_flag is set AND the ring is empty (drain-on-exit).
 *
 * Ownership: worker owns each mbuf from rte_ring_dequeue_burst until
 *            rte_pktmbuf_free — no double-free, no leak possible here.
 *
 * Constraints (SDD §6.3):
 *   - Never touches another worker's ring.
 *   - Never calls malloc, printf, or blocking system calls.
 *   - Never interacts with stats/logging directly.
 * ───────────────────────────────────────────────────────────────────────────── */
int worker_lcore_func(void *arg)
{
    /* TODO: worker_ctx_t *ctx  = (worker_ctx_t *)arg;
     *       struct rte_ring      *ring  = ctx->ring;
     *       worker_lcore_stats_t *stats = ctx->stats;
     *       struct rte_mbuf *pkts[SPIFAST_WORKER_BURST];
     *
     *       while (!g_shutdown_flag || rte_ring_count(ring) > 0):
     *         uint16_t nb = (uint16_t)rte_ring_dequeue_burst(
     *                           ring, (void **)pkts, SPIFAST_WORKER_BURST, NULL);
     *
     *         for i in [0, nb):
     *           stats->pkt_count++;
     *           stats->byte_count += pkts[i]->pkt_len;
     *           rte_pktmbuf_free(pkts[i]);
     *
     *       return 0;  */

    (void)arg;
    return 0;
}
