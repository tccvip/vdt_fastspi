#ifndef SPIFAST_RX_H
#define SPIFAST_RX_H

#include <stdint.h>
#include <rte_common.h>
#include "dpdk/dpdk_init.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * Per-lcore statistics for the RX / classifier lcore  (SDD §3.5)
 * Cache-line padded to prevent false sharing with worker stats.
 * Written only by the RX lcore; read by main/stats lcore without locking.
 * Occasional torn 64-bit reads by stats are acceptable (SDD §6.6).
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    uint64_t rx_packets;          /* total mbufs received from PMD             */
    uint64_t forward_packets;     /* mbufs enqueued to worker rings (FORWARD)  */
    uint64_t forward_bytes;       /* byte sum of forwarded packets (pkt_len)   */
    uint64_t drop_packets;        /* mbufs freed by rule ACTION_DROP           */
    uint64_t invalid_packets;     /* mbufs freed due to parse failure          */
    uint64_t ring_drop_packets;   /* mbufs freed due to full worker ring       */
    uint8_t  _pad[CACHE_LINE_SIZE
                  - (6 * sizeof(uint64_t)) % CACHE_LINE_SIZE];
} __rte_cache_aligned rx_lcore_stats_t;

/* ─────────────────────────────────────────────────────────────────────────────
 * Context passed to the RX lcore function at launch  (SDD §2.2)
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    uint16_t             port_id;
    struct rte_ring     *worker_rings[SPIFAST_MAX_GROUPS];
    uint32_t             num_workers;
    rx_lcore_stats_t    *stats;           /* pointer to global stats struct  */
} rx_ctx_t;

/* Global flag: RX lcore sets this to 1 when PCAP replay finishes.
 * Workers poll it to drain their rings and exit.  SDD §2.6, §6.6 */
extern volatile int g_shutdown_flag;

/* ─────────────────────────────────────────────────────────────────────────────
 * Public API  (SDD §2.2)
 * ───────────────────────────────────────────────────────────────────────────── */

/* Entry point for the RX / classifier lcore (launched via rte_eal_remote_launch).
 * Receives burst → parse → ACL lookup → dispatch/drop loop.
 * Signals shutdown on PCAP end-of-input.  SDD §2.2 */
int rx_lcore_func(void *arg);

#endif /* SPIFAST_RX_H */
