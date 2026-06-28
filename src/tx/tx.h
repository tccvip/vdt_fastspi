#ifndef SPIFAST_TX_H
#define SPIFAST_TX_H

#include <stdint.h>
#include <rte_common.h>
#include <rte_ring.h>
#include "dpdk/dpdk_init.h"   /* CACHE_LINE_SIZE, SPIFAST_TX_BURST_SIZE */

/* ─────────────────────────────────────────────────────────────────────────────
 * Per-lcore statistics for the TX lcore  (SDD §2.7, §3.5)
 *
 * 3 × uint64_t = 24 bytes.  Padded to one cache line (64 B).
 * Written exclusively by the TX lcore; read by main/stats lcore without locking.
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    uint64_t tx_packets;   /* mbufs successfully sent by rte_eth_tx_burst     */
    uint64_t tx_bytes;     /* bytes of those sent packets (sum of pkt_len)     */
    uint64_t tx_drop;      /* mbufs freed because NIC TX queue was full        */
    uint8_t  _pad[CACHE_LINE_SIZE - 3 * sizeof(uint64_t)];
} __rte_cache_aligned tx_lcore_stats_t;

_Static_assert(sizeof(tx_lcore_stats_t) == CACHE_LINE_SIZE,
               "tx_lcore_stats_t must occupy exactly one cache line");

/* ─────────────────────────────────────────────────────────────────────────────
 * Context passed to tx_lcore_func() at launch  (SDD §2.7)
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    struct rte_ring  *tx_ring;       /* MPSC ring: Worker×N → TX lcore     */
    uint16_t          port_id;       /* NIC port (single port design)       */
    uint16_t          tx_queue_id;   /* TX queue index; always 0 (SDD §2.1)*/
    tx_lcore_stats_t *stats;
} tx_ctx_t;

/* ─────────────────────────────────────────────────────────────────────────────
 * Public API  (SDD §2.7)
 * ───────────────────────────────────────────────────────────────────────────── */

/* Entry point for the TX lcore (launched via rte_eal_remote_launch).
 * Drains tx_ring → rte_eth_tx_burst → frees unsent mbufs.
 * Sole owner of the TX queue; no other lcore calls rte_eth_tx_burst.
 * Exits when g_shutdown_flag is set AND tx_ring is empty.  SDD §2.7 */
int tx_lcore_func(void *arg);

#endif /* SPIFAST_TX_H */
