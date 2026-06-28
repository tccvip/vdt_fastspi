#ifndef SPIFAST_STATS_H
#define SPIFAST_STATS_H

#include <stdint.h>
#include "dpdk/dpdk_init.h"      /* SPIFAST_MAX_GROUPS, SPIFAST_MAX_WORKERS */
#include "packet/rx.h"           /* rx_lcore_stats_t                        */
#include "packet/parser.h"       /* parser_lcore_stats_t                    */
#include "worker/worker.h"       /* worker_lcore_stats_t                    */
#include "tx/tx.h"               /* tx_lcore_stats_t                        */

/* ─────────────────────────────────────────────────────────────────────────────
 * Statistics snapshot  —  SDD §3.6
 *
 * Produced by stats_collect() each interval; consumed by log.c.
 * All cumulative totals are session-wide (since first packet).
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    /* Per-interval deltas (since previous snapshot) */
    uint64_t interval_rx_pkts;
    uint64_t interval_fwd_pkts;
    uint64_t interval_fwd_bytes;
    double   interval_mbps;
    double   interval_pps;
    double   interval_sec;        /* actual wall-clock seconds in this interval */

    /* Session-wide cumulative totals — four-lcore pipeline */
    uint64_t total_rx_pkts;           /* rx.rx_packets                           */
    uint64_t total_parsed_pkts;       /* parser.parsed                           */
    uint64_t total_fwd_pkts;          /* sum(worker.forwarded)  ACTION_FORWARD   */
    uint64_t total_drop_pkts;         /* sum(worker.dropped)    ACL action=DROP  */
    uint64_t total_invalid_pkts;      /* parser.invalid         parse failures   */
    uint64_t total_parser_ring_drop;  /* rx.parser_ring_drop    RX→Parser ring   */
    uint64_t total_worker_ring_drop;  /* parser.ring_drop       Parser→Worker ring*/
    uint64_t total_tx_ring_drop;      /* sum(worker.tx_ring_drop) Worker→TX ring */
    uint64_t total_tx_pkts;           /* tx.tx_packets          sent to NIC      */
    uint64_t total_tx_drop_pkts;      /* tx.tx_drop             TX queue full    */
    uint64_t total_bytes;             /* tx.tx_bytes            bytes sent to NIC*/

    /* Per-group ACL hit counts — aggregated from all worker group_hits[] arrays */
    uint64_t group_hits[SPIFAST_MAX_GROUPS];
    uint32_t num_groups;

    /* Session elapsed time */
    uint64_t elapsed_sec;      /* integer seconds (for display)         */
    double   elapsed_f;        /* fractional seconds (for avg PPS/Mbps) */

    /* Replay counters */
    uint64_t total_pcap_loops; /* completed passes through the pcap file */
} stats_snapshot_t;

/* ─────────────────────────────────────────────────────────────────────────────
 * stats_ctx_t  —  references to all per-lcore counter structs
 *
 * Passed to stats_init() once at startup.  All pointers must remain valid
 * for the entire session lifetime (they point to static globals in main.c).
 * parser_stats and tx_stats may be NULL if the lcore was not launched.
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    const rx_lcore_stats_t      *rx_stats;
    const parser_lcore_stats_t  *parser_stats;   /* NULL if parser not active  */
    const worker_lcore_stats_t  *worker_stats;   /* array [0..num_workers)     */
    const worker_ctx_t          *worker_ctxs;    /* array [0..num_workers), for group_hits */
    const tx_lcore_stats_t      *tx_stats;        /* NULL if TX not active     */
    uint32_t                     num_workers;
    uint32_t                     num_groups;
} stats_ctx_t;

/* ─────────────────────────────────────────────────────────────────────────────
 * Public API  (SDD §2.8, §8.1)
 * ───────────────────────────────────────────────────────────────────────────── */

/* Save ctx pointer and record session-start cycle counter.
 * Must be called once on the main lcore before any stats_collect(). */
void stats_init(const stats_ctx_t *ctx);

/* Aggregate per-lcore counters, compute interval Mbps/PPS, return snapshot.
 * Called once per second from the main lcore stats loop.  SDD §8.1 */
stats_snapshot_t stats_collect(void);

/* Verify pipeline conservation:
 *   rx = parser_ring_drop + invalid + worker_ring_drop
 *       + drop + tx_ring_drop + tx_drop + tx_pkts
 * Prints PASS or FAIL with lost-packet count.  SDD §8.1, FR-032 */
void validate_packet_accounting(const stats_snapshot_t *snap);

#endif /* SPIFAST_STATS_H */
