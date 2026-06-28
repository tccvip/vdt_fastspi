#include <string.h>
#include <stdio.h>

#include <rte_cycles.h>

#include "stats.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * Module-private state
 * ───────────────────────────────────────────────────────────────────────────── */

/* TODO: static const stats_ctx_t *g_ctx          = NULL;
 *       static uint64_t           g_session_start = 0;   (cycles)
 *       static uint64_t           g_prev_cycles   = 0;
 *       static stats_snapshot_t   g_prev          = {0};  */

/* ─────────────────────────────────────────────────────────────────────────────
 * stats_init()  —  SDD §2.7
 *
 * Saves context pointer and records the session-start cycle count.
 * Must be called once on the main lcore before any stats_collect() call.
 * ───────────────────────────────────────────────────────────────────────────── */
void stats_init(const stats_ctx_t *ctx)
{
    /* TODO: g_ctx          = ctx;
     *       g_session_start = rte_get_timer_cycles();
     *       g_prev_cycles   = g_session_start;
     *       memset(&g_prev, 0, sizeof(g_prev));  */
    (void)ctx;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * stats_collect()  —  SDD §8.1
 *
 * Called once per second from the main lcore stats loop.
 * Reads all per-lcore counters (no lock — torn 64-bit reads acceptable for
 * display-only stats; SDD §6.6), computes interval deltas, Mbps, and PPS,
 * and copies the per-group hit counters from the ACL engine.
 * ───────────────────────────────────────────────────────────────────────────── */
stats_snapshot_t stats_collect(void)
{
    stats_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));

    /* TODO: uint64_t now_cycles = rte_get_timer_cycles();
     *       uint64_t hz         = rte_get_timer_hz();
     *
     *       -- Aggregate cumulative totals from RX lcore --
     *       snap.total_rx_pkts       = g_ctx->rx_stats->rx_packets;
     *       snap.total_fwd_pkts      = g_ctx->rx_stats->forward_packets;
     *       snap.total_drop_pkts     = g_ctx->rx_stats->drop_packets;
     *       snap.total_invalid_pkts  = g_ctx->rx_stats->invalid_packets;
     *       snap.total_ring_drop_pkts= g_ctx->rx_stats->ring_drop_packets;
     *       snap.total_bytes         = g_ctx->rx_stats->forward_bytes;
     *
     *       -- Interval deltas --
     *       snap.interval_sec       = (double)(now_cycles - g_prev_cycles) / (double)hz;
     *       snap.interval_rx_pkts   = snap.total_rx_pkts   - g_prev.total_rx_pkts;
     *       snap.interval_fwd_pkts  = snap.total_fwd_pkts  - g_prev.total_fwd_pkts;
     *       snap.interval_fwd_bytes = snap.total_bytes      - g_prev.total_bytes;
     *
     *       -- Throughput and PPS --
     *       if (snap.interval_sec > 0.0):
     *         snap.interval_mbps = (snap.interval_fwd_bytes * 8.0)
     *                              / snap.interval_sec / 1e6;
     *         snap.interval_pps  = (double)snap.interval_fwd_pkts / snap.interval_sec;
     *
     *       -- Session elapsed time --
     *       snap.elapsed_sec = (now_cycles - g_session_start) / hz;
     *
     *       -- Per-group hit counters (snapshot copy) --
     *       const acl_hit_counters_t *hits = acl_get_hit_counters();
     *       snap.num_groups = g_ctx->num_groups;
     *       memcpy(snap.group_hits, hits->hit_count,
     *              snap.num_groups * sizeof(uint64_t));
     *
     *       -- Advance previous state --
     *       g_prev        = snap;
     *       g_prev_cycles = now_cycles;  */

    return snap;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * validate_packet_accounting()  —  SDD §8.1, FR-032
 *
 * Called once at session end on the main lcore.
 * Checks: total_rx == total_fwd + total_drop + total_invalid
 * Unaccounted packets (e.g., ring_drop) appear in the discrepancy delta.
 * ───────────────────────────────────────────────────────────────────────────── */
void validate_packet_accounting(const stats_snapshot_t *final_snap)
{
    /* TODO: uint64_t accounted = final_snap->total_fwd_pkts
     *                          + final_snap->total_drop_pkts
     *                          + final_snap->total_invalid_pkts;
     *
     *       if (accounted == final_snap->total_rx_pkts):
     *         printf("[SPIFAST] Packet accounting: PASS — zero unaccounted packets\n");
     *       else:
     *         uint64_t lost = final_snap->total_rx_pkts - accounted;
     *         fprintf(stderr, "[SPIFAST ERROR] Packet accounting: FAIL — "
     *                 "%lu unaccounted packets\n", lost);
     *
     *       fflush(stdout);  */
    (void)final_snap;
}
