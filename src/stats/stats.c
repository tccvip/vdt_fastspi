#include <string.h>
#include <stdio.h>

#include <rte_cycles.h>

#include "stats.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * Module-private state
 * ───────────────────────────────────────────────────────────────────────────── */
static const stats_ctx_t *g_ctx          = NULL;
static uint64_t           g_session_start = 0;   /* cycles at first stats_init */
static uint64_t           g_prev_cycles   = 0;   /* cycles at last collect     */
static stats_snapshot_t   g_prev;                /* snapshot from last collect  */

/* ─────────────────────────────────────────────────────────────────────────────
 * stats_init()  —  SDD §8.1
 * ───────────────────────────────────────────────────────────────────────────── */
void stats_init(const stats_ctx_t *ctx)
{
    g_ctx           = ctx;
    g_session_start = rte_get_timer_cycles();
    g_prev_cycles   = g_session_start;
    memset(&g_prev, 0, sizeof(g_prev));
}

/* ─────────────────────────────────────────────────────────────────────────────
 * stats_collect()  —  SDD §8.1
 *
 * Reads per-lcore counters without locks (torn 64-bit reads acceptable for
 * display-only stats; SDD §6.6).  Computes interval deltas and throughput.
 * ───────────────────────────────────────────────────────────────────────────── */
stats_snapshot_t stats_collect(void)
{
    stats_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));

    if (g_ctx == NULL)
        return snap;

    uint64_t now = rte_get_timer_cycles();
    uint64_t hz  = rte_get_timer_hz();

    /* ── RX lcore ──────────────────────────────────────────────────────────── */
    snap.total_rx_pkts          = g_ctx->rx_stats->rx_packets;
    snap.total_parser_ring_drop = g_ctx->rx_stats->parser_ring_drop;
    snap.total_pcap_loops       = g_ctx->rx_stats->pcap_loops;

    /* ── Parser lcore (may be NULL if not yet launched) ────────────────────── */
    if (g_ctx->parser_stats != NULL) {
        snap.total_parsed_pkts      = g_ctx->parser_stats->parsed;
        snap.total_invalid_pkts     = g_ctx->parser_stats->invalid;
        snap.total_worker_ring_drop = g_ctx->parser_stats->ring_drop;
    }

    /* ── Worker lcores (aggregate over all N workers) ──────────────────────── */
    for (uint32_t i = 0; i < g_ctx->num_workers; i++) {
        const worker_lcore_stats_t *ws = &g_ctx->worker_stats[i];
        snap.total_fwd_pkts     += ws->forwarded;
        snap.total_drop_pkts    += ws->dropped;
        snap.total_tx_ring_drop += ws->tx_ring_drop;
    }

    /* ── TX lcore (may be NULL if not yet launched) ────────────────────────── */
    if (g_ctx->tx_stats != NULL) {
        snap.total_tx_pkts      = g_ctx->tx_stats->tx_packets;
        snap.total_tx_drop_pkts = g_ctx->tx_stats->tx_drop;
        snap.total_bytes        = g_ctx->tx_stats->tx_bytes;
    }

    /* ── Interval deltas ────────────────────────────────────────────────────── */
    double interval_sec = (hz > 0)
                          ? (double)(now - g_prev_cycles) / (double)hz
                          : 0.0;
    if (interval_sec < 0.0)
        interval_sec = 0.0;

    snap.interval_sec       = interval_sec;
    snap.interval_rx_pkts   = snap.total_rx_pkts  - g_prev.total_rx_pkts;
    snap.interval_fwd_pkts  = snap.total_fwd_pkts - g_prev.total_fwd_pkts;
    snap.interval_fwd_bytes = snap.total_bytes     - g_prev.total_bytes;

    if (interval_sec > 0.0) {
        snap.interval_mbps = (double)snap.interval_fwd_bytes * 8.0
                             / interval_sec / 1e6;
        snap.interval_pps  = (double)snap.interval_fwd_pkts / interval_sec;
    }

    /* ── Session elapsed time ───────────────────────────────────────────────── */
    snap.elapsed_f   = (hz > 0) ? (double)(now - g_session_start) / (double)hz : 0.0;
    snap.elapsed_sec = (uint64_t)snap.elapsed_f;

    /* ── Per-group hits — aggregated from every worker's group_hits[] array ── */
    snap.num_groups = g_ctx->num_groups;
    if (g_ctx->worker_ctxs != NULL) {
        uint32_t n_groups = (g_ctx->num_groups < SPIFAST_MAX_GROUPS)
                            ? g_ctx->num_groups : SPIFAST_MAX_GROUPS;
        for (uint32_t i = 0; i < g_ctx->num_workers; i++) {
            const worker_ctx_t *wctx = &g_ctx->worker_ctxs[i];
            for (uint32_t g = 0; g < n_groups; g++)
                snap.group_hits[g] += wctx->group_hits[g];
        }
    }

    /* ── Advance state for next interval ────────────────────────────────────── */
    g_prev        = snap;
    g_prev_cycles = now;

    return snap;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * validate_packet_accounting()  —  SDD §8.1, FR-032
 *
 * Pipeline conservation law (SDD §2.2–2.7):
 *
 *   rx_packets = parser_ring_drop        (RX lcore: ring overflow)
 *              + invalid_pkts            (Parser lcore: bad header)
 *              + worker_ring_drop        (Parser lcore: ring overflow)
 *              + drop_pkts              (Worker lcore: ACL action=DROP)
 *              + tx_ring_drop           (Worker lcore: tx_ring overflow)
 *              + tx_drop_pkts           (TX lcore: NIC queue full)
 *              + tx_pkts                (TX lcore: sent to NIC)
 *
 * Called once at session end on the main lcore.
 * ───────────────────────────────────────────────────────────────────────────── */
void validate_packet_accounting(const stats_snapshot_t *snap)
{
    uint64_t accounted = 0 //snap->total_parser_ring_drop
                       + snap->total_invalid_pkts
                       + snap->total_worker_ring_drop
                       + snap->total_drop_pkts
                       + snap->total_tx_ring_drop
                       + snap->total_tx_drop_pkts
                       + snap->total_tx_pkts;

    uint64_t rx    = snap->total_rx_pkts;
    int64_t  delta = (int64_t)rx - (int64_t)accounted;

    /* Print full breakdown so PASS/FAIL is always interpretable. */
    printf("[SPIFAST] Packet accounting: %s"
           " — rx=%lu  p_ring_drop=%lu  inv=%lu  w_ring_drop=%lu"
           "  acl_drop=%lu  tx_ring_drop=%lu  tx_drop=%lu  tx_pkts=%lu  lost=%ld\n",
           (delta == 0) ? "PASS" : "FAIL",
           (unsigned long)rx,
           (unsigned long)snap->total_parser_ring_drop,
           (unsigned long)snap->total_invalid_pkts,
           (unsigned long)snap->total_worker_ring_drop,
           (unsigned long)snap->total_drop_pkts,
           (unsigned long)snap->total_tx_ring_drop,
           (unsigned long)snap->total_tx_drop_pkts,
           (unsigned long)snap->total_tx_pkts,
           (long)delta);

    /* Warn when accounting balances but zero packets reached the NIC.
     * This indicates a silent pipeline failure (ACL DROP-all, ring full, etc.). */
    if (delta == 0 && snap->total_tx_pkts == 0 && rx > 0)
        printf("[SPIFAST] Packet accounting: WARNING"
               " — PASS but zero packets forwarded to NIC\n");

    fflush(stdout);
}
