#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "perf_stats.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * Module-private helpers
 * ───────────────────────────────────────────────────────────────────────────── */

static uint64_t avg_cycles(const perf_stage_t *s)
{
    return (s->total_packets > 0) ? (s->total_cycles / s->total_packets) : 0;
}

static double to_ns(uint64_t cycles, uint64_t tsc_hz)
{
    return (tsc_hz > 0) ? ((double)cycles * 1.0e9 / (double)tsc_hz) : 0.0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * perf_report()  —  SDD perf extension
 *
 * Reads per-stage counters (torn reads acceptable — display only).
 * Aggregates per-worker slots before printing.
 * ───────────────────────────────────────────────────────────────────────────── */
void perf_report(const perf_ctx_t *ctx,
                 uint64_t          tsc_hz,
                 double            interval_pps,
                 double            interval_mbps,
                 uint64_t          total_rx,
                 uint64_t          total_tx)
{
    /* Aggregate per-worker lcore slots into single totals */
    perf_stage_t w;
    perf_stage_t a;
    memset(&w, 0, sizeof(w));
    memset(&a, 0, sizeof(a));

    for (uint32_t i = 0; i < ctx->num_workers; i++) {
        w.total_cycles  += ctx->worker[i].total_cycles;
        w.total_packets += ctx->worker[i].total_packets;
        w.total_samples += ctx->worker[i].total_samples;

        a.total_cycles  += ctx->acl[i].total_cycles;
        a.total_packets += ctx->acl[i].total_packets;
        a.total_samples += ctx->acl[i].total_samples;
    }

    uint64_t rx_c     = avg_cycles(&ctx->rx);
    uint64_t parser_c = avg_cycles(&ctx->parser);
    uint64_t worker_c = avg_cycles(&w);       /* full worker burst, includes ACL */
    uint64_t acl_c    = avg_cycles(&a);
    uint64_t tx_c     = avg_cycles(&ctx->tx);

    /* "Worker excl. ACL" avoids double-counting when showing the breakdown;
     * ACL is a subset of worker time, so total = rx + parser + worker + tx. */
    uint64_t w_no_acl = (worker_c > acl_c) ? (worker_c - acl_c) : 0;
    uint64_t total_c  = rx_c + parser_c + worker_c + tx_c;

    printf("============================\n");
    printf("  SPIFast Performance Report\n");
    printf("============================\n");

    printf("\nPackets:\n");
    printf("    RX: %lu\n", (unsigned long)total_rx);
    printf("    TX: %lu\n", (unsigned long)total_tx);

    printf("\nAverage cycles per packet  (1 in %u bursts sampled):\n\n",
           (unsigned)SPIFAST_PERF_SAMPLE_RATE);

    printf("  RX  (pcap read + mbuf alloc + memcpy):\n");
    printf("    %8lu cycles\n", (unsigned long)rx_c);
    printf("    %8.2f ns\n\n",  to_ns(rx_c, tsc_hz));

    printf("  Parser  (parse_packet per burst):\n");
    printf("    %8lu cycles\n", (unsigned long)parser_c);
    printf("    %8.2f ns\n\n",  to_ns(parser_c, tsc_hz));

    printf("  Worker  (excl. ACL):\n");
    printf("    %8lu cycles\n", (unsigned long)w_no_acl);
    printf("    %8.2f ns\n\n",  to_ns(w_no_acl, tsc_hz));

    printf("  Flat ACL  (flat_acl_match_burst):\n");
    printf("    %8lu cycles\n", (unsigned long)acl_c);
    printf("    %8.2f ns\n\n",  to_ns(acl_c, tsc_hz));

    printf("  TX  (rte_eth_tx_burst):\n");
    printf("    %8lu cycles\n", (unsigned long)tx_c);
    printf("    %8.2f ns\n\n",  to_ns(tx_c, tsc_hz));

    printf("  Total  (sum of stages):\n");
    printf("    %8lu cycles\n", (unsigned long)total_c);
    printf("    %8.2f ns\n\n",  to_ns(total_c, tsc_hz));

    printf("Throughput:\n");
    printf("    PPS:  %.0f\n",  interval_pps);
    printf("    Mbps: %.2f\n",  interval_mbps);
    printf("============================\n\n");
    fflush(stdout);
}
