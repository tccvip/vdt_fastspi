#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "dpdk/dpdk_init.h"
#include "log.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * Module-private state
 * ───────────────────────────────────────────────────────────────────────────── */
static FILE *g_log_file = NULL;

/* ─────────────────────────────────────────────────────────────────────────────
 * log_write()  —  dual-output helper  (SDD §8.2)
 *
 * Writes msg to stdout unconditionally; also writes to g_log_file if open.
 * All callers run on the main lcore — no concurrent writes, no locking needed.
 * ───────────────────────────────────────────────────────────────────────────── */
static void log_write(const char *msg)
{
    fputs(msg, stdout);
    if (g_log_file != NULL)
        fputs(msg, g_log_file);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * log_timestamp()  —  format current local time as ISO 8601  (SDD §8.3)
 *
 * Produces e.g. "[2025-06-26T14:32:05+0700]".
 * ───────────────────────────────────────────────────────────────────────────── */
static void log_timestamp(char *buf, size_t len)
{
    time_t     t = time(NULL);
    struct tm  tm_local;
    localtime_r(&t, &tm_local);
    strftime(buf, len, "[%Y-%m-%dT%H:%M:%S%z]", &tm_local);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * log_flush()  —  flush both output channels
 * ───────────────────────────────────────────────────────────────────────────── */
static void log_flush(void)
{
    fflush(stdout);
    if (g_log_file != NULL)
        fflush(g_log_file);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * log_open()  —  SDD §8.2
 * ───────────────────────────────────────────────────────────────────────────── */
void log_open(const char *path)
{
    if (path == NULL || path[0] == '\0')
        return;

    g_log_file = fopen(path, "a");
    if (g_log_file == NULL)
        fprintf(stderr, "[SPIFAST WARNING] cannot open log file '%s': %s\n",
                path, strerror(errno));
}

/* ─────────────────────────────────────────────────────────────────────────────
 * log_close()  —  SDD §8.2
 * ───────────────────────────────────────────────────────────────────────────── */
void log_close(void)
{
    if (g_log_file != NULL) {
        fflush(g_log_file);
        fclose(g_log_file);
        g_log_file = NULL;
    }
}

/* ─────────────────────────────────────────────────────────────────────────────
 * log_startup_event()  —  SDD §8.2, LOG-004
 *
 * Emits:
 *   [ts] STARTUP  pcap=...  rules=...  workers=N  mode=first-match|best-match
 *   [ts] RULES_LOADED  count=N  groups=M
 *   [ts] RULE  <name>  group=<g>  action=FORWARD|DROP  precedence=N
 *   ... (one RULE line per loaded rule, in file_order)
 * ───────────────────────────────────────────────────────────────────────────── */
void log_startup_event(const spifast_config_t  *cfg,
                       const flat_rule_table_t *tbl)
{
    char ts[64];
    char line[2048];   /* wide enough for two 512-char paths + fixed fields */

    log_timestamp(ts, sizeof(ts));

    const char *mode_str = (cfg->match_mode == MATCH_MODE_BEST)
                           ? "best-match" : "first-match";

    snprintf(line, sizeof(line),
             "%s STARTUP  pcap=%s  rules=%s  workers=%u  mode=%s\n",
             ts, cfg->pcap_path, cfg->rules_path,
             cfg->num_workers, mode_str);
    log_write(line);

    snprintf(line, sizeof(line),
             "%s RULES_LOADED  count=%u  groups=%u\n",
             ts, tbl->num_rules, tbl->num_groups);
    log_write(line);

    for (uint32_t i = 0; i < tbl->num_rules; i++) {
        const flat_rule_entry_t *r = &tbl->rules[i];
        const char *action_str = (r->action == ACTION_FORWARD) ? "FORWARD" : "DROP";
        snprintf(line, sizeof(line),
                 "%s RULE  %s  group=%s  action=%s  precedence=%u\n",
                 ts, r->rule_name, r->group_name, action_str, r->precedence);
        log_write(line);
    }

    log_flush();
}

/* ─────────────────────────────────────────────────────────────────────────────
 * log_periodic()  —  SDD §8.2, §8.3, LOG-002, LOG-003
 *
 * Called once per second from the main lcore stats loop.
 *
 * Output line format:
 *   [ts] elapsed=Ns  rx=N  fwd=N  drop=N  inv=N  p_drop=N  w_drop=N
 *        tx_drop=N  mbps=X.XX  pps=N  | <group>=N ...
 * ───────────────────────────────────────────────────────────────────────────── */
void log_periodic(const stats_snapshot_t  *snap,
                  const flat_rule_table_t *tbl)
{
    char ts[64];
    char line[2048];

    log_timestamp(ts, sizeof(ts));

    snprintf(line, sizeof(line),
             "%s elapsed=%lus  loops=%lu"
             "  rx=%lu  fwd=%lu  drop=%lu  inv=%lu"
             "  alloc_fail=%lu  p_drop=%lu  w_drop=%lu  tx_drop=%lu"
             "  mbps=%.2f  pps=%.0f",
             ts,
             (unsigned long)snap->elapsed_sec,
             (unsigned long)snap->total_pcap_loops,
             (unsigned long)snap->total_rx_pkts,
             (unsigned long)snap->total_fwd_pkts,
             (unsigned long)snap->total_drop_pkts,
             (unsigned long)snap->total_invalid_pkts,
             (unsigned long)snap->total_alloc_fail,
             (unsigned long)snap->total_parser_ring_drop,
             (unsigned long)snap->total_worker_ring_drop,
             (unsigned long)(snap->total_tx_ring_drop + snap->total_tx_drop_pkts),
             snap->interval_mbps,
             snap->interval_pps);
    log_write(line);

    /* Per-group hit counts — group_names[] indexed parallel to group_hits[] */
    if (snap->num_groups > 0 && tbl != NULL) {
        log_write("  |");
        uint32_t n = (snap->num_groups < tbl->num_groups)
                     ? snap->num_groups : tbl->num_groups;
        for (uint32_t i = 0; i < n; i++) {
            if (!snap->group_hits[i]) continue;
            char hit[128];
            snprintf(hit, sizeof(hit), " %s=%lu",
                     tbl->group_names[i],
                     (unsigned long)snap->group_hits[i]);
            log_write(hit);
        }
    }
    log_write("\n");
    log_flush();
}

/* ─────────────────────────────────────────────────────────────────────────────
 * log_final_summary()  —  SDD §8.2, FR-031, LOG-004
 *
 * Emits SESSION_END block:
 *   [ts] SESSION_END
 *   [ts] SUMMARY  elapsed=Ns  total_rx=N  ...
 *   [ts] THROUGHPUT_AVG  mbps=X.XX
 *   [ts] PPS_AVG  pps=N
 *   [ts] GROUP_HITS  <g1>=N <g2>=N ...
 *   [ts] PACKET_ACCOUNTING  ...  result=PASS|FAIL
 * ───────────────────────────────────────────────────────────────────────────── */
void log_final_summary(const stats_snapshot_t  *snap,
                       const flat_rule_table_t *tbl)
{
    char ts[64];
    char line[2048];

    log_timestamp(ts, sizeof(ts));

    snprintf(line, sizeof(line), "%s SESSION_END\n", ts);
    log_write(line);

    snprintf(line, sizeof(line),
             "%s SUMMARY"
             "  elapsed=%lus"
             "  pcap_loops=%lu"
             "  total_rx=%lu"
             "  total_parsed=%lu"
             "  total_fwd=%lu"
             "  total_drop=%lu"
             "  total_inv=%lu"
             "  total_alloc_fail=%lu"
             "  total_p_ring_drop=%lu"
             "  total_w_ring_drop=%lu"
             "  total_tx_ring_drop=%lu"
             "  total_tx_drop=%lu"
             "  total_tx=%lu\n",
             ts,
             (unsigned long)snap->elapsed_sec,
             (unsigned long)snap->total_pcap_loops,
             (unsigned long)snap->total_rx_pkts,
             (unsigned long)snap->total_parsed_pkts,
             (unsigned long)snap->total_fwd_pkts,
             (unsigned long)snap->total_drop_pkts,
             (unsigned long)snap->total_invalid_pkts,
             (unsigned long)snap->total_alloc_fail,
             (unsigned long)snap->total_parser_ring_drop,
             (unsigned long)snap->total_worker_ring_drop,
             (unsigned long)snap->total_tx_ring_drop,
             (unsigned long)snap->total_tx_drop_pkts,
             (unsigned long)snap->total_tx_pkts);
    log_write(line);

    double elapsed  = (snap->elapsed_f > 0.0) ? snap->elapsed_f
                      : (snap->elapsed_sec > 0) ? (double)snap->elapsed_sec : 0.0;
    double avg_mbps = (elapsed > 0.0)
                      ? (double)snap->total_bytes * 8.0 / elapsed / 1e6
                      : 0.0;
    double avg_pps  = (elapsed > 0.0)
                      ? (double)snap->total_tx_pkts / elapsed
                      : 0.0;

    snprintf(line, sizeof(line),
             "%s THROUGHPUT_AVG  mbps=%.2f\n", ts, avg_mbps);
    log_write(line);

    snprintf(line, sizeof(line),
             "%s PPS_AVG  pps=%.0f\n", ts, avg_pps);
    log_write(line);

    /* GROUP_HITS — write prefix then each entry directly to avoid large buffer */
    {
        snprintf(line, sizeof(line), "%s GROUP_HITS", ts);
        log_write(line);
        if (tbl != NULL) {
            uint32_t n = (snap->num_groups < tbl->num_groups)
                         ? snap->num_groups : tbl->num_groups;
            for (uint32_t i = 0; i < n; i++) {
                if (!snap->group_hits[i]) continue;
                char tmp[128];
                snprintf(tmp, sizeof(tmp), " %s=%lu",
                         tbl->group_names[i],
                         (unsigned long)snap->group_hits[i]);
                log_write(tmp);
            }
        }
        log_write("\n");
    }

    /* PACKET_ACCOUNTING — two-stage conservation model (SDD §8.2, FR-031) */
    {
        uint64_t rx        = snap->total_rx_pkts;
        uint64_t fwd_to_tx = snap->total_fwd_pkts;

        uint64_t pipe_drops = 0 // snap->total_parser_ring_drop
                            + snap->total_invalid_pkts
                            + snap->total_worker_ring_drop
                            + snap->total_drop_pkts
                            + snap->total_tx_ring_drop;
        int64_t  pipe_delta = (int64_t)rx - (int64_t)(pipe_drops + fwd_to_tx);
        double pipe_utilization = (rx) ? pipe_delta / (double)rx : 0;

        uint64_t tx_out   = snap->total_tx_pkts + snap->total_tx_drop_pkts;
        int64_t  tx_delta = (int64_t)fwd_to_tx - (int64_t)tx_out;
        double tx_ulilization = (rx) ? tx_delta / (double)rx : 0; 

        int overall_pass = (pipe_utilization <= PERF_SUCCESS) && (tx_ulilization <= PERF_SUCCESS);

        snprintf(line, sizeof(line),
                 "%s PACKET_ACCOUNTING"
                 "  stage1_pipeline: rx=%lu  pipe_drops=%lu  fwd_to_tx=%lu"
                 "  delta=%ld  result=%s"
                 "  |  stage2_tx: fwd_to_tx=%lu  tx_pkts=%lu  tx_drop=%lu"
                 "  delta=%ld  result=%s"
                 "  |  overall=%s\n",
                 ts,
                 (unsigned long)rx,
                 (unsigned long)pipe_drops,
                 (unsigned long)fwd_to_tx,
                 (long)pipe_delta,
                 (pipe_utilization < 0.001) ? "PASS" : "FAIL",
                 (unsigned long)fwd_to_tx,
                 (unsigned long)snap->total_tx_pkts,
                 (unsigned long)snap->total_tx_drop_pkts,
                 (long)tx_delta,
                 (tx_delta == 0) ? "PASS" : "FAIL",
                 overall_pass ? "PASS" : "FAIL");
        log_write(line);
    }

    log_flush();
}

/* ─────────────────────────────────────────────────────────────────────────────
 * log_perf_report()  —  emit performance report via dual-output channel
 *
 * Contains the same formatting logic as the former perf_stats.c perf_report(),
 * but routes every line through log_write() so output goes to both stdout and
 * the open log file (if any).  Must be called from the main lcore only.
 * ───────────────────────────────────────────────────────────────────────────── */
void log_perf_report(const perf_ctx_t          *ctx,
                     uint64_t                   tsc_hz,
                     double                     interval_pps,
                     double                     interval_mbps,
                     uint64_t                   total_rx,
                     uint64_t                   total_tx,
                     const worker_lcore_stats_t *worker_stats,
                     const parser_lcore_stats_t *parser_stats)
{
    /* Aggregate per-worker slots */
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

    uint64_t rx_c     = (ctx->rx.total_packets > 0)
                        ? ctx->rx.total_cycles / ctx->rx.total_packets : 0;
    uint64_t parser_c = (ctx->parser.total_packets > 0)
                        ? ctx->parser.total_cycles / ctx->parser.total_packets : 0;
    uint64_t worker_c = (w.total_packets > 0)
                        ? w.total_cycles / w.total_packets : 0;
    uint64_t acl_c    = (a.total_packets > 0)
                        ? a.total_cycles / a.total_packets : 0;
    uint64_t tx_c     = (ctx->tx.total_packets > 0)
                        ? ctx->tx.total_cycles / ctx->tx.total_packets : 0;

    uint64_t w_no_acl = (worker_c > acl_c) ? (worker_c - acl_c) : 0;
    uint64_t total_c  = rx_c + parser_c + worker_c + tx_c;

#define PERF_TO_NS(cyc) \
    ((tsc_hz > 0) ? ((double)(cyc) * 1.0e9 / (double)tsc_hz) : 0.0)

    char line[256];

    log_write("============================\n");
    log_write("  SPIFast Performance Report\n");
    log_write("============================\n");

    log_write("\nPackets:\n");
    snprintf(line, sizeof(line), "    RX: %lu\n", (unsigned long)total_rx);
    log_write(line);
    snprintf(line, sizeof(line), "    TX: %lu\n", (unsigned long)total_tx);
    log_write(line);

    snprintf(line, sizeof(line),
             "\nAverage cycles per packet  (1 in %u bursts sampled):\n\n",
             (unsigned)SPIFAST_PERF_SAMPLE_RATE);
    log_write(line);

    log_write("  RX  (pcap read + mbuf alloc + memcpy):\n");
    snprintf(line, sizeof(line), "    %8lu cycles\n", (unsigned long)rx_c);
    log_write(line);
    snprintf(line, sizeof(line), "    %8.2f ns\n\n", PERF_TO_NS(rx_c));
    log_write(line);

    log_write("  Parser  (parse_packet per burst):\n");
    snprintf(line, sizeof(line), "    %8lu cycles\n", (unsigned long)parser_c);
    log_write(line);
    snprintf(line, sizeof(line), "    %8.2f ns\n\n", PERF_TO_NS(parser_c));
    log_write(line);

    log_write("  Worker  (excl. ACL):\n");
    snprintf(line, sizeof(line), "    %8lu cycles\n", (unsigned long)w_no_acl);
    log_write(line);
    snprintf(line, sizeof(line), "    %8.2f ns\n\n", PERF_TO_NS(w_no_acl));
    log_write(line);

    log_write("  Flat ACL  (flat_acl_match_burst):\n");
    snprintf(line, sizeof(line), "    %8lu cycles\n", (unsigned long)acl_c);
    log_write(line);
    snprintf(line, sizeof(line), "    %8.2f ns\n\n", PERF_TO_NS(acl_c));
    log_write(line);

    log_write("  TX  (rte_eth_tx_burst):\n");
    snprintf(line, sizeof(line), "    %8lu cycles\n", (unsigned long)tx_c);
    log_write(line);
    snprintf(line, sizeof(line), "    %8.2f ns\n\n", PERF_TO_NS(tx_c));
    log_write(line);

    log_write("  Total  (sum of stages):\n");
    snprintf(line, sizeof(line), "    %8lu cycles\n", (unsigned long)total_c);
    log_write(line);
    snprintf(line, sizeof(line), "    %8.2f ns\n\n", PERF_TO_NS(total_c));
    log_write(line);

    log_write("Throughput:\n");
    snprintf(line, sizeof(line), "    PPS:  %.0f\n",  interval_pps);
    log_write(line);
    snprintf(line, sizeof(line), "    Mbps: %.2f\n",  interval_mbps);
    log_write(line);

    /* ── Per-worker section ────────────────────────────────────────────────── */
    if (ctx->num_workers > 0) {
        log_write("\nWorker Distribution (parser dispatch):\n");
        for (uint32_t i = 0; i < ctx->num_workers; i++) {
            uint64_t dispatched = (parser_stats != NULL)
                                  ? parser_stats->dispatched_to[i] : 0;
            snprintf(line, sizeof(line),
                     "  Worker %u: dispatched=%lu\n",
                     i, (unsigned long)dispatched);
            log_write(line);
        }

        log_write("\nPer-Worker Performance:\n");
        for (uint32_t i = 0; i < ctx->num_workers; i++) {
            uint64_t wc = (ctx->worker[i].total_packets > 0)
                          ? ctx->worker[i].total_cycles / ctx->worker[i].total_packets : 0;
            uint64_t ac = (ctx->acl[i].total_packets > 0)
                          ? ctx->acl[i].total_cycles / ctx->acl[i].total_packets : 0;

            snprintf(line, sizeof(line), "\n  Worker %u:\n", i);
            log_write(line);

            if (worker_stats != NULL) {
                snprintf(line, sizeof(line),
                         "    packets  received=%lu  forwarded=%lu"
                         "  dropped=%lu  tx_ring_drop=%lu\n",
                         (unsigned long)worker_stats[i].received,
                         (unsigned long)worker_stats[i].forwarded,
                         (unsigned long)worker_stats[i].dropped,
                         (unsigned long)worker_stats[i].tx_ring_drop);
                log_write(line);
            }

            snprintf(line, sizeof(line),
                     "    ACL   %8lu cycles  (%8.2f ns)\n",
                     (unsigned long)ac, PERF_TO_NS(ac));
            log_write(line);

            snprintf(line, sizeof(line),
                     "    Total %8lu cycles  (%8.2f ns)\n",
                     (unsigned long)wc, PERF_TO_NS(wc));
            log_write(line);
        }
        log_write("\n");
    }

    log_write("============================\n\n");

#undef PERF_TO_NS

    log_flush();
}
