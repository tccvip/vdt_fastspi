#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_common.h>

#include "dpdk/dpdk_init.h"
#include "packet/rx.h"
#include "packet/parser.h"
#include "rule/rule_loader.h"
#include "rule/acl_engine.h"
#include "worker/worker.h"
#include "tx/tx.h"
#include "stats/stats.h"
#include "logging/log.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * Global application state (read-only after initialisation)
 * ───────────────────────────────────────────────────────────────────────────── */
static spifast_config_t      g_config;
static dpdk_resources_t      g_dpdk;
static flat_rule_table_t     g_flat_rule_table;

static rx_lcore_stats_t      g_rx_stats;
static parser_lcore_stats_t  g_parser_stats;
static worker_lcore_stats_t  g_worker_stats[SPIFAST_MAX_WORKERS];
static tx_lcore_stats_t      g_tx_stats;

static rx_ctx_t              g_rx_ctx;
static parser_ctx_t          g_parser_ctx;
static worker_ctx_t          g_worker_ctx[SPIFAST_MAX_WORKERS];
static tx_ctx_t              g_tx_ctx;

/* Set to 1 by SIGINT/SIGTERM; polled by all lcores to drain and exit.
 * NOT set by pcap EOF — the RX lcore loops the file indefinitely. */
volatile int g_shutdown_flag = 0;

static void spifast_sighandler(int sig)
{
    (void)sig;
    g_shutdown_flag = 1;   /* volatile int; single-word write is async-signal-safe */
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Command-line option table  (SDD §9.1)
 * ───────────────────────────────────────────────────────────────────────────── */
static const struct option long_opts[] = {
    { "pcap",    required_argument, NULL, 'p' },
    { "rules",   required_argument, NULL, 'r' },
    { "workers", required_argument, NULL, 'w' },
    { "log",     required_argument, NULL, 'l' },
    { "mode",    required_argument, NULL, 'm' },
    { NULL,      0,                 NULL,  0  }
};

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [EAL options] -- "
            "--pcap <path> [--rules <path>] [--workers N] "
            "[--log <path>] [--mode first|best]\n",
            prog);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * main()  —  SDD §9.2 (10-step startup sequence)
 * ───────────────────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    /* ── Step 1: split argv at "--" ──────────────────────────────────────────
     * EAL receives argv[0..sep-1]; app receives argv[sep+1..argc-1].
     * argv[0] (program name) is prepended to app_argv so getopt starts at [1]. */
    int sep = argc;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) { sep = i; break; }
    }
    int eal_argc = sep;

#define SPIFAST_APP_ARGC_MAX 64
    char *app_argv[SPIFAST_APP_ARGC_MAX];
    int   app_argc = 0;
    app_argv[app_argc++] = argv[0];
    for (int i = sep + 1; i < argc && app_argc < SPIFAST_APP_ARGC_MAX - 1; i++)
        app_argv[app_argc++] = argv[i];
    app_argv[app_argc] = NULL;

    /* ── Step 2: parse application arguments ─────────────────────────────────
     * Defaults: rules=spi_rules.conf, workers=1, mode=first, log=(none). */
    memset(&g_config, 0, sizeof(g_config));
    strncpy(g_config.rules_path, "spi_rules.conf",
            sizeof(g_config.rules_path) - 1);
    g_config.num_workers        = 1;
    g_config.match_mode         = MATCH_MODE_FIRST;
    g_config.stats_interval_sec = 1;

    int pcap_set = 0;
    int opt;
    while ((opt = getopt_long(app_argc, app_argv, "", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p':
            strncpy(g_config.pcap_path, optarg,
                    sizeof(g_config.pcap_path) - 1);
            pcap_set = 1;
            break;
        case 'r':
            strncpy(g_config.rules_path, optarg,
                    sizeof(g_config.rules_path) - 1);
            break;
        case 'w': {
            long n = strtol(optarg, NULL, 10);
            if (n < 1 || n > (long)SPIFAST_MAX_WORKERS) {
                fprintf(stderr,
                        "[SPIFAST ERROR] --workers must be 1..%d\n",
                        SPIFAST_MAX_WORKERS);
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            g_config.num_workers = (uint32_t)n;
            break;
        }
        case 'l':
            strncpy(g_config.log_path, optarg,
                    sizeof(g_config.log_path) - 1);
            break;
        case 'm':
            if (strcmp(optarg, "best") == 0)
                g_config.match_mode = MATCH_MODE_BEST;
            else if (strcmp(optarg, "first") == 0)
                g_config.match_mode = MATCH_MODE_FIRST;
            else {
                fprintf(stderr,
                        "[SPIFAST ERROR] --mode must be 'first' or 'best'\n");
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            break;
        default:
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (!pcap_set) {
        fprintf(stderr, "[SPIFAST ERROR] --pcap is required\n");
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* Verify the pcap file is readable before the DPDK PMD tries to open it */
    {
        FILE *f = fopen(g_config.pcap_path, "r");
        if (f == NULL) {
            fprintf(stderr,
                    "[SPIFAST ERROR] cannot open pcap file '%s': %s\n",
                    g_config.pcap_path, strerror(errno));
            return EXIT_FAILURE;
        }
        fclose(f);
    }

    /* ── Step 3: initialise DPDK — EAL, mempool, net_pcap port, rings, lcores */
    dpdk_init(eal_argc, argv, &g_config, &g_dpdk);

    /* ── Step 4: open log file (log_open silently skips if path is empty) ──── */
    log_open(g_config.log_path);

    /* ── Step 5: load rule file and compile ACL index ───────────────────────── */
    if (rule_loader_load(g_config.rules_path, g_config.match_mode,
                         &g_flat_rule_table) != 0) {
        fprintf(stderr,
                "[SPIFAST ERROR] Failed to load rules from '%s'\n",
                g_config.rules_path);
        log_close();
        dpdk_cleanup(&g_dpdk);
        rte_eal_cleanup();
        return EXIT_FAILURE;
    }

    /* ── Step 6: emit STARTUP / RULES_LOADED / RULE log lines ──────────────── */
    log_startup_event(&g_config, &g_flat_rule_table);

    /* ── Step 7: wire contexts, init stats, launch remote lcores ────────────── */
    stats_ctx_t stats_ctx = {
        .rx_stats     = &g_rx_stats,
        .parser_stats = &g_parser_stats,
        .worker_stats = g_worker_stats,
        .worker_ctxs  = g_worker_ctx,
        .tx_stats     = &g_tx_stats,
        .num_workers  = g_config.num_workers,
        .num_groups   = g_flat_rule_table.num_groups,
    };
    stats_init(&stats_ctx);

    g_rx_ctx.port_id     = g_dpdk.port_id;
    g_rx_ctx.parser_ring = g_dpdk.parser_ring;
    g_rx_ctx.stats       = &g_rx_stats;
    g_rx_ctx.pcap_path   = g_config.pcap_path;
    g_rx_ctx.mempool     = g_dpdk.mempool;

    g_parser_ctx.parser_ring = g_dpdk.parser_ring;
    g_parser_ctx.num_workers = g_config.num_workers;
    for (uint32_t i = 0; i < g_config.num_workers; i++)
        g_parser_ctx.worker_rings[i] = g_dpdk.worker_rings[i];
    g_parser_ctx.stats = &g_parser_stats;

    for (uint32_t i = 0; i < g_config.num_workers; i++) {
        g_worker_ctx[i].ring            = g_dpdk.worker_rings[i];
        g_worker_ctx[i].tx_ring         = g_dpdk.tx_ring;
        g_worker_ctx[i].flat_rule_table = acl_get_flat_rule_table();
        g_worker_ctx[i].worker_idx      = i;
        g_worker_ctx[i].stats           = &g_worker_stats[i];
    }

    g_tx_ctx.tx_ring     = g_dpdk.tx_ring;
    g_tx_ctx.port_id     = g_dpdk.port_id;
    g_tx_ctx.tx_queue_id = 0;
    g_tx_ctx.stats       = &g_tx_stats;

    signal(SIGINT,  spifast_sighandler);
    signal(SIGTERM, spifast_sighandler);

    rte_eal_remote_launch(rx_lcore_func,     &g_rx_ctx,     g_dpdk.rx_lcore_id);
    rte_eal_remote_launch(parser_lcore_func, &g_parser_ctx, g_dpdk.parser_lcore_id);
    for (uint32_t i = 0; i < g_config.num_workers; i++)
        rte_eal_remote_launch(worker_lcore_func, &g_worker_ctx[i],
                              g_dpdk.worker_lcore_ids[i]);
    rte_eal_remote_launch(tx_lcore_func,     &g_tx_ctx,     g_dpdk.tx_lcore_id);

    /* ── Step 8: main lcore stats loop — 100 µs poll, 1 s collection interval  */
    uint64_t hz           = rte_get_timer_hz();
    uint64_t interval_cyc = (uint64_t)g_config.stats_interval_sec * hz;
    uint64_t last_collect = rte_get_timer_cycles();

    while (!g_shutdown_flag) {
        rte_delay_us_block(100);
        uint64_t now = rte_get_timer_cycles();
        if ((now - last_collect) >= interval_cyc) {
            stats_snapshot_t snap = stats_collect();
            log_periodic(&snap, &g_flat_rule_table);
            last_collect = now;
        }
    }

    /* ── Step 9: wait for RX lcore and all workers to return ────────────────── */
    rte_eal_mp_wait_lcore();

    /* ── Step 10: final summary, accounting validation, ordered teardown ─────── */
    stats_snapshot_t final_snap = stats_collect();
    validate_packet_accounting(&final_snap);
    log_final_summary(&final_snap, &g_flat_rule_table);
    log_close();
    acl_engine_destroy();
    dpdk_cleanup(&g_dpdk);
    rte_eal_cleanup();

    return EXIT_SUCCESS;
}
