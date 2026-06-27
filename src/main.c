#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_common.h>

#include "dpdk/dpdk_init.h"
#include "packet/rx.h"
#include "packet/parser.h"
#include "rule/rule_loader.h"
#include "rule/acl_engine.h"
#include "worker/worker.h"
#include "stats/stats.h"
#include "logging/log.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * Global application state (read-only after initialisation)
 * ───────────────────────────────────────────────────────────────────────────── */
static spifast_config_t      g_config;
static dpdk_resources_t      g_dpdk;
static filter_group_table_t  g_group_table;
static spi_rule_t            g_rules[SPIFAST_MAX_RULES];
static uint32_t              g_num_rules;

static rx_lcore_stats_t      g_rx_stats;
static worker_lcore_stats_t  g_worker_stats[SPIFAST_MAX_GROUPS];

static rx_ctx_t              g_rx_ctx;
static worker_ctx_t          g_worker_ctx[SPIFAST_MAX_GROUPS];

/* Shutdown flag shared with workers (SDD §6.6) */
volatile int g_shutdown_flag = 0;

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
    /* TODO: Step 1 — Split EAL args from application args at "--" separator. */

    /* TODO: Step 2 — Parse application args with getopt_long.
     *   --pcap  : mandatory; verify file is readable.
     *   --rules : optional, default "spi_rules.conf".
     *   --workers : optional, default 1; must be ≥ 1.
     *   --log   : optional; stored in g_config.log_path.
     *   --mode  : optional, default "first".
     *   On validation failure: usage(); exit(EXIT_FAILURE).  */

    /* TODO: Step 3 — Initialise DPDK (EAL, mempool, net_pcap port, rings).
     *   dpdk_init(&g_config, &g_dpdk);
     *   Verify total available lcores ≥ 2 + num_workers.  */

    /* TODO: Step 4 — Open log file (if --log was supplied).
     *   log_open(g_config.log_path);  */

    /* TODO: Step 5 — Load and compile rules.
     *   rule_loader_load(g_config.rules_path, &g_group_table,
     *                    g_rules, &g_num_rules);
     *   On failure: exit(EXIT_FAILURE).  */

    /* TODO: Step 6 — Log startup event.
     *   log_startup_event(&g_config, g_rules, g_num_rules, &g_group_table);  */

    /* TODO: Step 7 — Initialise stats context and launch lcores.
     *   stats_ctx_t stats_ctx = { &g_rx_stats, g_worker_stats,
     *                              g_config.num_workers, g_group_table.num_groups };
     *   stats_init(&stats_ctx);
     *   rte_eal_remote_launch(rx_lcore_func,     &g_rx_ctx,         rx_lcore_id);
     *   for each worker i:
     *     rte_eal_remote_launch(worker_lcore_func, &g_worker_ctx[i], worker_lcore_id[i]);  */

    /* TODO: Step 8 — Main lcore stats loop (SDD §6.4).
     *   Poll wall clock; call stats_collect() + log_periodic() every 1 second.
     *   rte_delay_us_block(100) between polls to avoid spinning.
     *   Exit loop when all remote lcores have finished.  */

    /* TODO: Step 9 — Wait for all lcores.
     *   rte_eal_mp_wait_lcore();  */

    /* TODO: Step 10 — Final summary, cleanup.
     *   stats_snapshot_t final = stats_collect();
     *   validate_packet_accounting(&final);
     *   log_final_summary(&final, &g_group_table);
     *   log_close();
     *   acl_engine_destroy();
     *   dpdk_cleanup(&g_dpdk);
     *   rte_eal_cleanup();  */

    (void)argc; (void)argv;
    usage(argv[0]);
    return EXIT_SUCCESS;
}
