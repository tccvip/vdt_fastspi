#ifndef SPIFAST_DPDK_INIT_H
#define SPIFAST_DPDK_INIT_H

#include <stdint.h>
#include <rte_mempool.h>
#include <rte_ring.h>

#include "include/config.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * Compile-time resource constants  (SDD §7.5)
 * All values can be overridden at build time via -D flag.
 * ───────────────────────────────────────────────────────────────────────────── */

/* Mempool */
#ifndef SPIFAST_MEMPOOL_SIZE
#define SPIFAST_MEMPOOL_SIZE              8192
#endif
#ifndef SPIFAST_MEMPOOL_CACHE
#define SPIFAST_MEMPOOL_CACHE             256
#endif

/* Burst sizes */
#ifndef SPIFAST_BURST_SIZE
#define SPIFAST_BURST_SIZE                32    /* RX burst */
#endif
#ifndef SPIFAST_WORKER_BURST
#define SPIFAST_WORKER_BURST              32    /* Worker dequeue burst */
#endif
#ifndef SPIFAST_TX_BURST_SIZE
#define SPIFAST_TX_BURST_SIZE             32    /* TX lcore drain burst */
#endif

/* Hardware queue descriptor counts */
#ifndef SPIFAST_RX_DESC
#define SPIFAST_RX_DESC                   512
#endif
#ifndef SPIFAST_TX_DESC
#define SPIFAST_TX_DESC                   512
#endif

/* Ring sizes — three-tier pipeline (SDD §7.3)
 * All sizes must be a power of two (rte_ring requirement). */
#ifndef SPIFAST_PARSER_RING_SIZE
#define SPIFAST_PARSER_RING_SIZE          1024  /* Tier 1: RX → Parser (SPSC) */
#endif
#ifndef SPIFAST_RING_SIZE
#define SPIFAST_RING_SIZE                 1024  /* Tier 2: Parser → Worker[i] (SPSC) */
#endif
#ifndef SPIFAST_TX_RING_SIZE
#define SPIFAST_TX_RING_SIZE              4096  /* Tier 3: Worker×N → TX (MPSC) */
#endif

/* Prefetch depth for Parser and Worker hot paths (SDD §2.3, §2.6) */
#ifndef SPIFAST_PREFETCH_AHEAD
#define SPIFAST_PREFETCH_AHEAD            4
#endif

/* Consecutive empty bursts before RX lcore declares end-of-input (SDD §7.2) */
#ifndef SPIFAST_EOI_THRESHOLD
#define SPIFAST_EOI_THRESHOLD             100
#endif

/* ACL scale limits (SDD §3.3, §7.5) */
#ifndef SPIFAST_MAX_GROUPS
#define SPIFAST_MAX_GROUPS                4096
#endif
#ifndef SPIFAST_MAX_FILTERS_PER_GROUP
#define SPIFAST_MAX_FILTERS_PER_GROUP     2048
#endif

/* Maximum number of Worker lcores.  Distinct from SPIFAST_MAX_GROUPS, which
 * bounds the ACL group table.  Sizes the worker_rings[] and worker_lcore_ids[]
 * arrays in dpdk_resources_t.  Practical ceiling per deployment. */
#ifndef SPIFAST_MAX_WORKERS
#define SPIFAST_MAX_WORKERS               64
#endif

/* Total rule budget for the flat rules[] array in main / rule_loader.
 * A static ceiling; will migrate to dynamic allocation in a later phase. */
#ifndef SPIFAST_MAX_RULES
#define SPIFAST_MAX_RULES                 SPIFAST_MAX_GROUPS
#endif

/* Cache-line size for stats padding (architecture constant) */
#define CACHE_LINE_SIZE                   64

/* ─────────────────────────────────────────────────────────────────────────────
 * Runtime DPDK resources produced by dpdk_init()  (SDD §2.1)
 *
 * Passed by pointer to every module that needs access to DPDK objects.
 * All fields are valid after dpdk_init() returns; zeroed before init.
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    /* Core DPDK objects */
    struct rte_mempool *mempool;        /* single shared pool (SDD §7.1)         */
    uint16_t            port_id;        /* net_pcap or physical NIC port index    */

    /* Three-tier ring pipeline (SDD §7.3) */
    struct rte_ring    *parser_ring;                        /* SPSC: RX → Parser     */
    struct rte_ring    *worker_rings[SPIFAST_MAX_WORKERS];  /* SPSC: Parser → Worker[i] */
    struct rte_ring    *tx_ring;                            /* MPSC: Worker×N → TX   */

    /* Lcore role assignments (SDD §6.1)
     * Assigned in ascending enumeration order: rx, parser, worker×N, tx. */
    unsigned int        rx_lcore_id;
    unsigned int        parser_lcore_id;
    unsigned int        worker_lcore_ids[SPIFAST_MAX_WORKERS];
    unsigned int        tx_lcore_id;

    uint32_t            num_workers;    /* actual worker count for this run */
} dpdk_resources_t;

/* ─────────────────────────────────────────────────────────────────────────────
 * Public API
 * ───────────────────────────────────────────────────────────────────────────── */

/* Initialise DPDK: EAL, mempool, net_pcap port (1 RX + 1 TX queue), three
 * ring tiers (parser_ring/SPSC, worker_rings[]/SPSC, tx_ring/MPSC), and lcore
 * role assignments.
 * argc/argv: EAL argument vector split at "--" by main().
 * Calls rte_exit() on any fatal failure — never returns on error.
 * Returns 0 on success.  SDD §2.1 */
int dpdk_init(int argc, char *argv[],
              const spifast_config_t *cfg,
              dpdk_resources_t *res);

/* Release all DPDK resources after all lcores have exited.
 * rte_eal_cleanup() is main()'s responsibility (SDD §9.2 Step 10). */
void dpdk_cleanup(dpdk_resources_t *res);

#endif /* SPIFAST_DPDK_INIT_H */
