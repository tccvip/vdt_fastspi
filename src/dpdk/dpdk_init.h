#ifndef SPIFAST_DPDK_INIT_H
#define SPIFAST_DPDK_INIT_H

#include <stdint.h>
#include <rte_mempool.h>
#include <rte_ring.h>

#include "include/config.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * Compile-time resource constants  (SDD §7.5)
 * Override at build time: cmake -DCMAKE_C_FLAGS="-DSPIFAST_MEMPOOL_SIZE=16384"
 * ───────────────────────────────────────────────────────────────────────────── */
#ifndef SPIFAST_MEMPOOL_SIZE
#define SPIFAST_MEMPOOL_SIZE    8192
#endif
#ifndef SPIFAST_MEMPOOL_CACHE
#define SPIFAST_MEMPOOL_CACHE   256
#endif
#ifndef SPIFAST_BURST_SIZE
#define SPIFAST_BURST_SIZE      32
#endif
#ifndef SPIFAST_RX_DESC
#define SPIFAST_RX_DESC         512
#endif
#ifndef SPIFAST_RING_SIZE
#define SPIFAST_RING_SIZE       1024
#endif
#ifndef SPIFAST_WORKER_BURST
#define SPIFAST_WORKER_BURST    32
#endif
#ifndef SPIFAST_EOI_THRESHOLD
#define SPIFAST_EOI_THRESHOLD   100
#endif
#ifndef SPIFAST_MAX_RULES
#define SPIFAST_MAX_RULES       99
#endif
#ifndef SPIFAST_MAX_GROUPS
#define SPIFAST_MAX_GROUPS      32
#endif

#define CACHE_LINE_SIZE         64

/* ─────────────────────────────────────────────────────────────────────────────
 * Runtime DPDK resources produced by dpdk_init()
 * Passed by pointer to all modules that need them.
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    struct rte_mempool *mempool;
    uint16_t            port_id;
    struct rte_ring    *worker_rings[SPIFAST_MAX_GROUPS]; /* indexed [0..num_workers) */
    unsigned int        rx_lcore_id;
    unsigned int        worker_lcore_ids[SPIFAST_MAX_GROUPS];
} dpdk_resources_t;

/* ─────────────────────────────────────────────────────────────────────────────
 * Public API
 * ───────────────────────────────────────────────────────────────────────────── */

/* Initialise DPDK: EAL, mempool, net_pcap port, worker rings, lcore roles.
 * argc/argv must be the EAL portion of the command line (split at "--" by main).
 * Calls rte_exit() on any fatal failure; never returns on error.
 * Returns 0 on success.  SDD §2.1 */
int dpdk_init(int argc, char *argv[],
              const spifast_config_t *cfg,
              dpdk_resources_t *res);

/* Release DPDK resources after all lcores have exited.  */
void dpdk_cleanup(dpdk_resources_t *res);

#endif /* SPIFAST_DPDK_INIT_H */
