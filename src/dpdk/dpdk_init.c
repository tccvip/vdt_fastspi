#include <stdio.h>
#include <string.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_dev.h>

#include "dpdk_init.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * assign_lcores()  —  SDD §2.1 Step 5, §6.1
 *
 * Iterates non-main lcores in ascending enumeration order and assigns roles:
 *   slot 0       → rx_lcore_id
 *   slot 1       → parser_lcore_id
 *   slot 2..N+1  → worker_lcore_ids[0..N-1]
 *   slot N+2     → tx_lcore_id
 *
 * Total lcores required: num_workers + 4
 *   (1 Main + 1 RX + 1 Parser + N Workers + 1 TX)
 * ───────────────────────────────────────────────────────────────────────────── */
static void assign_lcores(const spifast_config_t *cfg, dpdk_resources_t *res)
{
    unsigned int total_needed = cfg->num_workers + 4;

    if (rte_lcore_count() < total_needed)
        rte_exit(EXIT_FAILURE,
                 "[SPIFAST ERROR] dpdk_init: need %u lcores (%u available)."
                 " Pass '-l 0-%u' to EAL.\n",
                 total_needed, rte_lcore_count(), total_needed - 1);

    unsigned int lcore;
    uint32_t     slot = 0;

    RTE_LCORE_FOREACH_WORKER(lcore) {
        if (slot == 0) {
            res->rx_lcore_id = lcore;
        } else if (slot == 1) {
            res->parser_lcore_id = lcore;
        } else if (slot < 2 + cfg->num_workers) {
            res->worker_lcore_ids[slot - 2] = lcore;
        } else {
            /* slot == 2 + num_workers: TX lcore */
            res->tx_lcore_id = lcore;
            break;
        }
        slot++;
    }
}

/* ─────────────────────────────────────────────────────────────────────────────
 * dpdk_init()  —  SDD §2.1 (5-step initialisation sequence)
 *
 * argc/argv: EAL portion of the command line, split at "--" by main().
 * Calls rte_exit() on any fatal failure — never returns on error.
 * ───────────────────────────────────────────────────────────────────────────── */
int dpdk_init(int argc, char *argv[],
              const spifast_config_t *cfg,
              dpdk_resources_t *res)
{
    memset(res, 0, sizeof(*res));

    if (cfg->num_workers == 0 || cfg->num_workers > SPIFAST_MAX_WORKERS)
        rte_exit(EXIT_FAILURE,
                 "[SPIFAST ERROR] dpdk_init: num_workers=%u out of range [1..%u]\n",
                 cfg->num_workers, SPIFAST_MAX_WORKERS);

    /* Step 1: EAL initialisation — hugepage mapping, lcore-to-CPU affinity */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE,
                 "[SPIFAST ERROR] dpdk_init: rte_eal_init failed: %s\n",
                 rte_strerror(rte_errno));

    /* Step 2: Packet mbuf pool — single pool shared across all lcores (SDD §7.1) */
    res->mempool = rte_pktmbuf_pool_create(
        "spifast_mbuf_pool",
        SPIFAST_MEMPOOL_SIZE,
        SPIFAST_MEMPOOL_CACHE,
        0,                         /* priv_size: no per-mbuf private data */
        RTE_MBUF_DEFAULT_BUF_SIZE,
        SOCKET_ID_ANY);
    if (res->mempool == NULL)
        rte_exit(EXIT_FAILURE,
                 "[SPIFAST ERROR] dpdk_init: rte_pktmbuf_pool_create failed: %s\n",
                 rte_strerror(rte_errno));

    /* Step 3: net_pcap virtual device — 1 RX queue replaying cfg->pcap_path;
     *         1 TX queue sinking forwarded packets.  (SDD §2.1, §7.2) */
    char devargs[SPIFAST_MAX_PATH * 2 + 64];
    snprintf(devargs, sizeof(devargs),
             "rx_pcap=%s,tx_pcap=/tmp/spifast_tx.pcap", cfg->pcap_path);

    ret = rte_eal_hotplug_add("vdev", "net_pcap0", devargs);
    if (ret != 0)
        rte_exit(EXIT_FAILURE,
                 "[SPIFAST ERROR] dpdk_init: rte_eal_hotplug_add(net_pcap0)"
                 " failed: %s\n", rte_strerror(-ret));

    ret = rte_eth_dev_get_port_by_name("net_pcap0", &res->port_id);
    if (ret != 0)
        rte_exit(EXIT_FAILURE,
                 "[SPIFAST ERROR] dpdk_init: port 'net_pcap0' not found"
                 " after hotplug\n");

    struct rte_eth_conf port_conf;
    memset(&port_conf, 0, sizeof(port_conf));

    ret = rte_eth_dev_configure(res->port_id,
                                 1 /* RX queues */,
                                 1 /* TX queues */,
                                 &port_conf);
    if (ret != 0)
        rte_exit(EXIT_FAILURE,
                 "[SPIFAST ERROR] dpdk_init: rte_eth_dev_configure: %s\n",
                 rte_strerror(-ret));

    ret = rte_eth_rx_queue_setup(res->port_id,
                                  0 /* queue_id */,
                                  SPIFAST_RX_DESC,
                                  SOCKET_ID_ANY,
                                  NULL /* default rxconf */,
                                  res->mempool);
    if (ret != 0)
        rte_exit(EXIT_FAILURE,
                 "[SPIFAST ERROR] dpdk_init: rte_eth_rx_queue_setup: %s\n",
                 rte_strerror(-ret));

    ret = rte_eth_tx_queue_setup(res->port_id,
                                  0 /* queue_id */,
                                  SPIFAST_TX_DESC,
                                  SOCKET_ID_ANY,
                                  NULL /* default txconf */);
    if (ret != 0)
        rte_exit(EXIT_FAILURE,
                 "[SPIFAST ERROR] dpdk_init: rte_eth_tx_queue_setup: %s\n",
                 rte_strerror(-ret));

    ret = rte_eth_dev_start(res->port_id);
    if (ret != 0)
        rte_exit(EXIT_FAILURE,
                 "[SPIFAST ERROR] dpdk_init: rte_eth_dev_start: %s\n",
                 rte_strerror(-ret));

    /* Step 4: Three-tier ring creation (SDD §2.1 Step 4, §7.3) */

    /* Tier 1: parser_ring — RX lcore (single producer) → Parser lcore (single consumer) */
    res->parser_ring = rte_ring_create("spifast_parser_ring",
                                        SPIFAST_PARSER_RING_SIZE,
                                        SOCKET_ID_ANY,
                                        RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (res->parser_ring == NULL)
        rte_exit(EXIT_FAILURE,
                 "[SPIFAST ERROR] dpdk_init: rte_ring_create(parser_ring)"
                 " failed: %s\n", rte_strerror(rte_errno));

    /* Tier 2: worker_rings[i] — Parser lcore (SP) → Worker lcore i (SC) */
    char ring_name[32];
    for (uint32_t i = 0; i < cfg->num_workers; i++) {
        snprintf(ring_name, sizeof(ring_name), "spifast_worker_ring_%u", i);
        res->worker_rings[i] = rte_ring_create(ring_name,
                                                SPIFAST_RING_SIZE,
                                                SOCKET_ID_ANY,
                                                RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (res->worker_rings[i] == NULL)
            rte_exit(EXIT_FAILURE,
                     "[SPIFAST ERROR] dpdk_init: rte_ring_create(%s)"
                     " failed: %s\n",
                     ring_name, rte_strerror(rte_errno));
    }

    /* Tier 3: tx_ring — Worker lcore×N (multi-producer) → TX lcore (single consumer) */
    res->tx_ring = rte_ring_create("spifast_tx_ring",
                                    SPIFAST_TX_RING_SIZE,
                                    SOCKET_ID_ANY,
                                    RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (res->tx_ring == NULL)
        rte_exit(EXIT_FAILURE,
                 "[SPIFAST ERROR] dpdk_init: rte_ring_create(tx_ring)"
                 " failed: %s\n", rte_strerror(rte_errno));

    /* Step 5: Assign lcore roles — main (this lcore), rx, parser, workers, tx */
    res->num_workers = cfg->num_workers;
    assign_lcores(cfg, res);

    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * dpdk_cleanup()  —  release DPDK resources after all lcores have exited
 *
 * Order: stop → close port → free rings (parser, workers, tx) → free mempool.
 * rte_eal_cleanup() is main()'s responsibility (SDD §9.2 Step 10).
 * ───────────────────────────────────────────────────────────────────────────── */
void dpdk_cleanup(dpdk_resources_t *res)
{
    int ret = rte_eth_dev_stop(res->port_id);
    if (ret != 0)
        fprintf(stderr,
                "[SPIFAST WARNING] dpdk_cleanup: rte_eth_dev_stop(%u): %s\n",
                res->port_id, rte_strerror(-ret));

    rte_eth_dev_close(res->port_id);

    if (res->parser_ring != NULL) {
        rte_ring_free(res->parser_ring);
        res->parser_ring = NULL;
    }

    for (unsigned int i = 0; i < SPIFAST_MAX_WORKERS; i++) {
        if (res->worker_rings[i] != NULL) {
            rte_ring_free(res->worker_rings[i]);
            res->worker_rings[i] = NULL;
        }
    }

    if (res->tx_ring != NULL) {
        rte_ring_free(res->tx_ring);
        res->tx_ring = NULL;
    }

    if (res->mempool != NULL) {
        rte_mempool_free(res->mempool);
        res->mempool = NULL;
    }
}
