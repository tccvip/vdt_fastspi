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
 * assign_lcores()  —  SDD §2.1 Step 5
 *
 * Iterates all non-main lcores in enumeration order.
 * slot 0   → rx_lcore_id
 * slot 1…N → worker_lcore_ids[0…N-1]
 * ───────────────────────────────────────────────────────────────────────────── */
static void assign_lcores(const spifast_config_t *cfg, dpdk_resources_t *res)
{
    unsigned int total_needed = 2 + cfg->num_workers; /* main + rx + N workers */

    if (rte_lcore_count() < total_needed)
        rte_exit(EXIT_FAILURE,
                 "[SPIFAST ERROR] dpdk_init: need %u lcores (%u available)."
                 " Pass '-l 0-%u' to EAL.\n",
                 total_needed, rte_lcore_count(), total_needed - 1);

    unsigned int lcore;
    uint32_t     slot = 0; /* 0 = rx lcore; 1..N = worker lcores */

    RTE_LCORE_FOREACH_WORKER(lcore) {
        if (slot == 0)
            res->rx_lcore_id = lcore;
        else
            res->worker_lcore_ids[slot - 1] = lcore;
        slot++;
        if (slot > cfg->num_workers)
            break;
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
        0,                        /* priv_size: no per-mbuf private data */
        RTE_MBUF_DEFAULT_BUF_SIZE,
        SOCKET_ID_ANY);
    if (res->mempool == NULL)
        rte_exit(EXIT_FAILURE,
                 "[SPIFAST ERROR] dpdk_init: rte_pktmbuf_pool_create failed: %s\n",
                 rte_strerror(rte_errno));

    /* Step 3: net_pcap virtual device — RX-only, replays cfg->pcap_path (SDD §7.2) */
    char devargs[SPIFAST_MAX_PATH + 32];
    snprintf(devargs, sizeof(devargs), "rx_pcap=%s", cfg->pcap_path);

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
                                 0 /* TX queues */,
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

    ret = rte_eth_dev_start(res->port_id);
    if (ret != 0)
        rte_exit(EXIT_FAILURE,
                 "[SPIFAST ERROR] dpdk_init: rte_eth_dev_start: %s\n",
                 rte_strerror(-ret));

    /* Step 4: SPSC rings — one per worker (SDD §7.3)
     * RING_F_SP_ENQ: single producer = classifier lcore only
     * RING_F_SC_DEQ: single consumer = the dedicated worker lcore */
    char ring_name[32];
    for (uint32_t i = 0; i < cfg->num_workers; i++) {
        snprintf(ring_name, sizeof(ring_name), "spifast_ring_%u", i);
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

    /* Step 5: Assign lcore roles — main (this lcore), rx, then workers */
    assign_lcores(cfg, res);

    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * dpdk_cleanup()  —  release DPDK resources after all lcores have exited
 *
 * Order: stop → close port, free rings (NULL-guarded), free mempool.
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

    for (unsigned int i = 0; i < SPIFAST_MAX_GROUPS; i++) {
        if (res->worker_rings[i] != NULL) {
            rte_ring_free(res->worker_rings[i]);
            res->worker_rings[i] = NULL;
        }
    }

    if (res->mempool != NULL) {
        rte_mempool_free(res->mempool);
        res->mempool = NULL;
    }
}
