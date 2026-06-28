#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

#include "tx.h"

/* Set to 1 by RX lcore when PCAP replay ends; TX lcore drains and exits. */
extern volatile int g_shutdown_flag;

/* ─────────────────────────────────────────────────────────────────────────────
 * tx_lcore_func()  —  SDD §2.7
 *
 * Sole owner of the TX queue.  No other lcore calls rte_eth_tx_burst().
 *
 * Pipeline per burst:
 *   1. Dequeue burst from MPSC tx_ring (produced by all Worker lcores).
 *   2. Record pkt_len of every dequeued mbuf BEFORE handing them to the PMD
 *      (after tx_burst the PMD may free sent mbufs; accessing them is unsafe).
 *   3. rte_eth_tx_burst() — send as many as the NIC accepts.
 *   4. Update tx_packets and tx_bytes for sent packets.
 *   5. Free unsent mbufs (TX queue full); update tx_drop.
 *
 * mbuf ownership:
 *   After dequeue from tx_ring: TX lcore owns the mbuf.
 *   rte_eth_tx_burst() accepts mbuf → PMD owns it (TX lcore must not touch it).
 *   rte_pktmbuf_free() on unsent mbuf → returned to mempool.
 *
 * Constraints (SDD §6.4):
 *   No malloc, no free (outside rte_pktmbuf_free), no locks, no printf.
 * ───────────────────────────────────────────────────────────────────────────── */
int tx_lcore_func(void *arg)
{
    tx_ctx_t        *ctx   = (tx_ctx_t *)arg;
    struct rte_ring *ring  = ctx->tx_ring;
    tx_lcore_stats_t *stats = ctx->stats;

    struct rte_mbuf *pkts[SPIFAST_TX_BURST_SIZE];
    uint16_t         lens[SPIFAST_TX_BURST_SIZE];

    while (!g_shutdown_flag || rte_ring_count(ring) > 0) {
        unsigned int nb = rte_ring_dequeue_burst(
            ring, (void **)pkts, SPIFAST_TX_BURST_SIZE, NULL);
        if (nb == 0)
            continue;

        /* Record packet lengths before tx_burst; PMD may free sent mbufs. */
        for (unsigned int i = 0; i < nb; i++)
            lens[i] = pkts[i]->pkt_len;

        uint16_t nb_sent = rte_eth_tx_burst(
            ctx->port_id, ctx->tx_queue_id, pkts, (uint16_t)nb);

        stats->tx_packets += nb_sent;
        for (unsigned int i = 0; i < nb_sent; i++)
            stats->tx_bytes += lens[i];

        /* Free mbufs the NIC could not accept (TX queue full). */
        if (unlikely(nb_sent < (uint16_t)nb)) {
            for (unsigned int i = nb_sent; i < nb; i++) {
                rte_pktmbuf_free(pkts[i]);
                stats->tx_drop++;
            }
        }
    }

    return 0;
}
