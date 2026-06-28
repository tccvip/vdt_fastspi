#include <stdint.h>

#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

#include "rx.h"
#include "parser.h"

/* Defined in main.c; workers read this flag to know when to drain and exit. */
extern volatile int g_shutdown_flag;

/* ─────────────────────────────────────────────────────────────────────────────
 * select_worker()  —  round-robin dispatcher  (SDD §2.2, §4.3)
 * Single producer, no shared state needed.
 * ───────────────────────────────────────────────────────────────────────────── */
static inline uint32_t select_worker(uint32_t num_workers)
{
    /* TODO: static uint32_t rr_counter = 0;
     *       return rr_counter++ % num_workers;  */
    (void)num_workers;
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * process_packet()  —  inline per-packet path  (SDD §2.2)
 *
 * Called for every mbuf in a received burst.
 * All branches end in either rte_ring_enqueue or rte_pktmbuf_free.
 * No malloc, no printf, no blocking system call on this path.  (SDD §6.2)
 * ───────────────────────────────────────────────────────────────────────────── */
static inline void process_packet(struct rte_mbuf *mbuf, rx_ctx_t *ctx)
{
    /* TODO: pkt_meta_t meta;
     *       if (parse_packet(mbuf, &meta) != 0):
     *         rte_pktmbuf_free(mbuf);
     *         ctx->stats->invalid_packets++;
     *         return;
     *
     *       acl_result_t result = acl_lookup(&meta);
     *       acl_engine_increment_hit(result.group_id);
     *
     *       if (result.action == ACTION_FORWARD):
     *         uint32_t idx = select_worker(ctx->num_workers);
     *         int rc = rte_ring_enqueue(ctx->worker_rings[idx], mbuf);
     *         if (rc != 0):   // ring full → unintended drop (PR-005)
     *           rte_pktmbuf_free(mbuf);
     *           ctx->stats->ring_drop_packets++;
     *         else:
     *           ctx->stats->forward_packets++;
     *           ctx->stats->forward_bytes += mbuf->pkt_len;
     *       else:   // ACTION_DROP
     *         rte_pktmbuf_free(mbuf);
     *         ctx->stats->drop_packets++;  */
    (void)mbuf; (void)ctx;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * rx_lcore_func()  —  RX / classifier lcore entry point  (SDD §2.2)
 *
 * Runs a tight poll loop: burst-receive → parse → classify → dispatch/drop.
 * Signals g_shutdown_flag when net_pcap PMD reports end-of-file.
 * Never calls malloc, free (outside rte_pktmbuf_free), printf, or sleep.
 * ───────────────────────────────────────────────────────────────────────────── */
int rx_lcore_func(void *arg)
{
    /* TODO: rx_ctx_t *ctx = (rx_ctx_t *)arg;
     *       struct rte_mbuf *rx_pkts[SPIFAST_BURST_SIZE];
     *       uint32_t zero_empty = 0;
     *
     *       while (1):
     *         uint16_t nb_rx = rte_eth_rx_burst(ctx->port_id, 0,
     *                                            rx_pkts, SPIFAST_BURST_SIZE);
     *         if (nb_rx == 0):
     *           if (++zero_empty >= SPIFAST_EOI_THRESHOLD):
     *             g_shutdown_flag = 1;
     *             break;
     *           continue;
     *         zero_empty = 0;
     *         ctx->stats->rx_packets += nb_rx;
     *         for (i = 0; i < nb_rx; i++):
     *           process_packet(rx_pkts[i], ctx);
     *
     *       return 0;  */
    (void)arg;
    return 0;
}
