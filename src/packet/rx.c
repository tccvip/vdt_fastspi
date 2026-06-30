#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <pcap.h>

#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_memcpy.h>
#include <rte_ring.h>
#include <rte_common.h>
#include <rte_cycles.h>

#include "rx.h"

/* Set to 1 by SIGINT/SIGTERM handler in main.c.  NOT by pcap EOF. */
extern volatile int g_shutdown_flag;

/* ─────────────────────────────────────────────────────────────────────────────
 * rx_lcore_func()  —  SDD §2.2  (continuous pcap replay)
 *
 * Reads packets directly from a pcap file using libpcap, allocates mbufs from
 * ctx->mempool, copies packet data in, and enqueues into parser_ring.
 *
 * On reaching EOF the pcap handle is closed and reopened, continuing replay
 * indefinitely without touching any DPDK device state.  The net_pcap DPDK
 * port remains active for the TX lcore (rte_eth_tx_burst) throughout.
 *
 * Batching: packets are collected into a local array (up to SPIFAST_BURST_SIZE)
 * before a single rte_ring_enqueue_burst call, matching the burst pattern of
 * the downstream parser lcore.
 *
 * mbuf layout:
 *   rte_pktmbuf_alloc sets data_off = RTE_PKTMBUF_HEADROOM (128 B).
 *   Packet data is copied to rte_pktmbuf_mtod(m) — the Ethernet frame start.
 *   Parser writes pkt_meta_t 16 bytes before mtod(m), within the headroom.
 *   This is identical to the layout produced by the old net_pcap PMD path.
 *
 * mbuf ownership:
 *   After rte_pktmbuf_alloc:       RX lcore owns the mbuf.
 *   rte_ring_enqueue succeeds:     Parser lcore owns it.
 *   ring full / alloc fail:        rte_pktmbuf_free → returned to mempool.
 *
 * Exits when g_shutdown_flag is set (SIGINT/SIGTERM) or pcap file is empty.
 * ───────────────────────────────────────────────────────────────────────────── */
int rx_lcore_func(void *arg)
{
    rx_ctx_t    *ctx          = (rx_ctx_t *)arg;
    char         errbuf[PCAP_ERRBUF_SIZE];
    uint64_t     rx_pkt_count = 0;   /* counts every successfully-read packet */

    while (!g_shutdown_flag) {
        pcap_t *handle = pcap_open_offline(ctx->pcap_path, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "[RX] pcap_open_offline(%s) failed: %s\n",
                    ctx->pcap_path, errbuf);
            g_shutdown_flag = 1;
            break;
        }

        struct rte_mbuf *batch[SPIFAST_BURST_SIZE];
        unsigned int     nb_batch    = 0;
        bool             eof_reached = false;

        while (!g_shutdown_flag) {
            struct pcap_pkthdr *pkt_hdr;
            const uint8_t      *pkt_data;

            /* Sampling: capture rdtsc before pcap read on every Nth packet. */
            bool     do_sample = (ctx->perf != NULL) &&
                                 (rx_pkt_count % SPIFAST_PERF_SAMPLE_RATE == 0);
            uint64_t t0        = do_sample ? rte_rdtsc() : 0;

            int ret = pcap_next_ex(handle, &pkt_hdr, &pkt_data);
            if (ret == -2) { eof_reached = true; break; }  /* normal EOF     */
            if (ret != 1)  { break; }                       /* error / timeout */

            struct rte_mbuf *m = rte_pktmbuf_alloc(ctx->mempool);
            if (unlikely(m == NULL)) {
                ctx->stats->alloc_fail++;   /* pool exhausted — separate from ring-full */
                rx_pkt_count++;
                continue;
            }

            uint16_t caplen = (uint16_t)pkt_hdr->caplen;
            uint16_t maxlen = (uint16_t)(m->buf_len - RTE_PKTMBUF_HEADROOM);
            if (caplen > maxlen)
                caplen = maxlen;

            rte_memcpy(rte_pktmbuf_mtod(m, void *), pkt_data, caplen);
            m->data_len = caplen;
            m->pkt_len  = caplen;

            if (do_sample) {
                ctx->perf->total_cycles  += rte_rdtsc() - t0;
                ctx->perf->total_packets++;
                ctx->perf->total_samples++;
            }
            rx_pkt_count++;

            ctx->stats->rx_packets++;
            ctx->stats->rx_bytes += caplen;

            batch[nb_batch++] = m;

            if (nb_batch < SPIFAST_BURST_SIZE)
                continue;

            /* Flush full burst to parser_ring. */
            unsigned int nb_sent = rte_ring_enqueue_burst(
                ctx->parser_ring, (void * const *)batch, nb_batch, NULL);
            for (unsigned int i = nb_sent; i < nb_batch; i++) {
                rte_pktmbuf_free(batch[i]);
                ctx->stats->parser_ring_drop++;
            }
            nb_batch = 0;
        }

        /* Flush any remaining partial batch (e.g. end-of-file mid-burst). */
        if (nb_batch > 0) {
            unsigned int nb_sent = rte_ring_enqueue_burst(
                ctx->parser_ring, (void * const *)batch, nb_batch, NULL);
            for (unsigned int i = nb_sent; i < nb_batch; i++) {
                rte_pktmbuf_free(batch[i]);
                ctx->stats->parser_ring_drop++;
            }
        }

        pcap_close(handle);

        if (eof_reached) {
            // if (ctx->stats->rx_packets == pkts_at_open) {
            //     /* Zero packets read before EOF — empty pcap file.
            //      * Avoid a hot infinite-reopen loop. */
            //     fprintf(stderr,
            //             "[RX] pcap file '%s' contains no packets — "
            //             "stopping replay\n", ctx->pcap_path);
            //     g_shutdown_flag = 1;
            //     break;
            // }
            ctx->stats->pcap_loops++;   /* completed one full pass */
            // rte_delay_us_sleep(1000);
        }
    }

    return 0;
}
