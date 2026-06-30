#include <string.h>

#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cycles.h>

#include "worker.h"
#include "packet/pkt_ctx.h"    /* pkt_meta_read()                              */
#include "rule/acl_engine.h"   /* acl_key_t, flat_acl_match_burst()            */

/* Set to 1 by RX lcore when PCAP replay ends; workers drain and exit. */
extern volatile int g_shutdown_flag;

/* ─────────────────────────────────────────────────────────────────────────────
 * worker_lcore_func()  —  SDD §2.6
 *
 * Pipeline per burst:
 *   1. Dequeue burst from dedicated SPSC worker_ring.
 *   2. Read pkt_meta_t from mbuf headroom → build acl_key_t array.
 *   3. Batch flat ACL classify via flat_acl_match_burst() (single pass,
 *      no allocation).
 *   4. Per-packet: count group hit, then FORWARD or DROP.
 *   5. rte_ring_enqueue_burst(tx_ring); free any that don't fit (tx_ring_drop).
 *
 * mbuf ownership:
 *   After dequeue: worker owns the mbuf.
 *   rte_ring_enqueue_burst(tx_ring) succeeds → TX lcore owns the mbuf.
 *   rte_pktmbuf_free → mbuf returned to mempool (DROP or tx_ring full path).
 *
 * Constraints (SDD §6.3):
 *   No malloc, no free (outside rte_pktmbuf_free), no locks, no printf.
 *   Worker never touches another worker's ring.
 * ───────────────────────────────────────────────────────────────────────────── */
int worker_lcore_func(void *arg)
{
    worker_ctx_t              *ctx          = (worker_ctx_t *)arg;
    struct rte_ring           *ring         = ctx->ring;
    struct rte_ring           *tx_ring      = ctx->tx_ring;
    const flat_rule_table_t   *flat_rule_tbl = ctx->flat_rule_table;
    worker_lcore_stats_t      *stats        = ctx->stats;
    uint64_t                   burst_count  = 0;

    struct rte_mbuf          *pkts[SPIFAST_WORKER_BURST];
    acl_key_t                 keys[SPIFAST_WORKER_BURST];
    const acl_key_t          *key_ptrs[SPIFAST_WORKER_BURST];
    const flat_rule_entry_t  *results[SPIFAST_WORKER_BURST];
    struct rte_mbuf          *tx_burst[SPIFAST_WORKER_BURST];

    while (!g_shutdown_flag || rte_ring_count(ring) > 0) {
        unsigned int nb = rte_ring_dequeue_burst(
            ring, (void **)pkts, SPIFAST_WORKER_BURST, NULL);
        if (nb == 0)
            continue;

        stats->received += nb;

        /* Sampling: time every Nth burst for both full-worker and ACL-only. */
        bool     do_sample = (burst_count % SPIFAST_PERF_SAMPLE_RATE == 0);
        uint64_t t_worker  = (do_sample && ctx->perf_worker) ? rte_rdtsc() : 0;

        /* ── Step 2: build ACL key array from mbuf headroom metadata ──────── */
        for (unsigned int i = 0; i < nb; i++) {
            const pkt_meta_t *m = pkt_meta_read(pkts[i]);
            memset(&keys[i], 0, sizeof(keys[i]));
            keys[i].protocol = m->protocol;
            /* Parser writes IPs in network byte order; flat_acl_match expects
             * host byte order (SDD §4.6 — mirrors the worker→rte_acl contract). */
            keys[i].src_ip   = rte_be_to_cpu_32(m->src_ip);
            keys[i].dst_ip   = rte_be_to_cpu_32(m->dst_ip);
            keys[i].src_port = m->src_port;
            keys[i].dst_port = m->dst_port;
            key_ptrs[i] = &keys[i];
        }

        /* ── Step 3: batch flat ACL classify — single sorted-rule scan ─────── */
        if (do_sample && ctx->perf_acl) {
            uint64_t t_acl = rte_rdtsc();
            flat_acl_match_burst(flat_rule_tbl, key_ptrs, results, nb);
            ctx->perf_acl->total_cycles  += rte_rdtsc() - t_acl;
            ctx->perf_acl->total_packets += nb;
            ctx->perf_acl->total_samples++;
        } else {
            flat_acl_match_burst(flat_rule_tbl, key_ptrs, results, nb);
        }

        /* ── Steps 4–5: group accounting + dispatch ─────────────────────────── */
        unsigned int nb_tx = 0;

        for (unsigned int i = 0; i < nb; i++) {
            const flat_rule_entry_t *rule = results[i];

            if (rule && rule->group_idx < SPIFAST_MAX_GROUPS)
                ctx->group_hits[rule->group_idx]++;

            if (rule && rule->action == ACTION_FORWARD) {
                tx_burst[nb_tx++] = pkts[i];
                stats->forwarded++;
            } else {
                rte_pktmbuf_free(pkts[i]);
                stats->dropped++;
            }
        }

        /* ── Step 6: enqueue FORWARD batch to tx_ring (MPSC) ──────────────── */
        if (nb_tx == 0)
            continue;

        unsigned int nb_sent = rte_ring_enqueue_burst(
            tx_ring, (void * const *)tx_burst, nb_tx, NULL);

        if (unlikely(nb_sent < nb_tx)) {
            for (unsigned int i = nb_sent; i < nb_tx; i++)
                rte_pktmbuf_free(tx_burst[i]);
            stats->tx_ring_drop += nb_tx - nb_sent;
        }

        if (do_sample && ctx->perf_worker) {
            ctx->perf_worker->total_cycles  += rte_rdtsc() - t_worker;
            ctx->perf_worker->total_packets += nb;
            ctx->perf_worker->total_samples++;
        }
        burst_count++;
    }

    return 0;
}
