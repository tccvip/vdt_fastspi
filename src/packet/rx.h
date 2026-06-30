#ifndef SPIFAST_RX_H
#define SPIFAST_RX_H

#include <stdint.h>
#include <rte_common.h>
#include <rte_ring.h>
#include "dpdk/dpdk_init.h"   /* CACHE_LINE_SIZE, SPIFAST_* constants */
#include "perf/perf_stats.h"  /* perf_stage_t                         */

/* ─────────────────────────────────────────────────────────────────────────────
 * Per-lcore statistics for the RX lcore  (SDD §2.2, §3.5)
 *
 * Padded to exactly one cache line to prevent false sharing with adjacent
 * stats structs (parser_lcore_stats_t, worker_lcore_stats_t).
 * Written exclusively by the RX lcore; read by Main/stats lcore without
 * locking.  Occasional torn 64-bit reads by stats are acceptable (SDD §6.6).
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    uint64_t rx_packets;        /* total mbufs received (across all pcap loops)  */
    uint64_t rx_bytes;          /* total bytes (sum of pkt_len) received          */
    uint64_t alloc_fail;        /* rte_pktmbuf_alloc() returned NULL (pool empty) */
    uint64_t parser_ring_drop;  /* mbufs freed because parser_ring was full       */
    uint64_t pcap_loops;        /* number of completed passes through the pcap    */
    uint8_t  _pad[CACHE_LINE_SIZE - 5 * sizeof(uint64_t)];
} __rte_cache_aligned rx_lcore_stats_t;

_Static_assert(sizeof(rx_lcore_stats_t) == CACHE_LINE_SIZE,
               "rx_lcore_stats_t must occupy exactly one cache line");

/* ─────────────────────────────────────────────────────────────────────────────
 * Context passed to rx_lcore_func() at launch  (SDD §2.2)
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    uint16_t            port_id;       /* net_pcap device; kept active for TX lcore */
    struct rte_ring    *parser_ring;   /* SPSC ring: RX lcore → Parser lcore        */
    rx_lcore_stats_t   *stats;
    const char         *pcap_path;    /* path to pcap file for direct libpcap read  */
    struct rte_mempool *mempool;      /* mbuf pool for rte_pktmbuf_alloc()           */
    perf_stage_t       *perf;         /* perf counters for this lcore (may be NULL) */
} rx_ctx_t;

/* ─────────────────────────────────────────────────────────────────────────────
 * Global shutdown flag  (SDD §2.2, §6.6)
 *
 * Set to 1 by SIGINT/SIGTERM signal handler in main.c.
 * NOT set by pcap EOF — the RX lcore loops the pcap file indefinitely.
 * Parser, Worker, and TX lcores poll this flag to drain their rings and exit.
 *
 * volatile prevents compiler reordering across the flag check on reader side.
 * ───────────────────────────────────────────────────────────────────────────── */
extern volatile int g_shutdown_flag;

/* ─────────────────────────────────────────────────────────────────────────────
 * Public API
 * ───────────────────────────────────────────────────────────────────────────── */

/* Entry point for the RX lcore (launched via rte_eal_remote_launch).
 * Reads packets from pcap file via libpcap, allocates mbufs from ctx->mempool,
 * and enqueues into parser_ring.  On EOF, closes and reopens the pcap file to
 * loop continuously.  Exits only when g_shutdown_flag is set (SIGINT/SIGTERM).
 * SDD §2.2 */
int rx_lcore_func(void *arg);

#endif /* SPIFAST_RX_H */
