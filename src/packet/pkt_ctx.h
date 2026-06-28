#ifndef SPIFAST_PKT_CTX_H
#define SPIFAST_PKT_CTX_H

/*
 * pkt_ctx.h — Authoritative packet context shared by Parser lcore (writer)
 *             and Worker lcore (reader).  (SDD §3.1, §2.3, §6.7, DD-17)
 *
 * No other translation unit may define pkt_meta_t.
 * parser.h and worker.h include this header; they do not re-declare the type.
 */

#include <stdint.h>
#include <rte_mbuf.h>

/* ─────────────────────────────────────────────────────────────────────────────
 * pkt_meta_t  —  five-tuple + VLAN tag  (SDD §3.1)
 *
 * Normalised for stateless bidirectional flow matching (SDD §2.3, DD-10):
 * after normalisation the numerically smaller IPv4 address always occupies
 * src_ip; src_port is set consistently as the tie-breaker.
 *
 * Exact byte layout (16 bytes, no implicit padding):
 *
 *   offset  size  field       notes
 *   ------  ----  ----------  -----------------------------------------------
 *      0      4   src_ip      IPv4, network byte order; smaller IP after norm.
 *      4      4   dst_ip      IPv4, network byte order
 *      8      2   src_port    host byte order
 *     10      2   dst_port    host byte order
 *     12      1   protocol    IPPROTO_TCP (6) or IPPROTO_UDP (17)
 *     13      1   vlan_valid  1 if 802.1Q tag was present, 0 otherwise
 *     14      2   vlan_id     VLAN ID [0..4095]; defined only when vlan_valid
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint8_t  vlan_valid;
    uint16_t vlan_id;
} pkt_meta_t;

_Static_assert(sizeof(pkt_meta_t) == 16,
               "pkt_meta_t size changed — update SDD §3.1 and acl_key_t mapping");
_Static_assert(sizeof(pkt_meta_t) <= RTE_PKTMBUF_HEADROOM,
               "pkt_meta_t does not fit in default mbuf headroom (128 B)");

/* ─────────────────────────────────────────────────────────────────────────────
 * Headroom layout  (SDD §2.3, DD-17)
 *
 * pkt_meta_t is stored immediately before the packet data pointer, inside the
 * mbuf's pre-allocated headroom region.  No extra allocation is needed; the
 * metadata travels with the mbuf pointer across the SPSC ring.
 *
 *   ◄──────────────── RTE_PKTMBUF_HEADROOM (128 B) ─────────────────────►
 *   ┌─────────────────────────────────────┬──────────────┬────────────────
 *   │      unused headroom  (112 B)       │  pkt_meta_t  │  packet data …
 *   └─────────────────────────────────────┴──────────────┴────────────────
 *                                         ↑              ↑
 *                              mtod(m) - 16 B         mtod(m)
 *
 * Ownership contract (SDD §6.7):
 *
 *   Parser lcore  — calls pkt_meta_of() for write access, fills all fields,
 *                   then enqueues the mbuf pointer into worker_ring[i].
 *
 *   Worker lcore  — dequeues the mbuf pointer from worker_ring[i], then calls
 *                   pkt_meta_read() for read-only access to the filled struct.
 *
 * Memory ordering: the SPSC ring enqueue/dequeue pair acts as the
 * release/acquire barrier.  No explicit fence is needed (SDD §6.8).
 * The Worker must not access the headroom before dequeue completes.
 * ───────────────────────────────────────────────────────────────────────────── */

/* Writable pointer — used by Parser lcore to fill the metadata slot.
 * Also used by normalize_flow() which operates on the same in-place struct. */
static inline pkt_meta_t *
pkt_meta_of(struct rte_mbuf *m)
{
    return (pkt_meta_t *)(rte_pktmbuf_mtod(m, uint8_t *) - sizeof(pkt_meta_t));
}

/* Read-only pointer — used by Worker lcore after dequeue from worker_ring. */
static inline const pkt_meta_t *
pkt_meta_read(const struct rte_mbuf *m)
{
    return (const pkt_meta_t *)(rte_pktmbuf_mtod(m, const uint8_t *)
                                 - sizeof(pkt_meta_t));
}

#endif /* SPIFAST_PKT_CTX_H */
