#ifndef SPIFAST_ACL_ENGINE_H
#define SPIFAST_ACL_ENGINE_H

#include <stddef.h>   /* offsetof, _Static_assert */
#include <stdint.h>
#include "rule_loader.h"
#include "packet/parser.h"
#include "dpdk/dpdk_init.h"   /* SPIFAST_MAX_GROUPS */

/* ─────────────────────────────────────────────────────────────────────────────
 * ACL lookup key — 16-byte naturally-aligned buffer for rte_acl_classify()
 *
 * SDD §4.2 specifies five logical fields.  The fields are arranged here so
 * every member sits at its natural alignment boundary, enabling the compiler
 * and rte_acl to issue ordinary aligned loads.  Explicit _pad1 pushes the
 * 4-byte IP fields to a 4-byte boundary; no trailing pad is needed.
 *
 * Offset  Size  rte_acl input_index  Field
 *   0       1        0               protocol  (IPPROTO_TCP=6, UDP=17)
 *   1       3        0               _pad1     (explicit; deterministic zeros)
 *   4       4        1               src_ip    (IPv4, network byte order)
 *   8       4        2               dst_ip    (IPv4, network byte order)
 *  12       2        3               src_port  (host byte order)
 *  14       2        3               dst_port  (host byte order)
 * Total: 16 bytes
 *
 * src_port and dst_port share input_index=3 because rte_acl requires paired
 * RANGE fields to occupy the same 4-byte word.
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    uint8_t  protocol;
    uint8_t  _pad1[3];   /* explicit pad — zeroed by memset in acl_lookup() */
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
} acl_key_t;

_Static_assert(offsetof(acl_key_t, protocol) ==  0, "acl_key_t: protocol offset");
_Static_assert(offsetof(acl_key_t, src_ip)   ==  4, "acl_key_t: src_ip offset");
_Static_assert(offsetof(acl_key_t, dst_ip)   ==  8, "acl_key_t: dst_ip offset");
_Static_assert(offsetof(acl_key_t, src_port) == 12, "acl_key_t: src_port offset");
_Static_assert(offsetof(acl_key_t, dst_port) == 14, "acl_key_t: dst_port offset");
_Static_assert(sizeof(acl_key_t)             == 16, "acl_key_t: total size");

/* ─────────────────────────────────────────────────────────────────────────────
 * ACL lookup result  (SDD §3.4)
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    uint32_t       group_id;  /* index into filter_group_table                   */
    group_action_t action;    /* ACTION_FORWARD or ACTION_DROP                   */
    uint32_t       rule_id;   /* same as group_id; used for hit counter indexing */
} acl_result_t;

/* ─────────────────────────────────────────────────────────────────────────────
 * Per-group hit counters  (SDD §3.5)
 * Written only by RX/classifier lcore — no atomic operations needed.
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    uint64_t hit_count[SPIFAST_MAX_GROUPS];
} acl_hit_counters_t;

/* ─────────────────────────────────────────────────────────────────────────────
 * Public API  (SDD §2.5, §4)
 * ───────────────────────────────────────────────────────────────────────────── */

/* Build the compiled ACL context from validated rules.
 * Must be called once before any acl_lookup() call.
 * Returns 0 on success, -1 on rte_acl error.  SDD §4.3 */
int acl_engine_build(const spi_rule_t          rules[],
                     uint32_t                   num_rules,
                     const filter_group_table_t *group_table);

/* Per-packet ACL lookup.  Translates pkt_meta_t into an acl_key_t and
 * calls rte_acl_classify(); resolves group_id and action.  SDD §4.4 */
acl_result_t acl_lookup(const pkt_meta_t *meta);

/* Increment the hit counter for the matched group.  Called by rx.c after
 * every successful acl_lookup().  SDD §4.7 */
void acl_engine_increment_hit(uint32_t group_id);

/* Read-only pointer to the global hit counter array; consumed by stats.c. */
const acl_hit_counters_t *acl_get_hit_counters(void);

/* Free the compiled ACL context.  Called during shutdown.  */
void acl_engine_destroy(void);

#endif /* SPIFAST_ACL_ENGINE_H */
