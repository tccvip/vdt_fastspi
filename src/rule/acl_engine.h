#ifndef SPIFAST_ACL_ENGINE_H
#define SPIFAST_ACL_ENGINE_H

#include <stddef.h>      /* offsetof */
#include <stdint.h>
#include "rule_loader.h"      /* flat_rule_table_t, group_action_t */
#include "include/config.h"   /* match_mode_t */
#include "dpdk/dpdk_init.h"   /* SPIFAST_MAX_GROUPS */

struct rte_acl_ctx;   /* forward-declare — callers never allocate these */

/* ─────────────────────────────────────────────────────────────────────────────
 * ACL lookup key  (SDD §4.3)
 *
 * 16-byte naturally-aligned buffer fed to rte_acl_classify().  Layout matches
 * the field definitions in acl_engine.c (s_acl_fields[]).
 *
 * Offset  Size  input_index  Field
 *   0       1        0       protocol  (IPPROTO_TCP=6, UDP=17; 0=any)
 *   1       3        0       _pad1     (explicit zeros)
 *   4       4        1       src_ip    (IPv4, network byte order)
 *   8       4        2       dst_ip    (IPv4, network byte order)
 *  12       2        3       src_port  (host byte order)
 *  14       2        3       dst_port  (host byte order; same word as src_port)
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    uint8_t  protocol;
    uint8_t  _pad1[3];   /* must be zeroed before classify */
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
 * Flat single-stage build API  (SDD §4.5, §4.11)
 *
 * Called once at startup by rule_loader_load() after all rules are validated.
 * Must complete before any Worker lcore is launched — no lazy build.
 * ───────────────────────────────────────────────────────────────────────────── */

/* Build sorted match index from flat_rule_table.
 * match_mode controls iteration order used by flat_acl_match (SDD §4.4):
 *   MATCH_MODE_BEST  — sort (precedence DESC, file_order ASC)
 *   MATCH_MODE_FIRST — sort (file_order ASC)
 * Returns 0 on success, -1 on error. */
int acl_engine_build(const flat_rule_table_t *tbl, match_mode_t mode);

/* Return flat_acl_ctx pointer (NULL in Phase 3; populated by rte_acl in Phase 4+). */
struct rte_acl_ctx *acl_get_flat_ctx(void);

/* Return flat_rule_table pointer (read-only) for Worker lcore action lookup.
 * Valid only after acl_engine_build() returns 0. */
const flat_rule_table_t *acl_get_flat_rule_table(void);

/* Free engine state.  Call from main lcore after all Workers have exited. */
void acl_engine_destroy(void);

/* ─────────────────────────────────────────────────────────────────────────────
 * Flat linear-scan match API  (SDD §4.6)
 *
 * flat_acl_match iterates rules in the order built by acl_engine_build():
 *   MATCH_MODE_BEST  — highest precedence first; same-prec tiebreak by file_order
 *   MATCH_MODE_FIRST — parse (file) order
 *
 * key->src_ip / dst_ip must be in host byte order (worker does NBO→HBO).
 * The DEFAULT catch-all guarantees a non-NULL return for any valid packet.
 * No per-call allocation; safe on the Worker lcore hot path.
 * ───────────────────────────────────────────────────────────────────────────── */
const flat_rule_entry_t *flat_acl_match(const flat_rule_table_t *tbl,
                                         const acl_key_t         *key);

/* Burst variant — applies flat_acl_match to nb packets in one call.
 * keys[] and results[] must be pre-allocated arrays of length >= nb. */
void flat_acl_match_burst(const flat_rule_table_t    *tbl,
                           const acl_key_t * const     keys[],
                           const flat_rule_entry_t    *results[],
                           uint32_t                    nb);

#endif /* SPIFAST_ACL_ENGINE_H */
