#ifndef SPIFAST_ACL_ENGINE_H
#define SPIFAST_ACL_ENGINE_H

#include <stddef.h>      /* offsetof, _Static_assert */
#include <stdint.h>
#include "rule_loader.h"
#include "packet/parser.h"
#include "dpdk/dpdk_init.h"   /* SPIFAST_MAX_GROUPS, SPIFAST_MAX_FILTERS_PER_GROUP */

struct rte_acl_ctx;   /* forward-declare — callers never allocate these */

/* ─────────────────────────────────────────────────────────────────────────────
 * ACL lookup key  (SDD §4.2)
 *
 * 16-byte naturally-aligned buffer fed to rte_acl_classify().  Fields are
 * arranged so every member sits at its natural alignment boundary.
 *
 * Offset  Size  input_index  Field
 *   0       1        0       protocol  (IPPROTO_TCP=6, UDP=17; 0 if _pad)
 *   1       3        0       _pad1     (explicit zeros — part of word 0)
 *   4       4        1       src_ip    (IPv4, network byte order)
 *   8       4        2       dst_ip    (IPv4, network byte order)
 *  12       2        3       src_port  (host byte order; RANGE pair with dst_port)
 *  14       2        3       dst_port  (host byte order; same 4-byte word as src_port)
 *
 * src_port and dst_port share input_index=3: rte_acl RANGE fields must occupy
 * the same 4-byte word.
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    uint8_t  protocol;
    uint8_t  _pad1[3];   /* deterministic zeros — memset to 0 before classify */
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
    uint32_t       group_id;  /* index into filter_group_table                */
    group_action_t action;    /* ACTION_FORWARD or ACTION_DROP                */
    uint32_t       rule_id;   /* == group_id; used for hit counter indexing   */
} acl_result_t;

/* ─────────────────────────────────────────────────────────────────────────────
 * Two-stage build API  (SDD §4.3)
 *
 * Calling sequence (done once at startup by rule_loader → acl_engine_build):
 *   1. acl_engine_build_stage1(rules, num_rules, group_table)
 *   2. acl_engine_init_stage2()
 *
 * Stage-2 contexts are built lazily by Main lcore when a group is first hit:
 *   3. acl_engine_build_group(group_id, rules, num_rules, group_table)
 * ───────────────────────────────────────────────────────────────────────────── */

/* Build Stage-1 context: one representative rule per group.
 * The DEFAULT group (highest precedence, action=DROP) always uses a fully
 * wildcard rule so that unmatched packets fall through to it.
 * Returns 0 on success, -1 on rte_acl error. */
int acl_engine_build_stage1(const spi_rule_t          *rules,
                             uint32_t                   num_rules,
                             const filter_group_table_t *group_table);

/* Initialise Stage-2 array (all NULL = lazy, not yet built).
 * Must be called after acl_engine_build_stage1(). */
void acl_engine_init_stage2(void);

/* Build (or rebuild) the per-group Stage-2 context for group_id.
 * Adds all rules belonging to group_id plus a wildcard catch-all.
 * Atomically publishes the context so Worker lcores see it immediately.
 * Returns 0 on success, -1 on rte_acl error.  SDD §4.3 */
int acl_engine_build_group(uint32_t                    group_id,
                            const spi_rule_t           *rules,
                            uint32_t                    num_rules,
                            const filter_group_table_t *group_table);

/* Convenience wrapper: build_stage1 + init_stage2.
 * Called by rule_loader after all rules are validated.
 * Returns 0 on success, -1 on error.  SDD §2.4, §4.3 */
int acl_engine_build(const spi_rule_t          *rules,
                     uint32_t                   num_rules,
                     const filter_group_table_t *group_table);

/* ─────────────────────────────────────────────────────────────────────────────
 * Per-packet two-stage lookup  (SDD §4.4)
 *
 * Builds an acl_key_t from pkt_meta_t; calls rte_acl_classify Stage-1 to
 * identify the group, then Stage-2 (if built) to confirm.  Falls back to
 * DEFAULT group if Stage-1 returns no match or Stage-2 is not yet built.
 *
 * No allocation, no locking — safe on the Worker lcore hot path.
 * ───────────────────────────────────────────────────────────────────────────── */
acl_result_t acl_lookup(const pkt_meta_t *meta);

/* ─────────────────────────────────────────────────────────────────────────────
 * Context accessors for Worker lcore batch classify  (SDD §2.6)
 *
 * Worker calls these once at startup to cache ctx pointers in worker_ctx_t.
 * After acl_engine_build() returns, stage1_ctx is immutable (read-only).
 * group_ctx[g] may become non-NULL later (lazy build) — Worker must use
 * acl_get_group_ctx(g) per burst, not cache it permanently.
 * ───────────────────────────────────────────────────────────────────────────── */
struct rte_acl_ctx *acl_get_stage1_ctx(void);
struct rte_acl_ctx *acl_get_group_ctx(uint32_t group_id);
uint32_t            acl_get_default_group_id(void);

/* Free all ACL contexts.  Called during ordered shutdown after all lcores
 * have exited.  Sets all pointers to NULL.  SDD §9.2 */
void acl_engine_destroy(void);

#endif /* SPIFAST_ACL_ENGINE_H */
