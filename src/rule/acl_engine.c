#include <stdint.h>
#include <string.h>

#include <rte_acl.h>
#include <rte_errno.h>

#include "acl_engine.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * Module-private state (file-scope)
 * ───────────────────────────────────────────────────────────────────────────── */

/* TODO: static struct rte_acl_ctx      *g_acl_ctx    = NULL;
 *       static const filter_group_table_t *g_group_table = NULL;
 *       static uint32_t                 g_default_group_id = 0;  */

static acl_hit_counters_t g_hit_counters;   /* zeroed at build time */

/* ─────────────────────────────────────────────────────────────────────────────
 * ACL field definitions  (SDD §4.2, aligned layout)
 *
 * input_index groups each 4-byte word consumed by rte_acl:
 *   word 0 (bytes  0–3):  protocol + _pad1  → input_index 0
 *   word 1 (bytes  4–7):  src_ip            → input_index 1
 *   word 2 (bytes  8–11): dst_ip            → input_index 2
 *   word 3 (bytes 12–15): src_port+dst_port → input_index 3
 *
 * src_port and dst_port share input_index=3: rte_acl requires two RANGE
 * fields that form a port pair to reside in the same 4-byte word.
 * All .offset values are derived from offsetof() — no magic constants.
 * ───────────────────────────────────────────────────────────────────────────── */

/* TODO: #define NUM_ACL_FIELDS  5
 *
 * static const struct rte_acl_field_def spifast_acl_fields[NUM_ACL_FIELDS] = {
 *     { .type=RTE_ACL_FIELD_TYPE_BITMASK, .size=sizeof(uint8_t),
 *       .field_index=0, .input_index=0, .offset=offsetof(acl_key_t, protocol) },
 *     { .type=RTE_ACL_FIELD_TYPE_MASK,    .size=sizeof(uint32_t),
 *       .field_index=1, .input_index=1, .offset=offsetof(acl_key_t, src_ip) },
 *     { .type=RTE_ACL_FIELD_TYPE_MASK,    .size=sizeof(uint32_t),
 *       .field_index=2, .input_index=2, .offset=offsetof(acl_key_t, dst_ip) },
 *     { .type=RTE_ACL_FIELD_TYPE_RANGE,   .size=sizeof(uint16_t),
 *       .field_index=3, .input_index=3, .offset=offsetof(acl_key_t, src_port) },
 *     { .type=RTE_ACL_FIELD_TYPE_RANGE,   .size=sizeof(uint16_t),
 *       .field_index=4, .input_index=3, .offset=offsetof(acl_key_t, dst_port) },
 * };  */

/* ─────────────────────────────────────────────────────────────────────────────
 * acl_engine_build()  —  SDD §4.3
 *
 * Translates validated spi_rule_t array into an rte_acl compiled context.
 * Priority inversion: acl_priority = UINT32_MAX - rule.precedence
 *   (rte_acl picks highest integer priority; SPIFast lower number = higher priority)
 * ACL userdata: group_id + 1  (0 reserved for no-match)
 * ───────────────────────────────────────────────────────────────────────────── */
int acl_engine_build(const spi_rule_t          rules[],
                     uint32_t                   num_rules,
                     const filter_group_table_t *group_table)
{
    /* TODO: Step 1 — Create ACL context.
     *   struct rte_acl_param acl_param = {
     *       .name       = "spifast_acl",
     *       .socket_id  = SOCKET_ID_ANY,
     *       .rule_size  = RTE_ACL_RULE_SZ(NUM_ACL_FIELDS),
     *       .max_rule_num = SPIFAST_MAX_RULES,
     *   };
     *   g_acl_ctx = rte_acl_create(&acl_param);
     *   if (!g_acl_ctx):
     *     fprintf(stderr, "[SPIFAST ERROR] acl_engine: rte_acl_create: %s\n",
     *             rte_strerror(rte_errno));
     *     return -1;  */

    /* TODO: Step 2 — Add each rule to the context.
     *   for i in [0, num_rules):
     *     Allocate acl_rule on the stack via RTE_ACL_RULE_DEF(acl_rule, NUM_ACL_FIELDS).
     *     memset(&acl_rule, 0, sizeof(acl_rule));
     *
     *     acl_rule.data.priority = UINT32_MAX - rules[i].precedence;
     *     acl_rule.data.userdata = rules[i].group_id + 1;
     *
     *     -- protocol field: BITMASK
     *     if (rules[i].protocol == PROTO_MATCH_ANY):
     *       acl_rule.field[0].value.u8 = 0;
     *       acl_rule.field[0].mask_range.u8 = 0;  // wildcard mask
     *     else:
     *       acl_rule.field[0].value.u8 = (uint8_t)rules[i].protocol;
     *       acl_rule.field[0].mask_range.u8 = 0xFF;
     *
     *     -- src_ip field: prefix match
     *     acl_rule.field[1].value.u32   = rules[i].src_ip;
     *     acl_rule.field[1].mask_range.u32 = rules[i].src_prefix_len;
     *
     *     -- dst_ip field: prefix match
     *     acl_rule.field[2].value.u32   = rules[i].dst_ip;
     *     acl_rule.field[2].mask_range.u32 = rules[i].dst_prefix_len;
     *
     *     -- src_port field: range match
     *     acl_rule.field[3].value.u16      = rules[i].src_port_lo;
     *     acl_rule.field[3].mask_range.u16 = rules[i].src_port_hi;
     *
     *     -- dst_port field: range match
     *     acl_rule.field[4].value.u16      = rules[i].dst_port_lo;
     *     acl_rule.field[4].mask_range.u16 = rules[i].dst_port_hi;
     *
     *     if (rte_acl_add_rules(g_acl_ctx, (struct rte_acl_rule *)&acl_rule, 1) != 0):
     *       fprintf(stderr, "[SPIFAST ERROR] acl_engine: rte_acl_add_rules: %s\n",
     *               rte_strerror(rte_errno));
     *       rte_acl_free(g_acl_ctx); g_acl_ctx = NULL; return -1;  */

    /* TODO: Step 3 — Compile the ACL context.
     *   struct rte_acl_config acl_cfg = { .num_categories = 1 };
     *   RTE_ACL_FIELD_DEF_COPY(&acl_cfg.defs, spifast_acl_fields, NUM_ACL_FIELDS);
     *   acl_cfg.num_fields = NUM_ACL_FIELDS;
     *   if (rte_acl_build(g_acl_ctx, &acl_cfg) != 0):
     *     fprintf(stderr, "[SPIFAST ERROR] acl_engine: rte_acl_build: %s\n",
     *             rte_strerror(rte_errno));
     *     rte_acl_free(g_acl_ctx); g_acl_ctx = NULL; return -1;  */

    /* TODO: Step 4 — Store group table reference and locate default group.
     *   g_group_table = group_table;
     *   Scan groups[] for highest precedence value → that is the DEFAULT group.
     *   g_default_group_id = <group with max precedence>.group_id;  */

    /* TODO: Step 5 — Zero hit counters. */
    memset(&g_hit_counters, 0, sizeof(g_hit_counters));

    (void)rules; (void)num_rules; (void)group_table;
    return -1;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * acl_lookup()  —  SDD §4.4
 *
 * Builds an acl_key_t from pkt_meta_t, calls rte_acl_classify() for a
 * single packet, and resolves the result to group_id + action.
 * No allocation, no locking — called from the RX/classifier lcore hot path.
 * ───────────────────────────────────────────────────────────────────────────── */
acl_result_t acl_lookup(const pkt_meta_t *meta)
{
    /* TODO: acl_key_t key;
     *       memset(&key, 0, sizeof(key));
     *       key.protocol = meta->protocol;
     *       key.src_ip   = meta->src_ip;
     *       key.dst_ip   = meta->dst_ip;
     *       key.src_port = meta->src_port;
     *       key.dst_port = meta->dst_port;
     *
     *       const uint8_t *keys_ptr[1] = { (const uint8_t *)&key };
     *       uint32_t results[1] = { 0 };
     *       rte_acl_classify(g_acl_ctx, keys_ptr, results, 1, 1);
     *
     *       uint32_t userdata = results[0];
     *       uint32_t group_id = (userdata == 0) ? g_default_group_id
     *                                           : (userdata - 1);
     *
     *       return (acl_result_t){
     *           .group_id = group_id,
     *           .action   = g_group_table->groups[group_id].action,
     *           .rule_id  = group_id,
     *       };  */

    (void)meta;
    return (acl_result_t){ .group_id = 0, .action = ACTION_DROP, .rule_id = 0 };
}

/* ─────────────────────────────────────────────────────────────────────────────
 * acl_engine_increment_hit()  —  SDD §4.7
 *
 * Called by RX/classifier lcore after each acl_lookup().
 * Single writer (RX lcore only); no atomic needed.
 * ───────────────────────────────────────────────────────────────────────────── */
void acl_engine_increment_hit(uint32_t group_id)
{
    /* TODO: if (group_id < SPIFAST_MAX_GROUPS)
     *           g_hit_counters.hit_count[group_id]++;  */
    (void)group_id;
}

/* Read-only accessor consumed by stats.c (main lcore, non-atomic read). */
const acl_hit_counters_t *acl_get_hit_counters(void)
{
    return &g_hit_counters;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * acl_engine_destroy()  —  called once during ordered shutdown
 * ───────────────────────────────────────────────────────────────────────────── */
void acl_engine_destroy(void)
{
    /* TODO: if (g_acl_ctx) { rte_acl_free(g_acl_ctx); g_acl_ctx = NULL; }  */
}
