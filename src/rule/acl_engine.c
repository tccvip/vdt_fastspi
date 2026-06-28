#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <rte_byteorder.h>
#include <rte_acl.h>
#include <rte_errno.h>
#include <rte_common.h>

#include "acl_engine.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * rte_acl field layout — preserved for Phase 4+ rte_acl integration
 * ───────────────────────────────────────────────────────────────────────────── */
#define NUM_ACL_FIELDS  5

typedef struct {
    struct rte_acl_rule_data data;
    struct rte_acl_field     field[NUM_ACL_FIELDS];
} spifast_acl_rule_t;

static const struct rte_acl_field_def s_acl_fields[NUM_ACL_FIELDS] = {
    {
        .type        = RTE_ACL_FIELD_TYPE_BITMASK,
        .size        = sizeof(uint8_t),
        .field_index = 0,
        .input_index = 0,
        .offset      = offsetof(acl_key_t, protocol),
    },
    {
        .type        = RTE_ACL_FIELD_TYPE_MASK,
        .size        = sizeof(uint32_t),
        .field_index = 1,
        .input_index = 1,
        .offset      = offsetof(acl_key_t, src_ip),
    },
    {
        .type        = RTE_ACL_FIELD_TYPE_MASK,
        .size        = sizeof(uint32_t),
        .field_index = 2,
        .input_index = 2,
        .offset      = offsetof(acl_key_t, dst_ip),
    },
    {
        .type        = RTE_ACL_FIELD_TYPE_RANGE,
        .size        = sizeof(uint16_t),
        .field_index = 3,
        .input_index = 3,
        .offset      = offsetof(acl_key_t, src_port),
    },
    {
        .type        = RTE_ACL_FIELD_TYPE_RANGE,
        .size        = sizeof(uint16_t),
        .field_index = 4,
        .input_index = 3,
        .offset      = offsetof(acl_key_t, dst_port),
    },
};

/* ─────────────────────────────────────────────────────────────────────────────
 * Module-private state
 * ───────────────────────────────────────────────────────────────────────────── */
static struct rte_acl_ctx      *g_flat_ctx        = NULL;  /* NULL in Phase 3 */
static const flat_rule_table_t *g_flat_rule_table = NULL;

/* Sorted index into g_flat_rule_table->rules[], built by acl_engine_build */
static uint32_t g_sorted_idx[SPIFAST_MAX_RULES];
static uint32_t g_num_sorted = 0;

/* Sort context — valid only during the qsort call in acl_engine_build */
static const flat_rule_table_t *s_sort_tbl;
static match_mode_t             s_sort_mode;

/* ─────────────────────────────────────────────────────────────────────────────
 * Internal helpers
 * ───────────────────────────────────────────────────────────────────────────── */

/* Convert CIDR prefix length to a 32-bit network mask in host byte order.
 * prefix_len == 0 → 0 (wildcard, all bits don't-care). */
static uint32_t prefix_to_mask(uint8_t prefix_len)
{
    if (prefix_len == 0)
        return 0;
    return ~(uint32_t)0 << (32 - prefix_len);
}

/* Returns 1 if key matches rule entry, 0 otherwise.
 * key->src_ip / dst_ip are in host byte order.
 * rule->src_ip / dst_ip are in network byte order (from inet_aton);
 * converted to host byte order here before comparison. */
static int rule_matches(const flat_rule_entry_t *e, const acl_key_t *k)
{
    if (e->protocol != 0 && e->protocol != k->protocol)
        return 0;

    {
        uint32_t mask = prefix_to_mask(e->src_prefix_len);
        if ((k->src_ip & mask) != (rte_be_to_cpu_32(e->src_ip) & mask))
            return 0;
    }

    {
        uint32_t mask = prefix_to_mask(e->dst_prefix_len);
        if ((k->dst_ip & mask) != (rte_be_to_cpu_32(e->dst_ip) & mask))
            return 0;
    }

    if (k->src_port < e->src_port_lo || k->src_port > e->src_port_hi)
        return 0;

    if (k->dst_port < e->dst_port_lo || k->dst_port > e->dst_port_hi)
        return 0;

    return 1;
}

/* qsort comparator for g_sorted_idx[].
 * MATCH_MODE_BEST:  higher precedence first; same-prec → lower file_order first.
 * MATCH_MODE_FIRST: lower file_order first (parse order). */
static int cmp_rule_idx(const void *a, const void *b)
{
    uint32_t                 ia = *(const uint32_t *)a;
    uint32_t                 ib = *(const uint32_t *)b;
    const flat_rule_entry_t *ra = &s_sort_tbl->rules[ia];
    const flat_rule_entry_t *rb = &s_sort_tbl->rules[ib];

    if (s_sort_mode == MATCH_MODE_BEST && ra->precedence != rb->precedence)
        return (rb->precedence > ra->precedence) ? 1 : -1;

    /* MATCH_MODE_FIRST, or same-precedence tiebreak: lower file_order first */
    return (ra->file_order > rb->file_order) ? 1 :
           (ra->file_order < rb->file_order) ? -1 : 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * acl_engine_build()  —  SDD §4.5, §4.11
 *
 * Builds g_sorted_idx[] for flat_acl_match linear scan.
 * g_flat_ctx remains NULL in Phase 3 (no rte_acl_create).
 * ───────────────────────────────────────────────────────────────────────────── */
int acl_engine_build(const flat_rule_table_t *tbl, match_mode_t mode)
{
    (void)s_acl_fields;   /* retained for Phase 4+ rte_acl integration */

    if (!tbl || tbl->num_rules == 0) {
        fprintf(stderr, "[SPIFAST] acl_engine_build: empty rule table\n");
        return -1;
    }
    if (tbl->num_rules > SPIFAST_MAX_RULES) {
        fprintf(stderr, "[SPIFAST] acl_engine_build: num_rules %u exceeds max %u\n",
                tbl->num_rules, SPIFAST_MAX_RULES);
        return -1;
    }

    for (uint32_t i = 0; i < tbl->num_rules; i++)
        g_sorted_idx[i] = i;

    s_sort_tbl  = tbl;
    s_sort_mode = mode;
    qsort(g_sorted_idx, tbl->num_rules, sizeof(g_sorted_idx[0]), cmp_rule_idx);
    s_sort_tbl = NULL;

    g_flat_rule_table = tbl;
    g_num_sorted      = tbl->num_rules;

    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * flat_acl_match()  —  SDD §4.6
 * ───────────────────────────────────────────────────────────────────────────── */
const flat_rule_entry_t *flat_acl_match(const flat_rule_table_t *tbl,
                                         const acl_key_t         *key)
{
    for (uint32_t i = 0; i < g_num_sorted; i++) {
        const flat_rule_entry_t *rule = &tbl->rules[g_sorted_idx[i]];
        if (rule_matches(rule, key))
            return rule;
    }
    return NULL;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * flat_acl_match_burst()  —  batch wrapper for Worker lcore hot path
 * ───────────────────────────────────────────────────────────────────────────── */
void flat_acl_match_burst(const flat_rule_table_t    *tbl,
                           const acl_key_t * const     keys[],
                           const flat_rule_entry_t    *results[],
                           uint32_t                    nb)
{
    for (uint32_t i = 0; i < nb; i++)
        results[i] = flat_acl_match(tbl, keys[i]);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Context accessors  (SDD §4.11)
 * ───────────────────────────────────────────────────────────────────────────── */

struct rte_acl_ctx *acl_get_flat_ctx(void)
{
    return g_flat_ctx;
}

const flat_rule_table_t *acl_get_flat_rule_table(void)
{
    return g_flat_rule_table;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * acl_engine_destroy()  —  SDD §4.11
 * ───────────────────────────────────────────────────────────────────────────── */
void acl_engine_destroy(void)
{
    if (g_flat_ctx) {
        rte_acl_free(g_flat_ctx);
        g_flat_ctx = NULL;
    }
    g_flat_rule_table = NULL;
    g_num_sorted      = 0;
}
