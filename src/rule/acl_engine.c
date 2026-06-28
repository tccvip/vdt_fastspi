#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>

#include <rte_byteorder.h>  /* rte_be_to_cpu_32 */
#include <rte_acl.h>
#include <rte_errno.h>
#include <rte_common.h>    /* SOCKET_ID_ANY */

#include "acl_engine.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * Internal ACL rule struct
 *
 * Equivalent to RTE_ACL_RULE_DEF(name, NUM_ACL_FIELDS) but named so it can
 * be used as a local variable and cast to (struct rte_acl_rule *) cleanly.
 * ───────────────────────────────────────────────────────────────────────────── */
#define NUM_ACL_FIELDS  5

typedef struct {
    struct rte_acl_rule_data data;
    struct rte_acl_field     field[NUM_ACL_FIELDS];
} spifast_acl_rule_t;

/* ─────────────────────────────────────────────────────────────────────────────
 * ACL field definitions — shared by Stage-1 and Stage-2  (SDD §4.2)
 *
 * Input words (4 bytes each):
 *   word 0 (offset  0): protocol + _pad1  → input_index 0
 *   word 1 (offset  4): src_ip            → input_index 1
 *   word 2 (offset  8): dst_ip            → input_index 2
 *   word 3 (offset 12): src_port+dst_port → input_index 3
 *
 * RANGE fields (src_port, dst_port) must share the same input_index because
 * rte_acl requires port pairs to occupy the same 4-byte word.
 * ───────────────────────────────────────────────────────────────────────────── */
static const struct rte_acl_field_def s_acl_fields[NUM_ACL_FIELDS] = {
    {   /* protocol — bitmask: value & mask; 0xFF = exact, 0x00 = wildcard */
        .type        = RTE_ACL_FIELD_TYPE_BITMASK,
        .size        = sizeof(uint8_t),
        .field_index = 0,
        .input_index = 0,
        .offset      = offsetof(acl_key_t, protocol),
    },
    {   /* src_ip — CIDR prefix match; mask_range = prefix length */
        .type        = RTE_ACL_FIELD_TYPE_MASK,
        .size        = sizeof(uint32_t),
        .field_index = 1,
        .input_index = 1,
        .offset      = offsetof(acl_key_t, src_ip),
    },
    {   /* dst_ip — CIDR prefix match; mask_range = prefix length */
        .type        = RTE_ACL_FIELD_TYPE_MASK,
        .size        = sizeof(uint32_t),
        .field_index = 2,
        .input_index = 2,
        .offset      = offsetof(acl_key_t, dst_ip),
    },
    {   /* src_port — range match; value = lo, mask_range = hi */
        .type        = RTE_ACL_FIELD_TYPE_RANGE,
        .size        = sizeof(uint16_t),
        .field_index = 3,
        .input_index = 3,
        .offset      = offsetof(acl_key_t, src_port),
    },
    {   /* dst_port — range match; same input_index=3 as src_port */
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
static struct rte_acl_ctx  *g_stage1_ctx     = NULL;
static const filter_group_table_t *g_group_table = NULL;
static uint32_t             g_default_gid    = 0;

/* Stage-2 array — updated by Main lcore (lazy build), read by Worker lcores.
 * _Atomic guarantees release/acquire ordering across the store/load pair. */
static struct rte_acl_ctx *_Atomic g_group_ctx[SPIFAST_MAX_GROUPS];

/* ─────────────────────────────────────────────────────────────────────────────
 * Internal helpers
 * ───────────────────────────────────────────────────────────────────────────── */

/* Fill ACL rule fields from an spi_rule_t.
 *
 * IP byte order: rte_acl applies the prefix mask as a HOST-ORDER bitmask
 * (~0u << (32 - prefix_len)) against the value stored in the rule and the
 * field read from the key buffer — both as little-endian uint32_t on x86.
 * rule_loader stores IPs via inet_aton() → network byte order.
 * Convert to host byte order here so the prefix bits are in the expected
 * positions.  acl_lookup() must apply the same conversion to the key. */
static void fill_rule_fields(spifast_acl_rule_t *ar, const spi_rule_t *r)
{
    /* protocol — bitmask: 0xFF = exact, 0x00 = any */
    if (r->protocol == PROTO_MATCH_ANY) {
        ar->field[0].value.u8      = 0;
        ar->field[0].mask_range.u8 = 0x00;
    } else {
        ar->field[0].value.u8      = (uint8_t)r->protocol;
        ar->field[0].mask_range.u8 = 0xFF;
    }

    /* src_ip — CIDR; convert NBO → HBO so prefix mask works in host order */
    ar->field[1].value.u32      = rte_be_to_cpu_32(r->src_ip);
    ar->field[1].mask_range.u32 = r->src_prefix_len;

    /* dst_ip — CIDR; same conversion */
    ar->field[2].value.u32      = rte_be_to_cpu_32(r->dst_ip);
    ar->field[2].mask_range.u32 = r->dst_prefix_len;

    /* src_port — range [lo, hi]; already in host byte order */
    ar->field[3].value.u16      = r->src_port_lo;
    ar->field[3].mask_range.u16 = r->src_port_hi;

    /* dst_port — range [lo, hi]; already in host byte order */
    ar->field[4].value.u16      = r->dst_port_lo;
    ar->field[4].mask_range.u16 = r->dst_port_hi;
}

/* Fill ACL rule fields as a fully wildcard entry (matches all packets). */
static void fill_wildcard_fields(spifast_acl_rule_t *ar)
{
    ar->field[0].value.u8       = 0;  ar->field[0].mask_range.u8  = 0x00;
    ar->field[1].value.u32      = 0;  ar->field[1].mask_range.u32 = 0;
    ar->field[2].value.u32      = 0;  ar->field[2].mask_range.u32 = 0;
    ar->field[3].value.u16      = 0;  ar->field[3].mask_range.u16 = 65535;
    ar->field[4].value.u16      = 0;  ar->field[4].mask_range.u16 = 65535;
}

/* Compile a context — same rte_acl_config for Stage-1 and Stage-2. */
static int build_ctx(struct rte_acl_ctx *ctx)
{
    struct rte_acl_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.num_categories = 1;
    cfg.num_fields     = NUM_ACL_FIELDS;
    memcpy(cfg.defs, s_acl_fields, sizeof(s_acl_fields));

    if (rte_acl_build(ctx, &cfg) != 0) {
        fprintf(stderr,
                "[SPIFAST ERROR] acl_engine: rte_acl_build failed: %s\n",
                rte_strerror(rte_errno));
        return -1;
    }
    return 0;
}

/* Find the index of the group with the highest precedence value (DEFAULT). */
static uint32_t find_default_group(const filter_group_table_t *tbl)
{
    uint32_t max_prec = 0, idx = 0;
    for (uint32_t i = 0; i < tbl->num_groups; i++) {
        if (tbl->groups[i].precedence > max_prec) {
            max_prec = tbl->groups[i].precedence;
            idx      = i;
        }
    }
    return idx;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * acl_engine_build_stage1()  —  SDD §4.3
 *
 * Adds one representative rule per group to the Stage-1 context:
 *   • Non-DEFAULT groups only — first rule found for that group.
 *   • DEFAULT group is deliberately omitted.
 *
 * Why DEFAULT is excluded:
 *   rte_acl picks the rule with the HIGHEST integer priority when multiple rules
 *   match the same packet.  Priority = raw group precedence value.  DEFAULT has
 *   the largest precedence (e.g., 999), so if we added its wildcard, DEFAULT
 *   would outrank every specific rule and every packet would land in DEFAULT.
 *
 *   Instead, acl_lookup() maps r1==0 (no Stage-1 match) to g_default_gid.
 *   This gives the same result — unmatched packets go to DEFAULT — without
 *   the wildcard competing against specific rules.
 * ───────────────────────────────────────────────────────────────────────────── */
int acl_engine_build_stage1(const spi_rule_t          *rules,
                             uint32_t                   num_rules,
                             const filter_group_table_t *group_table)
{
    uint32_t default_gid = find_default_group(group_table);

    struct rte_acl_param param = {
        .name        = "spifast_stage1",
        .socket_id   = SOCKET_ID_ANY,
        .rule_size   = sizeof(spifast_acl_rule_t),
        .max_rule_num = SPIFAST_MAX_GROUPS,
    };

    struct rte_acl_ctx *ctx = rte_acl_create(&param);
    if (!ctx) {
        fprintf(stderr,
                "[SPIFAST ERROR] acl_engine: rte_acl_create(stage1) failed: %s\n",
                rte_strerror(rte_errno));
        return -1;
    }

    /* One entry per group: track which groups have been added. */
    uint8_t added[SPIFAST_MAX_GROUPS];
    memset(added, 0, sizeof(added));

    for (uint32_t i = 0; i < num_rules && i < UINT32_MAX; i++) {
        uint32_t gid = rules[i].group_id;
        if (gid >= SPIFAST_MAX_GROUPS || added[gid])
            continue;
        added[gid] = 1;

        /* DEFAULT excluded — see function comment. acl_lookup r1==0 handles it. */
        if (gid == default_gid)
            continue;

        spifast_acl_rule_t ar;
        memset(&ar, 0, sizeof(ar));
        ar.data.userdata      = gid + 1;   /* 0 reserved for no-match */
        ar.data.priority      = group_table->groups[gid].precedence;
        ar.data.category_mask = 1;
        fill_rule_fields(&ar, &rules[i]);

        printf("[DBG stage1] gid=%-2u name=%-12s prio=0x%08x user=%u "
               "proto=%u/0x%02x dst_ip=0x%08x plen=%-2u "
               "sport=[%u-%u] dport=[%u-%u]\n",
               gid, group_table->groups[gid].name,
               ar.data.priority, ar.data.userdata,
               ar.field[0].value.u8, ar.field[0].mask_range.u8,
               ar.field[2].value.u32, ar.field[2].mask_range.u32,
               ar.field[3].value.u16, ar.field[3].mask_range.u16,
               ar.field[4].value.u16, ar.field[4].mask_range.u16);

        if (rte_acl_add_rules(ctx, (struct rte_acl_rule *)&ar, 1) != 0) {
            fprintf(stderr,
                    "[SPIFAST ERROR] acl_engine: rte_acl_add_rules(stage1, gid=%u)"
                    " failed: %s\n", gid, rte_strerror(rte_errno));
            rte_acl_free(ctx);
            return -1;
        }
    }

    if (build_ctx(ctx) != 0) {
        rte_acl_free(ctx);
        return -1;
    }

    g_stage1_ctx  = ctx;
    g_group_table = group_table;
    g_default_gid = default_gid;
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * acl_engine_init_stage2()  —  SDD §4.3
 *
 * Initialise all per-group Stage-2 contexts to NULL (lazy build).
 * Must be called after acl_engine_build_stage1().
 * ───────────────────────────────────────────────────────────────────────────── */
void acl_engine_init_stage2(void)
{
    for (uint32_t i = 0; i < SPIFAST_MAX_GROUPS; i++)
        atomic_init(&g_group_ctx[i], NULL);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * acl_engine_build_group()  —  SDD §4.3
 *
 * Builds the Stage-2 per-group context for group_id.  Adds every rule that
 * belongs to this group, plus a wildcard catch-all at priority=0 so Stage-2
 * always returns non-zero (group_id+1) regardless of which specific filter
 * matches (or doesn't).
 *
 * Atomically publishes the finished context so Worker lcores see it on their
 * next ACQUIRE load without needing a separate synchronisation barrier.
 *
 * Called from Main lcore (lazy, on first group hit) — never on data path.
 * ───────────────────────────────────────────────────────────────────────────── */
int acl_engine_build_group(uint32_t                    group_id,
                            const spi_rule_t           *rules,
                            uint32_t                    num_rules,
                            const filter_group_table_t *group_table)
{
    if (group_id >= SPIFAST_MAX_GROUPS ||
        group_id >= group_table->num_groups) {
        fprintf(stderr,
                "[SPIFAST ERROR] acl_engine: build_group: invalid group_id %u"
                " (num_groups=%u)\n", group_id, group_table->num_groups);
        return -1;
    }

    char name[32];
    snprintf(name, sizeof(name), "spifast_group_%u", group_id);

    struct rte_acl_param param = {
        .name        = name,
        .socket_id   = SOCKET_ID_ANY,
        .rule_size   = sizeof(spifast_acl_rule_t),
        /* +1 for the wildcard catch-all */
        .max_rule_num = SPIFAST_MAX_FILTERS_PER_GROUP + 1,
    };

    struct rte_acl_ctx *ctx = rte_acl_create(&param);
    if (!ctx) {
        fprintf(stderr,
                "[SPIFAST ERROR] acl_engine: rte_acl_create(group_%u) failed: %s\n",
                group_id, rte_strerror(rte_errno));
        return -1;
    }

    /* Add every rule belonging to this group. */
    for (uint32_t i = 0; i < num_rules; i++) {
        if (rules[i].group_id != group_id)
            continue;

        spifast_acl_rule_t ar;
        memset(&ar, 0, sizeof(ar));
        ar.data.userdata      = group_id + 1;
        ar.data.priority      = rules[i].precedence;
        ar.data.category_mask = 1;
        fill_rule_fields(&ar, &rules[i]);

        printf("[DBG stage2 gid=%u] prio=0x%08x user=%u "
               "proto=%u/0x%02x dst_ip=0x%08x plen=%u "
               "sport=[%u-%u] dport=[%u-%u]\n",
               group_id, ar.data.priority, ar.data.userdata,
               ar.field[0].value.u8, ar.field[0].mask_range.u8,
               ar.field[2].value.u32, ar.field[2].mask_range.u32,
               ar.field[3].value.u16, ar.field[3].mask_range.u16,
               ar.field[4].value.u16, ar.field[4].mask_range.u16);

        if (rte_acl_add_rules(ctx, (struct rte_acl_rule *)&ar, 1) != 0) {
            fprintf(stderr,
                    "[SPIFAST ERROR] acl_engine: rte_acl_add_rules(group_%u)"
                    " failed: %s\n", group_id, rte_strerror(rte_errno));
            rte_acl_free(ctx);
            return -1;
        }
    }

    /* Wildcard catch-all at priority=0 — always wins as the last resort,
     * ensuring Stage-2 returns non-zero even if no specific filter matches. */
    {
        spifast_acl_rule_t wc;
        memset(&wc, 0, sizeof(wc));
        wc.data.userdata = group_id + 1;
        wc.data.priority = 1;   /* lowest possible */
        wc.data.category_mask = 1;
        fill_wildcard_fields(&wc);

        if (rte_acl_add_rules(ctx, (struct rte_acl_rule *)&wc, 1) != 0) {
            fprintf(stderr,
                    "[SPIFAST ERROR] acl_engine: rte_acl_add_rules(group_%u"
                    " wildcard) failed: %s\n", group_id, rte_strerror(rte_errno));
            rte_acl_free(ctx);
            return -1;
        }
    }

    if (build_ctx(ctx) != 0) {
        rte_acl_free(ctx);
        return -1;
    }

    /* Publish — RELEASE ordering ensures Worker sees fully-compiled ctx. */
    atomic_store_explicit(&g_group_ctx[group_id], ctx, memory_order_release);
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * acl_engine_build()  —  convenience wrapper  (SDD §4.3)
 *
 * Called by rule_loader_load() after all rules are validated.
 * Executes Stage-1 build + Stage-2 lazy init.
 * ───────────────────────────────────────────────────────────────────────────── */
int acl_engine_build(const spi_rule_t          *rules,
                     uint32_t                   num_rules,
                     const filter_group_table_t *group_table)
{
    if (acl_engine_build_stage1(rules, num_rules, group_table) != 0)
        return -1;
    acl_engine_init_stage2();
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * acl_lookup()  —  SDD §4.4
 *
 * Two-stage per-packet lookup:
 *   Stage-1 → group_id  (rte_acl_classify on stage1_ctx)
 *   Stage-2 → action    (rte_acl_classify on group_ctx[group_id], if built)
 *
 * Falls back to the DEFAULT group when Stage-1 returns no match (userdata=0)
 * or Stage-2 context is not yet built (lazy init pending).
 *
 * No allocation, no locking — safe on the Worker lcore hot path.
 * ───────────────────────────────────────────────────────────────────────────── */
acl_result_t acl_lookup(const pkt_meta_t *meta)
{
    /* Safe default: return DEFAULT group action. */
    acl_result_t res = {
        .group_id = g_default_gid,
        .action   = (g_group_table != NULL)
                    ? g_group_table->groups[g_default_gid].action
                    : ACTION_DROP,
        .rule_id  = g_default_gid,
    };

    if (g_stage1_ctx == NULL || g_group_table == NULL)
        return res;

    acl_key_t key;
    memset(&key, 0, sizeof(key));
    key.protocol = meta->protocol;
    key.src_ip   = meta->src_ip;   /* NBO → HBO (match fill_rule_fields) */
    key.dst_ip   = meta->dst_ip;   /* NBO → HBO */
    key.src_port = meta->src_port;
    key.dst_port = meta->dst_port;

    const uint8_t *kp[1] = { (const uint8_t *)&key };
    uint32_t r1 = 0;

    printf("[DBG lookup] proto=%u src_ip=0x%08x dst_ip=0x%08x sport=%u dport=%u\n",
           key.protocol, key.src_ip, key.dst_ip, key.src_port, key.dst_port);

    /* Stage-1: identify group */
    rte_acl_classify(g_stage1_ctx, kp, &r1, 1, 1);

    uint32_t gid = (r1 == 0) ? g_default_gid : (r1 - 1);

    printf("[DBG stage1 result] r1=%u -> gid=%u (%s)\n",
           r1, gid,
           (gid < g_group_table->num_groups)
               ? g_group_table->groups[gid].name : "?");

    /* Stage-2: confirm and determine action (lazy build via atomic load) */
    struct rte_acl_ctx *g2 =
        atomic_load_explicit(&g_group_ctx[gid], memory_order_acquire);

    if (g2 != NULL) {
        uint32_t r2 = 0;
        rte_acl_classify(g2, kp, &r2, 1, 1);
        if (r2 != 0)
            gid = r2 - 1;
    }

    res.group_id = gid;
    res.action   = g_group_table->groups[gid].action;
    res.rule_id  = gid;
    return res;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Context accessors for Worker lcore  (SDD §2.6)
 * ───────────────────────────────────────────────────────────────────────────── */

struct rte_acl_ctx *acl_get_stage1_ctx(void)
{
    return g_stage1_ctx;
}

struct rte_acl_ctx *acl_get_group_ctx(uint32_t group_id)
{
    if (group_id >= SPIFAST_MAX_GROUPS)
        return NULL;
    return atomic_load_explicit(&g_group_ctx[group_id], memory_order_acquire);
}

uint32_t acl_get_default_group_id(void)
{
    return g_default_gid;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * acl_engine_destroy()  —  ordered shutdown  (SDD §9.2)
 *
 * Frees Stage-1 and all built Stage-2 contexts.  Must be called after all
 * Worker lcores have exited so no classify() calls are in flight.
 * ───────────────────────────────────────────────────────────────────────────── */
void acl_engine_destroy(void)
{
    if (g_stage1_ctx) {
        rte_acl_free(g_stage1_ctx);
        g_stage1_ctx = NULL;
    }

    for (uint32_t i = 0; i < SPIFAST_MAX_GROUPS; i++) {
        struct rte_acl_ctx *ctx =
            atomic_load_explicit(&g_group_ctx[i], memory_order_relaxed);
        if (ctx) {
            rte_acl_free(ctx);
            atomic_store_explicit(&g_group_ctx[i], NULL, memory_order_relaxed);
        }
    }

    g_group_table = NULL;
}
