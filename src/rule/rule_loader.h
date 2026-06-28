#ifndef SPIFAST_RULE_LOADER_H
#define SPIFAST_RULE_LOADER_H

#include <stdint.h>
#include "dpdk/dpdk_init.h"   /* SPIFAST_MAX_RULES, SPIFAST_MAX_GROUPS */
#include "include/config.h"   /* match_mode_t */

/* ─────────────────────────────────────────────────────────────────────────────
 * Enumerations  (SDD §3.2, §3.3)
 * ───────────────────────────────────────────────────────────────────────────── */
typedef enum {
    PROTO_MATCH_ANY = 0,    /* wildcard — matches TCP and UDP */
    PROTO_MATCH_TCP = 6,
    PROTO_MATCH_UDP = 17
} proto_match_t;

typedef enum {
    ACTION_FORWARD = 0,
    ACTION_DROP    = 1
} group_action_t;

#define SPIFAST_RULE_NAME_LEN   64
#define SPIFAST_GROUP_NAME_LEN  64

/* ─────────────────────────────────────────────────────────────────────────────
 * Flat rule entry  (SDD §3.3, §4.2.1)
 *
 * One entry per rule in the config file.  Action from the group declaration is
 * embedded directly — no separate group table lookup required at runtime.
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    /* Identifiers — used for logging and stats only */
    char           rule_name[SPIFAST_RULE_NAME_LEN];
    char           group_name[SPIFAST_GROUP_NAME_LEN];
    uint32_t       group_idx;       /* index into flat_rule_table.group_names[] */

    /* Five-tuple match conditions */
    uint32_t       src_ip;          /* network byte order */
    uint8_t        src_prefix_len;  /* CIDR prefix [0-32]; 0 = wildcard */
    uint32_t       dst_ip;
    uint8_t        dst_prefix_len;
    uint16_t       src_port_lo;     /* range lo; 0 if wildcard */
    uint16_t       src_port_hi;     /* range hi; 65535 if wildcard */
    uint16_t       dst_port_lo;
    uint16_t       dst_port_hi;
    uint8_t        protocol;        /* IPPROTO_TCP(6), IPPROTO_UDP(17), 0=any */

    /* Embedded action — no runtime group-table lookup needed */
    group_action_t action;          /* ACTION_FORWARD or ACTION_DROP */

    /* Ordering metadata — consumed by acl_engine_build() */
    uint32_t       precedence;      /* from group declaration; higher = higher priority */
    uint32_t       file_order;      /* 0-based index in file; ACL userdata = file_order+1 */
} flat_rule_entry_t;

/* ─────────────────────────────────────────────────────────────────────────────
 * Flat rule table  (SDD §3.3, §4.2.2)
 *
 * rules[] is indexed by file_order.  Populated once at startup by
 * rule_loader; read-only after that.  Lives in BSS (static allocation).
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    flat_rule_entry_t rules[SPIFAST_MAX_RULES]; /* indexed by file_order        */
    uint32_t          num_rules;

    /* Group name table — for stats/logging only, not used for matching */
    char     group_names[SPIFAST_MAX_GROUPS][SPIFAST_GROUP_NAME_LEN];
    uint32_t num_groups;
} flat_rule_table_t;

/* ─────────────────────────────────────────────────────────────────────────────
 * Public API  (SDD §2.4, §5.2)
 * ───────────────────────────────────────────────────────────────────────────── */

/* Parse and validate a rule file (Steps 1-3 of SDD §5.2).
 * Populates *out without calling acl_engine_build().
 * Useful for unit testing the parsing logic in isolation.
 * Returns 0 on success, -1 on any parse or validation error. */
int rule_loader_parse(const char      *path,
                      flat_rule_table_t *out);

/* Load, validate and compile rules (all Steps of SDD §5.2).
 * Populates *out; calls acl_engine_build(out, mode) on success.
 * Returns 0 on success, -1 on any validation or build error.
 * Partial rule loads are not permitted (SRS RC-006). */
int rule_loader_load(const char      *path,
                     match_mode_t     mode,
                     flat_rule_table_t *out);

#endif /* SPIFAST_RULE_LOADER_H */
