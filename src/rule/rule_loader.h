#ifndef SPIFAST_RULE_LOADER_H
#define SPIFAST_RULE_LOADER_H

#include <stdint.h>
#include "dpdk/dpdk_init.h"   /* SPIFAST_MAX_RULES, SPIFAST_MAX_GROUPS, SPIFAST_MAX_PATH */

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

/* ─────────────────────────────────────────────────────────────────────────────
 * Per-rule representation after parsing and validation  (SDD §3.2)
 * Compiled into the ACL context by acl_engine_build().
 * ───────────────────────────────────────────────────────────────────────────── */
#define SPIFAST_RULE_NAME_LEN   64
#define SPIFAST_GROUP_NAME_LEN  64

typedef struct {
    char          rule_name[SPIFAST_RULE_NAME_LEN];
    char          group_name[SPIFAST_GROUP_NAME_LEN];

    /* Five-tuple match conditions */
    uint32_t      src_ip;           /* network address (host addr if prefix=32) */
    uint32_t      src_prefix_len;   /* CIDR prefix length [0..32]; 0 = wildcard */
    uint32_t      dst_ip;
    uint32_t      dst_prefix_len;
    uint16_t      src_port_lo;      /* port range low  bound; 0     if wildcard */
    uint16_t      src_port_hi;      /* port range high bound; 65535 if wildcard */
    uint16_t      dst_port_lo;
    uint16_t      dst_port_hi;
    proto_match_t protocol;

    uint32_t      precedence;       /* from group declaration; lower = higher priority */
    uint32_t      group_id;         /* index into filter_group_table */
} spi_rule_t;

/* ─────────────────────────────────────────────────────────────────────────────
 * Filter group table  (SDD §3.3)
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    char           name[SPIFAST_GROUP_NAME_LEN];
    group_action_t action;
    uint32_t       precedence;  /* smallest precedence value among rules in group */
    uint32_t       group_id;    /* index in table; also used as ACL userdata - 1  */
} filter_group_t;

typedef struct {
    filter_group_t groups[SPIFAST_MAX_GROUPS];
    uint32_t       num_groups;
} filter_group_table_t;

/* ─────────────────────────────────────────────────────────────────────────────
 * Public API  (SDD §2.4)
 * ───────────────────────────────────────────────────────────────────────────── */

/* Parse and validate a rule file (steps 1-3 of SDD §5.2).
 * Populates group_table and rules[] without calling acl_engine_build().
 * Useful for unit testing the parsing logic in isolation.
 * Returns 0 on success, -1 on any parse or validation error. */
int rule_loader_parse(const char          *path,
                      filter_group_table_t *group_table,
                      spi_rule_t           rules[],
                      uint32_t            *num_rules);

/* Load, validate and compile rules from path (all 5 steps of SDD §5.2).
 * Populates group_table and rules[]; calls acl_engine_build() on success.
 * Returns 0 on success, -1 on any validation or build error (with logging).
 * Partial rule loads are not permitted (SRS RC-006).  SDD §5.2 */
int rule_loader_load(const char          *path,
                     filter_group_table_t *group_table,
                     spi_rule_t           rules[],
                     uint32_t            *num_rules);

#endif /* SPIFAST_RULE_LOADER_H */
