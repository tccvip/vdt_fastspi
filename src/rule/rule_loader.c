#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>   /* inet_aton, struct in_addr */

#include "rule_loader.h"
#include "acl_engine.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * Internal constants
 * ───────────────────────────────────────────────────────────────────────────── */
#define MAX_LINE_LEN  512

/* ─────────────────────────────────────────────────────────────────────────────
 * String utilities
 * ───────────────────────────────────────────────────────────────────────────── */

static void trim(char *s)
{
    /* strip leading whitespace */
    size_t start = 0;
    while (s[start] && isspace((unsigned char)s[start]))
        start++;
    if (start)
        memmove(s, s + start, strlen(s) - start + 1);

    /* strip trailing whitespace */
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1]))
        s[--len] = '\0';
}

/* True if every character is in [a-zA-Z0-9_] and string is non-empty. */
static int is_valid_name(const char *s)
{
    if (!s || *s == '\0')
        return 0;
    for (; *s; s++)
        if (!isalnum((unsigned char)*s) && *s != '_')
            return 0;
    return 1;
}

/* Return group_id if name is in tbl, else -1. */
static int find_group(const char *name, const filter_group_table_t *tbl)
{
    for (uint32_t i = 0; i < tbl->num_groups; i++)
        if (strcmp(tbl->groups[i].name, name) == 0)
            return (int)i;
    return -1;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * parse_ip_condition()  —  SDD §5.1, §5.3
 *
 * token: trimmed field value from the rule CSV.
 * is_src: 1 for the src-IP position (field[3]), 0 for dst-IP (field[4]).
 *
 * Accepted forms:
 *   any                  → ip=0, prefix_len=0    (matches all)
 *   src_prefix=A.B.C.D/N → ip=network, prefix_len=N   (is_src must be 1)
 *   src_address=A.B.C.D  → ip=host,    prefix_len=32  (is_src must be 1)
 *   dst_prefix=A.B.C.D/N → ip=network, prefix_len=N   (is_src must be 0)
 *   dst_address=A.B.C.D  → ip=host,    prefix_len=32  (is_src must be 0)
 *
 * Returns 0 on success, -1 on any validation error.
 * ───────────────────────────────────────────────────────────────────────────── */
static int parse_ip_condition(const char *token, int is_src,
                               uint32_t *ip_out, uint32_t *prefix_out)
{
    if (strcmp(token, "any") == 0) {
        *ip_out     = 0;
        *prefix_out = 0;
        return 0;
    }

    const char *pfx_kw  = is_src ? "src_prefix="  : "dst_prefix=";
    const char *addr_kw = is_src ? "src_address=" : "dst_address=";
    const char *alt_pfx_kw  = is_src ? "dst_prefix="  : "src_prefix=";
    const char *alt_addr_kw = is_src ? "dst_address=" : "src_address=";

    /* Reject the wrong-direction keyword explicitly */
    if (strncmp(token, alt_pfx_kw,  strlen(alt_pfx_kw))  == 0 ||
        strncmp(token, alt_addr_kw, strlen(alt_addr_kw)) == 0) {
        return -1;
    }

    /* A.B.C.D/N — CIDR prefix */
    if (strncmp(token, pfx_kw, strlen(pfx_kw)) == 0) {
        const char *addr_part = token + strlen(pfx_kw);
        const char *slash     = strchr(addr_part, '/');
        if (!slash)
            return -1;

        char ip_str[INET_ADDRSTRLEN];
        size_t ip_len = (size_t)(slash - addr_part);
        if (ip_len == 0 || ip_len >= sizeof(ip_str))
            return -1;
        memcpy(ip_str, addr_part, ip_len);
        ip_str[ip_len] = '\0';

        /* Validate each octet explicitly (inet_aton is lenient with octal etc.) */
        int a, b, c, d, n;
        if (sscanf(ip_str, "%d.%d.%d.%d%n", &a, &b, &c, &d, &n) != 4
            || ip_str[n] != '\0'
            || a < 0 || a > 255 || b < 0 || b > 255
            || c < 0 || c > 255 || d < 0 || d > 255)
            return -1;

        struct in_addr inaddr;
        if (inet_aton(ip_str, &inaddr) == 0)
            return -1;

        /* prefix length */
        char *end;
        long pfx = strtol(slash + 1, &end, 10);
        if (end == slash + 1 || *end != '\0' || pfx < 0 || pfx > 32)
            return -1;

        *ip_out     = inaddr.s_addr;   /* network byte order */
        *prefix_out = (uint32_t)pfx;
        return 0;
    }

    /* A.B.C.D — exact host (/32) */
    if (strncmp(token, addr_kw, strlen(addr_kw)) == 0) {
        const char *addr_part = token + strlen(addr_kw);
        int a, b, c, d, n;
        if (sscanf(addr_part, "%d.%d.%d.%d%n", &a, &b, &c, &d, &n) != 4
            || addr_part[n] != '\0'
            || a < 0 || a > 255 || b < 0 || b > 255
            || c < 0 || c > 255 || d < 0 || d > 255)
            return -1;

        struct in_addr inaddr;
        if (inet_aton(addr_part, &inaddr) == 0)
            return -1;

        *ip_out     = inaddr.s_addr;
        *prefix_out = 32;
        return 0;
    }

    return -1;   /* unrecognised keyword */
}

/* ─────────────────────────────────────────────────────────────────────────────
 * parse_port_condition()  —  SDD §5.1, §5.3
 *
 * Accepted forms:
 *   any    → [0, 65535]
 *   N      → [N, N]   where N ∈ [0, 65535]
 *   lo-hi  → [lo, hi] where lo ≤ hi, both ∈ [0, 65535]
 *
 * Returns 0 on success, -1 on error.
 * ───────────────────────────────────────────────────────────────────────────── */
static int parse_port_condition(const char *token, uint16_t *lo, uint16_t *hi)
{
    if (strcmp(token, "any") == 0) {
        *lo = 0;
        *hi = 65535;
        return 0;
    }

    const char *dash = strchr(token, '-');
    if (dash) {
        /* range: lo-hi */
        char *end;
        long lv = strtol(token, &end, 10);
        if (end != dash || lv < 0 || lv > 65535)
            return -1;
        long hv = strtol(dash + 1, &end, 10);
        if (*end != '\0' || hv < 0 || hv > 65535 || lv > hv)
            return -1;
        *lo = (uint16_t)lv;
        *hi = (uint16_t)hv;
        return 0;
    }

    /* exact port */
    char *end;
    long v = strtol(token, &end, 10);
    if (*end != '\0' || v < 0 || v > 65535)
        return -1;
    *lo = *hi = (uint16_t)v;
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * parse_group_declaration()  —  SDD §5.1, §5.2 Step 2
 *
 * Parse: [group: <name>]  precedence=<N>  action=<FORWARD|DROP>
 * Validate and append to tbl.
 * ───────────────────────────────────────────────────────────────────────────── */
static int parse_group_declaration(const char *line, int line_no,
                                    filter_group_table_t *tbl)
{
    if (tbl->num_groups >= SPIFAST_MAX_GROUPS) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: line %d: group count exceeds"
                " maximum (%d)\n", line_no, SPIFAST_MAX_GROUPS);
        return -1;
    }

    /* ── Extract name between "[group:" and "]" ── */
    const char *name_start = line + 7;   /* skip "[group:" */
    while (*name_start == ' ') name_start++;

    const char *bracket = strchr(name_start, ']');
    if (!bracket) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: line %d: missing ']' in"
                " group declaration\n", line_no);
        return -1;
    }

    /* trim trailing spaces before ']' */
    const char *name_end = bracket - 1;
    while (name_end >= name_start && *name_end == ' ')
        name_end--;
    size_t name_len = (size_t)(name_end - name_start + 1);

    if (name_len == 0 || name_len >= SPIFAST_GROUP_NAME_LEN) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: line %d: group name empty or"
                " too long (max %d chars)\n",
                line_no, SPIFAST_GROUP_NAME_LEN - 1);
        return -1;
    }

    char name[SPIFAST_GROUP_NAME_LEN];
    memcpy(name, name_start, name_len);
    name[name_len] = '\0';

    if (!is_valid_name(name)) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: line %d: group name '%s'"
                " contains invalid characters (allowed: [a-zA-Z0-9_])\n",
                line_no, name);
        return -1;
    }

    if (find_group(name, tbl) >= 0) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: line %d: duplicate group"
                " name '%s'\n", line_no, name);
        return -1;
    }

    /* ── Parse "precedence=N" after ']' ── */
    const char *rest = bracket + 1;

    const char *p = strstr(rest, "precedence=");
    if (!p) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: line %d: missing 'precedence='"
                " in group declaration\n", line_no);
        return -1;
    }
    p += strlen("precedence=");
    char *end;
    long prec = strtol(p, &end, 10);
    if (end == p || prec < 1 || prec > 999) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: line %d: precedence must be"
                " in [1..999]\n", line_no);
        return -1;
    }

    /* ── Parse "action=FORWARD|DROP" after ']' ── */
    const char *a = strstr(rest, "action=");
    if (!a) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: line %d: missing 'action='"
                " in group declaration\n", line_no);
        return -1;
    }
    a += strlen("action=");

    char action_word[16];
    if (sscanf(a, "%15s", action_word) != 1) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: line %d: missing action"
                " value\n", line_no);
        return -1;
    }
    /* normalise to upper case */
    for (char *c = action_word; *c; c++)
        *c = (char)toupper((unsigned char)*c);

    group_action_t action;
    if (strcmp(action_word, "FORWARD") == 0)
        action = ACTION_FORWARD;
    else if (strcmp(action_word, "DROP") == 0)
        action = ACTION_DROP;
    else {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: line %d: unknown action '%s'"
                " (expected FORWARD or DROP)\n", line_no, action_word);
        return -1;
    }

    /* ── Append to table ── */
    filter_group_t *g = &tbl->groups[tbl->num_groups];
    memcpy(g->name, name, name_len + 1);
    g->action     = action;
    g->precedence = (uint32_t)prec;
    g->group_id   = tbl->num_groups;

    tbl->num_groups++;
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * parse_rule_entry()  —  SDD §5.1, §5.2 Step 2
 *
 * Split the 7 comma-separated fields, validate each, resolve group_id,
 * and append a complete spi_rule_t to rules[].
 *
 * filter_count[group_id] is incremented and checked against
 * SPIFAST_MAX_FILTERS_PER_GROUP.
 * ───────────────────────────────────────────────────────────────────────────── */
static int parse_rule_entry(const char *line, int line_no,
                             spi_rule_t rules[], uint32_t *num_rules,
                             const filter_group_table_t *tbl,
                             uint32_t filter_count[])
{
    if (*num_rules >= SPIFAST_MAX_RULES) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: line %d: rule count exceeds"
                " maximum (%d)\n", line_no, SPIFAST_MAX_RULES);
        return -1;
    }

    /* Work on a mutable copy */
    char buf[MAX_LINE_LEN];
    strncpy(buf, line, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    /* Split on ',' into exactly 7 fields */
    char *fields[7];
    int   nf = 0;
    char *tok = buf;
    while (nf < 7) {
        char *comma = strchr(tok, ',');
        if (comma)
            *comma = '\0';
        trim(tok);
        fields[nf++] = tok;
        if (!comma)
            break;
        tok = comma + 1;
    }

    if (nf != 7) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: line %d: expected 7 fields,"
                " got %d\n", line_no, nf);
        return -1;
    }

    /* Field 0: rule_name */
    if (!is_valid_name(fields[0]) ||
        strlen(fields[0]) >= SPIFAST_RULE_NAME_LEN) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: line %d: invalid rule name"
                " '%s' (max %d chars, [a-zA-Z0-9_])\n",
                line_no, fields[0], SPIFAST_RULE_NAME_LEN - 1);
        return -1;
    }

    /* Field 1: group_name — must reference a declared group */
    int gid = find_group(fields[1], tbl);
    if (gid < 0) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: line %d: group '%s' not"
                " declared\n", line_no, fields[1]);
        return -1;
    }

    /* Field 2: protocol */
    char proto_upper[8];
    strncpy(proto_upper, fields[2], sizeof(proto_upper) - 1);
    proto_upper[sizeof(proto_upper) - 1] = '\0';
    for (char *c = proto_upper; *c; c++)
        *c = (char)toupper((unsigned char)*c);

    proto_match_t protocol;
    if (strcmp(proto_upper, "ANY") == 0)
        protocol = PROTO_MATCH_ANY;
    else if (strcmp(proto_upper, "TCP") == 0)
        protocol = PROTO_MATCH_TCP;
    else if (strcmp(proto_upper, "UDP") == 0)
        protocol = PROTO_MATCH_UDP;
    else {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: line %d: unknown protocol"
                " '%s' (expected tcp, udp, or any)\n", line_no, fields[2]);
        return -1;
    }

    /* Field 3: src IP condition */
    uint32_t src_ip = 0, src_pfx = 0;
    if (parse_ip_condition(fields[3], 1, &src_ip, &src_pfx) != 0) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: line %d: invalid src IP"
                " condition '%s'\n", line_no, fields[3]);
        return -1;
    }

    /* Field 4: dst IP condition */
    uint32_t dst_ip = 0, dst_pfx = 0;
    if (parse_ip_condition(fields[4], 0, &dst_ip, &dst_pfx) != 0) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: line %d: invalid dst IP"
                " condition '%s'\n", line_no, fields[4]);
        return -1;
    }

    /* Field 5: src port condition */
    uint16_t src_lo = 0, src_hi = 65535;
    if (parse_port_condition(fields[5], &src_lo, &src_hi) != 0) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: line %d: invalid src port"
                " condition '%s'\n", line_no, fields[5]);
        return -1;
    }

    /* Field 6: dst port condition */
    uint16_t dst_lo = 0, dst_hi = 65535;
    if (parse_port_condition(fields[6], &dst_lo, &dst_hi) != 0) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: line %d: invalid dst port"
                " condition '%s'\n", line_no, fields[6]);
        return -1;
    }

    /* Per-group filter count check (SDD §5.2 / SRS FR-019) */
    filter_count[gid]++;
    if (filter_count[gid] > SPIFAST_MAX_FILTERS_PER_GROUP) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: line %d: group '%s' exceeds"
                " max filter count (%d)\n",
                line_no, fields[1], SPIFAST_MAX_FILTERS_PER_GROUP);
        return -1;
    }

    /* Assemble spi_rule_t */
    spi_rule_t *r = &rules[*num_rules];
    memset(r, 0, sizeof(*r));
    strncpy(r->rule_name,  fields[0], SPIFAST_RULE_NAME_LEN - 1);
    strncpy(r->group_name, fields[1], SPIFAST_GROUP_NAME_LEN - 1);
    r->src_ip        = src_ip;
    r->src_prefix_len = src_pfx;
    r->dst_ip        = dst_ip;
    r->dst_prefix_len = dst_pfx;
    r->src_port_lo   = src_lo;
    r->src_port_hi   = src_hi;
    r->dst_port_lo   = dst_lo;
    r->dst_port_hi   = dst_hi;
    r->protocol      = protocol;
    r->precedence    = tbl->groups[gid].precedence;
    r->group_id      = (uint32_t)gid;

    (*num_rules)++;
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * rl_parse_internal()  —  SDD §5.2 Steps 1-3
 *
 * Open file, parse all group declarations and rule entries, run post-parse
 * validation.  Does NOT call acl_engine_build.
 * ───────────────────────────────────────────────────────────────────────────── */
static int rl_parse_internal(const char          *path,
                              filter_group_table_t *tbl,
                              spi_rule_t           rules[],
                              uint32_t            *num_rules)
{
    /* Step 1: open file */
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: cannot open rule file '%s':"
                " %s\n", path, strerror(errno));
        return -1;
    }

    memset(tbl, 0, sizeof(*tbl));
    *num_rules = 0;

    /* Per-group filter counter; 4 KB stack allocation is safe at startup. */
    uint32_t filter_count[SPIFAST_MAX_GROUPS];
    memset(filter_count, 0, sizeof(filter_count));

    /* Step 2: parse each line */
    char line[MAX_LINE_LEN];
    int  line_no = 0;
    int  rc = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_no++;
        trim(line);

        if (line[0] == '\0' || line[0] == '#')
            continue;

        if (strncmp(line, "[group:", 7) == 0) {
            if (parse_group_declaration(line, line_no, tbl) != 0) {
                rc = -1;
                break;
            }
        } else {
            if (parse_rule_entry(line, line_no, rules, num_rules,
                                  tbl, filter_count) != 0) {
                rc = -1;
                break;
            }
        }
    }

    fclose(fp);
    if (rc != 0)
        return -1;

    /* Step 3: post-parse validation */
    if (*num_rules == 0) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: '%s': no rules defined\n", path);
        return -1;
    }

    if (tbl->num_groups == 0) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: '%s': no groups defined\n", path);
        return -1;
    }

    /* Find the DEFAULT group: the group with the numerically highest precedence.
     * It must have action=DROP to provide a catch-all deny. */
    uint32_t max_prec    = 0;
    int      default_idx = -1;
    for (uint32_t i = 0; i < tbl->num_groups; i++) {
        if (tbl->groups[i].precedence > max_prec) {
            max_prec    = tbl->groups[i].precedence;
            default_idx = (int)i;
        }
    }
    if (default_idx < 0 || tbl->groups[default_idx].action != ACTION_DROP) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: '%s': no DEFAULT group found."
                " The group with the highest precedence must have action=DROP"
                " to serve as the catch-all rule.\n", path);
        return -1;
    }

    /* Duplicate rule name check (O(n²); n ≤ SPIFAST_MAX_RULES) */
    for (uint32_t i = 0; i < *num_rules; i++) {
        for (uint32_t j = i + 1; j < *num_rules; j++) {
            if (strcmp(rules[i].rule_name, rules[j].rule_name) == 0) {
                fprintf(stderr,
                        "[SPIFAST ERROR] rule_loader: '%s': duplicate rule"
                        " name '%s'\n", path, rules[i].rule_name);
                return -1;
            }
        }
    }

    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Public API
 * ───────────────────────────────────────────────────────────────────────────── */

/* Steps 1–3: parse + validate; no ACL build.  SDD §5.2 */
int rule_loader_parse(const char          *path,
                      filter_group_table_t *group_table,
                      spi_rule_t           rules[],
                      uint32_t            *num_rules)
{
    return rl_parse_internal(path, group_table, rules, num_rules);
}

/* Steps 1–5: parse + validate + build ACL context.  SDD §5.2 */
int rule_loader_load(const char          *path,
                     filter_group_table_t *group_table,
                     spi_rule_t           rules[],
                     uint32_t            *num_rules)
{
    if (rl_parse_internal(path, group_table, rules, num_rules) != 0)
        return -1;

    /* Step 4: build ACL context */
    if (acl_engine_build(rules, *num_rules, group_table) != 0) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: acl_engine_build failed for"
                " '%s'\n", path);
        return -1;
    }

    return 0;
}
