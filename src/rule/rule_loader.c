#include <stdio.h>
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
 * String utilities (unchanged from previous version)
 * ───────────────────────────────────────────────────────────────────────────── */

static void trim(char *s)
{
    size_t start = 0;
    while (s[start] && isspace((unsigned char)s[start]))
        start++;
    if (start)
        memmove(s, s + start, strlen(s) - start + 1);

    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1]))
        s[--len] = '\0';
}

static int is_valid_name(const char *s)
{
    if (!s || *s == '\0')
        return 0;
    for (; *s; s++)
        if (!isalnum((unsigned char)*s) && *s != '_')
            return 0;
    return 1;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * find_group_idx()
 *
 * Search out->group_names[] for name.  Returns the index [0, num_groups) on
 * match, or -1 if not found.  Called both from group-declaration dedup check
 * and from rule-entry group resolution.
 * ───────────────────────────────────────────────────────────────────────────── */
static int find_group_idx(const char *name, const flat_rule_table_t *tbl)
{
    for (uint32_t i = 0; i < tbl->num_groups; i++)
        if (strcmp(tbl->group_names[i], name) == 0)
            return (int)i;
    return -1;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * parse_ip_condition()  —  SDD §5.1, §5.3
 *
 * Accepted forms (unchanged validation):
 *   any                  → ip=0, prefix_len=0
 *   src_prefix=A.B.C.D/N → ip=network, prefix_len=N   (is_src must be 1)
 *   src_address=A.B.C.D  → ip=host,    prefix_len=32  (is_src must be 1)
 *   dst_prefix=A.B.C.D/N → ip=network, prefix_len=N   (is_src must be 0)
 *   dst_address=A.B.C.D  → ip=host,    prefix_len=32  (is_src must be 0)
 *
 * Returns 0 on success, -1 on error.
 * ───────────────────────────────────────────────────────────────────────────── */
static int parse_ip_condition(const char *token, int is_src,
                               uint32_t *ip_out, uint32_t *prefix_out)
{
    if (strcmp(token, "any") == 0) {
        *ip_out     = 0;
        *prefix_out = 0;
        return 0;
    }

    const char *pfx_kw      = is_src ? "src_prefix="  : "dst_prefix=";
    const char *addr_kw     = is_src ? "src_address=" : "dst_address=";
    const char *alt_pfx_kw  = is_src ? "dst_prefix="  : "src_prefix=";
    const char *alt_addr_kw = is_src ? "dst_address=" : "src_address=";

    if (strncmp(token, alt_pfx_kw,  strlen(alt_pfx_kw))  == 0 ||
        strncmp(token, alt_addr_kw, strlen(alt_addr_kw)) == 0)
        return -1;

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

        int a, b, c, d, n;
        if (sscanf(ip_str, "%d.%d.%d.%d%n", &a, &b, &c, &d, &n) != 4
            || ip_str[n] != '\0'
            || a < 0 || a > 255 || b < 0 || b > 255
            || c < 0 || c > 255 || d < 0 || d > 255)
            return -1;

        struct in_addr inaddr;
        if (inet_aton(ip_str, &inaddr) == 0)
            return -1;

        char *end;
        long pfx = strtol(slash + 1, &end, 10);
        if (end == slash + 1 || *end != '\0' || pfx < 0 || pfx > 32)
            return -1;

        *ip_out     = inaddr.s_addr;
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

    return -1;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * parse_port_condition()  —  SDD §5.1, §5.3
 *
 * Accepted forms (unchanged validation):
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
 *
 * Appends group name to out->group_names[] and records action/precedence in
 * the caller's local_action[]/local_prec[] arrays (indexed parallel to
 * group_names).
 * ───────────────────────────────────────────────────────────────────────────── */
static int parse_group_declaration(const char    *line,
                                    int            line_no,
                                    flat_rule_table_t *out,
                                    group_action_t local_action[],
                                    uint32_t       local_prec[])
{
    if (out->num_groups >= SPIFAST_MAX_GROUPS) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: line %d: group count exceeds"
                " maximum (%d)\n", line_no, SPIFAST_MAX_GROUPS);
        return -1;
    }

    /* Extract name between "[group:" and "]" */
    const char *name_start = line + 7;   /* skip "[group:" */
    while (*name_start == ' ') name_start++;

    const char *bracket = strchr(name_start, ']');
    if (!bracket) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: line %d: missing ']' in"
                " group declaration\n", line_no);
        return -1;
    }

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

    if (find_group_idx(name, out) >= 0) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: line %d: duplicate group"
                " name '%s'\n", line_no, name);
        return -1;
    }

    /* Parse "precedence=N" */
    const char *rest = bracket + 1;
    const char *p    = strstr(rest, "precedence=");
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

    /* Parse "action=FORWARD|DROP" */
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

    /* Commit: append to group name table and record action/precedence */
    uint32_t idx = out->num_groups;
    memcpy(out->group_names[idx], name, name_len + 1);
    local_action[idx] = action;
    local_prec[idx]   = (uint32_t)prec;
    out->num_groups++;
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * parse_rule_entry()  —  SDD §5.1, §5.2 Step 2
 *
 * Split the 7 comma-separated fields, validate each, resolve group_idx,
 * and append a complete flat_rule_entry_t to out->rules[].
 *
 * Action and precedence are embedded directly from the group declaration —
 * no separate filter_group_table lookup needed at runtime.
 * ───────────────────────────────────────────────────────────────────────────── */
static int parse_rule_entry(const char          *line,
                             int                  line_no,
                             flat_rule_table_t   *out,
                             const group_action_t local_action[],
                             const uint32_t       local_prec[])
{
    if (out->num_rules >= SPIFAST_MAX_RULES) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: line %d: rule count exceeds"
                " maximum (%d)\n", line_no, SPIFAST_MAX_RULES);
        return -1;
    }

    char buf[MAX_LINE_LEN];
    strncpy(buf, line, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    /* Split on ',' into exactly 7 fields */
    char *fields[7];
    int   nf  = 0;
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
    int gidx = find_group_idx(fields[1], out);
    if (gidx < 0) {
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

    uint8_t protocol;
    if (strcmp(proto_upper, "ANY") == 0)
        protocol = (uint8_t)PROTO_MATCH_ANY;
    else if (strcmp(proto_upper, "TCP") == 0)
        protocol = (uint8_t)PROTO_MATCH_TCP;
    else if (strcmp(proto_upper, "UDP") == 0)
        protocol = (uint8_t)PROTO_MATCH_UDP;
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

    /* Assemble flat_rule_entry_t with embedded action and precedence */
    flat_rule_entry_t *e = &out->rules[out->num_rules];
    memset(e, 0, sizeof(*e));
    strncpy(e->rule_name,  fields[0], SPIFAST_RULE_NAME_LEN  - 1);
    strncpy(e->group_name, fields[1], SPIFAST_GROUP_NAME_LEN - 1);
    e->group_idx      = (uint32_t)gidx;
    e->src_ip         = src_ip;
    e->src_prefix_len = (uint8_t)src_pfx;
    e->dst_ip         = dst_ip;
    e->dst_prefix_len = (uint8_t)dst_pfx;
    e->src_port_lo    = src_lo;
    e->src_port_hi    = src_hi;
    e->dst_port_lo    = dst_lo;
    e->dst_port_hi    = dst_hi;
    e->protocol       = protocol;
    e->action         = local_action[gidx];   /* embedded from group declaration */
    e->precedence     = local_prec[gidx];     /* embedded from group declaration */
    e->file_order     = out->num_rules;       /* deterministic: 0, 1, 2, ...     */

    out->num_rules++;
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * rl_parse_internal()  —  SDD §5.2 Steps 1-3
 *
 * Open file, parse all group declarations and rule entries, run post-parse
 * validation.  Does NOT call acl_engine_build.
 *
 * local_action[] and local_prec[] are ephemeral parse-time arrays that record
 * per-group action and precedence (indexed parallel to out->group_names[]).
 * They are not exported — consumers derive action from flat_rule_entry_t.action.
 * ───────────────────────────────────────────────────────────────────────────── */
static int rl_parse_internal(const char *path, flat_rule_table_t *out)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: cannot open rule file '%s':"
                " %s\n", path, strerror(errno));
        return -1;
    }

    memset(out, 0, sizeof(*out));

    /* Ephemeral parse-time arrays — action and precedence per group index.
     * 32 KB total; safe on the startup call stack. */
    group_action_t local_action[SPIFAST_MAX_GROUPS];
    uint32_t       local_prec[SPIFAST_MAX_GROUPS];
    memset(local_action, 0, sizeof(local_action));
    memset(local_prec,   0, sizeof(local_prec));

    char line[MAX_LINE_LEN];
    int  line_no = 0;
    int  rc      = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_no++;
        trim(line);

        if (line[0] == '\0' || line[0] == '#')
            continue;

        if (strncmp(line, "[group:", 7) == 0) {
            if (parse_group_declaration(line, line_no, out,
                                         local_action, local_prec) != 0) {
                rc = -1;
                break;
            }
        } else {
            if (parse_rule_entry(line, line_no, out,
                                  local_action, local_prec) != 0) {
                rc = -1;
                break;
            }
        }
    }

    fclose(fp);
    if (rc != 0)
        return -1;

    /* Step 3: post-parse validation */
    if (out->num_rules == 0) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: '%s': no rules defined\n", path);
        return -1;
    }

    if (out->num_groups == 0) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: '%s': no groups defined\n", path);
        return -1;
    }

    /* Verify DEFAULT group: the group with the lowest precedence must be DROP.
     * This is the catch-all group; priority=0 in ACL build (SDD §4.9). */
    uint32_t min_prec    = UINT32_MAX;
    int      default_idx = -1;
    for (uint32_t i = 0; i < out->num_groups; i++) {
        if (local_prec[i] < min_prec) {
            min_prec    = local_prec[i];
            default_idx = (int)i;
        }
    }
    if (default_idx < 0 || local_action[default_idx] != ACTION_DROP) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: '%s': no DEFAULT group found."
                " The group with the lowest precedence must have action=DROP"
                " to serve as the catch-all rule.\n", path);
        return -1;
    }

    /* Duplicate rule name check (O(n²); n ≤ SPIFAST_MAX_RULES) */
    for (uint32_t i = 0; i < out->num_rules; i++) {
        for (uint32_t j = i + 1; j < out->num_rules; j++) {
            if (strcmp(out->rules[i].rule_name, out->rules[j].rule_name) == 0) {
                fprintf(stderr,
                        "[SPIFAST ERROR] rule_loader: '%s': duplicate rule"
                        " name '%s'\n", path, out->rules[i].rule_name);
                return -1;
            }
        }
    }

#ifdef SPIFAST_DEBUG_RULE_DUMP
    fprintf(stderr,
            "[SPIFAST DEBUG] rule_loader: '%s': %u rules, %u groups\n",
            path, out->num_rules, out->num_groups);
    for (uint32_t i = 0; i < out->num_rules; i++) {
        const flat_rule_entry_t *e = &out->rules[i];
        fprintf(stderr,
                "[SPIFAST DEBUG]   [%u] rule=%-32s group=%-24s"
                " group_idx=%u action=%s prec=%u proto=%u\n",
                e->file_order, e->rule_name, e->group_name,
                e->group_idx,
                e->action == ACTION_FORWARD ? "FORWARD" : "DROP",
                e->precedence, e->protocol);
    }
#endif

    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Public API
 * ───────────────────────────────────────────────────────────────────────────── */

int rule_loader_parse(const char *path, flat_rule_table_t *out)
{
    return rl_parse_internal(path, out);
}

int rule_loader_load(const char *path, match_mode_t mode, flat_rule_table_t *out)
{
    if (rl_parse_internal(path, out) != 0)
        return -1;

    if (acl_engine_build(out, mode) != 0) {
        fprintf(stderr,
                "[SPIFAST ERROR] rule_loader: acl_engine_build failed for"
                " '%s'\n", path);
        return -1;
    }

    return 0;
}
