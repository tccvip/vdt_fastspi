/*
 * tests/test_rule_loader.c — unit tests for rule/rule_loader.c
 *
 * Tests use rule_loader_parse() (steps 1-3 only, no ACL build) so they work
 * without EAL init and without a working acl_engine_build() implementation.
 *
 * One test exercises rule_loader_load() to confirm it reaches step 4 and
 * returns -1 because acl_engine_build() is still a stub.
 *
 * Build:  cmake --build build --target test_rule_loader
 * Run:    build/test_rule_loader
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "rule/rule_loader.h"

/* ─── minimal harness ──────────────────────────────────────────────────────── */
static int g_pass = 0;
static int g_fail = 0;

#define EXPECT(cond, msg)                                                      \
    do {                                                                       \
        if (cond) {                                                            \
            printf("  PASS  %s\n", (msg));                                    \
            g_pass++;                                                          \
        } else {                                                               \
            printf("  FAIL  %s  (%s:%d)\n", (msg), __FILE__, __LINE__);      \
            g_fail++;                                                          \
        }                                                                      \
    } while (0)

/* ─── test-file helpers ────────────────────────────────────────────────────── */
static filter_group_table_t g_groups;
static spi_rule_t           g_rules[SPIFAST_MAX_RULES];
static uint32_t             g_num_rules;

static void reset(void)
{
    memset(&g_groups, 0, sizeof(g_groups));
    memset(g_rules,   0, sizeof(g_rules));
    g_num_rules = 0;
}

/* Write content to a temp file; return the path.  Caller must not free. */
static const char *write_tmp(const char *name, const char *content)
{
    static char path[256];
    snprintf(path, sizeof(path), "/tmp/spifast_test_%s", name);
    FILE *fp = fopen(path, "w");
    if (!fp) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }
    fputs(content, fp);
    fclose(fp);
    return path;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 1: reference config from config/spi_rules.conf (abridged)
 * Validates group declarations, rule entries, and DEFAULT detection.
 * ═══════════════════════════════════════════════════════════════════════════ */
static void test_valid_config(void)
{
    puts("[ test_valid_config ]");

    const char *content =
        "# SPIFast rule file — abridged reference config\n"
        "\n"
        "[group: fg_l34_facebook]     precedence=100  action=FORWARD\n"
        "[group: fg_l34_youtube]      precedence=200  action=FORWARD\n"
        "[group: DEFAULT]             precedence=999  action=DROP\n"
        "\n"
        "f_l34_facebook_1, fg_l34_facebook, any, any, dst_prefix=31.13.64.0/18, any, any\n"
        "f_l34_youtube_1,  fg_l34_youtube,  tcp, any, dst_prefix=142.250.0.0/15, any, 443\n"
        "f_l34_default_1,  DEFAULT,          any, any, any, any, any\n";

    const char *path = write_tmp("valid.conf", content);
    reset();
    int rc = rule_loader_parse(path, &g_groups, g_rules, &g_num_rules);

    EXPECT(rc == 0,                 "parse succeeds");
    EXPECT(g_groups.num_groups == 3, "3 groups parsed");
    EXPECT(g_num_rules == 3,        "3 rules parsed");

    /* Group 0: fg_l34_facebook */
    EXPECT(strcmp(g_groups.groups[0].name, "fg_l34_facebook") == 0,
           "group[0].name = fg_l34_facebook");
    EXPECT(g_groups.groups[0].action     == ACTION_FORWARD,
           "group[0].action = FORWARD");
    EXPECT(g_groups.groups[0].precedence == 100,
           "group[0].precedence = 100");
    EXPECT(g_groups.groups[0].group_id   == 0,
           "group[0].group_id = 0");

    /* Group 2: DEFAULT */
    EXPECT(strcmp(g_groups.groups[2].name, "DEFAULT") == 0,
           "group[2].name = DEFAULT");
    EXPECT(g_groups.groups[2].action     == ACTION_DROP,
           "group[2].action = DROP");
    EXPECT(g_groups.groups[2].precedence == 999,
           "group[2].precedence = 999");

    /* Rule 0: f_l34_facebook_1 */
    EXPECT(strcmp(g_rules[0].rule_name, "f_l34_facebook_1") == 0,
           "rules[0].rule_name = f_l34_facebook_1");
    EXPECT(g_rules[0].group_id       == 0,          "rules[0].group_id = 0");
    EXPECT(g_rules[0].protocol       == PROTO_MATCH_ANY, "rules[0].proto = ANY");
    EXPECT(g_rules[0].src_ip         == 0,          "rules[0].src_ip = wildcard");
    EXPECT(g_rules[0].src_prefix_len == 0,          "rules[0].src_pfx = 0");
    EXPECT(g_rules[0].src_port_lo    == 0,          "rules[0].src_port_lo = 0");
    EXPECT(g_rules[0].src_port_hi    == 65535,      "rules[0].src_port_hi = 65535");

    /* dst = 31.13.64.0/18 */
    struct in_addr fb_net;
    inet_aton("31.13.64.0", &fb_net);
    EXPECT(g_rules[0].dst_ip         == fb_net.s_addr,
           "rules[0].dst_ip = 31.13.64.0");
    EXPECT(g_rules[0].dst_prefix_len == 18,
           "rules[0].dst_pfx = 18");

    /* Rule 1: f_l34_youtube_1 — TCP, dst port 443 */
    EXPECT(g_rules[1].protocol    == PROTO_MATCH_TCP,  "rules[1].proto = TCP");
    EXPECT(g_rules[1].dst_port_lo == 443,              "rules[1].dst_port_lo = 443");
    EXPECT(g_rules[1].dst_port_hi == 443,              "rules[1].dst_port_hi = 443");
    EXPECT(g_rules[1].group_id    == 1,                "rules[1].group_id = 1 (youtube)");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 2: IP condition variants — src_prefix, src_address, dst_address
 * ═══════════════════════════════════════════════════════════════════════════ */
static void test_ip_variants(void)
{
    puts("[ test_ip_variants ]");

    const char *content =
        "[group: g1]   precedence=10   action=FORWARD\n"
        "[group: DEFAULT]  precedence=999  action=DROP\n"
        "r_src_pfx,   g1, tcp, src_prefix=10.0.0.0/8, any, any, any\n"
        "r_src_addr,  g1, udp, src_address=192.168.1.1, any, 53, any\n"
        "r_dst_addr,  g1, tcp, any, dst_address=8.8.8.8, any, 443\n"
        "r_default,   DEFAULT, any, any, any, any, any\n";

    const char *path = write_tmp("ip_variants.conf", content);
    reset();
    int rc = rule_loader_parse(path, &g_groups, g_rules, &g_num_rules);

    EXPECT(rc == 0,        "parse succeeds");
    EXPECT(g_num_rules == 4, "4 rules");

    /* r_src_pfx: src=10.0.0.0/8 */
    struct in_addr net10;
    inet_aton("10.0.0.0", &net10);
    EXPECT(g_rules[0].src_ip         == net10.s_addr, "r_src_pfx: src_ip = 10.0.0.0");
    EXPECT(g_rules[0].src_prefix_len == 8,             "r_src_pfx: src_pfx = 8");
    EXPECT(g_rules[0].protocol       == PROTO_MATCH_TCP, "r_src_pfx: proto = TCP");

    /* r_src_addr: src=192.168.1.1/32 */
    struct in_addr h;
    inet_aton("192.168.1.1", &h);
    EXPECT(g_rules[1].src_ip         == h.s_addr, "r_src_addr: src_ip = 192.168.1.1");
    EXPECT(g_rules[1].src_prefix_len == 32,         "r_src_addr: src_pfx = 32");
    EXPECT(g_rules[1].src_port_lo    == 53,         "r_src_addr: src_port_lo = 53");
    EXPECT(g_rules[1].src_port_hi    == 53,         "r_src_addr: src_port_hi = 53");

    /* r_dst_addr: dst=8.8.8.8/32 */
    struct in_addr dns;
    inet_aton("8.8.8.8", &dns);
    EXPECT(g_rules[2].dst_ip         == dns.s_addr, "r_dst_addr: dst_ip = 8.8.8.8");
    EXPECT(g_rules[2].dst_prefix_len == 32,          "r_dst_addr: dst_pfx = 32");
    EXPECT(g_rules[2].dst_port_lo    == 443,         "r_dst_addr: dst_port_lo = 443");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 3: port range (lo-hi format)
 * ═══════════════════════════════════════════════════════════════════════════ */
static void test_port_range(void)
{
    puts("[ test_port_range ]");

    const char *content =
        "[group: g1]       precedence=10   action=FORWARD\n"
        "[group: DEFAULT]  precedence=999  action=DROP\n"
        "r_range, g1, tcp, any, any, 1024-65535, 80-443\n"
        "r_def,   DEFAULT, any, any, any, any, any\n";

    const char *path = write_tmp("port_range.conf", content);
    reset();
    int rc = rule_loader_parse(path, &g_groups, g_rules, &g_num_rules);

    EXPECT(rc == 0,                     "parse succeeds");
    EXPECT(g_rules[0].src_port_lo == 1024,  "src_port_lo = 1024");
    EXPECT(g_rules[0].src_port_hi == 65535, "src_port_hi = 65535");
    EXPECT(g_rules[0].dst_port_lo == 80,    "dst_port_lo = 80");
    EXPECT(g_rules[0].dst_port_hi == 443,   "dst_port_hi = 443");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 4: invalid cases — must all return -1
 * ═══════════════════════════════════════════════════════════════════════════ */
static void test_invalid_cases(void)
{
    puts("[ test_invalid_cases ]");

    int rc;

    /* 4a: non-existent file */
    reset();
    rc = rule_loader_parse("/tmp/spifast_nonexistent_file.conf",
                           &g_groups, g_rules, &g_num_rules);
    EXPECT(rc == -1, "non-existent file → -1");

    /* 4b: no DEFAULT group (highest-precedence group has action=FORWARD) */
    reset();
    const char *no_default =
        "[group: g1]  precedence=100  action=FORWARD\n"
        "[group: g2]  precedence=999  action=FORWARD\n"   /* max prec but FORWARD */
        "r1, g1, tcp, any, any, any, 80\n";
    rc = rule_loader_parse(write_tmp("no_default.conf", no_default),
                           &g_groups, g_rules, &g_num_rules);
    EXPECT(rc == -1, "no DEFAULT (max-prec group has FORWARD action) → -1");

    /* 4c: duplicate group name */
    reset();
    const char *dup_group =
        "[group: foo]     precedence=100  action=FORWARD\n"
        "[group: foo]     precedence=200  action=FORWARD\n"
        "[group: DEFAULT] precedence=999  action=DROP\n"
        "r1, foo, any, any, any, any, any\n"
        "r2, DEFAULT, any, any, any, any, any\n";
    rc = rule_loader_parse(write_tmp("dup_group.conf", dup_group),
                           &g_groups, g_rules, &g_num_rules);
    EXPECT(rc == -1, "duplicate group name → -1");

    /* 4d: duplicate rule name */
    reset();
    const char *dup_rule =
        "[group: g1]      precedence=100  action=FORWARD\n"
        "[group: DEFAULT] precedence=999  action=DROP\n"
        "r_same, g1,      tcp, any, any, any, 80\n"
        "r_same, DEFAULT, any, any, any, any, any\n";   /* same rule name */
    rc = rule_loader_parse(write_tmp("dup_rule.conf", dup_rule),
                           &g_groups, g_rules, &g_num_rules);
    EXPECT(rc == -1, "duplicate rule name → -1");

    /* 4e: rule references undeclared group */
    reset();
    const char *bad_group_ref =
        "[group: g1]      precedence=100  action=FORWARD\n"
        "[group: DEFAULT] precedence=999  action=DROP\n"
        "r1, unknown_group, tcp, any, any, any, 80\n"
        "r2, DEFAULT, any, any, any, any, any\n";
    rc = rule_loader_parse(write_tmp("bad_group_ref.conf", bad_group_ref),
                           &g_groups, g_rules, &g_num_rules);
    EXPECT(rc == -1, "rule references undeclared group → -1");

    /* 4f: invalid protocol */
    reset();
    const char *bad_proto =
        "[group: g1]      precedence=100  action=FORWARD\n"
        "[group: DEFAULT] precedence=999  action=DROP\n"
        "r1, g1, icmp, any, any, any, any\n"
        "r2, DEFAULT, any, any, any, any, any\n";
    rc = rule_loader_parse(write_tmp("bad_proto.conf", bad_proto),
                           &g_groups, g_rules, &g_num_rules);
    EXPECT(rc == -1, "unknown protocol 'icmp' → -1");

    /* 4g: invalid IP — octet > 255 */
    reset();
    const char *bad_ip =
        "[group: g1]      precedence=100  action=FORWARD\n"
        "[group: DEFAULT] precedence=999  action=DROP\n"
        "r1, g1, tcp, any, dst_prefix=999.0.0.0/8, any, any\n"
        "r2, DEFAULT, any, any, any, any, any\n";
    rc = rule_loader_parse(write_tmp("bad_ip.conf", bad_ip),
                           &g_groups, g_rules, &g_num_rules);
    EXPECT(rc == -1, "IP octet 999 → -1");

    /* 4h: invalid CIDR prefix (>32) */
    reset();
    const char *bad_cidr =
        "[group: g1]      precedence=100  action=FORWARD\n"
        "[group: DEFAULT] precedence=999  action=DROP\n"
        "r1, g1, tcp, any, dst_prefix=10.0.0.0/33, any, any\n"
        "r2, DEFAULT, any, any, any, any, any\n";
    rc = rule_loader_parse(write_tmp("bad_cidr.conf", bad_cidr),
                           &g_groups, g_rules, &g_num_rules);
    EXPECT(rc == -1, "CIDR prefix /33 → -1");

    /* 4i: port range lo > hi */
    reset();
    const char *bad_port =
        "[group: g1]      precedence=100  action=FORWARD\n"
        "[group: DEFAULT] precedence=999  action=DROP\n"
        "r1, g1, tcp, any, any, 8000-1000, any\n"
        "r2, DEFAULT, any, any, any, any, any\n";
    rc = rule_loader_parse(write_tmp("bad_port.conf", bad_port),
                           &g_groups, g_rules, &g_num_rules);
    EXPECT(rc == -1, "port range lo > hi → -1");

    /* 4j: fewer than 7 comma-separated fields in rule */
    reset();
    const char *short_rule =
        "[group: g1]      precedence=100  action=FORWARD\n"
        "[group: DEFAULT] precedence=999  action=DROP\n"
        "r1, g1, tcp, any, any, any\n"   /* only 6 fields */
        "r2, DEFAULT, any, any, any, any, any\n";
    rc = rule_loader_parse(write_tmp("short_rule.conf", short_rule),
                           &g_groups, g_rules, &g_num_rules);
    EXPECT(rc == -1, "rule with 6 fields → -1");

    /* 4k: group name with invalid characters */
    reset();
    const char *bad_name =
        "[group: my-group]  precedence=100  action=FORWARD\n"
        "[group: DEFAULT]   precedence=999  action=DROP\n"
        "r1, DEFAULT, any, any, any, any, any\n";
    rc = rule_loader_parse(write_tmp("bad_name.conf", bad_name),
                           &g_groups, g_rules, &g_num_rules);
    EXPECT(rc == -1, "group name with '-' → -1");

    /* 4l: missing precedence in group declaration */
    reset();
    const char *no_prec =
        "[group: g1]  action=FORWARD\n"
        "[group: DEFAULT] precedence=999  action=DROP\n"
        "r1, DEFAULT, any, any, any, any, any\n";
    rc = rule_loader_parse(write_tmp("no_prec.conf", no_prec),
                           &g_groups, g_rules, &g_num_rules);
    EXPECT(rc == -1, "missing precedence= → -1");

    /* 4m: unknown action */
    reset();
    const char *bad_action =
        "[group: g1]       precedence=100  action=REJECT\n"
        "[group: DEFAULT]  precedence=999  action=DROP\n"
        "r1, DEFAULT, any, any, any, any, any\n";
    rc = rule_loader_parse(write_tmp("bad_action.conf", bad_action),
                           &g_groups, g_rules, &g_num_rules);
    EXPECT(rc == -1, "unknown action 'REJECT' → -1");

    /* 4n: wrong-direction IP keyword in dst field */
    reset();
    const char *wrong_dir =
        "[group: g1]      precedence=100  action=FORWARD\n"
        "[group: DEFAULT] precedence=999  action=DROP\n"
        "r1, g1, tcp, any, src_prefix=10.0.0.0/8, any, any\n" /* src kw in dst pos */
        "r2, DEFAULT, any, any, any, any, any\n";
    rc = rule_loader_parse(write_tmp("wrong_dir.conf", wrong_dir),
                           &g_groups, g_rules, &g_num_rules);
    EXPECT(rc == -1, "src_prefix= in dst position → -1");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 5: comments and blank lines are silently skipped
 * ═══════════════════════════════════════════════════════════════════════════ */
static void test_comments_and_blanks(void)
{
    puts("[ test_comments_and_blanks ]");

    const char *content =
        "# This is a comment\n"
        "\n"
        "  # indented comment\n"
        "\n"
        "[group: g1]       precedence=50   action=FORWARD\n"
        "[group: DEFAULT]  precedence=999  action=DROP\n"
        "\n"
        "# rule section\n"
        "r1, g1,      tcp, any, dst_prefix=8.8.8.0/24, any, 53\n"
        "r_def, DEFAULT, any, any, any, any, any\n"
        "\n";

    const char *path = write_tmp("comments.conf", content);
    reset();
    int rc = rule_loader_parse(path, &g_groups, g_rules, &g_num_rules);

    EXPECT(rc == 0,              "parse succeeds despite comments/blanks");
    EXPECT(g_groups.num_groups == 2, "2 groups (comments skipped)");
    EXPECT(g_num_rules == 2,    "2 rules (comments skipped)");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 6: rule_loader_load() reaches acl_engine_build()
 *         acl_engine_build is a stub that returns -1, so load must also fail.
 *         This confirms the integration point between loader and ACL engine.
 * ═══════════════════════════════════════════════════════════════════════════ */
static void test_load_reaches_acl_build(void)
{
    puts("[ test_load_reaches_acl_build ]");

    const char *content =
        "[group: g1]       precedence=100  action=FORWARD\n"
        "[group: DEFAULT]  precedence=999  action=DROP\n"
        "r1,    g1,      tcp, any, any, any, 80\n"
        "r_def, DEFAULT, any, any, any, any, any\n";

    const char *path = write_tmp("load_acl.conf", content);
    reset();

    /* rule_loader_parse should succeed */
    int rc_parse = rule_loader_parse(path, &g_groups, g_rules, &g_num_rules);
    EXPECT(rc_parse == 0,
           "rule_loader_parse: parsing valid file → 0");

    /* rule_loader_load must fail because acl_engine_build() is a stub (returns -1) */
    reset();
    int rc_load = rule_loader_load(path, &g_groups, g_rules, &g_num_rules);
    EXPECT(rc_load == -1,
           "rule_loader_load: fails because acl_engine_build stub returns -1");
}

/* ─── entry point ───────────────────────────────────────────────────────────── */
int main(void)
{
    test_valid_config();
    test_ip_variants();
    test_port_range();
    test_invalid_cases();
    test_comments_and_blanks();
    test_load_reaches_acl_build();

    printf("\nResult: %d passed, %d failed\n", g_pass, g_fail);
    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
