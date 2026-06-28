/*
 * tests/test_acl.c — unit tests for rule/acl_engine.c
 *
 * Tests cover:
 *   • Stage-1 group classification (one rule per group → correct group_id)
 *   • Stage-2 action classification (per-group context → correct action)
 *   • acl_lookup() end-to-end (two-stage; lazy Stage-2 build)
 *   • rule_loader_load() integration (parse + ACL build in one call)
 *
 * EAL init is required because rte_acl_create allocates hugepage memory.
 * We use --no-huge to allow testing without pre-allocated hugepages.
 *
 * Build: cmake --build build --target test_acl
 * Run:   build/test_acl
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>   /* inet_aton */
#include <netinet/in.h>  /* IPPROTO_TCP, IPPROTO_UDP */

#include <rte_eal.h>

#include "rule/acl_engine.h"
#include "rule/rule_loader.h"
#include "packet/pkt_ctx.h"   /* pkt_meta_t */

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

/* ─── shared state ─────────────────────────────────────────────────────────── */
static filter_group_table_t g_groups;
static spi_rule_t           g_rules[SPIFAST_MAX_RULES];
static uint32_t             g_num_rules;

static void reset_state(void)
{
    memset(&g_groups,  0, sizeof(g_groups));
    memset(g_rules,    0, sizeof(g_rules));
    g_num_rules = 0;
    acl_engine_destroy();
}

/* Write a temp rule file and return its path. */
static const char *write_tmp(const char *name, const char *content)
{
    static char path[256];
    snprintf(path, sizeof(path), "/tmp/spifast_acl_test_%s", name);
    FILE *fp = fopen(path, "w");
    if (!fp) { perror("fopen"); exit(EXIT_FAILURE); }
    fputs(content, fp);
    fclose(fp);
    return path;
}

/* Build a pkt_meta_t for testing lookups. */
static pkt_meta_t make_meta(uint8_t proto,
                             const char *src_ip, const char *dst_ip,
                             uint16_t sport, uint16_t dport)
{
    pkt_meta_t m;
    memset(&m, 0, sizeof(m));
    m.protocol = proto;
    struct in_addr a;
    inet_aton(src_ip, &a); m.src_ip = a.s_addr;
    inet_aton(dst_ip, &a); m.dst_ip = a.s_addr;
    m.src_port = sport;
    m.dst_port = dport;
    return m;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Reference rule set used across all ACL tests:
 *
 *   Group 0: "youtube"   precedence=100 FORWARD
 *     Rules: TCP dst_prefix=142.250.0.0/15 any port
 *
 *   Group 1: "facebook"  precedence=200 FORWARD
 *     Rules: TCP dst_address=31.13.96.1 port 443
 *
 *   Group 2: "DEFAULT"   precedence=999 DROP
 *     Rules: any any any any any (wildcard catch-all)
 * ═══════════════════════════════════════════════════════════════════════════ */
static const char *k_ref_rules =
    "[group: youtube]    precedence=100  action=FORWARD\n"
    "[group: facebook]   precedence=200  action=FORWARD\n"
    "[group: DEFAULT]    precedence=999  action=DROP\n"
    "r_yt,  youtube,  tcp, any, dst_prefix=142.250.0.0/15, any, any\n"
    "r_fb,  facebook, tcp, any, dst_address=31.13.96.1,    any, 443\n"
    "r_def, DEFAULT,  any, any, any, any, any\n";

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 1: Stage-1 group classification
 *
 * After acl_engine_build_stage1():
 *   • TCP to 142.250.1.1 → group 0 (youtube)
 *   • TCP to 31.13.96.1 port 443 → group 1 (facebook) — only if stage1 rule matched
 *   • TCP to 8.8.8.8 → group 2 (DEFAULT)
 * ═══════════════════════════════════════════════════════════════════════════ */
static void test_stage1_classify(void)
{
    puts("[ test_stage1_classify ]");
    reset_state();

    const char *path = write_tmp("stage1.conf", k_ref_rules);
    int rc = rule_loader_parse(path, &g_groups, g_rules, &g_num_rules);
    EXPECT(rc == 0, "rule_loader_parse succeeds");

    rc = acl_engine_build_stage1(g_rules, g_num_rules, &g_groups);
    EXPECT(rc == 0, "acl_engine_build_stage1 succeeds");
    EXPECT(acl_get_stage1_ctx() != NULL, "stage1_ctx is non-NULL after build");

    /* Packet to YouTube prefix (142.250.x.x) → group 0 (youtube) */
    pkt_meta_t m_yt = make_meta(IPPROTO_TCP, "1.2.3.4", "142.250.1.1", 12345, 443);
    acl_result_t r_yt = acl_lookup(&m_yt);
    printf("  YouTube lookup: group_id=%u action=%s\n",
           r_yt.group_id,
           (r_yt.action == ACTION_FORWARD) ? "FORWARD" : "DROP");
    EXPECT(r_yt.group_id == 0,           "YouTube packet → group 0 (youtube)");
    EXPECT(r_yt.action == ACTION_FORWARD, "YouTube action = FORWARD");

    /* Packet to 8.8.8.8 (no specific rule) → DEFAULT group */
    pkt_meta_t m_def = make_meta(IPPROTO_TCP, "1.2.3.4", "8.8.8.8", 12345, 80);
    acl_result_t r_def = acl_lookup(&m_def);
    EXPECT(r_def.action == ACTION_DROP,   "8.8.8.8 packet → DEFAULT (DROP)");
    EXPECT(r_def.group_id == acl_get_default_group_id(),
           "8.8.8.8 packet → default group_id");

    /* UDP packet (rules only specify tcp for youtube/facebook) → DEFAULT */
    pkt_meta_t m_udp = make_meta(IPPROTO_UDP, "1.2.3.4", "142.250.1.1", 1234, 53);
    acl_result_t r_udp = acl_lookup(&m_udp);
    EXPECT(r_udp.action == ACTION_DROP,   "UDP to YouTube prefix → DEFAULT (TCP-specific rule)");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 2: Stage-2 per-group action classification
 *
 * After acl_engine_build_group(group_id=0, ...):
 *   • group_ctx[0] becomes non-NULL
 *   • Packet to 142.250.x.x TCP → action FORWARD
 *   • acl_get_group_ctx(0) returns non-NULL
 * ═══════════════════════════════════════════════════════════════════════════ */
static void test_stage2_action(void)
{
    puts("[ test_stage2_action ]");
    reset_state();

    const char *path = write_tmp("stage2.conf", k_ref_rules);
    rule_loader_parse(path, &g_groups, g_rules, &g_num_rules);
    acl_engine_build_stage1(g_rules, g_num_rules, &g_groups);
    acl_engine_init_stage2();

    /* Before build_group: ctx is NULL */
    EXPECT(acl_get_group_ctx(0) == NULL,
           "group_ctx[0] NULL before build_group");

    /* Build Stage-2 for group 0 (youtube) */
    int rc = acl_engine_build_group(0, g_rules, g_num_rules, &g_groups);
    EXPECT(rc == 0, "acl_engine_build_group(group=0) succeeds");
    EXPECT(acl_get_group_ctx(0) != NULL,
           "group_ctx[0] non-NULL after build_group");

    /* Packet to YouTube → Stage-2 built → FORWARD */
    pkt_meta_t m = make_meta(IPPROTO_TCP, "1.2.3.4", "142.250.10.1", 5000, 443);
    acl_result_t r = acl_lookup(&m);
    EXPECT(r.group_id == 0,           "YouTube (Stage-2 built) → group 0");
    EXPECT(r.action == ACTION_FORWARD, "YouTube (Stage-2 built) → FORWARD");

    /* Build Stage-2 for DEFAULT group (group 2) */
    rc = acl_engine_build_group(
        acl_get_default_group_id(), g_rules, g_num_rules, &g_groups);
    EXPECT(rc == 0, "acl_engine_build_group(DEFAULT) succeeds");
    EXPECT(acl_get_group_ctx(acl_get_default_group_id()) != NULL,
           "group_ctx[DEFAULT] non-NULL after build");

    /* Packet to unmatched destination → DEFAULT → DROP */
    pkt_meta_t m2 = make_meta(IPPROTO_TCP, "1.2.3.4", "10.0.0.1", 5000, 80);
    acl_result_t r2 = acl_lookup(&m2);
    EXPECT(r2.action == ACTION_DROP, "unmatched packet (Stage-2) → DROP");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 3: acl_lookup() without Stage-2 (lazy path)
 *
 * When group_ctx[group_id] == NULL (Stage-2 not yet built), acl_lookup
 * must fall back to the group's action from filter_group_table.
 * ═══════════════════════════════════════════════════════════════════════════ */
static void test_lazy_fallback(void)
{
    puts("[ test_lazy_fallback ]");
    reset_state();

    const char *path = write_tmp("lazy.conf", k_ref_rules);
    rule_loader_parse(path, &g_groups, g_rules, &g_num_rules);
    acl_engine_build_stage1(g_rules, g_num_rules, &g_groups);
    acl_engine_init_stage2();
    /* Do NOT call build_group — all Stage-2 contexts remain NULL */

    /* YouTube packet — Stage-2 NULL → fall back to group table action */
    pkt_meta_t m = make_meta(IPPROTO_TCP, "5.6.7.8", "142.250.5.5", 9999, 80);
    acl_result_t r = acl_lookup(&m);
    EXPECT(r.group_id == 0,           "lazy fallback: YouTube → group 0");
    EXPECT(r.action == ACTION_FORWARD, "lazy fallback: YouTube group action = FORWARD");

    /* Default packet */
    pkt_meta_t m2 = make_meta(IPPROTO_TCP, "5.6.7.8", "9.9.9.9", 9999, 80);
    acl_result_t r2 = acl_lookup(&m2);
    EXPECT(r2.action == ACTION_DROP,   "lazy fallback: default → DROP");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 4: rule_loader_load() integration
 *
 * rule_loader_load = parse + validate + acl_engine_build.
 * Verifies end-to-end pipeline succeeds and lookup works immediately.
 * ═══════════════════════════════════════════════════════════════════════════ */
static void test_loader_integration(void)
{
    puts("[ test_loader_integration ]");
    reset_state();

    const char *path = write_tmp("integration.conf", k_ref_rules);
    int rc = rule_loader_load(path, &g_groups, g_rules, &g_num_rules);
    EXPECT(rc == 0, "rule_loader_load succeeds (full pipeline)");
    EXPECT(g_num_rules == 3,          "3 rules loaded");
    EXPECT(g_groups.num_groups == 3,  "3 groups in table");

    /* Stage-1 immediately usable after load */
    EXPECT(acl_get_stage1_ctx() != NULL, "stage1_ctx available after load");

    pkt_meta_t m_yt = make_meta(IPPROTO_TCP, "10.10.10.10", "142.250.0.1", 4321, 443);
    acl_result_t r_yt = acl_lookup(&m_yt);
    EXPECT(r_yt.group_id == 0,           "load + lookup: YouTube → group 0");
    EXPECT(r_yt.action == ACTION_FORWARD, "load + lookup: YouTube → FORWARD");

    pkt_meta_t m_def = make_meta(IPPROTO_TCP, "10.10.10.10", "1.1.1.1", 4321, 53);
    acl_result_t r_def = acl_lookup(&m_def);
    EXPECT(r_def.action == ACTION_DROP, "load + lookup: unmatched → DROP");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 5: default_group_id and destroy
 * ═══════════════════════════════════════════════════════════════════════════ */
static void test_default_and_destroy(void)
{
    puts("[ test_default_and_destroy ]");
    reset_state();

    const char *path = write_tmp("default.conf", k_ref_rules);
    rule_loader_parse(path, &g_groups, g_rules, &g_num_rules);
    acl_engine_build_stage1(g_rules, g_num_rules, &g_groups);
    acl_engine_init_stage2();

    uint32_t dflt = acl_get_default_group_id();
    EXPECT(dflt < g_groups.num_groups, "default_group_id in bounds");
    EXPECT(g_groups.groups[dflt].action == ACTION_DROP,
           "DEFAULT group has action=DROP");
    EXPECT(g_groups.groups[dflt].precedence == 999,
           "DEFAULT group has precedence=999");

    /* After destroy: ctx becomes NULL */
    acl_engine_destroy();
    EXPECT(acl_get_stage1_ctx() == NULL, "stage1_ctx NULL after destroy");
    for (uint32_t i = 0; i < g_groups.num_groups; i++)
        EXPECT(acl_get_group_ctx(i) == NULL, "group_ctx NULL after destroy");
}

/* ─── EAL init ──────────────────────────────────────────────────────────────── */
static void eal_init(void)
{
    /* --no-huge: use regular memory instead of hugepages (testing only). */
    char *argv[] = {
        "test_acl",
        "-l", "0",
        "--no-huge",
        "-m", "64",
        NULL
    };
    int argc = 6;
    if (rte_eal_init(argc, argv) < 0) {
        fprintf(stderr, "rte_eal_init failed — cannot run ACL tests\n");
        exit(EXIT_FAILURE);
    }
}

/* ─── entry point ───────────────────────────────────────────────────────────── */
int main(void)
{
    eal_init();

    test_stage1_classify();
    test_stage2_action();
    test_lazy_fallback();
    test_loader_integration();
    test_default_and_destroy();

    printf("\nResult: %d passed, %d failed\n", g_pass, g_fail);
    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
