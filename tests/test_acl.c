/*
 * tests/test_acl.c — unit tests for flat single-stage ACL engine (Phase 3)
 *
 * Tests flat_acl_match correctness with synthetic packets covering:
 *   • BEST-match mode  (highest-precedence rule wins)
 *   • FIRST-match mode (first rule in parse order wins)
 *   • Protocol discrimination (TCP-only rule does not match UDP)
 *   • CIDR prefix matching
 *   • Port-range matching
 *   • flat_acl_match_burst (batch path)
 *   • acl_engine_destroy clears module state
 *
 * No EAL init required — flat_acl_match uses pure C linear scan with no
 * hugepage or rte_acl allocations.
 *
 * Build: cmake --build build --target test_acl
 * Run:   build/test_acl
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>    /* inet_aton, ntohl */
#include <netinet/in.h>   /* IPPROTO_TCP, IPPROTO_UDP */

#include "rule/acl_engine.h"
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

/* ─── shared state ─────────────────────────────────────────────────────────── */
static flat_rule_table_t g_flat;

static void reset(void)
{
    memset(&g_flat, 0, sizeof(g_flat));
    acl_engine_destroy();
}

/* Write content to a temp file and return the path. */
static const char *write_tmp(const char *name, const char *content)
{
    static char path[256];
    snprintf(path, sizeof(path), "/tmp/spifast_acl3_test_%s", name);
    FILE *fp = fopen(path, "w");
    if (!fp) { perror("fopen"); exit(EXIT_FAILURE); }
    fputs(content, fp);
    fclose(fp);
    return path;
}

/* Build an acl_key_t from human-readable arguments.
 * src/dst IPs are given as dotted-decimal strings and converted to host byte
 * order, matching the NBO→HBO conversion done by the Worker lcore (SDD §2.6). */
static acl_key_t make_key(uint8_t proto,
                            const char *src_ip, const char *dst_ip,
                            uint16_t sport, uint16_t dport)
{
    acl_key_t k;
    memset(&k, 0, sizeof(k));
    k.protocol = proto;
    struct in_addr a;
    inet_aton(src_ip, &a);
    k.src_ip = ntohl(a.s_addr);   /* NBO → HBO */
    inet_aton(dst_ip, &a);
    k.dst_ip = ntohl(a.s_addr);
    k.src_port = sport;
    k.dst_port = dport;
    return k;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Reference rule set used across all tests:
 *
 *   Group 0: "youtube"   precedence=100 FORWARD
 *     r_yt : TCP dst_prefix=142.250.0.0/15 any-port   (file_order=0)
 *
 *   Group 1: "facebook"  precedence=200 FORWARD
 *     r_fb : TCP dst_address=31.13.96.1 dport=443      (file_order=1)
 *
 *   Group 2: "DEFAULT"   precedence=1   DROP
 *     r_def: any any any any any (wildcard catch-all)   (file_order=2)
 *
 * BEST-match sort order  (prec DESC, file_order ASC):
 *   r_fb(200,1) → r_yt(100,0) → r_def(1,2)
 *
 * FIRST-match sort order (file_order ASC):
 *   r_yt(0) → r_fb(1) → r_def(2)
 * ═══════════════════════════════════════════════════════════════════════════ */
static const char *k_ref_rules =
    "[group: youtube]   precedence=100  action=FORWARD\n"
    "[group: facebook]  precedence=200  action=FORWARD\n"
    "[group: DEFAULT]   precedence=1    action=DROP\n"
    "r_yt,  youtube,  tcp, any, dst_prefix=142.250.0.0/15, any, any\n"
    "r_fb,  facebook, tcp, any, dst_address=31.13.96.1,    any, 443\n"
    "r_def, DEFAULT,  any, any, any,                       any, any\n";

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 1: BEST-match mode
 *
 * facebook (prec=200) beats youtube (prec=100) when both match.
 * ═══════════════════════════════════════════════════════════════════════════ */
static void test_best_match(void)
{
    puts("[ test_best_match ]");
    reset();

    const char *path = write_tmp("best.conf", k_ref_rules);
    int rc = rule_loader_parse(path, &g_flat);
    EXPECT(rc == 0, "rule_loader_parse succeeds");

    rc = acl_engine_build(&g_flat, MATCH_MODE_BEST);
    EXPECT(rc == 0, "acl_engine_build BEST succeeds");
    EXPECT(acl_get_flat_rule_table() == &g_flat, "flat_rule_table stored");

    /* TCP → 142.250.1.1 : only youtube rule matches → FORWARD */
    acl_key_t k1 = make_key(IPPROTO_TCP, "1.2.3.4", "142.250.1.1", 9000, 80);
    const flat_rule_entry_t *r1 = flat_acl_match(&g_flat, &k1);
    EXPECT(r1 != NULL,                        "142.250.1.1 TCP: non-NULL result");
    EXPECT(r1->action == ACTION_FORWARD,      "142.250.1.1 TCP: FORWARD");
    EXPECT(strcmp(r1->group_name, "youtube") == 0,
                                              "142.250.1.1 TCP: youtube group");

    /* TCP → 31.13.96.1:443 : only facebook rule matches → FORWARD */
    acl_key_t k2 = make_key(IPPROTO_TCP, "1.2.3.4", "31.13.96.1", 9000, 443);
    const flat_rule_entry_t *r2 = flat_acl_match(&g_flat, &k2);
    EXPECT(r2 != NULL,                        "31.13.96.1:443 TCP: non-NULL result");
    EXPECT(r2->action == ACTION_FORWARD,      "31.13.96.1:443 TCP: FORWARD");
    EXPECT(strcmp(r2->group_name, "facebook") == 0,
                                              "31.13.96.1:443 TCP: facebook group");

    /* UDP → 8.8.8.8 : no specific rule → DEFAULT → DROP */
    acl_key_t k3 = make_key(IPPROTO_UDP, "1.2.3.4", "8.8.8.8", 9000, 53);
    const flat_rule_entry_t *r3 = flat_acl_match(&g_flat, &k3);
    EXPECT(r3 != NULL,                        "8.8.8.8 UDP: non-NULL result");
    EXPECT(r3->action == ACTION_DROP,         "8.8.8.8 UDP: DROP (DEFAULT)");

    /* TCP → 1.1.1.1:80 : no rule matches port/IP combo → DEFAULT → DROP */
    acl_key_t k4 = make_key(IPPROTO_TCP, "1.2.3.4", "1.1.1.1", 9000, 80);
    const flat_rule_entry_t *r4 = flat_acl_match(&g_flat, &k4);
    EXPECT(r4 != NULL,                        "1.1.1.1:80 TCP: non-NULL result");
    EXPECT(r4->action == ACTION_DROP,         "1.1.1.1:80 TCP: DROP (DEFAULT)");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 2: FIRST-match mode
 *
 * With FIRST-match, r_yt (file_order=0) beats r_fb (file_order=1) if both
 * match — but the reference rules don't overlap (r_fb requires dport=443).
 * A separate overlapping rule set validates that FIRST wins over precedence.
 * ═══════════════════════════════════════════════════════════════════════════ */
static void test_first_match(void)
{
    puts("[ test_first_match ]");
    reset();

    /*
     * Overlapping rules: two groups with overlapping IP ranges, where the
     * lower-precedence group appears first in the file.  FIRST-match must
     * return the first-declared rule even when a higher-precedence rule also
     * matches.
     *
     * Group A: prec=200 FORWARD — r_hi: tcp dst_prefix=10.0.0.0/8 any
     * Group B: prec=100 FORWARD — r_lo: tcp dst_prefix=10.1.0.0/16 any
     * DEFAULT: prec=1   DROP
     *
     * File order: r_lo(0), r_hi(1), r_def(2)
     * BEST:  r_hi(200) beats r_lo(100) for 10.1.1.1 → r_hi
     * FIRST: r_lo(file_order=0) wins for 10.1.1.1 → r_lo
     */
    static const char *overlap_rules =
        "[group: high]    precedence=200  action=FORWARD\n"
        "[group: low]     precedence=100  action=FORWARD\n"
        "[group: DEFAULT] precedence=1    action=DROP\n"
        "r_lo,  low,     tcp, any, dst_prefix=10.1.0.0/16, any, any\n"
        "r_hi,  high,    tcp, any, dst_prefix=10.0.0.0/8,  any, any\n"
        "r_def, DEFAULT, any, any, any, any, any\n";

    const char *path = write_tmp("first.conf", overlap_rules);
    int rc = rule_loader_parse(path, &g_flat);
    EXPECT(rc == 0, "rule_loader_parse (overlap) succeeds");

    rc = acl_engine_build(&g_flat, MATCH_MODE_FIRST);
    EXPECT(rc == 0, "acl_engine_build FIRST succeeds");

    /* 10.1.1.1 TCP — matches both r_lo and r_hi; FIRST → r_lo (low group) */
    acl_key_t k1 = make_key(IPPROTO_TCP, "1.2.3.4", "10.1.1.1", 9000, 80);
    const flat_rule_entry_t *r1 = flat_acl_match(&g_flat, &k1);
    EXPECT(r1 != NULL,                       "10.1.1.1 FIRST: non-NULL");
    EXPECT(r1->action == ACTION_FORWARD,     "10.1.1.1 FIRST: FORWARD");
    EXPECT(strcmp(r1->group_name, "low") == 0,
                                             "10.1.1.1 FIRST: low group (file_order wins over precedence)");

    /* 10.2.0.1 TCP — only r_hi (/8) matches (not in /16 of r_lo) → high group */
    acl_key_t k2 = make_key(IPPROTO_TCP, "1.2.3.4", "10.2.0.1", 9000, 80);
    const flat_rule_entry_t *r2 = flat_acl_match(&g_flat, &k2);
    EXPECT(r2 != NULL,                       "10.2.0.1 FIRST: non-NULL");
    EXPECT(r2->action == ACTION_FORWARD,     "10.2.0.1 FIRST: FORWARD");
    EXPECT(strcmp(r2->group_name, "high") == 0,
                                             "10.2.0.1 FIRST: high group");

    /* 192.168.1.1 TCP — no specific match → DEFAULT → DROP */
    acl_key_t k3 = make_key(IPPROTO_TCP, "1.2.3.4", "192.168.1.1", 9000, 80);
    const flat_rule_entry_t *r3 = flat_acl_match(&g_flat, &k3);
    EXPECT(r3 != NULL,                       "192.168.1.1 FIRST: non-NULL");
    EXPECT(r3->action == ACTION_DROP,        "192.168.1.1 FIRST: DROP (DEFAULT)");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 3: Protocol discrimination
 *
 * youtube rule is TCP-only.  A UDP packet to the same destination must fall
 * through to DEFAULT (DROP), not match the TCP rule.
 * ═══════════════════════════════════════════════════════════════════════════ */
static void test_protocol(void)
{
    puts("[ test_protocol ]");
    reset();

    const char *path = write_tmp("proto.conf", k_ref_rules);
    rule_loader_parse(path, &g_flat);
    acl_engine_build(&g_flat, MATCH_MODE_BEST);

    acl_key_t tcp_pkt = make_key(IPPROTO_TCP, "5.6.7.8", "142.250.5.5", 1234, 80);
    const flat_rule_entry_t *r_tcp = flat_acl_match(&g_flat, &tcp_pkt);
    EXPECT(r_tcp != NULL,                        "142.250.5.5 TCP: non-NULL");
    EXPECT(r_tcp->action == ACTION_FORWARD,      "142.250.5.5 TCP: FORWARD (youtube)");

    acl_key_t udp_pkt = make_key(IPPROTO_UDP, "5.6.7.8", "142.250.5.5", 1234, 53);
    const flat_rule_entry_t *r_udp = flat_acl_match(&g_flat, &udp_pkt);
    EXPECT(r_udp != NULL,                        "142.250.5.5 UDP: non-NULL");
    EXPECT(r_udp->action == ACTION_DROP,         "142.250.5.5 UDP: DROP (TCP rule doesn't match)");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 4: CIDR prefix matching
 *
 * 142.250.0.0/15 covers 142.250.0.0 – 142.251.255.255.
 *   • 142.250.1.1   → inside /15 → youtube FORWARD
 *   • 142.251.255.0 → inside /15 → youtube FORWARD
 *   • 142.252.0.0   → outside /15 → DEFAULT DROP
 * ═══════════════════════════════════════════════════════════════════════════ */
static void test_cidr(void)
{
    puts("[ test_cidr ]");
    reset();

    const char *path = write_tmp("cidr.conf", k_ref_rules);
    rule_loader_parse(path, &g_flat);
    acl_engine_build(&g_flat, MATCH_MODE_BEST);

    acl_key_t k1 = make_key(IPPROTO_TCP, "1.1.1.1", "142.250.1.1",   9000, 80);
    acl_key_t k2 = make_key(IPPROTO_TCP, "1.1.1.1", "142.251.255.0", 9000, 80);
    acl_key_t k3 = make_key(IPPROTO_TCP, "1.1.1.1", "142.252.0.0",   9000, 80);
    acl_key_t k4 = make_key(IPPROTO_TCP, "1.1.1.1", "31.13.96.1",    9000, 443);

    const flat_rule_entry_t *r1 = flat_acl_match(&g_flat, &k1);
    EXPECT(r1 && r1->action == ACTION_FORWARD,
           "142.250.1.1 in /15 → youtube FORWARD");

    const flat_rule_entry_t *r2 = flat_acl_match(&g_flat, &k2);
    EXPECT(r2 && r2->action == ACTION_FORWARD,
           "142.251.255.0 in /15 → youtube FORWARD");

    const flat_rule_entry_t *r3 = flat_acl_match(&g_flat, &k3);
    EXPECT(r3 && r3->action == ACTION_DROP,
           "142.252.0.0 outside /15 → DROP");

    /* Exact /32 host match for facebook */
    const flat_rule_entry_t *r4 = flat_acl_match(&g_flat, &k4);
    EXPECT(r4 && r4->action == ACTION_FORWARD,
           "31.13.96.1/32 exact match → facebook FORWARD");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 5: Port-range matching
 *
 * facebook rule requires dport=443 exactly.
 *   • TCP → 31.13.96.1 dport=443 → match (FORWARD)
 *   • TCP → 31.13.96.1 dport=80  → no match → DEFAULT (DROP)
 * ═══════════════════════════════════════════════════════════════════════════ */
static void test_port_range(void)
{
    puts("[ test_port_range ]");
    reset();

    const char *path = write_tmp("port.conf", k_ref_rules);
    rule_loader_parse(path, &g_flat);
    acl_engine_build(&g_flat, MATCH_MODE_BEST);

    acl_key_t k_match  = make_key(IPPROTO_TCP, "1.2.3.4", "31.13.96.1", 9000, 443);
    acl_key_t k_nomatch = make_key(IPPROTO_TCP, "1.2.3.4", "31.13.96.1", 9000, 80);

    const flat_rule_entry_t *r1 = flat_acl_match(&g_flat, &k_match);
    EXPECT(r1 && r1->action == ACTION_FORWARD,
           "31.13.96.1 dport=443 → facebook FORWARD");

    const flat_rule_entry_t *r2 = flat_acl_match(&g_flat, &k_nomatch);
    EXPECT(r2 && r2->action == ACTION_DROP,
           "31.13.96.1 dport=80 → no port match → DROP");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 6: flat_acl_match_burst
 *
 * Process a burst of 4 packets and verify each result is correct.
 * ═══════════════════════════════════════════════════════════════════════════ */
static void test_burst(void)
{
    puts("[ test_burst ]");
    reset();

    const char *path = write_tmp("burst.conf", k_ref_rules);
    rule_loader_parse(path, &g_flat);
    acl_engine_build(&g_flat, MATCH_MODE_BEST);

    acl_key_t keys[4];
    keys[0] = make_key(IPPROTO_TCP, "1.1.1.1", "142.250.1.1", 9000, 80);   /* youtube */
    keys[1] = make_key(IPPROTO_TCP, "1.1.1.1", "31.13.96.1",  9000, 443);  /* facebook */
    keys[2] = make_key(IPPROTO_UDP, "1.1.1.1", "8.8.8.8",     9000, 53);   /* DEFAULT */
    keys[3] = make_key(IPPROTO_TCP, "1.1.1.1", "31.13.96.1",  9000, 80);   /* DEFAULT (wrong port) */

    const acl_key_t *key_ptrs[4] = { &keys[0], &keys[1], &keys[2], &keys[3] };
    const flat_rule_entry_t *results[4];

    flat_acl_match_burst(&g_flat, key_ptrs, results, 4);

    EXPECT(results[0] && results[0]->action == ACTION_FORWARD,
           "burst[0] 142.250.1.1 TCP → youtube FORWARD");
    EXPECT(results[1] && results[1]->action == ACTION_FORWARD,
           "burst[1] 31.13.96.1:443 TCP → facebook FORWARD");
    EXPECT(results[2] && results[2]->action == ACTION_DROP,
           "burst[2] 8.8.8.8 UDP → DROP");
    EXPECT(results[3] && results[3]->action == ACTION_DROP,
           "burst[3] 31.13.96.1:80 TCP → DROP (port mismatch)");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 7: rule_loader_load() integration
 *
 * rule_loader_load = parse + acl_engine_build; must return 0 and leave the
 * engine ready to match.
 * ═══════════════════════════════════════════════════════════════════════════ */
static void test_loader_load(void)
{
    puts("[ test_loader_load ]");
    reset();

    const char *path = write_tmp("load.conf", k_ref_rules);
    int rc = rule_loader_load(path, MATCH_MODE_BEST, &g_flat);
    EXPECT(rc == 0,                      "rule_loader_load succeeds");
    EXPECT(g_flat.num_rules == 3,        "3 rules loaded");
    EXPECT(acl_get_flat_rule_table() == &g_flat,
                                         "flat_rule_table stored after load");

    acl_key_t k = make_key(IPPROTO_TCP, "1.1.1.1", "142.250.1.1", 9000, 80);
    const flat_rule_entry_t *r = flat_acl_match(&g_flat, &k);
    EXPECT(r && r->action == ACTION_FORWARD,
           "match after load: youtube FORWARD");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 8: acl_engine_destroy
 *
 * After destroy the module pointers are cleared and flat_acl_match on a
 * freshly-built engine still works (rebuild after destroy).
 * ═══════════════════════════════════════════════════════════════════════════ */
static void test_destroy(void)
{
    puts("[ test_destroy ]");
    reset();

    const char *path = write_tmp("destroy.conf", k_ref_rules);
    rule_loader_parse(path, &g_flat);
    acl_engine_build(&g_flat, MATCH_MODE_BEST);

    EXPECT(acl_get_flat_rule_table() != NULL, "table non-NULL before destroy");

    acl_engine_destroy();
    EXPECT(acl_get_flat_rule_table() == NULL, "table NULL after destroy");
    EXPECT(acl_get_flat_ctx()        == NULL, "flat_ctx NULL after destroy");

    /* Rebuild from same table and verify matching still works */
    int rc = acl_engine_build(&g_flat, MATCH_MODE_BEST);
    EXPECT(rc == 0, "rebuild after destroy succeeds");

    acl_key_t k = make_key(IPPROTO_TCP, "9.9.9.9", "142.250.0.1", 1111, 80);
    const flat_rule_entry_t *r = flat_acl_match(&g_flat, &k);
    EXPECT(r && r->action == ACTION_FORWARD, "match after rebuild → youtube FORWARD");
}

/* ─── entry point ───────────────────────────────────────────────────────────── */
int main(void)
{
    test_best_match();
    test_first_match();
    test_protocol();
    test_cidr();
    test_port_range();
    test_burst();
    test_loader_load();
    test_destroy();

    printf("\nResult: %d passed, %d failed\n", g_pass, g_fail);
    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
