/*
 * tests/test_parser.c — standalone unit tests for packet/parser.c
 *
 * No external test framework; uses a minimal assert harness.
 * No EAL initialization required: rte_pktmbuf_mtod is a pointer-arithmetic
 * macro; only buf_addr, data_off, and data_len are read from rte_mbuf.
 *
 * Build (from repo root):
 *   cmake --build build --target test_parser
 *   build/test_parser
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>          /* htons(), htonl() */
#include <netinet/in.h>         /* IPPROTO_TCP, IPPROTO_UDP */

#include <rte_mbuf.h>

#include "packet/parser.h"

/* ─── minimal harness ──────────────────────────────────────────────────────── */
static int g_pass = 0;
static int g_fail = 0;

#define EXPECT(cond, msg)                                                   \
    do {                                                                    \
        if (cond) {                                                         \
            printf("  PASS  %s\n", (msg));                                  \
            g_pass++;                                                       \
        } else {                                                            \
            printf("  FAIL  %s  (%s:%d)\n", (msg), __FILE__, __LINE__);    \
            g_fail++;                                                       \
        }                                                                   \
    } while (0)

/* ─── fake mbuf (no EAL, no mempool) ──────────────────────────────────────── */
static void fake_mbuf(struct rte_mbuf *m, void *buf, uint16_t len)
{
    memset(m, 0, sizeof(*m));
    m->buf_addr = buf;
    m->data_off = 0;
    m->data_len = len;
}

/* ─── raw-packet builders ──────────────────────────────────────────────────── */

/* 14-byte Ethernet header */
static void put_eth(uint8_t *p, uint16_t etype)
{
    /* dst MAC */
    p[0]=0xFF; p[1]=0xFF; p[2]=0xFF; p[3]=0xFF; p[4]=0xFF; p[5]=0xFF;
    /* src MAC */
    p[6]=0x00; p[7]=0x11; p[8]=0x22; p[9]=0x33; p[10]=0xAA; p[11]=0xBB;
    uint16_t et = htons(etype);
    memcpy(p + 12, &et, 2);
}

/* 20-byte minimal IPv4 header (no options, IHL=5) */
static void put_ipv4(uint8_t *p, uint8_t proto, uint32_t src_hbo, uint32_t dst_hbo)
{
    memset(p, 0, 20);
    p[0] = 0x45;                   /* version=4, IHL=5 */
    p[9] = proto;
    uint32_t s = htonl(src_hbo);   memcpy(p + 12, &s, 4);
    uint32_t d = htonl(dst_hbo);   memcpy(p + 16, &d, 4);
}

/* 4-byte IEEE 802.1Q VLAN header */
static void put_vlan(uint8_t *p, uint16_t vid, uint16_t inner_etype)
{
    uint16_t tci = htons(vid & 0x0FFF);
    uint16_t et  = htons(inner_etype);
    memcpy(p,     &tci, 2);
    memcpy(p + 2, &et,  2);
}

/* 20-byte minimal TCP header */
static void put_tcp(uint8_t *p, uint16_t sport, uint16_t dport)
{
    memset(p, 0, 20);
    uint16_t s = htons(sport);  memcpy(p,     &s, 2);
    uint16_t d = htons(dport);  memcpy(p + 2, &d, 2);
    p[12] = 0x50;               /* data offset = 5 (20 bytes) */
}

/* 8-byte minimal UDP header */
static void put_udp(uint8_t *p, uint16_t sport, uint16_t dport)
{
    memset(p, 0, 8);
    uint16_t s   = htons(sport);  memcpy(p,     &s, 2);
    uint16_t d   = htons(dport);  memcpy(p + 2, &d, 2);
    uint16_t len = htons(8);      memcpy(p + 4, &len, 2);
}

/* ─── helper: IP in host byte order → network-byte-order uint32_t for assert */
static inline uint32_t nbo(uint32_t host) { return htonl(host); }

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 1: valid IPv4/TCP frame, no VLAN
 *   src = 10.0.0.1:1234   dst = 192.168.1.100:80
 *   Expected: smaller IP (10.0.0.1) → src; no port swap (port 1234 stayed
 *   with the larger IP — after IP swap, src_port=80, dst_port=1234).
 * ═══════════════════════════════════════════════════════════════════════════ */
static void test_tcp_valid(void)
{
    puts("[ test_tcp_valid ]");

    uint8_t pkt[54];   /* 14 ETH + 20 IP + 20 TCP */
    put_eth  (pkt,       0x0800);
    put_ipv4 (pkt + 14, IPPROTO_TCP,
              0x0A000001,    /* src 10.0.0.1       */
              0xC0A80164);   /* dst 192.168.1.100  */
    put_tcp  (pkt + 34, 1234, 80);

    struct rte_mbuf m;
    fake_mbuf(&m, pkt, sizeof(pkt));

    pkt_meta_t meta;
    EXPECT(parse_packet(&m, &meta) == 0, "returns 0 on success");
    EXPECT(meta.protocol == IPPROTO_TCP, "protocol = TCP");
    EXPECT(meta.vlan_valid == 0,         "no VLAN");

    /* Normalization: src_ip(10.0.0.1) < dst_ip(192.168.1.100) → no IP swap
     * 10.0.0.1    NBO bytes 0A 00 00 01 → uint32_t 0x0100000A on LE
     * 192.168.1.100 NBO bytes C0 A8 01 64 → uint32_t 0x6401A8C0 on LE
     * 0x0100000A < 0x6401A8C0 → no swap → src stays 10.0.0.1, port stays 1234 */
    EXPECT(meta.src_ip   == nbo(0x0A000001), "src_ip = 10.0.0.1");
    EXPECT(meta.dst_ip   == nbo(0xC0A80164), "dst_ip = 192.168.1.100");
    EXPECT(meta.src_port == 1234,            "src_port = 1234 (no swap)");
    EXPECT(meta.dst_port == 80,              "dst_port = 80 (no swap)");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 2: valid IPv4/UDP frame, IPs trigger normalization swap
 *   src = 192.168.2.1:5000   dst = 192.168.1.1:53
 *   192.168.2.1 (NBO uint32_t 0x0102A8C0) > 192.168.1.1 (0x0101A8C0) → swap
 * ═══════════════════════════════════════════════════════════════════════════ */
static void test_udp_valid(void)
{
    puts("[ test_udp_valid ]");

    uint8_t pkt[42];   /* 14 ETH + 20 IP + 8 UDP */
    put_eth (pkt,       0x0800);
    put_ipv4(pkt + 14, IPPROTO_UDP,
             0xC0A80201,   /* src 192.168.2.1 */
             0xC0A80101);  /* dst 192.168.1.1 */
    put_udp (pkt + 34, 5000, 53);

    struct rte_mbuf m;
    fake_mbuf(&m, pkt, sizeof(pkt));

    pkt_meta_t meta;
    EXPECT(parse_packet(&m, &meta) == 0, "returns 0 on success");
    EXPECT(meta.protocol == IPPROTO_UDP, "protocol = UDP");

    /* After swap: src = 192.168.1.1 (smaller), dst = 192.168.2.1 (larger)
     * Ports also swap: src_port = 53 (was dst), dst_port = 5000 (was src) */
    EXPECT(meta.src_ip   == nbo(0xC0A80101), "src_ip = 192.168.1.1 (after swap)");
    EXPECT(meta.dst_ip   == nbo(0xC0A80201), "dst_ip = 192.168.2.1 (after swap)");
    EXPECT(meta.src_port == 53,              "src_port = 53 (after swap)");
    EXPECT(meta.dst_port == 5000,            "dst_port = 5000 (after swap)");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 3: IEEE 802.1Q VLAN-tagged IPv4/TCP frame
 *   ETH(0x8100) | VLAN(vid=100, inner=0x0800) | IPv4 | TCP
 * ═══════════════════════════════════════════════════════════════════════════ */
static void test_vlan_tagged(void)
{
    puts("[ test_vlan_tagged ]");

    uint8_t pkt[58];   /* 14 ETH + 4 VLAN + 20 IP + 20 TCP */
    put_eth  (pkt,       0x8100);
    put_vlan (pkt + 14,  100, 0x0800);
    put_ipv4 (pkt + 18, IPPROTO_TCP,
              0x01020304,   /* src 1.2.3.4 */
              0x05060708);  /* dst 5.6.7.8 */
    put_tcp  (pkt + 38, 443, 9999);

    struct rte_mbuf m;
    fake_mbuf(&m, pkt, sizeof(pkt));

    pkt_meta_t meta;
    EXPECT(parse_packet(&m, &meta) == 0,  "returns 0 on success");
    EXPECT(meta.vlan_valid == 1,          "VLAN tag detected");
    EXPECT(meta.vlan_id    == 100,        "VLAN ID = 100");
    EXPECT(meta.protocol   == IPPROTO_TCP, "protocol = TCP");

    /* 1.2.3.4  NBO uint32_t 0x04030201 on LE
     * 5.6.7.8  NBO uint32_t 0x08070605 on LE
     * 0x04030201 < 0x08070605 → no swap; src stays 1.2.3.4:443 */
    EXPECT(meta.src_ip   == nbo(0x01020304), "src_ip = 1.2.3.4");
    EXPECT(meta.dst_ip   == nbo(0x05060708), "dst_ip = 5.6.7.8");
    EXPECT(meta.src_port == 443,             "src_port = 443");
    EXPECT(meta.dst_port == 9999,            "dst_port = 9999");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 4: invalid / malformed packets — all must return -1
 * ═══════════════════════════════════════════════════════════════════════════ */
static void test_invalid(void)
{
    puts("[ test_invalid_packets ]");

    pkt_meta_t meta;
    struct rte_mbuf m;

    /* 4a: packet too short for Ethernet header */
    uint8_t tiny[5] = { 0 };
    fake_mbuf(&m, tiny, sizeof(tiny));
    EXPECT(parse_packet(&m, &meta) == -1,
           "packet shorter than ETH header → -1");

    /* 4b: non-IPv4 EtherType (ARP = 0x0806) */
    uint8_t arp[60];
    memset(arp, 0, sizeof(arp));
    put_eth(arp, 0x0806);
    fake_mbuf(&m, arp, sizeof(arp));
    EXPECT(parse_packet(&m, &meta) == -1,
           "ARP EtherType → -1");

    /* 4c: IPv4 but unsupported transport (ICMP = 1) */
    uint8_t icmp_pkt[54];
    put_eth  (icmp_pkt, 0x0800);
    put_ipv4 (icmp_pkt + 14, 1 /* ICMP */, 0x01020304, 0x05060708);
    memset   (icmp_pkt + 34, 0, 20);
    fake_mbuf(&m, icmp_pkt, sizeof(icmp_pkt));
    EXPECT(parse_packet(&m, &meta) == -1,
           "ICMP protocol → -1");

    /* 4d: packet truncated inside IPv4 header (ETH ok, IP header missing bytes) */
    uint8_t trunc[20];   /* 14 ETH + 6 bytes — less than the 20-byte IPv4 header */
    put_eth(trunc, 0x0800);
    memset (trunc + 14, 0x45, 6);
    fake_mbuf(&m, trunc, sizeof(trunc));
    EXPECT(parse_packet(&m, &meta) == -1,
           "truncated IPv4 header → -1");

    /* 4e: IPv4 header present but TCP segment truncated (missing last 4 bytes) */
    uint8_t trunc_tcp[50];   /* 14 + 20 + 16 — TCP needs 20 bytes */
    put_eth  (trunc_tcp,       0x0800);
    put_ipv4 (trunc_tcp + 14, IPPROTO_TCP, 0x01020304, 0x05060708);
    memset   (trunc_tcp + 34, 0, 16);
    fake_mbuf(&m, trunc_tcp, sizeof(trunc_tcp));
    EXPECT(parse_packet(&m, &meta) == -1,
           "truncated TCP header → -1");

    /* 4f: corrupt IHL (IHL=0, ihl_bytes=0 < 20) */
    uint8_t bad_ihl[54];
    put_eth  (bad_ihl,       0x0800);
    put_ipv4 (bad_ihl + 14, IPPROTO_TCP, 0x01020304, 0x05060708);
    bad_ihl[14] = 0x40;          /* version=4, IHL=0 → ihl_bytes = 0 */
    memset   (bad_ihl + 34, 0, 20);
    fake_mbuf(&m, bad_ihl, sizeof(bad_ihl));
    EXPECT(parse_packet(&m, &meta) == -1,
           "corrupt IHL=0 → -1");
}

/* ─── entry point ───────────────────────────────────────────────────────────── */
int main(void)
{
    test_tcp_valid();
    test_udp_valid();
    test_vlan_tagged();
    test_invalid();

    printf("\nResult: %d passed, %d failed\n", g_pass, g_fail);
    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
