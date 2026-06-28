#!/usr/bin/env python3
"""
tools/pcap_gen/gen_pcap.py — SPIFast integration-test PCAP generator.

Pure Python (stdlib only: struct, socket, json, os, argparse).
Produces five test-plan PCAPs plus JSON manifests into tests/pcaps/generated/.

Test plans:
  TP-01  64-byte Ethernet frames, high-PPS (10 000 pkts, Facebook traffic)
  TP-02  1024-byte frames, bulk-throughput (1 000 pkts, YouTube TCP/443)
  TP-03  Full ACL rule coverage (≥10 pkts per group, every rule exercised)
  TP-04  Bidirectional flow (forward + reverse in one PCAP; normalize_flow check)
  TP-05  VLAN-tagged vs untagged (two PCAPs; classification must be identical)

Usage:
    python3 tools/pcap_gen/gen_pcap.py [--out-dir tests/pcaps/generated]
"""

import argparse
import json
import os
import socket
import struct
import sys

# ─── PCAP file format (RFC / Wireshark "classic" PCAP) ──────────────────────
PCAP_MAGIC_LE   = 0xA1B2C3D4   # little-endian timestamps
PCAP_VER_MAJOR  = 2
PCAP_VER_MINOR  = 4
PCAP_SNAPLEN    = 65535
LINKTYPE_ETHERNET = 1

def _pcap_global_header():
    """24-byte global header (little-endian)."""
    return struct.pack('<IHHiIII',
        PCAP_MAGIC_LE,
        PCAP_VER_MAJOR,
        PCAP_VER_MINOR,
        0,               # thiszone (UTC)
        0,               # sigfigs
        PCAP_SNAPLEN,
        LINKTYPE_ETHERNET)

def _pcap_packet_record(data, ts_sec=0, ts_usec=0):
    """16-byte packet record header + data."""
    n = len(data)
    return struct.pack('<IIII', ts_sec, ts_usec, n, n) + data


class PcapWriter:
    """Context-manager that writes PCAP records to a file."""

    def __init__(self, path):
        self._path = path
        self._f    = None
        self._count = 0

    def __enter__(self):
        self._f = open(self._path, 'wb')
        self._f.write(_pcap_global_header())
        return self

    def write(self, frame, ts_sec=0, ts_usec=0):
        self._f.write(_pcap_packet_record(frame, ts_sec, ts_usec))
        self._count += 1

    @property
    def count(self):
        return self._count

    def __exit__(self, *_):
        self._f.close()


# ─── Packet builders ─────────────────────────────────────────────────────────

_SRC_MAC = b'\x02\x00\x00\x00\x00\x01'
_DST_MAC = b'\x02\x00\x00\x00\x00\x02'


def _ipv4_header(src_ip_b: bytes, dst_ip_b: bytes,
                 protocol: int, l4_len: int, pkt_id: int = 1) -> bytes:
    """Minimal IPv4 header (20 bytes).  Checksum left at 0 (PCAP replay is OK)."""
    total_len = 20 + l4_len
    return struct.pack('>BBHHHBBH4s4s',
        0x45,       # version=4, IHL=5 (20 bytes)
        0,          # DSCP/ECN
        total_len,
        pkt_id,
        0x4000,     # DF flag, fragment offset = 0
        64,         # TTL
        protocol,
        0,          # checksum (0 is accepted for PCAP replay)
        src_ip_b,
        dst_ip_b)


def _tcp_header(sport: int, dport: int, seq: int = 0) -> bytes:
    """Minimal TCP header (20 bytes, SYN flag)."""
    # data_offset = 5 (20 bytes), flags = SYN (0x002)
    data_offset_flags = (5 << 12) | 0x002
    return struct.pack('>HHIIHHHH',
        sport, dport,
        seq, 0,             # seq, ack
        data_offset_flags,
        65535,              # window
        0,                  # checksum (0 OK for PCAP)
        0)                  # urgent pointer


def _udp_header(sport: int, dport: int, payload_len: int) -> bytes:
    """8-byte UDP header."""
    return struct.pack('>HHHH',
        sport, dport,
        8 + payload_len,
        0)                  # checksum (0 OK for PCAP)


def _eth_frame(ip_payload: bytes, vlan_id: int | None = None) -> bytes:
    """Build Ethernet II frame.  Optional 802.1Q VLAN tag."""
    if vlan_id is not None:
        # 4-byte 802.1Q tag: EtherType=0x8100, TCI = VID (PCP=0, DEI=0)
        vlan_tag = struct.pack('>HH', 0x8100, vlan_id & 0x0FFF)
        etype    = struct.pack('>H', 0x0800)
        return _DST_MAC + _SRC_MAC + vlan_tag + etype + ip_payload
    else:
        etype = struct.pack('>H', 0x0800)
        return _DST_MAC + _SRC_MAC + etype + ip_payload


def build_tcp(src_ip: str, dst_ip: str, sport: int, dport: int,
              payload_size: int = 10, vlan_id: int | None = None,
              pkt_id: int = 1) -> bytes:
    src_b   = socket.inet_aton(src_ip)
    dst_b   = socket.inet_aton(dst_ip)
    payload = bytes(payload_size)
    tcp_hdr = _tcp_header(sport, dport, seq=pkt_id)
    ip_hdr  = _ipv4_header(src_b, dst_b, 6, len(tcp_hdr) + payload_size, pkt_id)
    return _eth_frame(ip_hdr + tcp_hdr + payload, vlan_id)


def build_udp(src_ip: str, dst_ip: str, sport: int, dport: int,
              payload_size: int = 10, vlan_id: int | None = None,
              pkt_id: int = 1) -> bytes:
    src_b   = socket.inet_aton(src_ip)
    dst_b   = socket.inet_aton(dst_ip)
    payload = bytes(payload_size)
    udp_hdr = _udp_header(sport, dport, payload_size)
    ip_hdr  = _ipv4_header(src_b, dst_b, 17, len(udp_hdr) + payload_size, pkt_id)
    return _eth_frame(ip_hdr + udp_hdr + payload, vlan_id)


def _padded_tcp(src_ip, dst_ip, sport, dport, total_frame_bytes, pkt_id=1):
    """Build TCP frame padded to exactly total_frame_bytes (no VLAN)."""
    eth_hdr  = 14   # 6 + 6 + 2
    ip_hdr   = 20
    tcp_hdr  = 20
    overhead = eth_hdr + ip_hdr + tcp_hdr
    payload_size = max(0, total_frame_bytes - overhead)
    src_b    = socket.inet_aton(src_ip)
    dst_b    = socket.inet_aton(dst_ip)
    payload  = bytes(payload_size)
    tcp      = _tcp_header(sport, dport, seq=pkt_id)
    ip       = _ipv4_header(src_b, dst_b, 6, len(tcp) + payload_size, pkt_id)
    return _eth_frame(ip + tcp + payload)


# ─── Manifest helpers ────────────────────────────────────────────────────────

def _write_manifest(path: str, meta: dict):
    with open(path, 'w') as f:
        json.dump(meta, f, indent=2)
        f.write('\n')


# ─── Test plan generators ────────────────────────────────────────────────────

RULE_FILE = "config/spi_rules.conf"


def gen_tp01(out_dir: str):
    """TP-01: 64-byte Ethernet frames, high PPS (Facebook traffic)."""
    pcap_name = "tp01_64byte_high_pps.pcap"
    pcap_path = os.path.join(out_dir, pcap_name)
    n_pkts    = 10_000
    frame_sz  = 64

    with PcapWriter(pcap_path) as w:
        for i in range(n_pkts):
            frame = _padded_tcp("10.0.0.1", "31.13.64.1",
                                sport=1024 + (i % 60000), dport=80,
                                total_frame_bytes=frame_sz, pkt_id=i)
            w.write(frame, ts_sec=i // 1_000_000, ts_usec=i % 1_000_000)

    _write_manifest(os.path.join(out_dir, "tp01_64byte_high_pps.manifest"), {
        "test_id":        "TP-01",
        "description":    "64-byte Ethernet frames, high PPS",
        "pcap_file":      pcap_name,
        "packet_count":   n_pkts,
        "frame_size":     frame_sz,
        "flows": [{
            "src_ip": "10.0.0.1", "dst_ip": "31.13.64.1",
            "sport":  "1024-61023", "dport": 80, "protocol": "tcp"
        }],
        "vlan":              None,
        "expected_group":    "fg_l34_facebook",
        "expected_action":   "FORWARD",
        "rule_file":         RULE_FILE,
        "generated_by":      "tools/pcap_gen/gen_pcap.py",
    })
    return pcap_path, n_pkts


def gen_tp02(out_dir: str):
    """TP-02: 1024-byte frames, bulk-throughput (YouTube TCP/443)."""
    pcap_name = "tp02_1024byte_throughput.pcap"
    pcap_path = os.path.join(out_dir, pcap_name)
    n_pkts    = 1_000
    frame_sz  = 1024

    with PcapWriter(pcap_path) as w:
        for i in range(n_pkts):
            frame = _padded_tcp("10.0.0.2", "142.250.1.1",
                                sport=5000 + (i % 60000), dport=443,
                                total_frame_bytes=frame_sz, pkt_id=i)
            w.write(frame, ts_sec=0, ts_usec=i * 1000)

    _write_manifest(os.path.join(out_dir, "tp02_1024byte_throughput.manifest"), {
        "test_id":        "TP-02",
        "description":    "1024-byte frames, bulk throughput",
        "pcap_file":      pcap_name,
        "packet_count":   n_pkts,
        "frame_size":     frame_sz,
        "flows": [{
            "src_ip": "10.0.0.2", "dst_ip": "142.250.1.1",
            "sport":  "5000-65000", "dport": 443, "protocol": "tcp"
        }],
        "vlan":             None,
        "expected_group":   "fg_l34_youtube",
        "expected_action":  "FORWARD",
        "rule_file":        RULE_FILE,
        "generated_by":     "tools/pcap_gen/gen_pcap.py",
    })
    return pcap_path, n_pkts


def gen_tp03(out_dir: str):
    """TP-03: Full ACL rule coverage — every group hit at least once.

    Groups (from config/spi_rules.conf):
      fg_l34_facebook  — dst 31.13.64.0/18 (any proto/port)
                        — dst 69.220.144.5 (any proto/port, exact host)
      fg_l34_youtube   — TCP dst 142.250.0.0/15 dport 443 (prefix)
                        — TCP dst 74.125.0.1 dport 443 (exact host)
      fg_l34_http_sdf1003 — TCP any dport 80
      fg_l34_dns_sdf1005  — UDP any dport 53
                          — TCP any dport 53
      DEFAULT          — no rule matches (UDP dport 9999)
    """
    pcap_name = "tp03_acl_coverage.pcap"
    pcap_path = os.path.join(out_dir, pcap_name)
    reps      = 10          # repetitions per rule entry
    flows     = []

    # Flow definitions: (builder, kwargs, group, rule_desc)
    rule_flows = [
        # ── fg_l34_facebook (prefix 31.13.64.0/18 = .0–.63 in third octet)
        ("tcp", dict(src_ip="10.0.0.1", dst_ip="31.13.64.1",  sport=12345, dport=80),
         "fg_l34_facebook", "prefix 31.13.64.0/18"),
        # ── fg_l34_facebook (exact host)
        ("tcp", dict(src_ip="10.0.0.1", dst_ip="69.220.144.5", sport=12345, dport=80),
         "fg_l34_facebook", "exact 69.220.144.5"),
        # ── fg_l34_youtube (prefix 142.250.0.0/15 = 142.250.x.x and 142.251.x.x)
        ("tcp", dict(src_ip="10.0.0.1", dst_ip="142.250.10.1", sport=12345, dport=443),
         "fg_l34_youtube", "prefix 142.250.0.0/15 dport=443"),
        # ── fg_l34_youtube (exact host)
        ("tcp", dict(src_ip="10.0.0.1", dst_ip="74.125.0.1",  sport=12345, dport=443),
         "fg_l34_youtube", "exact 74.125.0.1 dport=443"),
        # ── fg_l34_http_sdf1003 (TCP dport 80, destination outside other rules)
        ("tcp", dict(src_ip="10.0.0.1", dst_ip="93.184.216.34", sport=12345, dport=80),
         "fg_l34_http_sdf1003", "TCP dport=80"),
        # ── fg_l34_dns_sdf1005 UDP
        ("udp", dict(src_ip="10.0.0.1", dst_ip="8.8.8.8",    sport=12345, dport=53),
         "fg_l34_dns_sdf1005", "UDP dport=53"),
        # ── fg_l34_dns_sdf1005 TCP
        ("tcp", dict(src_ip="10.0.0.1", dst_ip="8.8.8.8",    sport=12345, dport=53),
         "fg_l34_dns_sdf1005", "TCP dport=53"),
        # ── DEFAULT (UDP to unmatched destination / port)
        ("udp", dict(src_ip="10.0.0.1", dst_ip="1.2.3.4",    sport=12345, dport=9999),
         "DEFAULT", "no matching rule"),
    ]

    with PcapWriter(pcap_path) as w:
        pkt_id = 0
        for proto, kwargs, _group, _desc in rule_flows:
            for _ in range(reps):
                kwargs["pkt_id"]       = pkt_id
                kwargs["payload_size"] = 10
                if proto == "tcp":
                    frame = build_tcp(**kwargs)
                else:
                    frame = build_udp(**kwargs)
                w.write(frame, ts_sec=0, ts_usec=pkt_id)
                pkt_id += 1

    flows = [
        {"proto": p, **kw, "expected_group": g, "rule_desc": d}
        for p, kw, g, d in rule_flows
    ]
    n_pkts = len(rule_flows) * reps
    _write_manifest(os.path.join(out_dir, "tp03_acl_coverage.manifest"), {
        "test_id":       "TP-03",
        "description":   "Full ACL rule coverage — every group_id appears at least once",
        "pcap_file":     pcap_name,
        "packet_count":  n_pkts,
        "frame_size":    "variable (64-byte padded TCP/UDP)",
        "flows":         flows,
        "vlan":          None,
        "rule_file":     RULE_FILE,
        "generated_by":  "tools/pcap_gen/gen_pcap.py",
        "notes": (
            "Repetitions per rule: " + str(reps) + ". "
            "DEFAULT group uses UDP dport=9999 which matches no specific rule."
        ),
    })
    return pcap_path, n_pkts


def gen_tp04(out_dir: str):
    """TP-04: Bidirectional flow — verify normalize_flow symmetry.

    Forward:  src=10.0.0.1  dst=31.13.64.1  sport=12345  dport=80  TCP
    Reverse:  src=31.13.64.1 dst=10.0.0.1  sport=80    dport=12345 TCP

    normalize_flow rule (SDD §2.3):
      if src_ip > dst_ip: swap(src_ip, dst_ip); swap(src_port, dst_port)

    10.0.0.1 NBO = 0x0A000001 < 31.13.64.1 NBO = 0x1F0D4001
      → forward: no swap → (10.0.0.1, 31.13.64.1, 12345, 80)
      → reverse: src_ip > dst_ip → swap → (10.0.0.1, 31.13.64.1, 12345, 80)
      Both normalise to the same five-tuple. ✓

    Both directions should classify as fg_l34_facebook (dst matches 31.13.64.0/18).
    Both packets are interleaved in a single PCAP.
    """
    pcap_name = "tp04_bidir_flow.pcap"
    pcap_path = os.path.join(out_dir, pcap_name)
    n_per_dir = 500

    with PcapWriter(pcap_path) as w:
        for i in range(n_per_dir):
            # Forward direction
            fwd = build_tcp("10.0.0.1", "31.13.64.1",
                            sport=12345, dport=80, pkt_id=i * 2)
            w.write(fwd, ts_sec=0, ts_usec=i * 2)
            # Reverse direction (swapped IP and port)
            rev = build_tcp("31.13.64.1", "10.0.0.1",
                            sport=80, dport=12345, pkt_id=i * 2 + 1)
            w.write(rev, ts_sec=0, ts_usec=i * 2 + 1)

    n_pkts = n_per_dir * 2
    _write_manifest(os.path.join(out_dir, "tp04_bidir_flow.manifest"), {
        "test_id":      "TP-04",
        "description":  "Bidirectional flow — normalize_flow symmetry check",
        "pcap_file":    pcap_name,
        "packet_count": n_pkts,
        "frame_size":   64,
        "flows": [
            {
                "direction":    "forward",
                "src_ip": "10.0.0.1",   "dst_ip": "31.13.64.1",
                "sport":  12345,         "dport":  80,
                "protocol": "tcp",
                "normalized": "(10.0.0.1, 31.13.64.1, 12345, 80)",
            },
            {
                "direction":    "reverse",
                "src_ip": "31.13.64.1", "dst_ip": "10.0.0.1",
                "sport":  80,           "dport":  12345,
                "protocol": "tcp",
                "normalized": "(10.0.0.1, 31.13.64.1, 12345, 80)",
            },
        ],
        "vlan":              None,
        "expected_group":    "fg_l34_facebook",
        "expected_action":   "FORWARD",
        "rule_file":         RULE_FILE,
        "generated_by":      "tools/pcap_gen/gen_pcap.py",
        "notes": (
            "Forward and reverse packets alternate. "
            "normalize_flow maps both to (10.0.0.1, 31.13.64.1, 12345, 80). "
            "Both must classify as fg_l34_facebook (FORWARD)."
        ),
    })
    return pcap_path, n_pkts


def gen_tp05(out_dir: str):
    """TP-05: VLAN-tagged vs untagged — classification must be identical.

    Both PCAPs carry TCP to 31.13.64.1 dport=80 (→ fg_l34_facebook, FORWARD).
    tp05_untagged.pcap: standard Ethernet II frames (EtherType 0x0800).
    tp05_vlan100.pcap:  802.1Q frames (EtherType 0x8100, VLAN ID 100).

    Parser normalises both to the same five-tuple; classification is identical.
    """
    n_pkts = 500

    # Untagged
    pcap_untagged = "tp05_untagged.pcap"
    path_untagged = os.path.join(out_dir, pcap_untagged)
    with PcapWriter(path_untagged) as w:
        for i in range(n_pkts):
            frame = build_tcp("10.1.0.1", "31.13.64.1",
                              sport=20000 + i, dport=80,
                              vlan_id=None, pkt_id=i)
            w.write(frame, ts_sec=0, ts_usec=i)

    # VLAN 100
    pcap_vlan = "tp05_vlan100.pcap"
    path_vlan  = os.path.join(out_dir, pcap_vlan)
    with PcapWriter(path_vlan) as w:
        for i in range(n_pkts):
            frame = build_tcp("10.1.0.1", "31.13.64.1",
                              sport=20000 + i, dport=80,
                              vlan_id=100, pkt_id=i)
            w.write(frame, ts_sec=0, ts_usec=i)

    common_flow = {
        "src_ip": "10.1.0.1", "dst_ip": "31.13.64.1",
        "sport":  "20000-20499", "dport": 80, "protocol": "tcp",
    }
    for name, vlan in [(pcap_untagged, None), (pcap_vlan, 100)]:
        _write_manifest(os.path.join(out_dir, name.replace('.pcap', '.manifest')), {
            "test_id":       "TP-05",
            "description":   "VLAN-tagged vs untagged — same classification",
            "pcap_file":     name,
            "packet_count":  n_pkts,
            "frame_size":    64 if vlan is None else 68,  # +4 for 802.1Q tag
            "flows":         [common_flow],
            "vlan":          vlan,
            "expected_group":   "fg_l34_facebook",
            "expected_action":  "FORWARD",
            "rule_file":        RULE_FILE,
            "generated_by":     "tools/pcap_gen/gen_pcap.py",
            "notes": (
                "Compare classification of both PCAPs: "
                "result must be identical regardless of VLAN tag presence."
            ),
        })

    return [(path_untagged, n_pkts), (path_vlan, n_pkts)]


# ─── Entry point ─────────────────────────────────────────────────────────────

def main():
    repo_root = os.path.join(os.path.dirname(__file__), '..', '..')
    default_out = os.path.join(repo_root, 'tests', 'pcaps', 'generated')

    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--out-dir', default=default_out,
                   help='Directory for generated PCAPs and manifests '
                        f'(default: {default_out})')
    p.add_argument('--test', choices=['tp01','tp02','tp03','tp04','tp05','all'],
                   default='all', help='Which test plan to generate (default: all)')
    args = p.parse_args()

    out_dir = os.path.realpath(args.out_dir)
    os.makedirs(out_dir, exist_ok=True)

    results = []

    if args.test in ('tp01', 'all'):
        path, n = gen_tp01(out_dir)
        results.append(('TP-01', path, n))

    if args.test in ('tp02', 'all'):
        path, n = gen_tp02(out_dir)
        results.append(('TP-02', path, n))

    if args.test in ('tp03', 'all'):
        path, n = gen_tp03(out_dir)
        results.append(('TP-03', path, n))

    if args.test in ('tp04', 'all'):
        path, n = gen_tp04(out_dir)
        results.append(('TP-04', path, n))

    if args.test in ('tp05', 'all'):
        for path, n in gen_tp05(out_dir):
            results.append(('TP-05', path, n))

    print(f"\nGenerated {len(results)} PCAP(s) in: {out_dir}\n")
    print(f"{'Test':<8} {'Packets':>8}  File")
    print('-' * 60)
    for tid, path, n in results:
        print(f"{tid:<8} {n:>8}  {os.path.basename(path)}")
    print()


if __name__ == '__main__':
    main()
