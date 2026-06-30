# Dàn Bài Báo Cáo — SPIFast: Hệ Thống Kiểm Tra Gói Tin Hiệu Năng Cao Sử Dụng DPDK

**Mục đích tài liệu:** Kế hoạch viết báo cáo. Chưa có nội dung cuối.
**Nguồn sự thật:** Codebase triển khai thực tế (src/), logs/run1.log, logs/run2.log, SRS v1.1, HLD v1.5, SDD v1.4.

---

## I. Giới Thiệu

**Mục đích phần:** Đặt vấn đề — tại sao packet inspection hiệu năng cao là cần thiết và SPIFast giải quyết vấn đề gì. Kết thúc bằng phát biểu mục tiêu cụ thể của đề tài.

### 1.1 Bối cảnh và động lực

- **Nội dung:** Nhu cầu xử lý gói tin tốc độ cao trong mạng hiện đại (firewall, 5G UPF, load balancer). Kernel network stack là bottleneck. DPDK bypass kernel → line-rate trên PC thông thường.
- **Nguồn:** `docs/SRS.md §1.3` (Động Lực Dự Án)

### 1.2 Vấn đề cần giải quyết

- **Nội dung:** Shallow Packet Inspection (SPI) vs Deep Packet Inspection — phân loại gói tin dựa trên header L2-L4 mà không cần phân tích payload. Thách thức: đạt Mpps/Gbps trên single machine mà không có hardware NIC chuyên dụng.
- **Nguồn:** `docs/SRS.md §1.2` (Phạm Vi), `docs/SRS.md §1.3`

### 1.3 Mục tiêu đề tài

- **Nội dung:** Liệt kê 5–6 mục tiêu chính: (1) xây dựng pipeline SPI 5-stage trên DPDK; (2) triển khai flat ACL engine; (3) đo throughput/PPS; (4) xác nhận packet accounting; (5) phân tích bottleneck.
- **Nguồn:** `docs/SRS.md §1.4` (bảng OBJ-01 → OBJ-0x)

### 1.4 Phạm vi và giới hạn

- **Nội dung:** Trong phạm vi (PCAP replay, IPv4, L2-L4 header, đa lõi cấu hình được). Ngoài phạm vi (NIC vật lý, IPv6, DPI, stateful tracking, dynamic rule update).
- **Nguồn:** `docs/SRS.md §1.2`

---

## II. Nội Dung và Phương Pháp

**Mục đích phần:** Trình bày kiến trúc hệ thống và các quyết định thiết kế. Đây là phần nặng nhất về mặt kỹ thuật.

### 2.1 Tổng quan DPDK

- **Nội dung:** DPDK là gì — EAL, Poll Mode Driver (PMD), rte_mbuf, rte_ring, rte_mempool, rte_acl. Mô hình "lcore pinning" và "busy-poll loop". Vì sao kernel bypass → latency thấp, throughput cao.
- **Nguồn:** `docs/HLD.md §1.1`, `docs/HLD.md §1.2` (Nền Tảng Công Nghệ), `docs/SRS.md §1.3`

### 2.2 Kiến trúc pipeline 5-stage

- **Nội dung:** Sơ đồ luồng tổng thể: File PCAP → RX lcore → parser_ring → Parser lcore → worker_ring[i] → Worker lcore(s) → tx_ring → TX lcore. Giải thích: tại sao phân tách 5 lcore, mô hình SPSC/MPSC ring, zero-copy mbuf ownership.
- **Nguồn:** `docs/HLD.md §1.3` (sơ đồ pipeline và bảng vai trò lcore), `docs/SDD.md §6.1` (luồng tổng thể)

### 2.3 RX lcore — đọc PCAP và replay liên tục

- **Nội dung:** Cơ chế libpcap (`pcap_open_offline` + `pcap_next_ex`). Tại sao dùng libpcap thay net_pcap PMD: kiểm soát chính xác EOF và replay. Continuous loop: EOF → `pcap_close` → `pcap_loops++` → mở lại. `rte_pktmbuf_alloc` + `rte_memcpy`. Shutdown chỉ qua SIGINT/SIGTERM. Counters: `rx_packets`, `rx_bytes`, `alloc_fail`, `parser_ring_drop`, `pcap_loops`.
- **Nguồn:** `docs/HLD.md §2.2`, `docs/SDD.md §2.2` (pseudocode), `src/packet/rx.c`

### 2.4 Parser lcore — phân tích header và điều phối luồng

- **Nội dung:** Parse Ethernet → VLAN (optional) → IPv4 → TCP/UDP. Five-tuple trích xuất vào `pkt_meta_t` (16 bytes, ghi vào mbuf headroom tại `rte_pktmbuf_mtod(m) - 16`). Flow normalization stateless: src_ip nhỏ hơn ở src position. Hash dispatch: `rte_hash_crc(meta, 16, 0) % N_workers` → enqueue vào `worker_ring[i]`.
- **Nguồn:** `docs/HLD.md §2.3`, `docs/SDD.md §3.1` (pkt_meta_t layout), `docs/SDD.md §4.1–4.3`, `src/packet/parser.c`, `src/packet/pkt_ctx.h`

### 2.5 Hệ thống rule — flat ACL engine

- **Nội dung:** Mô hình filter-group / filter: mỗi group có precedence và action (FORWARD/DROP); mỗi rule gắn với một group, định nghĩa 5-tuple matching condition. File cấu hình `config/spi_rules.conf`: format text, `[group: name] precedence=N action=X` + rule entries. Rule loader parse → `flat_rule_table_t`.
- Mô tả rule test: 13 rules, 105 groups (100 test groups fg_test_001–100, plus fg_l34_facebook, fg_l34_youtube, fg_l34_http_sdf1003, fg_l34_dns_sdf1005, DEFAULT).
- **Phase 3 (triển khai hiện tại):** `acl_engine_build()` tạo `g_sorted_idx[]` bằng `qsort()` theo precedence. `flat_acl_match_burst()` thực hiện linear scan per-packet qua `g_sorted_idx[]`, gọi `rule_matches()` kiểm tra tường minh từng trường. Kết quả: `const flat_rule_entry_t *`.
- **Phase 4 (kế hoạch):** Thay bằng `rte_acl_classify()` một lần mỗi burst — SIMD/AVX2.
- **Nguồn:** `docs/HLD.md §2.4`, `docs/SDD.md §4.5` (Phase 3 vs Phase 4), `docs/SDD.md §4.6–4.12`, `config/spi_rules.conf`, `src/rule/acl_engine.c`, `src/rule/rule_loader.c`

### 2.6 Worker lcore — ACL classify và action dispatch

- **Nội dung:** Dequeue từ `worker_ring[i]`, đọc `pkt_meta_t` từ headroom, gọi `flat_acl_match_burst()` cho toàn batch. FORWARD → enqueue `tx_ring`; DROP → free mbuf ngay. Per-worker `group_hits[SPIFAST_MAX_GROUPS]` trong `worker_ctx_t` (không phải `worker_lcore_stats_t`).
- **Nguồn:** `docs/HLD.md §2.5`, `docs/SDD.md §4.7` (Worker lcore flow), `src/worker/worker.c`

### 2.7 TX lcore — ghi ra net_pcap port

- **Nội dung:** Dequeue từ `tx_ring` (MPSC, 65536 slot). Ghi `lens[i] = m->pkt_len` TRƯỚC `rte_eth_tx_burst()` (tránh PMD free mbuf). Tích lũy `tx_bytes` chỉ cho packet đã sent thành công. `tx_pkts`, `tx_drop`.
- **Nguồn:** `docs/HLD.md §2.6`, `docs/SDD.md §6.5`, `src/tx/tx.c`

### 2.8 Thu thập thống kê và logging

- **Nội dung:** Stats module thu thập mỗi 1 giây. Throughput = `tx_bytes_delta × 8 / interval / 1e6` (chỉ forwarded). PPS = forwarded packets / interval. `group_hits` aggregate từ `worker_ctxs[i].group_hits[]`. Packet accounting (FR-032): loại trừ `parser_ring_drop`, ngưỡng 0,1% (PERF_SUCCESS=0.001). Logging: stdout + file (append), ISO 8601 timestamps. perf_stats module: `rte_rdtsc()` trước/sau mỗi stage, sample rate 1/1000 burst.
- **Nguồn:** `docs/HLD.md §7.2–7.5`, `docs/SDD.md §8.1`, `docs/SDD.md §8.4`, `src/stats/stats.c`, `src/logging/log.c`, `src/perf/perf_stats.h`

### 2.9 PCAP test và môi trường kiểm thử

- **Nội dung:** 6 PCAP test files được generate bằng `tools/pcap_gen/gen_pcap.py`:

  | File | Mục đích |
  |---|---|
  | `tp01_small.pcap` | Max PPS (small frame) |
  | `tp02_1024byte_throughput.pcap` | Max Mbps (1024-byte frame) |
  | `tp03_acl_coverage.pcap` | Bao phủ toàn bộ ACL rules |
  | `tp04_bidir_flow.pcap` | Bidirectional flow normalization |
  | `tp05_untagged.pcap` | Untagged Ethernet |
  | `tp05_vlan100.pcap` | VLAN 100 tagged |

  Unit tests: `tests/test_parser.c`, `tests/test_acl.c`, `tests/test_rule_loader.c`.
- **Nguồn:** `tests/pcaps/generated/*.manifest`, `tests/test_*.c`, `docs/SRS.md §8`

---

## III. Kết Quả Thực Hiện và Đánh Giá

**Mục đích phần:** Trình bày kết quả đo được từ log thực tế, đánh giá so với yêu cầu SRS, và phân tích các quan sát bất ngờ.

### 3.1 Kết quả chức năng

- **Nội dung:** Xác nhận các tính năng đã được triển khai đầy đủ:
  - Pipeline 5-stage hoạt động: RX → Parser → Worker(s) → TX
  - Rule loader: 13 rules, 105 groups load thành công (log `RULES_LOADED count=13 groups=105`)
  - Flow normalization: bidirectional test tp04 pass
  - VLAN parsing: tp05_vlan100 pass
  - Continuous PCAP replay: pcap_loops=285 (run1), 4187–4304 (run2)
  - GROUP_HITS: `fg_l34_facebook` nhận toàn bộ traffic → rule matching chính xác
  - PACKET_ACCOUNTING: `result=PASS` (delta/rx ≤ 0,1%) trong các session ổn định
- **Nguồn:** `logs/run1.log` (SESSION_END, RULES_LOADED, GROUP_HITS, PACKET_ACCOUNTING), `logs/run2.log`, `docs/architecture_validation.md`

### 3.2 Kết quả hiệu năng — 1 worker (run1.log)

- **Nội dung:** Kết quả tốt nhất với cấu hình 1 worker:
  - **Throughput:** 2066,91 Mbps (session ngắn), ổn định ~2000–2050 Mbps
  - **PPS:** 4.036.930 pps (~4 Mpps)
  - **Packet accounting:** PASS — delta/rx_total ≤ 0,1%; `total_rx=2.850.417`, `total_fwd=2.850.384`, `total_drop=0`, `total_p_ring_drop=0`, `total_w_ring_drop=0`
  - **PCAP:** tp01_small.pcap, small frames → max PPS scenario
- **Nguồn:** `logs/run1.log` (SUMMARY, THROUGHPUT_AVG, PPS_AVG, PACKET_ACCOUNTING line đầu tiên)

### 3.3 Kết quả hiệu năng — 2 workers (run2.log)

- **Nội dung:** Kết quả với cấu hình 2 workers:
  - **Throughput:** 1854–1895 Mbps (giảm ~8–10% so với 1 worker)
  - **PPS:** 3.622.000–3.701.000 pps (giảm ~10% so với 1 worker)
  - **w_ring_drop:** xuất hiện trong một số session (`w_ring_drop=1126–6473`) khi ring 4096 đầy
  - **Packet accounting:** PASS overall (w_ring_drop được tính vào `pipe_drops`, delta/rx ≤ 0,1%)
  - **Quan sát:** 2 workers không cải thiện throughput — thực tế giảm.
- **Nguồn:** `logs/run2.log` (các SUMMARY, THROUGHPUT_AVG, PPS_AVG, PACKET_ACCOUNTING)

### 3.4 Phân tích bottleneck: tại sao 2 workers không cải thiện throughput

- **Nội dung:** Phân tích 3 nguyên nhân chính:
  1. **Parser single-threaded là bottleneck:** Parser lcore đơn lẻ phải parse + hash dispatch cho toàn bộ traffic. Thêm worker không giúp ích nếu Parser không đủ nhanh để cấp gói tin.
  2. **worker_ring[i] nhỏ (4096) tương phản với parser_ring (65536):** Khi 2 workers, mỗi worker nhận ~50% traffic nhưng ring buffer nhỏ hơn 16 lần so với đầu vào → nguy cơ overflow cao hơn → w_ring_drop quan sát thấy.
  3. **MPSC tx_ring CAS overhead:** 2 workers cùng enqueue vào tx_ring (MPSC) → CAS contention tăng theo số writer.
  4. **Phase 3 linear scan:** ACL O(N_rules) per-packet không scale với worker count — chi phí per-packet ở worker nhỏ hơn chi phí overhead coordination.
- **Nguồn:** `logs/run2.log` (w_ring_drop field), `docs/HLD.md §4.6` (bottleneck table), `docs/IMPLEMENTATION_DEVIATION_REPORT.md` (D-10, D-03), `src/dpdk/dpdk_init.h` (RING_SIZE=4096 vs PARSER_RING=65536)

### 3.5 Đánh giá so với yêu cầu SRS

- **Nội dung:** Bảng đối chiếu:

  | Yêu cầu SRS | Giá trị yêu cầu | Kết quả đo được | Trạng thái |
  |---|---|---|---|
  | PR-001: Throughput | ≥ 1 Gbps (1000 Mbps) | 2067 Mbps (1W), 1895 Mbps (2W) | ĐẠT |
  | PR-002: PPS | ≥ 1 Mpps | 4,04 Mpps (1W), 3,70 Mpps (2W) | ĐẠT |
  | PR-005: Drop rate | ≤ 0,1% | 0% (1W), < 0,01% (2W) | ĐẠT |
  | FR-032: Packet accounting | delta/rx ≤ 0,1% | PASS tất cả session ổn định | ĐẠT |
  | FR-019: Rule model | Filter-group / filter hierarchy | 13 rules, 105 groups | ĐẠT |

  Các yêu cầu không đo được trong session này: IPv6 (ngoài phạm vi), hardware NIC (ngoài phạm vi).
- **Nguồn:** `docs/SRS.md §5` (Performance Requirements), `logs/run1.log`, `logs/run2.log`

### 3.6 Những điểm sai lệch so với thiết kế ban đầu (design evolution)

- **Nội dung:** Tóm tắt ngắn các thay đổi kiến trúc đáng chú ý (không phải bug — là quyết định kỹ thuật):
  1. RX: libpcap thay net_pcap PMD (D-01) — linh hoạt hơn, kiểm soát EOF tốt hơn
  2. ACL: 1 stage thay 2 stage (D-02) — đơn giản hóa, đủ cho use case hiện tại
  3. ACL implementation: Phase 3 linear scan thay `rte_acl_classify` (D-03) — ưu tiên correctness trước performance
  4. Shutdown: SIGINT/SIGTERM thay EOF cascade (D-05) — deterministic, không phụ thuộc PCAP file
  5. Throughput: forwarded bytes only (D-06) — phản ánh chính xác traffic ra NIC
  6. pkt_meta_t: 16 bytes thay 12 bytes (D-08) — thêm VLAN fields
- **Nguồn:** `docs/IMPLEMENTATION_DEVIATION_REPORT.md` (D-01 đến D-10), `docs/architecture_validation.md`

---

## IV. Kết Luận

**Mục đích phần:** Tổng kết những gì đã đạt được, thừa nhận hạn chế hiện tại, và đề xuất hướng phát triển tiếp theo.

### 4.1 Tổng kết kết quả

- **Nội dung:** SPIFast đã triển khai thành công pipeline SPI 5-stage trên DPDK, đạt >2 Gbps và >4 Mpps với 1 worker trên phần cứng PC thông thường, vượt yêu cầu SRS. Packet accounting PASS. Rule engine flat ACL hoạt động chính xác (GROUP_HITS khớp traffic).
- **Nguồn:** `logs/run1.log` (THROUGHPUT_AVG=2066.91, PPS=4036930), `docs/SRS.md §5`

### 4.2 Hạn chế hiện tại

- **Nội dung:**
  1. **Phase 3 ACL linear scan:** O(N_rules) per-packet — sẽ degraded khi rule count lớn. Phase 4 (`rte_acl_classify` SIMD) chưa triển khai.
  2. **Parser single-threaded:** Bottleneck khi scale lên nhiều workers.
  3. **worker_ring asymmetry:** RING_SIZE=4096 nhỏ hơn nhiều so với parser_ring=65536 → w_ring_drop ở tải cao.
  4. **Chỉ hỗ trợ IPv4:** IPv6 ngoài phạm vi.
  5. **PCAP replay, không có NIC vật lý:** Kết quả không phản ánh latency I/O thực tế.
- **Nguồn:** `docs/HLD.md §4.6`, `docs/IMPLEMENTATION_DEVIATION_REPORT.md` (D-03, D-10), `docs/SDD.md §4.5`

### 4.3 Hướng phát triển tiếp theo

- **Nội dung:**
  1. **Phase 4:** Migrate sang `rte_acl_classify()` — SIMD/AVX2 batch matching → giảm ACL latency, scale tốt hơn với rule count lớn.
  2. **Tăng worker_ring size** từ 4096 → 65536 hoặc cân bằng với parser_ring để giảm w_ring_drop.
  3. **Multi-parser:** Scale Parser lcore để không còn là single-threaded bottleneck.
  4. **Hardware NIC integration:** Thay libpcap bằng DPDK PMD thực tế (e.g., VFIO, mlx5) để đo line-rate thực.
  5. **IPv6 support** nếu mở rộng phạm vi.
- **Nguồn:** `docs/HLD.md §4.6`, `docs/SDD.md §4.5` (Phase 3 vs Phase 4 migration warning), `docs/IMPLEMENTATION_DEVIATION_REPORT.md` (Required doc update cho D-03, D-10)

---

## Tài Liệu Tham Khảo

**Mục đích phần:** Liệt kê nguồn chính thức để người đọc tra cứu.

- **[1] DPDK Documentation** — Data Plane Development Kit programmer's guide, API reference. dpdk.org.
  - Relevant APIs: `rte_mbuf`, `rte_ring`, `rte_acl`, `rte_mempool`, `rte_hash_crc`, `rte_rdtsc`, `rte_eth_tx_burst`.

- **[2] SRS** — SPIFAST-SRS-001 v1.1. Đặc Tả Yêu Cầu Phần Mềm. `docs/SRS.md`.

- **[3] HLD** — SPIFAST-HLD-001 v1.5. Thiết Kế Mức Cao. `docs/HLD.md`.

- **[4] SDD** — SPIFAST-SDD-001 v1.4. Thiết Kế Chi Tiết Phần Mềm. `docs/SDD.md`.

- **[5] IMPLEMENTATION_DEVIATION_REPORT** — Báo cáo sai lệch thiết kế - triển khai. `docs/IMPLEMENTATION_DEVIATION_REPORT.md`.

- **[6] libpcap** — `pcap_open_offline(3)`, `pcap_next_ex(3)`. tcpdump.org.

- **[7] Intel, "DPDK Performance Report"** — các phiên bản chính thức, dpdk.org/perf-reports.

- **[8] RFC 791** — Internet Protocol (IPv4). IETF.

- **[9] IEEE 802.1Q** — Virtual Bridged Local Area Networks (VLAN tagging).

- **[10] Source code** — `src/` directory, commit `bd0bdb3` (branch main).
  - Các file chính: `src/main.c`, `src/packet/rx.c`, `src/packet/parser.c`, `src/worker/worker.c`, `src/rule/acl_engine.c`, `src/tx/tx.c`, `src/stats/stats.c`, `src/logging/log.c`, `src/perf/perf_stats.h`.

- **[11] Run logs** — `logs/run1.log` (workers=1), `logs/run2.log` (workers=2). Ngày: 2026-06-30.

---

## Ghi Chú Viết

- **Ngôn ngữ:** Tiếng Việt kỹ thuật. Giữ nguyên thuật ngữ tiếng Anh không có bản dịch tốt (lcore, burst, zero-copy, ring, mbuf, ACL, PMD, libpcap, VLAN, five-tuple).
- **Không dùng số tương lai:** Mọi số liệu phải từ log thực (run1.log, run2.log) — không ước tính.
- **Phần III.3.4 là điểm nổi bật:** Quan sát 2 workers < 1 worker là kết quả bất ngờ, cần giải thích rõ ràng với bằng chứng từ log (w_ring_drop) và phân tích kiến trúc.
- **Bảng trong III.3.5:** Điền số SRS thực tế từ `docs/SRS.md §5` trước khi viết — kiểm tra lại giá trị PR-001, PR-002, PR-005.
- **Thứ tự ưu tiên khi viết:** II.2.2 (pipeline) → II.2.5 (ACL) → III.3.2–3.3 (kết quả) → III.3.4 (bottleneck analysis) → I, IV viết cuối.
