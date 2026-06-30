# Thiết Kế Mức Cao

---

**Tiêu đề tài liệu:** Thiết Kế Mức Cao — SPIFast: Hệ Thống Kiểm Tra Gói Tin Hiệu Năng Cao Sử Dụng DPDK

**Mã tài liệu:** SPIFAST-HLD-001

**Phiên bản:** 1.4

**Trạng thái:** Draft

**Người soạn thảo:** Nhóm Kỹ Thuật Hệ Thống

**Ngày:** 2026-06-30

**SRS áp dụng:** SPIFAST-SRS-001 v1.0

---

## Lịch Sử Sửa Đổi

| Phiên bản | Ngày | Tác giả | Mô tả |
|---|---|---|---|
| 0.1 | 2025-06-26 | Kỹ thuật hệ thống | Bản thảo HLD ban đầu, căn chỉnh theo SRS baseline |
| 1.0 | 2025-06-26 | Kỹ thuật hệ thống | Baseline HLD để rà soát thiết kế |
| 1.1 | 2025-06-26 | Kỹ thuật hệ thống | Dịch sang tiếng Việt; bổ sung thành phần Statistics and Logging Component tách biệt |
| 1.2 | 2025-06-26 | Kỹ thuật hệ thống | Bổ sung tối ưu hóa data plane: batch ACL classify, parser prefetch, metadata qua mbuf headroom, SPSC ring, hugepage và CPU isolation |
| 1.3 | 2025-06-26 | Kỹ thuật hệ thống | Cập nhật kiến trúc pipeline 5 giai đoạn: tách Parser thành lcore riêng; chuyển ACL classify xuống Worker (batch, two-stage); bổ sung TX lcore chuyên biệt; hash dispatch tại Parser; ring ba tầng SPSC/SPSC/MPSC |
| 1.4 | 2026-06-30 | Kỹ thuật hệ thống | Đồng bộ hóa tài liệu với flat ACL implementation: thay thế two-stage ACL (stage1_ctx + group_ctx[]) bằng single-stage flat ACL (flat_acl_ctx + flat_rule_table_t); loại bỏ filter_group_table, lazy build, LRU eviction; cập nhật DD-15; cập nhật luồng xử lý |
| 1.5 | 2026-06-30 | Kỹ thuật hệ thống | Đồng bộ hóa với implementation cuối: RX lcore dùng libpcap thay net_pcap PMD; replay liên tục (continuous loop) thay single-pass; shutdown qua SIGINT/SIGTERM thay EOF cascade; throughput chỉ đo forwarded bytes (tx_bytes); packet accounting loại trừ parser_ring_drop và dùng ngưỡng 0,1%; bổ sung worker_ring size vào phân tích bottleneck; cập nhật DD-06, DD-15 |

---

## Mục Lục

1. Tổng Quan Kiến Trúc Hệ Thống
2. Thiết Kế Thành Phần
3. Luồng Xử Lý Gói Tin
4. Thiết Kế Kiến Trúc Đa Lõi
5. Kiến Trúc Quản Lý Rule
6. Kiến Trúc Lưu Lượng và Kiểm Thử
7. Kiến Trúc Đo Hiệu Năng
8. Quyết Định Thiết Kế
9. Hướng Mở Rộng Tương Lai

---

## 1. Tổng Quan Kiến Trúc Hệ Thống

### 1.1 Tổng Quan

SPIFast là hệ thống Shallow Packet Inspection (SPI) chạy trong userspace, bỏ qua kernel (kernel-bypass), được xây dựng trên nền tảng Data Plane Development Kit (DPDK). Hệ thống vận hành như một instance ứng dụng đơn lẻ trên máy chủ Linux, tiêu thụ lưu lượng gói tin từ NIC vật lý hoặc file PCAP thông qua DPDK PMD. Hệ thống phân loại gói tin theo bộ ACL rule được nạp tĩnh, điều phối gói tin đến các Worker Core xử lý song song, và truyền kết quả ra NIC TX.

Thiết kế được xây dựng trên ba nguyên tắc kiến trúc cốt lõi:

- **Kernel bypass:** Toàn bộ I/O gói tin và xử lý đều diễn ra trong userspace thông qua DPDK, loại bỏ overhead của kernel network stack trên data path.
- **Giao tiếp liên lõi lock-free:** Giao tiếp data path giữa các giai đoạn pipeline sử dụng cấu trúc ring lock-free của DPDK, ngăn ngừa suy giảm Throughput do tranh chấp tài nguyên.
- **Phân loại gói tin phi trạng thái theo từng gói:** Mỗi gói tin được phân loại độc lập bằng cách tra cứu five-tuple đã chuẩn hóa, không duy trì trạng thái theo từng luồng, cho phép vận hành với Throughput cao và ổn định.

### 1.2 Mô Hình Triển Khai

SPIFast được triển khai dưới dạng ứng dụng đơn tiến trình trên máy Linux tiêu chuẩn. Các điều kiện tiên quyết triển khai bao gồm:

- Hệ điều hành Linux (khuyến nghị Ubuntu 20.04 LTS trở lên)
- DPDK đã được cài đặt và cấu hình (phiên bản cụ thể được chỉ định trong SDD)
- Hugepages được cấp phát trước khi khởi chạy ứng dụng:

```
echo 2048 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
```

  Lệnh trên cấp phát 2048 hugepage kích thước 2 MB, tổng cộng 4 GB hugepage memory. Đây là dung lượng đủ để đáp ứng toàn bộ nhu cầu mempool, ring buffer và ACL context của SPIFast với margin dự phòng thoải mái.

- Đủ lõi CPU để gán độc quyền cho DPDK lcore. Cấu hình tối thiểu: **N + 4 lcore** gồm 1 RX + 1 Parser + N Worker + 1 TX + 1 Main. Với N = 1 worker, tối thiểu cần 5 lcore.
- Cô lập CPU được khuyến nghị để tránh OS scheduler và interrupt xâm nhập vào data path lcore:

```
isolcpus=2-11
```

  Tham số kernel này dành riêng các CPU từ 2 đến 11 cho DPDK, giữ CPU 0 và 1 cho OS và control plane. Cần thêm vào kernel command line trong `/etc/default/grub` và chạy `update-grub`.

- Không có ứng dụng DPDK nào khác chạy đồng thời trên cùng máy trong quá trình thực thi kiểm thử.

Người vận hành cung cấp hai đầu vào khi khởi chạy: đường dẫn file PCAP (hoặc tham số NIC vật lý) và đường dẫn file cấu hình rule. Hệ thống xử lý lưu lượng liên tục và xuất tóm tắt thống kê cuối phiên khi kết thúc.

### 1.3 Các Giai Đoạn Xử Lý Chính

Pipeline xử lý của SPIFast gồm 5 giai đoạn tuần tự, mỗi giai đoạn chạy trên một hoặc nhiều lcore chuyên biệt:

```
+---------------------------+
|   File PCAP (đĩa)         |
|   libpcap: pcap_next_ex() |
+-------------+-------------+
              |
              v
+---------------------------+
|   RX lcore                |
|  pcap_next_ex()           |
|  rte_pktmbuf_alloc()      |
|  rte_memcpy(data→mbuf)    |
|  Enqueue → parser_ring    |
+-------------+-------------+
              |  parser_ring (SPSC)
              v
+---------------------------+
|   Parser lcore            |
|  Prefetch mbuf data       |
|  Parse L2/VLAN/L3/L4      |
|  Flow normalization        |
|  Ghi metadata → headroom  |
|  Hash five-tuple           |
|  Dispatch → worker_ring[i]|
+-------------+-------------+
              |  worker_ring[i] (SPSC, mỗi worker 1 ring)
              v
+---------------------------+
|   Worker lcore(s) × N     |
|  Dequeue burst            |
|  Đọc metadata từ headroom |
|  Single-stage flat ACL    |
|    classify               |
|  Tra cứu action O(1)      |
|    từ flat_rule_table     |
|  FORWARD → tx_ring        |
|  DROP → rte_pktmbuf_free  |
+------+--------------------+
       |  tx_ring (MPSC)
       v
+---------------------------+
|   TX lcore                |
|  Dequeue từ tx_ring       |
|  rte_eth_tx_burst()       |
|  Sở hữu TX queue          |
+-------------+-------------+
              |
              v
+---------------------------+
|   NIC TX                  |
+---------------------------+

+------------------------------------------+
|   Main lcore                             |
|  Khởi tạo, nạp rule                     |
|  Statistics Timer (thu thập per-lcore)   |
|  Logging (stdout + file)                 |
|  Điều phối tắt máy                      |
+------------------------------------------+
```

**Mô tả các giai đoạn:**

| Giai đoạn | lcore | Mục đích |
|---|---|---|
| File PCAP / libpcap | — | Nguồn lưu lượng; RX lcore đọc qua `pcap_next_ex()`; net_pcap port chỉ được dùng cho TX |
| RX lcore | 1 | `pcap_next_ex()` + `rte_pktmbuf_alloc()` + `rte_memcpy()`; replay liên tục (continuous loop); enqueue mbuf pointer vào parser_ring |
| Parser lcore | 1 | Prefetch mbuf data; parse L2/VLAN/L3/L4; flow normalization; ghi five-tuple metadata vào mbuf headroom; hash dispatch chọn worker_ring |
| Worker lcore(s) | N | Single-stage flat ACL classify; tra cứu action O(1) từ flat_rule_table; áp dụng FORWARD/DROP; enqueue mbuf vào tx_ring (FORWARD) hoặc free mbuf (DROP) |
| TX lcore | 1 | Drain tx_ring; rte_eth_tx_burst() ra NIC TX; sở hữu TX queue duy nhất |
| Main lcore | 1 | Init, rule loading, statistics aggregation, logging, shutdown coordination |

---

## 2. Thiết Kế Thành Phần

### 2.1 Thành Phần Khởi Tạo DPDK

**Trách nhiệm:**

Thành phần Khởi Tạo DPDK là hệ thống con đầu tiên thực thi khi ứng dụng khởi động. Thành phần này chịu trách nhiệm đưa môi trường runtime DPDK vào trạng thái hoạt động đầy đủ trước khi bất kỳ gói tin nào được nhận hoặc bất kỳ rule nào được đánh giá. Ngoài ra mở file log (nếu được cấu hình) trong giai đoạn khởi tạo và truyền file handle cho Logging Component trước khi bắt đầu xử lý gói tin. Đóng file handle khi tắt máy.

Các trách nhiệm cụ thể bao gồm:

- Phân tích tham số EAL từ dòng lệnh và khởi tạo DPDK Environment Abstraction Layer (EAL), thiết lập ánh xạ lcore-to-CPU affinity, memory channel mapping và hugepage backing.
- Cấp phát và cấu hình một hoặc nhiều DPDK mempool từ bộ nhớ hugepage để làm nguồn cung cấp đối tượng mbuf trong suốt vòng đời ứng dụng. Kích thước mempool phải tính đến số lượng mbuf đang in-flight tối đa trên tất cả giai đoạn pipeline và ring buffer, bao gồm cả tx_ring.
- Cấu hình NIC port hoặc PMD virtual device `net_pcap`, liên kết với đường dẫn file PCAP hoặc NIC vật lý được cung cấp qua dòng lệnh. Port được cấu hình với một RX queue và một TX queue.
- Khởi tạo toàn bộ cấu trúc ring lock-free của DPDK cho ba tầng giao tiếp: parser_ring (SPSC), worker_ring[i] (SPSC mỗi worker), và tx_ring (MPSC).
- Ghim các lcore vào vai trò được chỉ định: RX lcore, Parser lcore, N Worker lcore, TX lcore, và Main lcore.

Nếu bất kỳ bước khởi tạo nào thất bại, thành phần này phát ra thông báo lỗi mô tả rõ hệ thống con bị lỗi và kết thúc ứng dụng. Trạng thái khởi tạo một phần không được phép; ứng dụng không tiến hành xử lý gói tin trừ khi tất cả tài nguyên đã được cấp phát và cấu hình đầy đủ.

### 2.2 Thành Phần Nhận Gói Tin (Packet Receive — RX lcore)

**Trách nhiệm:**

Thành phần Nhận Gói Tin vận hành trên RX lcore được dành riêng. Thành phần này đọc packet từ file PCAP qua **libpcap** (`pcap_next_ex`), cấp phát mbuf thủ công từ mempool, copy dữ liệu packet vào mbuf, và enqueue vào `parser_ring`. Replay là **continuous loop** — sau khi hết file PCAP, RX lcore đóng và mở lại file từ đầu, không bao giờ tự khởi tạo shutdown. DPDK net_pcap port vẫn được giữ active chỉ để TX lcore gọi `rte_eth_tx_burst()`.

Các trách nhiệm cụ thể bao gồm:

- Gọi `pcap_open_offline(pcap_path, ...)` để mở file PCAP. Tích lũy packet vào batch tới `SPIFAST_BURST_SIZE`, rồi flush bằng `rte_ring_enqueue_burst(parser_ring, ...)`.
- Với mỗi packet: `pcap_next_ex()` → `rte_pktmbuf_alloc()` → `rte_memcpy(rte_pktmbuf_mtod(m), data, caplen)` → set `m->data_len` và `m->pkt_len`.
- Xử lý `alloc_fail`: nếu `rte_pktmbuf_alloc()` trả về NULL (mempool cạn), tăng `alloc_fail` counter và bỏ qua packet.
- Xử lý `parser_ring` đầy: free mbuf, tăng `parser_ring_drop`.
- Khi EOF (`pcap_next_ex` trả về -2): đóng handle, tăng `pcap_loops`, mở lại file từ đầu. **Không đặt `g_shutdown_flag`**.
- Thoát vòng lặp khi `g_shutdown_flag == 1` (được đặt bởi SIGINT/SIGTERM handler).
- Duy trì `rx_lcore_stats`: `rx_packets`, `rx_bytes`, `alloc_fail`, `parser_ring_drop`, `pcap_loops`.

RX lcore không thực hiện parse header, ACL lookup, hay bất kỳ lightweight hash nào.

### 2.3 Thành Phần Phân Tích Gói Tin (Packet Parser — Parser lcore)

**Trách nhiệm:**

Thành phần Packet Parser vận hành trên một Parser lcore chuyên biệt, tách biệt hoàn toàn khỏi RX lcore. Parser dequeue mbuf từ parser_ring, thực hiện toàn bộ quá trình phân tích header và điều phối gói tin đến worker phù hợp.

**Chuỗi xử lý:**

1. **Dequeue burst từ parser_ring:** Parser lcore drain parser_ring bằng `rte_ring_dequeue_burst()`, nhận batch mbuf pointer từ RX lcore.

2. **Prefetch mbuf data (tối ưu hóa cache):** Trước khi parse từng mbuf, Parser phát lệnh `rte_prefetch0()` cho dữ liệu mbuf của các packet tiếp theo trong batch. Điều này che giấu cache miss latency khi truy cập dữ liệu gói tin lần đầu, cải thiện hiệu quả sử dụng CPU đáng kể đặc biệt với 64-byte frames.

3. **Phân tích Ethernet header (FR-005):** Đọc 14-byte Ethernet II header. Trích xuất trường EtherType để xác định giao thức lớp tiếp theo.

4. **Xử lý VLAN header (FR-006):** Nếu EtherType bằng `0x8100` (IEEE 802.1Q), parser bóc VLAN tag 4 byte và đọc lại inner EtherType. VLAN ID được giữ lại như metadata chẩn đoán tùy chọn.

5. **Phân tích IPv4 header (FR-007):** Nếu EtherType bằng `0x0800`, parser giải mã IPv4 header, trích xuất IP nguồn, IP đích, số giao thức IP và IHL. Các gói tin có EtherType khác bị hủy; counter giao thức không hỗ trợ được tăng lên.

6. **Phân tích header tầng giao vận (FR-008):** Với giao thức 6 (TCP) hoặc 17 (UDP), parser giải mã transport header và trích xuất số cổng nguồn và đích. Các giao thức IP khác bị hủy.

7. **Ghép five-tuple (FR-009):** Parser ghép các trường đã trích xuất thành metadata five-tuple: `{src_ip, dst_ip, src_port, dst_port, protocol}`.

8. **Chuẩn hóa luồng hai chiều (FR-012, FR-013):** Five-tuple được biến đổi thành canonical flow key phi trạng thái: endpoint có địa chỉ IP số học nhỏ hơn luôn được đặt ở vị trí "source" (dùng port làm tiebreaker nếu IP bằng nhau).

9. **Ghi metadata vào mbuf headroom:** Five-tuple đã chuẩn hóa được ghi vào vùng headroom của chính mbuf đó. Mbuf headroom mặc định là 128 byte; metadata struct chỉ chiếm 16 byte, hoàn toàn phù hợp mà không cần cấp phát thêm bộ nhớ. Ring ở tầng tiếp theo chỉ cần truyền mbuf pointer — Worker đọc lại metadata từ headroom của mbuf, đảm bảo locality tốt vì metadata và packet data nằm gần nhau trong bộ nhớ.

10. **Hash dispatch — chọn worker_ring (DD-14):** Sau khi có five-tuple đầy đủ và đã chuẩn hóa, Parser tính `worker_idx = hash(five-tuple) % N_workers` và enqueue mbuf pointer vào `worker_ring[worker_idx]` tương ứng. Đây là điểm duy nhất trong pipeline có đủ thông tin five-tuple để thực hiện hash dispatch chính xác. Cùng một flow luôn được điều phối về cùng một Worker lcore, đảm bảo flow affinity và warm cache ACL context per-worker.

**Xử lý gói tin không hợp lệ (FR-010, FR-011):** Bất kỳ gói tin nào không thể phân tích đầy đủ đều bị hủy im lặng tại điểm xảy ra lỗi. mbuf được giải phóng ngay lập tức, counter invalid_packets được tăng lên. Parsing không ảnh hưởng đến các gói tin tiếp theo trong batch.

### 2.4 Thành Phần ACL Rule Engine (chạy trong Worker lcore)

**Trách nhiệm:**

Thành phần ACL Rule Engine thực hiện phân loại gói tin bên trong mỗi Worker lcore, không còn chạy trên RX/classifier lcore như kiến trúc cũ. Mỗi Worker lcore thực hiện ACL lookup độc lập trên batch mbufs của mình, cho phép ACL classification chạy song song trên N core đồng thời.

**Nạp rule:**

Khi khởi động, Main lcore đọc và phân tích file cấu hình rule. Với mỗi mục rule, engine trích xuất:

- Điều kiện khớp cho từng trường five-tuple: giá trị chính xác, wildcard, tiền tố CIDR subnet IPv4, port range (min–max), hoặc địa chỉ IP host.
- Tên group liên kết cùng với action (FORWARD/DROP) và số nguyên precedence đã khai báo của group.

Tất cả rule được làm phẳng (flattened) vào `flat_rule_table_t` — action được nhúng trực tiếp vào mỗi `flat_rule_entry_t`, không cần tra cứu group table riêng biệt trong runtime. Từ đó, một `rte_acl_ctx` duy nhất (`flat_acl_ctx`) được build chứa toàn bộ rule. Context này là read-only sau khi build và được tất cả Worker lcore truy cập đồng thời mà không cần lock. Không hỗ trợ chỉnh sửa rule trong runtime.

**Single-stage flat ACL lookup (DD-15) — Phase 3 và Phase 4:**

Worker lcore áp dụng mô hình single-stage flat ACL lookup bên trong vòng xử lý của mình.

**Phase 3 (triển khai hiện tại):** Sử dụng sorted index linear scan với `flat_acl_match_burst()`. Hàm này duyệt qua `g_sorted_idx[]` theo thứ tự đã sắp xếp và gọi `rule_matches()` kiểm tra tường minh từng trường. Kết quả trả về là `const flat_rule_entry_t *` (con trỏ trực tiếp đến entry, không phải `uint32_t userdata`).

**Phase 4 (kế hoạch tương lai):** Sẽ thay thế bằng một lần gọi `rte_acl_classify` duy nhất cho toàn bộ burst:

```
rte_acl_classify(flat_acl_ctx, keys_ptr, results[], nb, 1)
→ results[i] = file_order + 1 của rule khớp có priority cao nhất
→ action = flat_rule_table.rules[results[i] - 1].action  (O(1))
```

Cả hai phase đều không có Stage-2 lookup, không có lazy build, không có group context riêng biệt. Action (FORWARD/DROP) có sẵn trực tiếp sau một lần lookup duy nhất.

**Batch ACL classify (DD-13):**

Worker lcore thu thập toàn bộ batch mbuf từ ring, đọc metadata từ headroom của mỗi mbuf, rồi gọi `flat_acl_match_burst()` một lần cho cả batch. Ở Phase 3 (triển khai hiện tại), `flat_acl_match_burst()` thực hiện linear scan per-packet theo vòng lặp, chưa phải SIMD batch thực sự. Phase 4 sẽ thay bằng `rte_acl_classify` với SIMD acceleration để che giấu cache miss latency — đặc biệt quan trọng với 64-byte frames có budget per-packet rất nhỏ.

**ACL matching:**

Với mỗi gói tin, logic khớp đánh giá các kiểu điều kiện sau:

| Kiểu điều kiện | Trường áp dụng | Ngữ nghĩa khớp |
|---|---|---|
| Exact match | Tất cả trường | Giá trị trường phải bằng chính xác giá trị được chỉ định trong rule |
| Wildcard | Tất cả trường | Bất kỳ giá trị trường nào đều được chấp nhận |
| IPv4 subnet match | src_ip, dst_ip | Giá trị trường phải nằm trong tiền tố CIDR (network/mask) |
| IPv4 host address match | src_ip, dst_ip | Giá trị trường phải bằng chính xác địa chỉ host được chỉ định |
| Port range match | src_port, dst_port | Giá trị trường phải nằm trong phạm vi bao gồm [min, max] |
| Protocol match | protocol | Giá trị trường phải khớp với số giao thức được chỉ định |

**Xử lý precedence và chế độ khớp:**

Rule engine hỗ trợ hai chế độ khớp có thể cấu hình, chọn qua tham số dòng lệnh khi khởi động (mặc định: first-match):

- **Chế độ First-match:** Các rule được đánh giá theo thứ tự precedence tăng dần. Rule đầu tiên có điều kiện được thỏa mãn bởi gói tin sẽ được chọn.
- **Chế độ Best-match:** Tất cả rule có điều kiện được thỏa mãn đều là ứng viên. Ứng viên có số precedence nhỏ nhất (ưu tiên cao nhất) được chọn.

Một rule mặc định (catch-all) bắt buộc với số precedence cao nhất phải có mặt trong bộ rule, đảm bảo mọi gói tin đều nhận được một hành động (FR-017, FR-023).

**Đếm lượt khớp rule (FR-020):**

Mỗi Worker lcore duy trì per-worker hit counter riêng — không chia sẻ counter giữa các Worker, không cần atomic operation. Main lcore aggregate tất cả per-worker counters theo chu kỳ khi report thống kê.

**Giới hạn số lượng rule (FR-019):**

Rule engine hỗ trợ tối đa `SPIFAST_MAX_RULES` (65536) rule trong `flat_rule_table_t` và tối đa `SPIFAST_MAX_GROUPS` (4096) group. Cấu hình vượt giới hạn này sẽ bị từ chối trong quá trình kiểm tra khi khởi động.
### 2.5 Action Dispatch (trong Worker lcore)

**Trách nhiệm:**

Sau khi `rte_acl_classify(flat_acl_ctx, ...)` trả về `results[]`, Worker lcore tra cứu action O(1) từ `flat_rule_table` và dispatch mbuf theo action đó. Không có group table riêng biệt — action được nhúng trực tiếp trong `flat_rule_entry_t`.

**Tra cứu action và dispatch (Phase 3):**

```
entry  = flat_acl_match(flat_rule_tbl, &keys[i])  /* linear scan, trả về con trỏ trực tiếp */
action = entry->action                             /* ACTION_FORWARD hoặc ACTION_DROP */
```

Ở Phase 4 (kế hoạch), sẽ dùng:
```
entry  = &flat_rule_table.rules[results[i] - 1]  /* O(1) sau rte_acl_classify */
action = entry->action
```

| Hành động | Xử lý tại Worker |
|---|---|
| ACTION_FORWARD | mbuf được enqueue vào tx_ring bằng `rte_ring_enqueue_burst()`. TX lcore sẽ drain tx_ring và truyền ra NIC TX. |
| ACTION_DROP | mbuf được giải phóng ngay lập tức về mempool bằng `rte_pktmbuf_free()`. Drop counter được tăng lên. Gói tin không đến TX lcore. |

Mỗi gói tin nhận đúng một hành động. Rule DEFAULT (catch-all) đảm bảo `results[i]` luôn khác 0 cho mọi gói tin IPv4 hợp lệ (FR-023).

**Vòng đời mbuf khi DROP:** Khi một gói tin bị hủy, mbuf phải được giải phóng về mempool trên cùng code path trong Worker lcore, không có deferred release, đảm bảo không có rò rỉ mbuf (FR-004, FR-027).

### 2.6 Thành Phần Truyền Gói Tin (TX lcore)

**Trách nhiệm:**

TX lcore là thành phần mới trong kiến trúc v1.3. Thành phần này vận hành trên một lcore chuyên biệt, drain tx_ring nhận gói tin FORWARD từ tất cả Worker lcore và truyền ra NIC TX.

Các trách nhiệm cụ thể bao gồm:

- Drain tx_ring (MPSC) bằng `rte_ring_dequeue_burst()` liên tục theo poll-mode.
- Gọi `rte_eth_tx_burst()` để truyền batch mbuf ra TX queue của NIC. TX lcore là thành phần duy nhất sở hữu và truy cập TX queue — không có Worker lcore nào gọi `rte_eth_tx_burst()` trực tiếp.
- Xử lý các mbuf chưa được gửi hết (nếu TX queue đầy): free ngay lập tức, tăng tx_drop counter.
- Duy trì per-lcore counter: tx_packets, tx_bytes, tx_drop.
- Tiếp tục drain tx_ring cho đến khi ring rỗng sau khi nhận tín hiệu shutdown.

Việc tập trung TX vào một lcore chuyên biệt loại bỏ nhu cầu Worker phải truy cập TX queue trực tiếp, tránh tranh chấp TX queue giữa các Worker và đơn giản hóa quản lý vòng đời mbuf trên đường FORWARD.

### 2.7 Thành Phần Statistics and Logging

**Trách nhiệm:**

Thành phần Statistics and Logging được tách biệt thành hai chức năng phối hợp với nhau: thu thập số liệu runtime (Statistics) và xuất log thực thi (Logging). Thành phần này vận hành trên Main lcore, độc lập với tất cả các lcore xử lý data path.

**Quyết định kiến trúc quan trọng — Tách biệt fast path và logging path:**

Logging không được đưa overhead xử lý nặng vào packet fast path. Các lcore data path (RX, Parser, Worker, TX) chỉ cập nhật counter nội bộ cục bộ theo từng lcore (local per-lcore counters) mà không thực hiện bất kỳ thao tác I/O hay đồng bộ hóa nặng nào. Thành phần Statistics and Logging đọc các counter đó theo định kỳ, tổng hợp kết quả và ghi log ra stdout và file log. Fast path luôn lock-free và không bị tác động bởi hoạt động ghi log.

#### 2.7.1 Statistics Component

**Thu thập và duy trì số liệu:**

Statistics Component đọc counter từ tất cả lcore theo chu kỳ 1 giây, bao gồm: RX lcore, Parser lcore, tất cả Worker lcore, và TX lcore. Tất cả counter là per-lcore local variable; Statistics Component đọc và tổng hợp mà không cần khóa (lock-free aggregation).

**Số liệu được theo dõi:**

| Số liệu | Phạm vi | Mô tả |
|---|---|---|
| RX packets (theo chu kỳ) | Chu kỳ | Gói tin nhận được từ NIC trong khoảng 1 giây vừa qua |
| RX packets (lũy kế) | Phiên | Tổng gói tin nhận được từ khi ứng dụng khởi động |
| Processed packets (lũy kế) | Phiên | Tổng gói tin đã qua ACL classify thành công |
| Dropped packets (lũy kế) | Phiên | Tổng gói tin bị hủy do hành động DROP của rule |
| Invalid packets (lũy kế) | Phiên | Tổng gói tin bị hủy do lỗi parsing |
| TX packets (lũy kế) | Phiên | Tổng gói tin đã truyền ra NIC TX |
| TX drop packets (lũy kế) | Phiên | Tổng gói tin bị hủy do TX queue đầy |
| Throughput | Chu kỳ | Tốc độ dữ liệu tính bằng Mbps trong khoảng 1 giây vừa qua |
| PPS | Chu kỳ | Tốc độ gói tin trong khoảng 1 giây vừa qua |
| Rule / group hit counts | Lũy kế | Số lượt khớp theo từng rule hoặc từng group từ khi khởi động |

**Tính toán số liệu:**

```
Throughput (Mbps) = (Delta bytes × 8) / Khoảng thời gian lấy mẫu (giây) / 1.000.000

PPS = Delta packets / Khoảng thời gian lấy mẫu (giây)
```

**Xác nhận gói tin bị mất (FR-032):**

Cuối phiên, Statistics Component xác minh:

```
RX_total == TX_total + DROP_total + Invalid_total + TX_drop_total
```

Bất kỳ sai lệch nào được báo cáo là lỗi gói tin bị mất. Một phiên sạch báo cáo zero gói tin không được hạch toán.

#### 2.7.2 Logging Component

**Trách nhiệm xuất log:**

Logging Component chịu trách nhiệm xuất số liệu thống kê đã tổng hợp ra đầu ra tiêu chuẩn (stdout) và ghi log thực thi phục vụ xác nhận và đo hiệu năng.

Cơ chế dual output: Logging Component ghi đồng thời ra stdout và file log. Đường dẫn file log được chỉ định qua tham số dòng lệnh (ví dụ `--log-file <path>`); nếu không chỉ định thì chỉ ghi ra stdout.
Chế độ ghi file: Append mode — mỗi lần chạy tiếp nối vào file hiện có, không ghi đè, để bảo toàn lịch sử nhiều phiên.
Đảm bảo fast path: File I/O phải thực hiện hoàn toàn trên Main lcore, không bao giờ trên các data path lcore.
Xử lý lỗi: Nếu file log không thể mở/ghi được, hệ thống ghi cảnh báo ra stderr và tiếp tục vận hành bình thường với stdout — không được làm gián đoạn xử lý gói tin.
Flush policy: Ghi buffer và flush ra file sau mỗi lần ghi log định kỳ (không flush liên tục theo từng dòng) để tránh overhead I/O quá mức.

**Hành vi báo cáo:**

- Một bản ghi thống kê được xuất ra stdout mỗi giây trong quá trình vận hành bình thường (FR-028, LOG-003).
- Khi ứng dụng kết thúc, một bản ghi tóm tắt cuối phiên được xuất ra, bao gồm tổng lũy kế toàn phiên, Mbps và PPS trung bình cuối cùng, hit count theo từng group và kết quả xác nhận gói tin bị mất (FR-031, FR-032).
- Các sự kiện vòng đời khởi động và tắt máy được ghi log kèm dấu thời gian (LOG-004).
- Tất cả mục log sử dụng định dạng trường nhất quán kèm đơn vị và dấu thời gian ISO 8601 (LOG-005).

**Nội dung mục log định kỳ:**

| Trường | Mô tả |
|---|---|
| Dấu thời gian | Thời gian thực tế của mục log (ISO 8601) |
| Thời gian đã trôi qua | Số giây từ khi ứng dụng khởi động |
| RX packets (chu kỳ) | Gói tin nhận được trong chu kỳ hiện tại |
| RX packets (tổng) | Gói tin nhận được từ khi khởi động |
| Processed packets (tổng) | Gói tin đã qua ACL classify từ khi khởi động |
| Dropped packets (tổng) | Gói tin bị hủy do hành động rule từ khi khởi động |
| Invalid packets (tổng) | Gói tin bị hủy do lỗi parsing từ khi khởi động |
| TX packets (tổng) | Gói tin đã truyền ra NIC TX từ khi khởi động |
| Throughput | Throughput đo được tính bằng Mbps cho chu kỳ hiện tại |
| PPS | Tốc độ gói tin đo được cho chu kỳ hiện tại |
| Lượt khớp theo nhóm | Số lượt khớp theo từng filter group từ khi khởi động |

---

## 3. Luồng Xử Lý Gói Tin

### 3.1 Trường Hợp Bình Thường — Gói Tin Khớp Rule FORWARD

Mô tả dưới đây trình bày vòng đời đầy đủ của một gói tin được phân tích thành công và khớp với rule FORWARD.

```
Bước 1: RX lcore đọc PCAP qua libpcap
  - pcap_next_ex(handle, &pkt_hdr, &pkt_data) đọc một packet từ file PCAP.
  - rte_pktmbuf_alloc(mempool) cấp phát mbuf từ hugepage pool.
  - rte_memcpy(rte_pktmbuf_mtod(m), pkt_data, caplen) copy dữ liệu vào mbuf.
  - m->data_len = m->pkt_len = caplen.
  - Nếu EOF: đóng + mở lại file (continuous replay), tăng pcap_loops.

Bước 2: Tích lũy batch và Enqueue vào parser_ring
  - RX lcore tích lũy mbuf đến SPIFAST_BURST_SIZE.
  - rte_ring_enqueue_burst() mbuf pointer vào parser_ring (SPSC).
  - RX counter (rx_packets, rx_bytes) được cập nhật.

Bước 3: (bước này không còn — lightweight hash đã được loại bỏ)

Bước 4: Parser Dequeue và Prefetch
  - Parser lcore drain parser_ring bằng rte_ring_dequeue_burst().
  - Phát lệnh rte_prefetch0() cho dữ liệu mbuf của các packet tiếp theo
    trong batch để hide cache miss latency.

Bước 5: Phân Tích Ethernet
  - Ethernet header được đọc từ offset 0 của dữ liệu mbuf.
  - EtherType được trích xuất.

Bước 6: Bóc VLAN (có điều kiện)
  - Nếu EtherType == 0x8100:
    - VLAN tag được phân tích; VLAN ID được giữ lại như metadata.
    - Inner EtherType được đọc.

Bước 7: Phân Tích IPv4 Header
  - Nếu EtherType == 0x0800:
    - src_ip, dst_ip, protocol và IHL được trích xuất.
  - Ngược lại: hủy mbuf, tăng invalid counter, chuyển sang mbuf tiếp theo.

Bước 8: Phân Tích Transport Header
  - Nếu protocol == 6 (TCP) hoặc 17 (UDP):
    - src_port và dst_port được trích xuất từ L4 header.
  - Ngược lại: hủy mbuf, tăng invalid counter, tiếp tục.

Bước 9: Ghép Five-Tuple và Flow Normalization
  - Bản ghi five-tuple {src_ip, dst_ip, src_port, dst_port, protocol}
    được ghép lại.
  - Five-tuple được chuẩn hóa (IP nhỏ hơn về vị trí source).

Bước 10: Ghi Metadata vào mbuf Headroom
  - Five-tuple đã chuẩn hóa được ghi vào mbuf headroom (16 bytes).
  - Không cấp phát thêm bộ nhớ.

Bước 11: Hash Dispatch — Chọn Worker
  - Parser tính worker_idx = hash(five-tuple) % N_workers.
  - rte_ring_enqueue() mbuf pointer vào worker_ring[worker_idx] (SPSC).
  - Cùng flow luôn được điều phối về cùng Worker (flow affinity).

Bước 12: Worker Dequeue và Single-Stage Flat ACL Classify (Phase 3)
  - Worker lcore drain worker_ring bằng rte_ring_dequeue_burst().
  - Đọc pkt_meta_t từ headroom của từng mbuf trong batch.
  - Build mảng keys[] từ five-tuple metadata (NBO→HBO cho IP).
  - Phase 3: flat_acl_match_burst(flat_rule_tbl, key_ptrs, results, nb)
    → results[i] = const flat_rule_entry_t* trỏ đến rule khớp.
    → action = results[i]->action (ACTION_FORWARD hoặc ACTION_DROP)
  - Per-worker hit counter (group_hits[group_idx]) được tăng trong worker_ctx_t.

Bước 13: Action Dispatch — FORWARD
  - Hành động là FORWARD.
  - rte_ring_enqueue() mbuf vào tx_ring (MPSC).
  - Worker fwd counter và byte counter được tăng.

Bước 14: TX lcore Transmit
  - TX lcore drain tx_ring bằng rte_ring_dequeue_burst().
  - rte_eth_tx_burst() gửi batch mbuf ra NIC TX queue.
  - TX counter được tăng.

Bước 15: Cập Nhật Thống Kê
  - Main lcore đọc per-lcore counter theo chu kỳ 1 giây.
  - Throughput (Mbps) và PPS được tính từ giá trị delta.
  - Logging Component xuất bản ghi thống kê ra stdout và file log.
```

### 3.2 Trường Hợp Hủy — Gói Tin Khớp Rule DROP

Bước 1–12 giống với trường hợp bình thường. Luồng phân kỳ tại Bước 13:

```
Bước 13 (đường DROP): Action — DROP
  - Hành động là DROP.
  - rte_pktmbuf_free() được gọi ngay lập tức trên mbuf tại Worker lcore.
  - DROP counter được tăng.
  - mbuf được trả về mempool.
  - Không thực hiện enqueue vào tx_ring.
  - TX lcore không tham gia.
```

### 3.3 Trường Hợp Không Khớp Rule — Rule Mặc Định

Nếu không có rule nào được cấu hình tường minh khớp với five-tuple đã chuẩn hóa, rule catch-all mặc định (ưu tiên thấp nhất) được chọn. Hành động liên kết với default filter group (thường là DROP) được áp dụng tại Worker lcore. Default rule hit counter được tăng lên.

### 3.4 Trường Hợp Gói Tin Không Hợp Lệ

Nếu parsing thất bại ở bất kỳ giai đoạn nào tại Parser lcore (EtherType không được hỗ trợ, giao thức IP không được hỗ trợ, header bị cắt ngắn), mbuf được giải phóng ngay tại điểm xảy ra lỗi trong Parser lcore. Invalid-packet counter được tăng lên. Quá trình xử lý tiếp tục với mbuf tiếp theo trong batch. Gói tin không hợp lệ không được enqueue vào worker_ring và không đến được Worker lcore.

### 3.5 Tắt Máy — Signal-Driven Shutdown

RX lcore **không** khởi tạo shutdown khi PCAP hết. Sau EOF, RX lcore mở lại file PCAP và tiếp tục replay (continuous loop). Tắt máy chỉ xảy ra khi SIGINT hoặc SIGTERM được nhận.

**Cơ chế:**

```c
static void spifast_sighandler(int sig) {
    g_shutdown_flag = 1;   /* volatile int; single-word write, async-signal-safe */
}
signal(SIGINT,  spifast_sighandler);
signal(SIGTERM, spifast_sighandler);
```

Khi `g_shutdown_flag == 1`:
- **RX lcore**: thoát vòng lặp ngay khi biến được set.
- **Parser lcore**: thoát khi `g_shutdown_flag == 1` VÀ `parser_ring` rỗng.
- **Worker lcore**: thoát khi `g_shutdown_flag == 1` VÀ `worker_ring[i]` rỗng.
- **TX lcore**: thoát khi `g_shutdown_flag == 1` VÀ `tx_ring` rỗng.

Mô hình "drain-then-exit" này đảm bảo pipeline drain theo thứ tự tự nhiên mà không cần explicit cascade signal: RX ngừng push trước, rồi parser_ring drain, rồi worker_ring drain, rồi tx_ring drain. Main lcore gọi `rte_eal_mp_wait_lcore()` để chờ tất cả lcore thoát trước khi thu thập final stats và tắt ứng dụng.

---

## 4. Thiết Kế Kiến Trúc Đa Lõi

### 4.1 Mô Hình Kiến Trúc

SPIFast v1.3 áp dụng mô hình đa lõi **pipeline chuyên biệt 5 giai đoạn**. Mỗi giai đoạn chạy trên một hoặc nhiều lcore riêng biệt, giao tiếp qua DPDK ring lock-free. ACL classification được thực hiện tại Worker lcore theo batch, không còn trên RX/classifier lcore đơn như kiến trúc cũ.

```
  CPU Core 0 (Main lcore)
  ┌──────────────────────────────────────┐
  │  Khởi tạo ứng dụng                  │
  │  Nạp rule, build ACL context        │
  │  Statistics Timer (1 giây)          │
  │  Logging (stdout + file)            │
  │  Điều phối tắt máy                  │
  └──────────────────────────────────────┘

  CPU Core 1 (RX lcore)
  ┌──────────────────────────────────────┐
  │  rte_eth_rx_burst()                  │
  │  Lightweight hash (IP src offset)   │
  │  → parser_ring (SPSC)              │
  └──────────────────────────────────────┘
                    │
                    │ parser_ring (SPSC, pointer only)
                    ▼
  CPU Core 2 (Parser lcore)
  ┌──────────────────────────────────────┐
  │  rte_ring_dequeue_burst()           │
  │  rte_prefetch0() ahead              │
  │  Parse L2 / VLAN / L3 / L4         │
  │  Flow normalization                  │
  │  Ghi five-tuple → mbuf headroom     │
  │  hash(five-tuple) % N → worker_idx │
  │  → worker_ring[worker_idx] (SPSC)  │
  └──────────────────────────────────────┘
         │                    │
         │ SPSC               │ SPSC
         ▼                    ▼
  CPU Core 3               CPU Core 4      ... Worker N-1
  ┌────────────┐           ┌────────────┐
  │  Worker 0  │           │  Worker 1  │
  │  Dequeue   │           │  Dequeue   │
  │  Read meta │           │  Read meta │
  │  Flat ACL  │           │  Flat ACL  │
  │  classify  │           │  classify  │
  │  (1 call)  │           │  (1 call)  │
  │  action    │           │  action    │
  │  lookup    │           │  lookup    │
  │  FORWARD → │           │  FORWARD → │
  │   tx_ring  │           │   tx_ring  │
  │  DROP →    │           │  DROP →    │
  │   free()   │           │   free()   │
  └────────────┘           └────────────┘
         │                    │
         └──────────┬─────────┘
                    │ tx_ring (MPSC)
                    ▼
  CPU Core N+3 (TX lcore)
  ┌──────────────────────────────────────┐
  │  rte_ring_dequeue_burst()           │
  │  rte_eth_tx_burst()                 │
  │  Sở hữu TX queue                   │
  └──────────────────────────────────────┘
                    │
                    ▼
              NIC TX Queue

  ←────────── per-lcore counters ──────────→
  (Main lcore đọc định kỳ từ tất cả lcore)
```

### 4.2 Mô Hình Giao Tiếp Ring

Kiến trúc v1.3 sử dụng ba tầng ring với đặc tính khác nhau:

**Tầng 1 — parser_ring (RX → Parser): SPSC**

RX lcore là producer duy nhất, Parser lcore là consumer duy nhất. Sử dụng `RING_F_SP_ENQ | RING_F_SC_DEQ` để tận dụng SPSC optimization của DPDK. Ring chỉ truyền mbuf pointer (8 byte/entry), không sao chép dữ liệu gói tin.

**Tầng 2 — worker_ring[i] (Parser → Worker i): SPSC per worker**

Parser lcore là producer duy nhất cho mỗi worker_ring[i]. Worker lcore i là consumer duy nhất của worker_ring[i]. Mỗi worker có ring riêng, loại bỏ hoàn toàn tranh chấp giữa các worker ở phía consumer. Ring chỉ truyền mbuf pointer (8 byte/entry); metadata được đọc từ headroom của mbuf.

**Tầng 3 — tx_ring (Worker → TX): MPSC**

Tất cả N Worker lcore là producer của tx_ring duy nhất. TX lcore là consumer duy nhất. Sử dụng `RING_F_SC_DEQ` (single consumer) nhưng không thể dùng `RING_F_SP_ENQ` vì nhiều Worker enqueue đồng thời. tx_ring được cấu hình với `RING_F_MP_ENQ` để đảm bảo thread-safe enqueue từ N producer. Đây là điểm duy nhất trong pipeline có nhiều producer vào một ring; overhead CAS của MPSC enqueue được chấp nhận vì TX không phải bottleneck chính.

**Các thuộc tính chung:**

- **Hoạt động lock-free trên data path:** Tất cả ring operation là lock-free (SPSC) hoặc wait-free (MPSC với CAS), đáp ứng NFR-003.
- **Không có system call trên data path:** Tất cả thao tác ring là userspace memory operation, đáp ứng NFR-002.
- **Xử lý backpressure:** Nếu bất kỳ ring nào đầy, gói tin bị hủy tại điểm enqueue và tăng unintended drop counter. Ring sizing phải đủ lớn để drop rate ≤ 0,1% (PR-005).

### 4.3 Chiến Lược Phân Phối Worker — Hash Dispatch tại Parser

Dispatch gói tin đến Worker lcore được thực hiện tại **Parser lcore** bằng five-tuple hash, thay thế hoàn toàn cơ chế round-robin đã dùng trong kiến trúc cũ.

**Lý do thay đổi:**

Round-robin tại RX lcore (kiến trúc cũ) không có thông tin five-tuple vì parse chưa được thực hiện, do đó không thể đảm bảo flow affinity. Parser lcore là điểm duy nhất trong pipeline đã hoàn thành parse và flow normalization, có đủ five-tuple để tính hash chính xác.

**Cách hoạt động:**

```
worker_idx = hash(src_ip, dst_ip, src_port, dst_port, protocol) % N_workers
rte_ring_enqueue(worker_ring[worker_idx], mbuf)
```

Hash function là hàm thuần túy, không trạng thái, thực hiện trong O(1). Không cần shared state giữa Parser và Worker lcore.

**Lợi ích:**

- **Flow affinity:** Cùng một flow (cùng five-tuple sau normalization) luôn được điều phối về cùng một Worker lcore. Worker đó sẽ warm cache `flat_acl_ctx` với các pattern phổ biến trong flow set của mình, giảm cache miss khi classify.
- **Phân phối đều:** Hash phân phối đều các flow trên N worker, tránh hot spot khi traffic đa dạng.
- **Không cần lock:** Hash là stateless, không chia sẻ state giữa Parser và Worker.

Với cấu hình N = 1 worker, toàn bộ gói tin vào worker_ring[0].

### 4.4 Cấu Hình Số Lượng Worker

Số lượng Worker lcore được chỉ định thông qua tham số dòng lệnh `--workers N` khi khởi động ứng dụng (FR-025). Hệ thống không hardcode số lượng Worker Core. Cấu hình tối thiểu là một Worker lcore.

Tổng lcore cần thiết: **N + 4** (1 RX + 1 Parser + N Worker + 1 TX + 1 Main).

EAL lcore mask hoặc tham số `--lcores` ánh xạ lcore ID logic sang lõi CPU vật lý. Cô lập CPU (`isolcpus`) được khuyến nghị để tránh OS scheduler interrupt vào data path lcore.

**Chiến lược scale:**

Trước khi tăng số Worker, cần tối ưu hóa per-core throughput bằng batch ACL classify và prefetch. Chỉ tăng N_workers khi benchmark xác nhận Worker là bottleneck thực sự, không phải Parser hay TX.

### 4.5 Xem Xét Thứ Tự Gói Tin

SPIFast không cung cấp đảm bảo về thứ tự gói tin trên các Worker Core. Khi N > 1 worker đang hoạt động, các gói tin điều phối đến các worker ring khác nhau có thể được xử lý và enqueue vào tx_ring theo thứ tự khác với chuỗi gốc. Điều này được chấp nhận về mặt kiến trúc vì thống kê được tổng hợp trên tất cả lcore và không yêu cầu ordered output stream.

### 4.6 Phân Tích Bottleneck

Với kiến trúc pipeline 5 giai đoạn, bottleneck có thể xuất hiện tại:

| Giai đoạn | Nguyên nhân bottleneck tiềm ẩn | Cách giảm thiểu |
|---|---|---|
| RX lcore | libpcap `pcap_next_ex` overhead + `rte_pktmbuf_alloc` + `memcpy` | Không phải bottleneck chính ở quy mô thực tế; file PCAP được OS cache từ loop 2 trở đi |
| Parser lcore | Parse + hash dispatch single-threaded; parser_ring_drop khi burst imbalance | Tối ưu prefetch; scale thêm Parser lcore trong tương lai nếu cần |
| worker_ring[i] | Size 4096 nhỏ hơn 16× so với parser_ring; hash skew tập trung vào một worker | Tăng `SPIFAST_RING_SIZE`; kiểm tra phân phối `dispatched_to[]` |
| Worker lcore | ACL linear scan O(N_rules) per-packet (Phase 3); cache miss | Migrate sang `rte_acl_classify` (Phase 4); tăng N_workers khi xác nhận Worker là bottleneck |
| tx_ring (MPSC) | CAS overhead tăng theo N Worker khi nhiều worker enqueue đồng thời | Thường không là bottleneck ở ≤ 40 Gbps; tx_ring size 65536 đủ lớn |
| TX lcore | MPSC dequeue + tx_burst serialization | TX lcore được giải phóng khỏi classify overhead; thường không là bottleneck |

Chiến lược tối ưu hóa tuần tự: đo per-stage throughput trước khi quyết định tăng parallelism.

---

## 5. Kiến Trúc Quản Lý Rule

### 5.1 Vòng Đời Rule

Rule được quản lý hoàn toàn khi ứng dụng khởi động. Vòng đời rule tuân theo chuỗi sau:

```
  Khởi động ứng dụng
       |
       v
  Nạp File Rule
  (đọc spi_rules.conf hoặc đường dẫn do người vận hành chỉ định)
       |
       v
  Kiểm Tra Cấu Hình Rule
  - Kiểm tra cú pháp từng mục
  - Kiểm tra định dạng địa chỉ IP và tiền tố
  - Kiểm tra tính hợp lệ của port range
  - Kiểm tra giá trị giao thức
  - Kiểm tra giới hạn số lượng group (≤ 4096)
  - Kiểm tra giới hạn số lượng filter mỗi group (≤ 2048)
  - Phát hiện tên rule trùng lặp
       |
       v
  Xây Dựng flat_rule_table_t
  - Phân tích khai báo group; lưu tên group và action vào bảng tạm
  - Với mỗi rule: điền flat_rule_entry_t; nhúng action từ group declaration
  - Gán file_order tăng dần cho mỗi rule entry
       |
       v
  Build Flat Single-Stage ACL Context
  - Ánh xạ từng flat_rule_entry_t thành rte_acl_rule với fields five-tuple
  - Gán data.priority theo match_mode (precedence hoặc file_order)
  - DEFAULT rule: data.priority = 0
  - Gọi rte_acl_build() một lần — flat_acl_ctx là read-only sau khi build
       |
       v
  Xác Nhận Sự Hiện Diện Của Rule Mặc Định
  - Xác nhận rằng rule catch-all tồn tại với ưu tiên thấp nhất
  - Hủy nếu không có rule mặc định nào được định nghĩa
       |
       v
  Ghi Log Các Rule Đã Nạp
  - Xuất log khởi động liệt kê từng rule đã nạp kèm group và action
       |
       v
  Sẵn Sàng Khởi Chạy Data Path lcore
```

Nếu bất kỳ bước kiểm tra nào thất bại, ứng dụng phát ra thông báo lỗi mô tả rõ mục bị lỗi và kết thúc. Nạp rule một phần khi có lỗi không được phép (RC-006).

### 5.2 Bảng Kiểm Tra Hợp Lệ

| Kiểm tra | Rule | Hành vi khi lỗi |
|---|---|---|
| Định dạng địa chỉ IP (dotted-decimal) | RC-002 | Lỗi + kết thúc |
| Định dạng tiền tố CIDR (a.b.c.d/len, len 0–32) | RC-002 | Lỗi + kết thúc |
| Tính hợp lệ port range (min ≤ max, giá trị 0–65535) | RC-002 | Lỗi + kết thúc |
| Giá trị giao thức (tcp, udp, hoặc wildcard) | RC-002 | Lỗi + kết thúc |
| Giới hạn số lượng filter-group (≤ 4096 group) | FR-019 | Lỗi + kết thúc |
| Giới hạn số lượng filter mỗi group (≤ 2048 filter/group) | FR-019 | Lỗi + kết thúc |
| Tên rule trùng lặp | RC-002 | Lỗi + kết thúc |
| Rule mặc định hiện diện | FR-017 | Lỗi + kết thúc |
| Thiếu trường bắt buộc | RC-002 | Lỗi + kết thúc |
| File không tìm thấy hoặc không đọc được | RC-001 | Lỗi + kết thúc |

### 5.3 Định Dạng Cấu Hình Rule

File cấu hình rule là file văn bản thuần. Khai báo group xuất hiện trước các mục rule. Dòng bắt đầu bằng `#` là chú thích và bị bỏ qua. Dòng trống bị bỏ qua (RC-005).

Cấu trúc cấu hình theo định dạng được trình bày trong SRS (RC-004):

- Dòng khai báo group khai báo tên group, số nguyên precedence và action.
- Dòng mục rule khai báo tên rule, tư cách thành viên group và điều kiện khớp cho từng trường.
- Từ khóa `any` đại diện cho wildcard cho trường tương ứng.
- Ký hiệu CIDR (`a.b.c.d/prefix_len`) được dùng cho subnet matching.
- Địa chỉ host chính xác (`dst_address=`) được dùng cho host-specific matching.
- Port range được biểu diễn dạng `min–max`.

Ngữ pháp chính xác và quy tắc parsing được định nghĩa trong SDD.

### 5.4 Biểu Diễn Nội Bộ ACL Rule

Mỗi rule đã được kiểm tra hợp lệ được dịch thành một `flat_rule_entry_t` chứa đầy đủ điều kiện khớp five-tuple, action (FORWARD/DROP) nhúng trực tiếp, và `file_order` làm ACL userdata (`file_order + 1`).

**Flat single-stage ACL context (`flat_acl_ctx`):** Một `rte_acl_ctx` duy nhất chứa tất cả rule từ tất cả group. Priority được gán theo `match_mode`:
- `best-match`: `data.priority = rule.precedence`
- `first-match`: `data.priority = num_explicit_rules - rule.file_order`
- Rule DEFAULT: `data.priority = 0` (luôn bị đánh bại bởi explicit rule)

ACL engine sắp xếp các entry theo priority. `rte_acl_classify` với `categories=1` trả về đúng 1 kết quả — rule có priority cao nhất trong số các rule khớp. Hành vi chi tiết được định nghĩa trong SDD Mục 4.

---

## 6. Kiến Trúc Lưu Lượng và Kiểm Thử

### 6.1 Công Cụ Sinh PCAP

SPIFast yêu cầu một công cụ sinh PCAP đồng hành tạo ra các file lưu lượng tổng hợp có thể cấu hình và tái hiện được cho mục đích kiểm thử. Công cụ này là một script hoặc tiện ích độc lập (không phải một phần của ứng dụng data plane SPIFast) tạo ra các file PCAP hợp lệ đáp ứng các đặc tả traffic profile trong SRS.

**Khả năng sinh yêu cầu (TR-004, TR-005):**

- Tổng số gói tin có thể cấu hình
- Phân phối giao thức có thể cấu hình (phần trăm TCP / UDP)
- Phân phối cổng đích có thể cấu hình (ánh xạ đến các danh mục loại lưu lượng)
- Kích thước gói tin có thể cấu hình (kích thước cố định hoặc phân phối theo các nhóm kích thước)
- Dải địa chỉ IP nguồn và đích có thể cấu hình
- Sinh cặp luồng hai chiều cho kiểm thử flow normalization (TP-04)
- Sinh frame có thẻ IEEE 802.1Q VLAN (TP-05)

**Tính tái hiện (TR-007):** Công cụ sinh phải tạo ra đầu ra PCAP bit-identical khi được gọi với cùng file cấu hình profile.

### 6.2 Traffic Profile

Các profile có tên sau đây được định nghĩa trong SRS và phải được công cụ sinh hỗ trợ:

| Profile ID | Mục đích | Đặc tính chính |
|---|---|---|
| TP-01 | Small Packet Stress — PPS tối đa | Frame 64 byte, hỗn hợp TCP/UDP |
| TP-02 | Medium Mixed Throughput — Mbps tối đa | Frame ~1024 byte, hỗn hợp TCP/UDP |
| TP-03 | Full Rule Coverage — toàn bộ rule được kích hoạt | Hỗn hợp, được thiết kế để kích hoạt mọi rule đã định nghĩa |
| TP-04 | Bidirectional Flow — xác nhận flow normalization | Frame 128 byte, cặp gói tin chiều đi/chiều về |
| TP-05 | VLAN Tagged — xác nhận VLAN parsing | Frame 256 byte, có thẻ IEEE 802.1Q, hỗn hợp TCP/UDP |

Mỗi profile được chỉ định đầy đủ bởi file cấu hình của nó. Người kiểm thử không cần xây dựng gói tin thủ công.

### 6.3 Luồng Kiểm Thử

Quy trình kiểm thử end-to-end là:

```
  File Cấu Hình Traffic Profile
          |
          v
  Script Sinh PCAP
  (tạo ra PCAP xác định)
          |
          v
  File PCAP (lưu trên đĩa)
          |
          v
  Ứng Dụng SPIFast
  (DPDK + net_pcap PMD replay PCAP)
          |
          v
  Đầu Ra Thống Kê Runtime (stdout + log file)
          |
          v
  Đo Hiệu Năng
  (Throughput Mbps, PPS, Drop Rate, Packet Loss)
          |
          v
  Đánh Giá PASS / FAIL
  (so sánh với tiêu chí chấp nhận của SRS)
```

Log thực thi kiểm thử (stdout chuyển hướng) và các file PCAP được sử dụng được giữ lại làm bằng chứng kiểm thử.

---

## 7. Kiến Trúc Đo Hiệu Năng

### 7.1 Phương Pháp Đo

Tất cả số liệu hiệu năng được suy ra từ các software counter nội bộ do SPIFast duy trì. Không cần hạ tầng đo lưu lượng bên ngoài. Statistics Component tính tất cả số liệu từ các per-lcore counter được lấy mẫu theo khoảng thời gian 1 giây.

### 7.2 Throughput (Mbps)

Throughput được đo là tốc độ dữ liệu **forwarded ra TX** (chỉ gói tin ACTION_FORWARD, không bao gồm gói tin DROP). Nguồn dữ liệu là `tx_lcore_stats.tx_bytes` — byte tích lũy từ các mbuf đã được `rte_eth_tx_burst()` gửi thành công.

**Công thức (triển khai thực tế):**

```
Forwarded Throughput (Mbps) = (tx_bytes_delta × 8) / Khoảng thời gian (giây) / 1.000.000
```

`tx_bytes_delta` là `tx_bytes` tại thời điểm hiện tại trừ `tx_bytes` tại snapshot trước. `tx_bytes` được tích lũy từ `pkt_len` của mbuf ngay **trước** khi gọi `rte_eth_tx_burst()` (tránh PMD freeing mbuf trước khi đọc).

**Phân biệt hai định nghĩa throughput:**

| Định nghĩa | Mô tả | Nguồn |
|---|---|---|
| Forwarded Throughput | Chỉ FWD bytes — thực tế ra NIC TX | `tx_stats.tx_bytes` ← **đo hiện tại** |
| Classified Throughput | FWD + DROP bytes — tất cả bytes đã classify | Worker stage (`pkt_len` sau ACL) ← chưa triển khai |

Khi DROP rate = 0%, hai định nghĩa tương đương. Tiêu chí PASS ≥ 700 Mbps áp dụng theo Forwarded Throughput.

**Tiêu chí chấp nhận:**

| Kết quả | Tiêu chí |
|---|---|
| PASS | ≥ 700 Mbps duy trì |
| EXCELLENT | ≥ 950 Mbps duy trì |
| FAIL | < 700 Mbps |

### 7.3 Tốc Độ Gói Tin (PPS)

PPS được đo là số gói tin mà giai đoạn phân loại hoàn tất một hành động (FORWARD hoặc DROP) trong một đơn vị thời gian.

**Công thức (triển khai thực tế):**

```
PPS = Forwarded packets delta / Khoảng thời gian (giây)
```

Nguồn: `worker_stats[i].forwarded` tổng hợp từ tất cả Worker lcore. Chỉ tính gói tin FORWARD, không tính DROP.

**Tiêu chí chấp nhận:**

| Kết quả | Tiêu chí |
|---|---|
| PASS | ≥ 500.000 pps duy trì |
| EXCELLENT | ≥ 1.488.000 pps duy trì |
| FAIL | < 500.000 pps |

Mục tiêu EXCELLENT 1.488.000 pps tương ứng với tốc độ gói tin line-rate lý thuyết cho frame Ethernet 64 byte trên liên kết 1 Gbps.

### 7.4 Tỷ Lệ Rơi Gói Tin (Unintended)

Tỷ lệ rơi gói tin ngoài ý muốn đo lường sự mất gói tin do các ràng buộc năng lực hệ thống (ví dụ: ring overflow, TX queue full), không phải do hành động DROP được cấu hình trong rule.

**Công thức (SRS PR-005):**

```
Tỷ lệ rơi (%) = (Gói tin rơi ngoài ý muốn / Tổng gói tin RX) × 100
```

Gói tin rơi ngoài ý muốn bao gồm: ring overflow tại parser_ring, worker_ring, tx_ring, và TX queue full tại NIC. DROP theo rule là hành vi mong đợi và không được tính vào giới hạn tỷ lệ rơi.

**Tiêu chí chấp nhận:** Tỷ lệ rơi ngoài ý muốn ≤ 0,1% dưới tải duy trì với bất kỳ traffic profile nào đã định nghĩa.

### 7.5 Xác Nhận Gói Tin Bị Mất (Packet Accounting)

Cuối phiên, hệ thống xác nhận rằng mọi gói tin đã được hạch toán (FR-032). Do replay liên tục (continuous loop), `parser_ring_drop` không được đưa vào công thức — giá trị này tích lũy qua nhiều vòng replay và không phản ánh "packet lost" theo nghĩa kiểm thử.

**Công thức (triển khai thực tế):**

```
accounted = invalid_pkts
          + worker_ring_drop
          + drop_pkts        (ACL DROP rule)
          + tx_ring_drop
          + tx_drop_pkts     (TX queue full)
          + tx_pkts

delta = rx_total - accounted

Điều kiện PASS:  delta / rx_total ≤ 0,1%   (PERF_SUCCESS = 0.001)
Điều kiện FAIL:  delta / rx_total > 0,1%
```

`parser_ring_drop` được theo dõi riêng trong log nhưng không tính vào `accounted`. Kết quả PASS/FAIL được báo cáo trong `PACKET_ACCOUNTING` line của log tóm tắt cuối phiên.

### 7.6 Điều Kiện Đo

Theo SRS Mục 5.5, các phép đo hiệu năng phải được thực hiện trong các điều kiện sau:

- Hugepages được cấp phát trước (2048 × 2 MB = 4 GB) và xác nhận có sẵn trước khi chạy kiểm thử
- CPU isolation được cấu hình (`isolcpus=2-11`) để tránh OS scheduler interrupt
- Không có ứng dụng xử lý gói tin nào khác chạy đồng thời trên máy chủ
- DPDK lcore được ghim vào các lõi CPU đã được isolate
- Cho phép có giai đoạn khởi động (warm-up) trước khi bắt đầu đo hiệu năng
- Các phép đo được thực hiện trong suốt một phiên replay PCAP ổn định và hoàn chỉnh

---

## 8. Quyết Định Thiết Kế

Bảng dưới đây ghi lại các quyết định kiến trúc chính được đưa ra trong HLD này, cùng với lý do cho mỗi lựa chọn.

| # | Quyết định | Lựa chọn | Lý do |
|---|---|---|---|
| DD-01 | Theo dõi trạng thái luồng gói tin | Không có flow table; xử lý phi trạng thái theo từng gói tin | Loại bỏ cấp phát bộ nhớ theo từng luồng và độ trễ tra cứu hash table trên data path. Nhận dạng luồng hai chiều đạt được qua chuẩn hóa five-tuple xác định, đáp ứng FR-012 và FR-013 mà không cần trạng thái. Nhất quán với ràng buộc CON-06 và OBJ-04 của SRS. |
| DD-02 | Hỗ trợ lớp mạng | Chỉ IPv4; IPv6 bị loại trừ tường minh | Giới hạn độ phức tạp triển khai trong môi trường xác nhận mục tiêu. IPv6 bị loại trừ theo CON-05 và SRS Mục 1.2. Đơn giản hóa parser, độ rộng trường ACL và mã hóa five-tuple. |
| DD-03 | Classification engine | ACL dựa trên ưu tiên với chế độ first-match hoặc best-match có thể cấu hình | Phân loại dựa trên ACL hỗ trợ tự nhiên subnet prefix matching, port range matching, wildcard và sắp xếp ưu tiên mà không cần hash table. Tránh độ phức tạp về collision và resize của các phương án exact-match dựa trên hash. Đáp ứng FR-014 đến FR-017. |
| DD-04 | Mô hình nạp rule | Nạp tĩnh khi khởi động; không cập nhật runtime | Loại bỏ nhu cầu đồng bộ hóa truy cập đồng thời giữa rule engine và code phân loại data path. Nhất quán với CON-06. ACL context read-only sau build cho phép tất cả Worker lcore truy cập đồng thời không cần lock, cải thiện hành vi cache. |
| DD-05 | Khớp rule dựa trên ưu tiên | Số nguyên precedence gán cho từng group; giá trị thấp hơn = ưu tiên cao hơn | Cung cấp thứ tự đánh giá rule xác định và do người vận hành kiểm soát. Cho phép rule catch-all mặc định luôn được đánh giá cuối cùng (số precedence cao nhất). Đáp ứng FR-016 và FR-017. |
| DD-06 | Cơ chế I/O gói tin đầu vào | **libpcap** (`pcap_next_ex`) cho RX đầu vào; DPDK net_pcap port chỉ dùng cho TX | libpcap cho phép kiểm soát chính xác hành vi replay và EOF detection mà không phụ thuộc hành vi nội bộ của net_pcap PMD. RX lcore tự alloc mbuf từ mempool và memcpy data — layout mbuf giống hệt PMD path, các module downstream (Parser, Worker, TX) không bị ảnh hưởng. |
| DD-07 | Mô hình đa lõi | Pipeline 5 giai đoạn chuyên biệt: RX → Parser → Worker(N) → TX + Main | Tách biệt từng concern vào lcore riêng: RX tập trung poll, Parser tập trung parse và dispatch, Worker tập trung ACL classify song song trên N core, TX tập trung truyền ra NIC. Loại bỏ bottleneck single-core ACL của kiến trúc cũ. |
| DD-08 | Giao tiếp liên lõi | Ba tầng ring: SPSC (RX→Parser), SPSC per worker (Parser→Worker), MPSC (Worker→TX) | Tối ưu từng tầng theo đặc tính producer/consumer thực tế. SPSC là lựa chọn tốt nhất khi chỉ có 1 producer và 1 consumer. MPSC bắt buộc ở tầng Worker→TX vì N Worker enqueue đồng thời. Không có system call trên data path. Đáp ứng NFR-002 và NFR-003. |
| DD-09 | Thu thập thống kê và logging | Per-lcore software counter; Main lcore tổng hợp định kỳ; Logging xuất ra stdout và file log | Tránh phụ thuộc vào hardware performance counter. Cập nhật counter bởi các thành phần data path là thao tác cục bộ không cần khóa. Logging định kỳ bởi Main lcore ngăn I/O xâm nhập vào fast path. Đáp ứng NFR-002, NFR-003, LOG-003 và FR-028. |
| DD-10 | Chuẩn hóa luồng hai chiều | Sắp xếp five-tuple chuẩn tắc phi trạng thái (IP/cổng nhỏ hơn luôn ở vị trí source) | Đạt FR-012 mà không cần flow table. Hàm chuẩn hóa là phép biến đổi thuần túy với thời gian hằng số, thêm độ trễ không đáng kể cho mỗi gói tin. Đáp ứng FR-013. |
| DD-11 | Đầu ra log | Dual output: stdout + file log (append mode, tùy chọn) | stdout đảm bảo quan sát trực tiếp trong khi chạy; file log bảo toàn lịch sử nhiều phiên phục vụ phân tích sau. Append mode tránh mất dữ liệu phiên cũ. File I/O thực hiện ngoài fast path để không ảnh hưởng Throughput. |
| DD-12 | Tối ưu hóa hugepage và CPU isolation | 2048 hugepage × 2 MB = 4 GB; isolcpus=2-11 | 4 GB hugepage cung cấp đủ bộ nhớ cho mempool, ring, ACL context với margin dự phòng lớn. CPU isolation loại bỏ OS scheduler interrupt khỏi data path lcore, đảm bảo latency ổn định và throughput cao. |
| DD-13 | Flat ACL classify tại Worker lcore với batch | Chuyển ACL từ RX/classifier lcore sang Worker lcore; batch `rte_acl_classify(flat_acl_ctx, keys[], results[], nb, 1)` | ACL trên nhiều Worker lcore cho phép classify song song thay vì bottleneck trên 1 core. Batch classify với n=64 cho phép CPU prefetch và SIMD hide cache miss latency, cải thiện effective throughput từ ~10 Mpps lên ~30 Mpps per core so với single-packet lookup. |
| DD-14 | Hash dispatch tại Parser thay round-robin | five-tuple hash tại Parser lcore sau khi parse xong | Parser là điểm duy nhất có đầy đủ five-tuple đã chuẩn hóa để tính hash chính xác. Hash dispatch đảm bảo flow affinity (cùng flow → cùng Worker), cải thiện ACL cache locality per-worker. Round-robin không đảm bảo flow affinity vì không có thông tin five-tuple. |
| DD-15 | Single-stage flat ACL lookup trong Worker | **Phase 3:** sorted index linear scan (`flat_acl_match_burst`); **Phase 4 (kế hoạch):** `rte_acl_ctx` duy nhất + `rte_acl_classify` một lần mỗi burst | Phase 3 ưu tiên tính đúng đắn và khả năng debug: `rule_matches()` minh bạch, không phụ thuộc SIMD ISA, dễ kiểm tra từng trường. Phase 4 sẽ khai thác SIMD/AVX2 để cải thiện throughput. Cả hai phase đều loại bỏ two-stage lookup, lazy build và LRU eviction. |
| DD-16 | TX lcore chuyên biệt, tách biệt khỏi Worker | Worker enqueue vào tx_ring (MPSC); TX lcore drain và gọi rte_eth_tx_burst() | TX lcore là thành phần duy nhất sở hữu TX queue, tránh tranh chấp TX queue giữa N Worker lcore. Worker không cần biết về TX queue hay NIC TX, đơn giản hóa logic Worker. TX serialization không phải bottleneck ở quy mô ≤ 40 Gbps. |
| DD-17 | Metadata qua mbuf headroom | Five-tuple metadata ghi vào headroom 16 byte của mbuf; ring chỉ truyền pointer | Tránh cấp phát bộ nhớ riêng cho metadata. Metadata và packet data gần nhau trong bộ nhớ, tốt cho cache locality khi Worker đọc. Ring entry nhỏ (8 byte pointer) cải thiện ring throughput so với truyền {pointer + struct} (24–32 byte). |

---

## 9. Hướng Mở Rộng Tương Lai

Thiết kế SPIFast v1.3 hiện tại được phạm vi hóa có chủ ý theo mô hình phân loại SPI pipeline 5 giai đoạn. Các mở rộng kiến trúc sau đây được xác định là các hướng phát triển tự nhiên cho các phiên bản tương lai.

### 9.1 Flow Table và Stateful Inspection

Một bảng trạng thái theo từng luồng (hash map được khóa bởi five-tuple đã chuẩn hóa) có thể được đưa vào để cho phép stateful packet inspection. Điều này sẽ cho phép hệ thống theo dõi trạng thái kết nối (máy trạng thái phiên TCP, liên kết dựa trên timeout UDP), tạo điều kiện cho hành vi tường lửa có trạng thái, giới hạn tốc độ kết nối và phát hiện bất thường dựa trên lịch sử theo từng luồng.

Tác động kiến trúc: flow table sẽ yêu cầu thiết kế an toàn truy cập đồng thời (per-flow locking hoặc hash table lock-free), quản lý bộ nhớ cho flow expiry và cơ chế timeout/aging trên một lcore riêng. Đường phân loại phi trạng thái sẽ được giữ lại như fast path cho các lần tra cứu flow table.

### 9.2 Scale Parser lcore

Khi Parser lcore trở thành bottleneck thực sự (đo được qua benchmark), có thể mở rộng sang nhiều Parser lcore. RX lcore lúc này sẽ sử dụng lightweight hash để phân phối mbuf đến parser_ring[p] tương ứng. Mỗi Parser lcore sẽ có ring riêng đến tập con Worker của nó để giữ SPSC semantics.

### 9.3 Hỗ Trợ NIC Vật Lý và RSS

Hỗ trợ NIC vật lý thông qua DPDK hardware PMD (ví dụ: Intel ixgbe, Mellanox mlx5) sẽ cho phép SPIFast vận hành ở tốc độ line-rate thực sự (10 GbE, 25 GbE, 100 GbE). Với RSS (Receive-Side Scaling), NIC tự phân phối flow về nhiều RX queue theo five-tuple hash, loại bỏ nhu cầu Parser làm hash dispatch và cho phép mô hình RTC (run-to-completion) mỗi lcore tự poll queue riêng.

### 9.4 Hỗ Trợ IPv6

Mở rộng parser và ACL engine để hỗ trợ IPv6 (RFC 8200) sẽ mở rộng phạm vi bao phủ lưu lượng. Điều này yêu cầu trường địa chỉ 128-bit trong five-tuple, mở rộng định nghĩa trường ACL và parsing chuỗi extension header để xác định vị trí transport layer header. Thuật toán chuẩn hóa sẽ cần thích ứng cho ngữ nghĩa sắp xếp địa chỉ IPv6.

### 9.5 Cập Nhật Rule Động

Chỉnh sửa rule runtime sẽ cho phép người vận hành thêm, xóa hoặc sửa đổi rule mà không cần khởi động lại ứng dụng. Điều này yêu cầu mô hình Read-Copy-Update (RCU) hoặc versioned double-buffer cho cấu trúc phân loại ACL, cho phép data path đọc bộ rule hiện tại mà không cần khóa trong khi một control-plane thread chuẩn bị và cài đặt nguyên tử một phiên bản cập nhật.

### 9.6 Deep Packet Inspection (DPI)

Khả năng DPI sẽ mở rộng phân loại vượt ra ngoài header L2–L4 vào nội dung payload tầng ứng dụng, cho phép nhận dạng giao thức (HTTP, TLS, DNS, QUIC) và thực thi chính sách dựa trên nội dung. Điều này sẽ yêu cầu một payload inspection engine được tích hợp như giai đoạn xử lý sau ACL classify trong Worker lcore, với reassembly có chọn lọc cho payload bị phân mảnh hoặc đa segment.

### 9.7 Giao Diện Quản Lý

Một giao diện quản lý (gRPC, NETCONF hoặc REST API) sẽ cho phép các hệ thống bên ngoài truy vấn thống kê runtime, lấy rule hit counter và (với hỗ trợ cập nhật rule động) sửa đổi bộ rule đang hoạt động. Điều này sẽ yêu cầu một management lcore riêng và một API contract được định nghĩa rõ ràng, giữ cho lưu lượng quản lý được cô lập khỏi các data path lcore.

---

*Kết thúc tài liệu — SPIFAST-HLD-001-VI v1.5*
