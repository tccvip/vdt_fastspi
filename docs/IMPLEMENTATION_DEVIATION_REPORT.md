# Báo Cáo Sai Lệch Triển Khai

---

**Tiêu đề tài liệu:** Báo Cáo Sai Lệch Giữa Thiết Kế và Triển Khai — SPIFast

**Mã tài liệu:** SPIFAST-DEV-001

**Phiên bản:** 1.0

**Ngày:** 2026-06-30

**Tài liệu tham chiếu:**
- SPIFAST-HLD-001 v1.4
- SPIFAST-SDD-001 v1.2 / v1.3
- SPIFAST-SRS-001 v1.1

---

## Mục Đích

Tài liệu này ghi lại tất cả sai lệch giữa thiết kế được định nghĩa trong HLD/SDD và mã nguồn thực tế được triển khai. Mỗi sai lệch được phân tích theo nguyên nhân kỹ thuật, tác động đến kiến trúc/hiệu năng/kiểm thử, và hành động cập nhật tài liệu cần thiết.

Các sai lệch trong tài liệu này **không phải là bug** trừ khi được ghi rõ. Chúng phản ánh quá trình tiến hóa thiết kế trong quá trình triển khai thực tế.

---

## Tổng Quan Sai Lệch

| # | Thành phần | Loại sai lệch | Mức độ tác động |
|---|---|---|---|
| D-01 | RX lcore | Thay đổi cơ chế I/O | Cao |
| D-02 | PCAP Replay | Thay đổi hành vi vòng đời | Trung bình |
| D-03 | ACL Engine | Thay đổi thuật toán matching | Cao |
| D-04 | Throughput đo lường | Thay đổi định nghĩa chỉ số | Trung bình |
| D-05 | Packet Accounting | Thay đổi công thức bảo toàn | Thấp |
| D-06 | pkt_meta_t kích thước | Thay đổi cấu trúc dữ liệu | Thấp |
| D-07 | Per-group hit counting | Thay đổi vị trí lưu trữ | Thấp |
| D-08 | Logging: perf_stats | Module bổ sung ngoài SDD | Thấp |
| D-09 | Shutdown sequence | Thay đổi cơ chế tắt máy | Trung bình |
| D-10 | Worker ring size | Thay đổi tham số tài nguyên | Trung bình |

---

## D-01 — RX lcore: libpcap thay vì DPDK net_pcap PMD

### 1. Thành phần
`src/packet/rx.c` — RX lcore

### 2. Thiết kế gốc (HLD §2.2, SDD §2.2)

SDD §2.2 định nghĩa RX lcore hoạt động như sau:

> "Thành phần Nhận Gói Tin vận hành trên RX lcore được dành riêng. Thành phần này liên tục poll NIC hoặc virtual port `net_pcap` bằng DPDK burst receive API (`rte_eth_rx_burst`) để drain các mbuf có sẵn từ PMD vào local burst buffer."

Pseudo-code trong SDD:
```c
nb_rx = rte_eth_rx_burst(port_id, queue_id=0, rx_pkts[], burst_size=BURST_SIZE)
```

DPDK net_pcap PMD được cấu hình là nguồn đầu vào duy nhất (DD-06). Mbuf được cấp phát tự động bởi PMD từ mempool đã đăng ký.

HLD §2.2 cũng mô tả lightweight hash trên IP src tại fixed byte offset ngay sau `rte_eth_rx_burst`.

### 3. Triển khai thực tế (rx.c)

RX lcore sử dụng **libpcap trực tiếp** thay vì DPDK PMD:

```c
pcap_t *handle = pcap_open_offline(ctx->pcap_path, errbuf);
// ...
int ret = pcap_next_ex(handle, &pkt_hdr, &pkt_data);
// ...
struct rte_mbuf *m = rte_pktmbuf_alloc(ctx->mempool);
rte_memcpy(rte_pktmbuf_mtod(m, void *), pkt_data, caplen);
m->data_len = caplen;
m->pkt_len  = caplen;
```

RX lcore tự tay:
- Gọi `pcap_next_ex()` để lấy từng packet từ file PCAP
- Gọi `rte_pktmbuf_alloc()` để cấp phát mbuf
- Gọi `rte_memcpy()` để copy dữ liệu packet vào mbuf

DPDK net_pcap port vẫn được `dpdk_init()` khởi tạo và start, nhưng **chỉ được dùng bởi TX lcore** thông qua `rte_eth_tx_burst()`.

Lightweight hash (placeholder) không được triển khai — toàn bộ burst được enqueue thẳng vào `parser_ring` duy nhất mà không có hash.

### 4. Lý do sai lệch

Phương án libpcap cho phép kiểm soát chính xác hơn quá trình đọc PCAP, đặc biệt:
- Dễ dàng phát hiện EOF và quyết định hành vi replay
- Không phụ thuộc vào hành vi nội bộ của `net_pcap` PMD (như số lần loop, xử lý EOF)
- Thuận tiện hơn cho kiểm thử và debug trong môi trường phát triển
- `rte_pktmbuf_alloc` + `memcpy` tạo ra layout mbuf giống hệt PMD (headroom 128B, data tại `rte_pktmbuf_mtod`)

### 5. Tác động

**Kiến trúc:**
- DPDK port không còn là nguồn đầu vào thực tế; nó chỉ là TX sink
- Mbuf layout giống hệt PMD path → các module downstream (Parser, Worker, TX) không bị ảnh hưởng
- Zero-copy model bị phá vỡ: có một lần `memcpy` tại RX (từ libpcap buffer vào mbuf data); tuy nhiên đây là copy bắt buộc khi dùng libpcap

**Hiệu năng:**
- `rte_pktmbuf_alloc` + `memcpy` thêm overhead so với PMD path (PMD cấp phát mbuf trước, không cần memcpy)
- `pcap_next_ex` có overhead của libpcap (I/O hệ thống)
- `alloc_fail` counter (`ctx->stats->alloc_fail`) theo dõi trường hợp mempool cạn — điều không xảy ra với PMD path

**Kiểm thử:**
- Kết quả RX stage cycles (perf_stats) phản ánh `pcap_next_ex + alloc + memcpy`, không phải `rte_eth_rx_burst`
- Điều kiện đo hiệu năng cần ghi nhận rằng RX không phải là DPDK poll-mode thuần túy

### 6. Cập nhật tài liệu cần thiết

- **HLD §2.2**: Cập nhật mô tả RX lcore để phản ánh libpcap path
- **SDD §2.2**: Thay thế pseudo-code `rte_eth_rx_burst` bằng `pcap_next_ex` + `rte_pktmbuf_alloc` + `rte_memcpy`
- **HLD §1.3 (bảng giai đoạn)**: Cập nhật dòng "RX lcore: `rte_eth_rx_burst()`" thành "RX lcore: `pcap_next_ex()` + mbuf alloc + memcpy"
- **SDD §7.1 (Mempool)**: Thêm ghi chú rằng mempool cung cấp mbuf cho cả RX lcore (thủ công) và TX PMD

---

## D-02 — PCAP Replay: Continuous Loop thay vì Single-Pass

### 1. Thành phần
`src/packet/rx.c` — vòng đời PCAP replay

### 2. Thiết kế gốc (SDD §2.2, HLD §3.5, SRS TR-002)

**SRS TR-002:**
> "Hệ thống phải replay file PCAP đúng một lần. Khi tất cả gói tin trong file PCAP đã được nhận, virtual device phải báo hiệu kết thúc đầu vào và hệ thống phải hoàn thành xử lý các gói tin còn trong bộ đệm rồi kết thúc bình thường."

**HLD §3.5** mô tả shutdown sequence rõ ràng:
> "Khi PMD net_pcap đã replay hết tất cả frame, rte_eth_rx_burst() tiếp tục trả về không mbuf. RX lcore phát hiện điều kiện này và khởi tạo quá trình tắt máy có trật tự."

**SDD §2.2** định nghĩa `EOI_THRESHOLD`:
> "PMD net_pcap trả về 0 mbuf khi file PCAP đã được tiêu thụ hết. Counter liên tiếp bằng không EOI_THRESHOLD (mặc định: 100 lần poll liên tiếp) ngăn false positive."

### 3. Triển khai thực tế (rx.c)

RX lcore **loop vô hạn**, mở lại file sau mỗi lần EOF:

```c
/* Comment trong main.c:
 * NOT set by pcap EOF — the RX lcore loops the file indefinitely. */
volatile int g_shutdown_flag = 0;

// Trong rx.c:
while (!g_shutdown_flag) {
    pcap_t *handle = pcap_open_offline(ctx->pcap_path, errbuf);
    // ...
    while (!g_shutdown_flag) {
        int ret = pcap_next_ex(handle, &pkt_hdr, &pkt_data);
        if (ret == -2) { eof_reached = true; break; }  /* normal EOF */
        // ...
    }
    pcap_close(handle);
    if (eof_reached) {
        ctx->stats->pcap_loops++;   /* completed one full pass */
        // rte_delay_us_sleep(1000);  /* commented out */
    }
}
```

Khi EOF: đóng handle, tăng `pcap_loops`, mở lại file ở đầu. Không bao giờ đặt `g_shutdown_flag`. Shutdown chỉ xảy ra khi có SIGINT/SIGTERM.

`SPIFAST_EOI_THRESHOLD` được định nghĩa trong `dpdk_init.h` (mặc định 100) nhưng không được dùng trong rx.c hiện tại.

### 4. Lý do sai lệch

Continuous replay cho phép:
- Đo throughput bền vững trong khoảng thời gian dài (không dừng khi hết file nhỏ)
- Benchmark với file PCAP nhỏ mà không cần sinh file lớn
- Pipeline luôn có gói tin để xử lý — tránh tình trạng lcore idle sau khi PCAP hết

Đây là quyết định thiết kế có chủ ý cho môi trường benchmark.

### 5. Tác động

**Kiến trúc:**
- Không có automatic shutdown; người vận hành phải dừng bằng Ctrl+C hoặc SIGTERM
- `pcap_loops` counter cần thiết để theo dõi số lần replay
- Packet accounting (`validate_packet_accounting`) đo trên toàn bộ session (nhiều loops), không phải per-loop

**Packet Accounting:**
- `rx_total` tích lũy qua tất cả loops, không thể đối chiếu với số packet trong file PCAP gốc
- Đây là lý do `parser_ring_drop` bị loại khỏi công thức bảo toàn (xem D-05)

**Kiểm thử:**
- SRS TR-002 ("replay một lần duy nhất") không được đáp ứng trong cài đặt hiện tại
- Các test case FT-018 (tóm tắt cuối phiên) và PT-004 (zero packet loss) cần điều chỉnh định nghĩa "phiên chạy"

**Hiệu năng:**
- File PCAP được đọc lại từ đầu mỗi loop — OS page cache giữ file sau lần đầu, overhead I/O gần bằng không từ loop thứ 2
- `pcap_loops` có thể được dùng để ước tính tổng số packet duy nhất

### 6. Cập nhật tài liệu cần thiết

- **SRS TR-002**: Thêm chế độ hoạt động thứ hai "continuous replay mode" như một mode được hỗ trợ bên cạnh single-pass
- **HLD §3.5**: Bổ sung nhánh "continuous replay": "RX lcore mở lại file PCAP sau EOF; không khởi tạo shutdown"
- **SDD §2.2**: Cập nhật vòng lặp chính, thêm trường `pcap_loops` vào `rx_lcore_stats_t`
- **HLD §7 (Kiến trúc đo hiệu năng)**: Ghi chú rằng các chỉ số hiệu năng được đo trên continuous replay session

---

## D-03 — ACL Engine: Linear Scan thay vì rte_acl_classify

### 1. Thành phần
`src/rule/acl_engine.c` — ACL matching engine

### 2. Thiết kế gốc (SDD §4, HLD §2.4, DD-15)

**SDD §4.5** mô tả build `flat_acl_ctx`:
```
acl_engine_build(flat_rule_table, match_mode):
  ctx = rte_acl_create("spifast_flat")
  rte_acl_add_rules(ctx, ...)
  rte_acl_build(ctx, &acl_build_cfg)
  flat_acl_ctx = ctx
```

**SDD §4.6** mô tả lookup:
```
rte_acl_classify(flat_acl_ctx, keys_ptr, results, nb, 1)
→ results[i] = file_order + 1 của rule khớp có priority cao nhất
→ action = flat_rule_table.rules[results[i] - 1].action  (O(1))
```

**DD-15** (HLD §8): "Một `rte_acl_ctx` duy nhất... Worker gọi `rte_acl_classify` một lần duy nhất mỗi burst... Batch classify cho phép CPU prefetch và SIMD pipeline che giấu cache miss latency."

### 3. Triển khai thực tế (acl_engine.c)

`rte_acl_classify` **không được gọi**. `g_flat_ctx = NULL`. ACL matching là **linear scan qua sorted index**:

```c
/* Comment trong acl_engine.c: */
static struct rte_acl_ctx *g_flat_ctx = NULL;  /* NULL in Phase 3 */
static uint32_t g_sorted_idx[SPIFAST_MAX_RULES];

int acl_engine_build(const flat_rule_table_t *tbl, match_mode_t mode) {
    (void)s_acl_fields;   /* retained for Phase 4+ rte_acl integration */
    // Build sorted index via qsort()
    for (uint32_t i = 0; i < tbl->num_rules; i++)
        g_sorted_idx[i] = i;
    qsort(g_sorted_idx, tbl->num_rules, sizeof(...), cmp_rule_idx);
    // No rte_acl_create, no rte_acl_build
}

const flat_rule_entry_t *flat_acl_match(const flat_rule_table_t *tbl,
                                         const acl_key_t *key) {
    for (uint32_t i = 0; i < g_num_sorted; i++) {
        const flat_rule_entry_t *rule = &tbl->rules[g_sorted_idx[i]];
        if (rule_matches(rule, key))
            return rule;
    }
    return NULL;
}

void flat_acl_match_burst(..., uint32_t nb) {
    for (uint32_t i = 0; i < nb; i++)
        results[i] = flat_acl_match(tbl, keys[i]);  /* per-packet loop */
}
```

`rule_matches()` thực hiện so sánh explicit từng trường:
- Protocol: `e->protocol != 0 && e->protocol != k->protocol`
- IP src/dst: CIDR mask `(k->src_ip & mask) != (rte_be_to_cpu_32(e->src_ip) & mask)`
- Port src/dst: range `k->src_port < e->src_port_lo || k->src_port > e->src_port_hi`

`s_acl_fields[]` (định nghĩa trường cho rte_acl) được khai báo nhưng chỉ để dành cho "Phase 4+ rte_acl integration".

**Phân loại giai đoạn:**
- Phase 3 (hiện tại): Custom linear scan
- Phase 4 (tương lai): rte_acl_classify với SIMD acceleration

### 4. Lý do sai lệch

`rte_acl` có API phức tạp và yêu cầu chính xác về định nghĩa trường, byte order, và format rule. Giai đoạn Phase 3 ưu tiên tính đúng đắn và khả năng debug. Linear scan với sorted index:
- Dễ debug: `rule_matches()` minh bạch, dễ kiểm tra từng trường
- Không phụ thuộc vào SIMD ISA (tránh lỗi biên dịch trên CPU không hỗ trợ)
- Đủ hiệu năng cho quy mô rule nhỏ (< 100 rules) trong môi trường kiểm thử

### 5. Tác động

**Hiệu năng:**
- Complexity: O(N_rules) mỗi packet thay vì O(log N) với rte_acl trie
- Với N = 10–20 rules: ảnh hưởng không đáng kể; với N = 1000+ rules: sẽ là bottleneck
- Không có SIMD parallelism → không tận dụng được AVX2/AVX-512 của CPU
- `flat_acl_match_burst()` là vòng lặp per-packet, không phải batch thực sự (không có SIMD pipeline)
- Perf report ghi nhận "Flat ACL (flat_acl_match_burst)" cycles — đây là linear scan cycles, không phải rte_acl cycles

**Kiến trúc:**
- Kết quả `results[]` là `const flat_rule_entry_t *` (con trỏ trực tiếp), khác với SDD mô tả `uint32_t results[]` (userdata index)
- Worker code: `rule->action` thay vì `flat_rule_table.rules[results[i]-1].action` — interface thay đổi nhưng ngữ nghĩa tương đương
- `acl_get_flat_ctx()` trả về `NULL` — Worker không gọi hàm này; Worker gọi `flat_acl_match_burst()` trực tiếp

**Kiểm thử:**
- FT-008 đến FT-012 (rule matching tests): kết quả phụ thuộc vào `rule_matches()` chứ không phải rte_acl trie — cần test riêng khi migrate sang Phase 4
- Hiệu năng ACL reported qua `perf_acl` không có giá trị so sánh với rte_acl

### 6. Cập nhật tài liệu cần thiết

- **SDD §4**: Thêm ghi chú "Phase 3 implementation" với mô tả linear scan; giữ nguyên §4.5/§4.6 như spec Phase 4
- **SDD §2.5 (Module ACL Engine)**: Thêm bảng phân biệt Phase 3 (linear scan) và Phase 4 (rte_acl_classify)
- **HLD DD-15**: Ghi chú "Planned for Phase 4; Phase 3 uses sorted linear scan"
- **SDD §4.11 (API)**: Cập nhật `flat_acl_match_burst()` signature — trả về `const flat_rule_entry_t *[]` thay vì `uint32_t results[]`

---

## D-04 — Throughput Đo Lường: TX Bytes thay vì Classified Bytes

### 1. Thành phần
`src/stats/stats.c` — `stats_collect()`, trường `interval_mbps`

### 2. Thiết kế gốc (HLD §7.2, SRS PR-001)

**HLD §7.2:**
> "Throughput được đo là tốc độ dữ liệu được xử lý qua giai đoạn phân loại, **bao gồm cả gói tin FORWARD lẫn DROP**."

**Công thức HLD:**
```
Throughput (Mbps) = (Tổng byte đã xử lý × 8) / Thời gian runtime (giây) / 1.000.000
```

"Byte đã xử lý được tích lũy theo từng mbuf từ trường `pkt_len` của mbuf" — tức là đo tại giai đoạn Worker sau khi classify.

**SRS PR-001:** Ngưỡng PASS: ≥ 700 Mbps.

### 3. Triển khai thực tế (stats.c)

Throughput chỉ đo **bytes forwarded đến TX** (không bao gồm DROP):

```c
/* stats.c - stats_collect() */
snap.total_bytes = g_ctx->tx_stats->tx_bytes;  /* chỉ tx_bytes từ TX lcore */

// ...
snap.interval_fwd_bytes = snap.total_bytes - g_prev.total_bytes;
snap.interval_mbps = (double)snap.interval_fwd_bytes * 8.0
                     / interval_sec / 1e6;
```

`tx_bytes` được tích lũy trong `tx_lcore_stats_t`:
```c
/* tx.c */
for (unsigned int i = 0; i < nb_sent; i++)
    stats->tx_bytes += lens[i];  /* chỉ các packet được gửi thành công */
```

Packet bị DROP bởi ACL rule **không** tính vào `interval_mbps`.

**log_final_summary** tính average Mbps:
```c
double avg_mbps = (elapsed > 0.0)
    ? (double)snap->total_bytes * 8.0 / elapsed / 1e6
    : 0.0;  /* total_bytes = tx_bytes only */
```

### 4. Lý do sai lệch

Đo TX bytes phản ánh thực tế phần lưu lượng đi qua NIC TX — thước đo hữu ích hơn về throughput thực sự của hệ thống khi DROP rate cao. Đây là cách đo phổ biến trong thực tế (không đếm traffic bị loại bỏ).

### 5. Tác động

**Đo hiệu năng:**
- Khi DROP rate = 0%: `interval_mbps` = throughput SRS (hai cách bằng nhau)
- Khi DROP rate = 50%: `interval_mbps` sẽ thấp hơn ~50% so với SRS PR-001 definition
- Ngưỡng PASS 700 Mbps (SRS PR-001) áp dụng cho classified bytes — với cách đo hiện tại, ngưỡng này tương đương với forwarded bytes khi rule set chủ yếu là FORWARD

**Kiểm thử:**
- PT-001 (Throughput test) cần ghi rõ cách đo: "forwarded bytes only" hay "total classified bytes"
- Khi test với rule set có nhiều DROP rules, kết quả Mbps sẽ thấp hơn thực tế xử lý

### 6. Cập nhật tài liệu cần thiết

- **HLD §7.2**: Thêm hai định nghĩa: (a) "Classified Throughput" = FWD+DROP bytes tại Worker, (b) "Forwarded Throughput" = TX bytes tại TX lcore; ghi rõ implementation hiện tại dùng (b)
- **SRS PR-001**: Ghi rõ Throughput đo theo "Forwarded Throughput" để nhất quán với implementation

---

## D-05 — Packet Accounting: parser_ring_drop bị loại khỏi Công Thức

### 1. Thành phần
`src/stats/stats.c` — `validate_packet_accounting()` và `src/logging/log.c` — `log_final_summary()`

### 2. Thiết kế gốc (HLD §7.5, SDD §8.1, FR-032)

**HLD §7.5:**
```
RX_total == TX_total + DROP_total + Invalid_total + TX_drop_total
```

**SDD §8.1** (conservation law):
```
rx_packets = parser_ring_drop
           + invalid_pkts
           + worker_ring_drop
           + drop_pkts
           + tx_ring_drop
           + tx_drop_pkts
           + tx_pkts
```

### 3. Triển khai thực tế (stats.c, log.c)

`parser_ring_drop` bị **comment out** khỏi cả hai vị trí:

```c
/* stats.c - validate_packet_accounting() */
uint64_t accounted = 0 //snap->total_parser_ring_drop  ← bị comment
                   + snap->total_invalid_pkts
                   + snap->total_worker_ring_drop
                   + snap->total_drop_pkts
                   + snap->total_tx_ring_drop
                   + snap->total_tx_drop_pkts
                   + snap->total_tx_pkts;
```

```c
/* log.c - log_final_summary() */
uint64_t pipe_drops = 0 // snap->total_parser_ring_drop  ← bị comment
                    + snap->total_invalid_pkts
                    + snap->total_worker_ring_drop
                    + snap->total_drop_pkts
                    + snap->total_tx_ring_drop;
```

Thêm vào đó, `log_final_summary` dùng **threshold 0.1% thay vì đối chiếu chính xác 0**:

```c
int overall_pass = (pipe_utilization <= PERF_SUCCESS)  /* PERF_SUCCESS = 0.001 */
                && (tx_ulilization <= PERF_SUCCESS);
```

### 4. Lý do sai lệch

Với **continuous replay** (D-02), `rx_packets` tích lũy qua nhiều vòng loop. `parser_ring_drop` là drop tại biên RX→Parser — khi parser_ring đầy tức thời rồi nhanh chóng có chỗ, drop này là đặc điểm bình thường của pipeline bất đồng bộ và không phản ánh "packet lost" theo nghĩa kiểm thử.

Nếu tính parser_ring_drop vào formula với continuous replay, sai số tích lũy sẽ làm PASS condition không đạt ngay cả khi pipeline hoạt động đúng.

Threshold 0.1% (PERF_SUCCESS) thay vì delta == 0 cho phép chấp nhận một tỷ lệ nhỏ ring overflow mà không mark FAIL.

### 5. Tác động

**Tính đúng đắn:**
- Packet accounting không còn đảm bảo 100% conserved — parser_ring_drop không được hạch toán
- Nếu parser_ring_drop lớn (ring overflow thường xuyên), PASS có thể trả về sai

**Kiểm thử:**
- FR-032 ("Xác nhận gói tin bị mất = 0%") không thể được xác nhận chính xác theo nghĩa gốc
- PT-004 (packet loss test) cần điều chỉnh định nghĩa "lost" để phù hợp với model continuous replay

### 6. Cập nhật tài liệu cần thiết

- **SDD §8.1**: Cập nhật conservation law cho hai chế độ: single-pass (parser_ring_drop tính) và continuous replay (parser_ring_drop loại trừ vì cross-loop)
- **HLD §7.5**: Ghi chú threshold 0.1% cho PASS condition thay vì delta = 0
- **SRS FR-032**: Làm rõ "gói tin bị mất" áp dụng cho single-pass mode; continuous replay mode có định nghĩa riêng

---

## D-06 — pkt_meta_t Kích Thước: 16 Byte thay vì 12 Byte

### 1. Thành phần
`src/packet/pkt_ctx.h` — `pkt_meta_t`

### 2. Thiết kế gốc (SDD §3.1)

SDD §3.1 ghi chú:
> "Tổng kích thước: 12 bytes. Vừa trong một cache line cùng với các biến cục bộ."

### 3. Triển khai thực tế (pkt_ctx.h)

```c
typedef struct {
    uint32_t src_ip;      // offset 0,  size 4
    uint32_t dst_ip;      // offset 4,  size 4
    uint16_t src_port;    // offset 8,  size 2
    uint16_t dst_port;    // offset 10, size 2
    uint8_t  protocol;    // offset 12, size 1
    uint8_t  vlan_valid;  // offset 13, size 1
    uint16_t vlan_id;     // offset 14, size 2
} pkt_meta_t;             // total: 16 bytes

_Static_assert(sizeof(pkt_meta_t) == 16, ...);
```

Struct 16 byte không có padding ngầm (tất cả trường đều căn chỉnh tự nhiên).

### 4. Lý do sai lệch

SDD §3.1 đã ghi đúng cấu trúc với `vlan_id` là `uint16_t`, nhưng ghi chú "12 bytes" không tính đến kích thước thực. Đây là lỗi chú thích trong tài liệu, không phải lỗi triển khai.

Kích thước 16 byte là chính xác và có lợi: struct chiếm đúng 16 byte — là kích thước cache-friendly (2 lần kích thước của một dword).

### 5. Tác động

**Kiến trúc:**
- `rte_hash_crc(meta, sizeof(pkt_meta_t), 0)` trong parser.c hash 16 byte — bao gồm cả `vlan_valid` và `vlan_id`. Điều này ổn nhưng có thể gây bất đối xứng nếu gói tin có VLAN và gói tin không VLAN của cùng flow có kết quả hash khác nhau
- Headroom: SDD nói 12B, thực tế 16B — vẫn trong giới hạn 128B headroom

**Hiệu năng:**
- 16B thay vì 12B trong hash input — không đáng kể

### 6. Cập nhật tài liệu cần thiết

- **SDD §3.1**: Sửa "Tổng kích thước: 12 bytes" thành "Tổng kích thước: 16 bytes"

---

## D-07 — Per-Group Hit Counting: worker_ctx_t thay vì worker_lcore_stats_t

### 1. Thành phần
`src/worker/worker.h` và `src/stats/stats.h`

### 2. Thiết kế gốc (SDD §3.5)

SDD §3.5 định nghĩa `worker_lcore_stats_t`:
```c
typedef struct {
    uint64_t fwd_packets;
    uint64_t fwd_bytes;
    uint64_t drop_packets;
    uint64_t tx_ring_drop;
    uint64_t hit_count[SPIFAST_MAX_GROUPS];  /* per-group match count */
    uint8_t  _pad[...];
} __rte_cache_aligned worker_lcore_stats_t;
```

`hit_count[]` nằm trong stats struct.

### 3. Triển khai thực tế

Hit counts nằm trong `worker_ctx_t`, không phải `worker_lcore_stats_t`:

```c
/* worker.h */
typedef struct {
    // ...
    uint64_t group_hits[SPIFAST_MAX_GROUPS];  /* hit counts per group */
    // ...
} worker_ctx_t;

/* worker_lcore_stats_t không có hit_count[] */
typedef struct {
    uint64_t received;
    uint64_t forwarded;
    uint64_t dropped;
    uint64_t tx_ring_drop;
    // Không có group_hits[]
} worker_lcore_stats_t;
```

Stats module đọc từ `worker_ctxs[i].group_hits[]`, không phải từ `worker_stats[i]`:

```c
/* stats.c */
const worker_ctx_t *wctx = &g_ctx->worker_ctxs[i];
for (uint32_t g = 0; g < n_groups; g++)
    snap.group_hits[g] += wctx->group_hits[g];
```

### 4. Lý do sai lệch

Đặt `group_hits[]` trong `worker_ctx_t` tách biệt per-group accounting (điều phối logic) khỏi per-lcore performance counters (thống kê hiệu năng). `worker_lcore_stats_t` tập trung vào packet throughput; `worker_ctx_t.group_hits[]` là ACL hit counters cho reporting.

Thực tế này cũng tránh làm `worker_lcore_stats_t` quá lớn (thêm `4096 × 8 = 32KB` vào một struct đã có cache-line padding).

### 5. Tác động

**Kiến trúc:**
- `stats_ctx_t` cần trỏ vào cả `worker_stats[]` và `worker_ctxs[]`
- Main.c khởi tạo cả hai: `stats_ctx.worker_stats = g_worker_stats; stats_ctx.worker_ctxs = g_worker_ctx`
- Không ảnh hưởng đến tính đúng đắn của hit counting

### 6. Cập nhật tài liệu cần thiết

- **SDD §3.5**: Di chuyển `hit_count[]` từ `worker_lcore_stats_t` vào `worker_ctx_t`
- **SDD §2.8 (Module Stats)**: Cập nhật mô tả đọc hit counts từ `worker_ctxs[i].group_hits[]`

---

## D-08 — Logging: perf_stats Module Bổ Sung

### 1. Thành phần
`src/perf/perf_stats.h`, `src/logging/log.c` — `log_perf_report()`

### 2. Thiết kế gốc (SDD §8, HLD §7)

SDD và HLD không định nghĩa module đo cycles per-stage. Thống kê hiệu năng chỉ bao gồm Mbps và PPS từ software counters.

### 3. Triển khai thực tế

Module `perf_stats` bổ sung đo thời gian cycles trên mỗi giai đoạn pipeline:

```c
/* perf_stats.h */
typedef struct {
    uint64_t total_cycles;
    uint64_t total_packets;
    uint64_t total_samples;
    uint8_t  _pad[CACHE_LINE_SIZE - 3 * sizeof(uint64_t)];
} __rte_cache_aligned perf_stage_t;

typedef struct {
    perf_stage_t rx;
    perf_stage_t parser;
    perf_stage_t worker[SPIFAST_MAX_WORKERS];  /* worker total */
    perf_stage_t acl[SPIFAST_MAX_WORKERS];     /* ACL-only subset */
    perf_stage_t tx;
    uint32_t     num_workers;
} perf_ctx_t;
```

Sampling rate: `SPIFAST_PERF_SAMPLE_RATE = 1000` (đo 1 trong 1000 burst/packet). Mỗi giai đoạn dùng `rte_rdtsc()` trước và sau tác vụ chính của mình.

`log_perf_report()` trong `log.c` xuất báo cáo đầy đủ qua dual-output channel, bao gồm:
- cycles/packet và nanoseconds/packet cho từng stage: RX, Parser, Worker (excl. ACL), Flat ACL, TX
- Tổng cycles/packet toàn pipeline
- PPS và Mbps hiện tại
- Per-worker: dispatched packets, ACL cycles, total cycles

### 4. Lý do sai lệch

Module này được thêm vào để đáp ứng nhu cầu điều tra hiệu năng ("why adding workers does not always improve throughput"). Đây là công cụ diagnostic, không phải phần của data path chính.

### 5. Tác động

**Overhead:**
- Sampling 1/1000 → overhead `rte_rdtsc()` < 0.1% tổng thời gian xử lý
- `perf_stage_t` cache-line aligned để tránh false sharing giữa các lcore

**Giá trị chẩn đoán:**
- Cho phép xác định bottleneck theo stage (RX, Parser, Worker, ACL, TX)
- ACL stage được tách riêng từ Worker để đo chính xác contribution của ACL
- Per-worker data: số packet dispatched, cycles — để phát hiện imbalance giữa workers

### 6. Cập nhật tài liệu cần thiết

- **SDD §8**: Thêm mục §8.4 "Performance Sampling" mô tả `perf_stage_t`, `perf_ctx_t`, sampling rate, và `log_perf_report()`
- **HLD §7**: Thêm mục "7.7 Per-Stage Latency Measurement" ghi nhận cơ chế rdtsc sampling

---

## D-09 — Shutdown Sequence: SIGINT/SIGTERM thay vì Pipeline EOF Cascade

### 1. Thành phần
`src/main.c`, tất cả lcore functions

### 2. Thiết kế gốc (HLD §3.5, SDD §2.2)

**HLD §3.5** định nghĩa tắt máy có trật tự theo thứ tự pipeline:
> "RX lcore báo hiệu Parser lcore → Parser lcore drain xong rồi báo hiệu Worker lcore(s) → Worker lcore(s) drain xong rồi báo hiệu TX lcore → TX lcore drain tx_ring rồi thoát."

Trigger: RX lcore phát hiện `rte_eth_rx_burst()` trả về 0 liên tục vượt `EOI_THRESHOLD`.

### 3. Triển khai thực tế

Tất cả lcore poll cùng một biến `g_shutdown_flag`:

```c
/* main.c */
static void spifast_sighandler(int sig) {
    (void)sig;
    g_shutdown_flag = 1;  /* set bởi SIGINT/SIGTERM */
}

signal(SIGINT,  spifast_sighandler);
signal(SIGTERM, spifast_sighandler);
```

Mỗi lcore thoát khi `g_shutdown_flag == 1` VÀ ring của nó rỗng:

```c
/* rx.c */   while (!g_shutdown_flag) { ... }
/* parser */ while (!g_shutdown_flag || !rte_ring_empty(ctx->parser_ring)) { ... }
/* worker */ while (!g_shutdown_flag || rte_ring_count(ring) > 0) { ... }
/* tx.c  */  while (!g_shutdown_flag || rte_ring_count(ring) > 0) { ... }
```

Main lcore gọi `rte_eal_mp_wait_lcore()` để chờ tất cả lcore thoát.

### 4. Lý do sai lệch

Với continuous replay (D-02), không có "EOF event" từ RX lcore. Pipeline cascade từ RX EOF không áp dụng được. Thay vào đó, signal handler là cơ chế clean shutdown duy nhất.

Mô hình drain-ring trước khi thoát (`!rte_ring_empty()` / `rte_ring_count() > 0`) đảm bảo pipeline drain theo thứ tự tự nhiên mà không cần explicit cascade.

### 5. Tác động

**Tính đúng đắn:**
- Drain sequence vẫn được đảm bảo: RX ngừng trước (không push thêm), Parser drain parser_ring, Worker drain worker_ring, TX drain tx_ring
- Không có packet loss do shutdown nếu signal được xử lý đúng lúc

**Kiểm thử:**
- Shutdown cần Ctrl+C hoặc SIGTERM từ bên ngoài
- Không có tự động kết thúc sau khi PCAP hết — cần script wrapper để test tự động

### 6. Cập nhật tài liệu cần thiết

- **HLD §3.5**: Thay thế "Pipeline EOF Cascade" bằng "Signal-driven shutdown với drain-then-exit pattern"
- **SDD §2.2**: Loại bỏ `EOI_THRESHOLD` logic (hoặc đánh dấu "not implemented") và mô tả `g_shutdown_flag` pattern

---

## D-10 — Worker Ring Size: 4096 (nhỏ hơn Parser Ring)

### 1. Thành phần
`src/dpdk/dpdk_init.h` — `SPIFAST_RING_SIZE`

### 2. Thiết kế gốc (SDD §7.3)

SDD §7.3 định nghĩa ba ring sizes (tất cả phải là power-of-two):
- `PARSER_RING_SIZE`: ring RX→Parser
- `RING_SIZE`: ring Parser→Worker[i]
- `TX_RING_SIZE`: ring Worker→TX

SDD không chỉ định giá trị cụ thể cho worker ring trong v1.2/v1.3; đây là tham số cấu hình.

### 3. Triển khai thực tế (dpdk_init.h)

```c
#define SPIFAST_PARSER_RING_SIZE  65536  /* Tier 1: RX → Parser (SPSC) */
#define SPIFAST_RING_SIZE          4096  /* Tier 2: Parser → Worker[i] (SPSC) */
#define SPIFAST_TX_RING_SIZE      65536  /* Tier 3: Worker×N → TX (MPSC) */
```

`worker_ring[i]` chỉ có 4096 slots, nhỏ hơn 16× so với `parser_ring` và `tx_ring`.

### 4. Lý do sai lệch

Ring size nhỏ hơn để giảm bộ nhớ (N workers × 4096 × 8 bytes thay vì N × 65536 × 8 bytes). Với N = 2 workers, worker_ring tổng = 2 × 4096 × 8 = 64KB; nếu dùng 65536 sẽ là 1MB.

Giả định: nếu parser đủ nhanh và worker drain nhanh, worker_ring 4096 đủ để không bị tràn.

### 5. Tác động

**Hiệu năng và Điều tra:**
- Nếu parser nhanh hơn worker (đặc biệt khi N_workers = 1), worker_ring có thể trở thành bottleneck
- `parser_ring_drop` tăng khi parser_ring đầy là bình thường; nhưng `worker_ring_drop` tăng khi worker không drain kịp là dấu hiệu worker quá tải hoặc ring quá nhỏ
- Đây liên quan trực tiếp đến vấn đề đang điều tra: "adding workers does not improve throughput" có thể do parser dispatch không đều (hash skew) hoặc worker_ring 4096 tạo backpressure sớm

**Kiểm thử:**
- Cần benchmark so sánh `SPIFAST_RING_SIZE = 4096` vs `8192` vs `16384` để xác định optimal size cho workload cụ thể

### 6. Cập nhật tài liệu cần thiết

- **SDD §7.3**: Ghi rõ giá trị mặc định: `PARSER_RING_SIZE=65536`, `RING_SIZE=4096`, `TX_RING_SIZE=65536` và lý do asymmetric sizing
- **HLD §4.6 (Phân tích Bottleneck)**: Thêm "worker_ring size" vào danh sách nguyên nhân bottleneck tiềm ẩn tại Parser→Worker tier

---

## Tóm Tắt Hành Động

### Tài Liệu Cần Cập Nhật

| Tài liệu | Mục cần cập nhật | Ưu tiên |
|---|---|---|
| SDD §2.2 (RX) | libpcap path, continuous replay | Cao |
| SDD §4 (ACL) | Phase 3 linear scan vs Phase 4 rte_acl | Cao |
| HLD §2.2 (RX) | Mô tả libpcap path | Cao |
| HLD §3.5 (Shutdown) | Signal-driven shutdown | Trung bình |
| HLD §7.2 (Throughput) | TX-only bytes definition | Trung bình |
| SDD §3.1 (pkt_meta_t) | Sửa kích thước 12→16 bytes | Thấp |
| SDD §3.5 (Stats structs) | Di chuyển group_hits vào worker_ctx_t | Thấp |
| SDD §7.3 (Ring sizes) | Ghi rõ asymmetric sizing | Thấp |
| SDD §8 (Logging) | Thêm perf_stats module | Thấp |
| SRS TR-002 | Thêm continuous replay mode | Trung bình |

### Điều Tra Kỹ Thuật Liên Quan

Các sai lệch D-02 (continuous replay), D-03 (linear scan ACL), và D-10 (worker ring size) liên quan trực tiếp đến vấn đề đang điều tra: **tại sao tăng số worker không luôn cải thiện throughput**.

Nguyên nhân có thể:
1. **Parser là bottleneck** (single-threaded): parser_ring đầy → parser_ring_drop tăng → worker không nhận đủ packet
2. **worker_ring 4096 gây backpressure**: nếu hash dispatch tập trung vào một worker (hash skew), worker_ring của worker đó đầy nhanh → parser phải drop tại worker_ring
3. **tx_ring MPSC overhead**: với N_workers > 1, CAS contention tại tx_ring tăng theo N
4. **Linear scan ACL**: flat_acl_match_burst không thực sự parallel per-packet; O(N_rules) per packet chia đều cho tất cả worker

---

*Kết thúc tài liệu — SPIFAST-DEV-001 v1.0*
