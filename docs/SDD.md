# Thiết Kế Chi Tiết Phần Mềm

---

**Tiêu đề tài liệu:** Thiết Kế Chi Tiết Phần Mềm — SPIFast: Hệ Thống Kiểm Tra Gói Tin Hiệu Năng Cao Sử Dụng DPDK

**Mã tài liệu:** SPIFAST-SDD-001

**Phiên bản:** 1.4

**Trạng thái:** Draft

**Người soạn thảo:** Nhóm Kỹ Thuật Hệ Thống

**Ngày:** 2025-06-28

**HLD áp dụng:** SPIFAST-HLD-001 v1.5

**SRS áp dụng:** SPIFAST-SRS-001 v1.0

**Phiên bản DPDK mục tiêu:** 23.11 LTS (tối thiểu 21.11 LTS)

**Công cụ build:** GCC 10+, GNU Make hoặc CMake 3.16+, Linux kernel 5.4+

---

## Lịch Sử Sửa Đổi

| Phiên bản | Ngày | Tác giả | Mô tả |
|---|---|---|---|
| 0.1 | 2025-06-26 | Kỹ thuật hệ thống | Bản thảo SDD ban đầu |
| 1.0 | 2025-06-26 | Kỹ thuật hệ thống | Baseline SDD căn chỉnh với HLD v1.1 và SRS v1.0 |
| 1.1 | 2025-06-28 | Kỹ thuật hệ thống | Cập nhật theo HLD v1.3: pipeline 5 giai đoạn; tách Parser lcore riêng; ACL classify batch two-stage tại Worker; thêm TX lcore; ba tầng ring SPSC/SPSC/MPSC; metadata qua mbuf headroom; hash dispatch tại Parser |
| 1.2 | 2026-06-28 | Kỹ thuật hệ thống | Mục 4: Thay thế Two-Stage ACL (stage1_ctx + group_ctx[]) bằng Flat Single-Stage ACL (flat_acl_ctx + flat_rule_table_t); loại bỏ lazy build, filter_group_table, acl_result_t; giữ nguyên ACL field definitions và worker burst interface |
| 1.3 | 2026-06-30 | Kỹ thuật hệ thống | Đồng bộ hóa với cài đặt thực tế: cập nhật rx_lcore_stats_t (thêm rx_bytes, alloc_fail, pcap_loops); cập nhật Section 6.2 RX dùng libpcap; cập nhật hằng số tài nguyên (mempool, ring, burst); cập nhật stats_collect pseudo-code; cập nhật định dạng log |
| 1.4 | 2026-06-30 | Kỹ thuật hệ thống | Đồng bộ hóa implementation cuối: cập nhật §2.2 pseudocode sang libpcap path; sửa pkt_meta_t kích thước 12→16 bytes (§3.1); cập nhật worker_lcore_stats_t (loại bỏ hit_count[], chuyển sang worker_ctx_t.group_hits[]); thêm Phase 3/Phase 4 note cho ACL engine (§4); cập nhật shutdown_flag writer (§6.8); cập nhật stats_collect sources (§8.1 — tx_bytes từ tx_stats, group_hits từ worker_ctxs); cập nhật validate_packet_accounting (loại trừ parser_ring_drop, dùng ngưỡng 0,1%); thêm §8.4 perf_stats module |

---

## Mục Lục

1. Tổng Quan Kiến Trúc Phần Mềm
2. Thiết Kế Chi Tiết Module
3. Thiết Kế Cấu Trúc Dữ Liệu
4. Thiết Kế ACL Rule Engine
5. Thiết Kế Cấu Hình Rule
6. Thiết Kế Đa Lõi và Luồng
7. Thiết Kế Tài Nguyên DPDK
8. Thiết Kế Thống Kê và Logging
9. Thiết Kế Cấu Hình
10. Thiết Kế Xử Lý Lỗi
11. Trình Tự Triển Khai

---

## 1. Tổng Quan Kiến Trúc Phần Mềm

### 1.1 Ánh Xạ Từ Thành Phần HLD Sang Module Phần Mềm

HLD v1.3 định nghĩa pipeline 5 giai đoạn với các lcore chuyên biệt. Mỗi giai đoạn ánh xạ sang một module phần mềm riêng biệt trong cây thư mục `src/`. Điểm vào `main` đóng vai trò bộ điều phối (orchestrator) khởi tạo tất cả module theo thứ tự phụ thuộc và khởi chạy các DPDK lcore.

```
spifast/
├── Makefile               # File build cấp cao nhất (hoặc CMakeLists.txt)
├── config/
│   └── spi_rules.conf     # File cấu hình rule tham chiếu
├── src/
│   ├── main.c             # Điểm vào: phân tích tham số, trình tự khởi tạo, khởi chạy lcore
│   ├── dpdk/
│   │   ├── dpdk_init.c    # EAL init, mempool, port, tạo ba tầng ring
│   │   └── dpdk_init.h
│   ├── packet/
│   │   ├── rx.c           # RX lcore: burst poll, lightweight hash, enqueue parser_ring
│   │   ├── rx.h
│   │   ├── parser.c       # Parser lcore: prefetch, parse L2-L4, headroom write, hash dispatch
│   │   └── parser.h
│   ├── rule/
│   │   ├── rule_loader.c  # Phân tích file rule, kiểm tra hợp lệ, bảng filter-group
│   │   ├── rule_loader.h
│   │   ├── acl_engine.c   # Build flat single-stage ACL (flat_acl_ctx); single-step batch lookup
│   │   └── acl_engine.h
│   ├── worker/
│   │   ├── worker.c       # Worker lcore: dequeue, đọc headroom, single-stage flat ACL, FORWARD/DROP
│   │   └── worker.h
│   ├── tx/
│   │   ├── tx.c           # TX lcore: drain tx_ring, rte_eth_tx_burst, sở hữu TX queue
│   │   └── tx.h
│   ├── stats/
│   │   ├── stats.c        # Tổng hợp counter từ tất cả lcore; tính Mbps/PPS
│   │   └── stats.h
│   └── logging/
│       ├── log.c          # Xuất log định kỳ và cuối phiên ra stdout và file log
│       └── log.h
└── tools/
    └── pcap_gen/          # Script sinh lưu lượng PCAP độc lập
```

### 1.2 Tóm Tắt Trách Nhiệm Module

| Module | Thành phần HLD | Trách nhiệm chính |
|---|---|---|
| `main` | Orchestrator | Phân tích tham số; trình tự khởi tạo; gán và khởi chạy lcore; tắt máy có trật tự |
| `dpdk/dpdk_init` | Khởi tạo DPDK | EAL init; cấp phát mempool; cấu hình port; tạo parser_ring (SPSC), worker_ring[i] (SPSC), tx_ring (MPSC) |
| `packet/rx` | RX lcore | Poll-mode burst RX; lightweight hash trên IP src offset; enqueue mbuf pointer vào parser_ring; phát hiện kết thúc PCAP |
| `packet/parser` | Parser lcore | Dequeue từ parser_ring; prefetch mbuf data; parse L2/VLAN/L3/L4; flow normalization; ghi five-tuple metadata vào mbuf headroom; hash dispatch chọn worker_ring[i] |
| `rule/rule_loader` | ACL Rule Engine (giai đoạn nạp) | Phân tích file rule; kiểm tra hợp lệ trường; xây dựng `flat_rule_table_t` với action nhúng trực tiếp trong mỗi entry |
| `rule/acl_engine` | ACL Rule Engine (giai đoạn build + lookup) | Build `flat_acl_ctx` duy nhất từ `flat_rule_table_t`; cung cấp single-stage batch lookup được gọi từ Worker lcore |
| `worker/worker` | Worker lcore | Dequeue burst từ worker_ring; đọc metadata từ mbuf headroom; single-stage flat ACL classify; tra cứu action từ flat_rule_table; FORWARD → enqueue tx_ring; DROP → rte_pktmbuf_free |
| `tx/tx` | TX lcore | Drain tx_ring (MPSC); rte_eth_tx_burst(); sở hữu TX queue duy nhất; xử lý mbuf chưa gửi được |
| `stats/stats` | Statistics Component | Tổng hợp counter lock-free từ tất cả lcore (RX, Parser, Worker×N, TX); tính Mbps và PPS |
| `logging/log` | Logging Component | Xuất log định kỳ và cuối phiên ra stdout và file log tùy chọn; quản lý dual-output; xuất `log_perf_report()` per-stage cycles |
| `perf/perf_stats` | (ngoài HLD) | Cấu trúc đo cycles per-stage (`perf_stage_t`, `perf_ctx_t`); sampling 1/1000 burst bằng `rte_rdtsc()`; không có I/O trên data path |

### 1.3 Đồ Thị Phụ Thuộc Liên Module

```
main
 ├── dpdk_init        (gọi đầu tiên; tạo parser_ring, worker_ring[], tx_ring)
 ├── rule_loader      (gọi sau EAL; xây dựng flat_rule_table_t)
 │    └── acl_engine  (build flat_acl_ctx duy nhất từ flat_rule_table_t)
 ├── log              (mở sau khi config đã biết)
 ├── rx               (khởi chạy trên RX lcore; poll NIC → enqueue parser_ring)
 ├── parser           (khởi chạy trên Parser lcore; dequeue parser_ring →
 │                     parse → write headroom → hash dispatch → worker_ring[i])
 ├── worker×N         (khởi chạy trên N Worker lcore; dequeue worker_ring →
 │                     single-stage flat ACL → FORWARD→tx_ring | DROP→free)
 │    └── acl_engine  (flat lookup: read-only flat_acl_ctx + flat_rule_table)
 ├── tx               (khởi chạy trên TX lcore; drain tx_ring → rte_eth_tx_burst)
 └── stats            (chạy trên timer của main lcore; đọc counter từ tất cả lcore)
      └── log         (stats kích hoạt xuất log)
```

---

## 2. Thiết Kế Chi Tiết Module

### 2.1 Module Khởi Tạo DPDK (`dpdk/dpdk_init`)

**Trách nhiệm:** Đưa môi trường runtime DPDK vào trạng thái hoạt động đầy đủ trước khi bắt đầu bất kỳ quá trình xử lý gói tin nào.

**Đầu vào:** Cấu hình ứng dụng đã phân tích (`spifast_config_t`), bao gồm số lượng worker và đường dẫn file PCAP.

**Đầu ra:** Các tài nguyên toàn cục đã khởi tạo: `rte_mempool`, `uint16_t port_id`, `rte_ring *parser_ring`, `rte_ring *worker_rings[]`, `rte_ring *tx_ring`, phân công vai trò lcore.

**Trình tự xử lý nội bộ:**

```
1. rte_eal_init(argc, argv)
   - Truyền các tham số EAL được build từ config ứng dụng.
   - Thiết lập ánh xạ lcore-to-CPU core affinity.
   - Ánh xạ hugepage memory cho DPDK sử dụng.
   - Khi thất bại: in lỗi và exit(EXIT_FAILURE).

2. Tạo mempool
   - rte_pktmbuf_pool_create(name, nb_mbufs, cache_size,
                              priv_size, data_room_size, socket_id)
   - nb_mbufs = SPIFAST_MEMPOOL_SIZE (xem Mục 7).
   - Một mempool duy nhất dùng chung trên tất cả lcore.
   - Khi thất bại: lỗi fatal.

3. Cấu hình NIC port hoặc net_pcap virtual device
   - Build chuỗi tham số thiết bị (PCAP) hoặc cấu hình NIC vật lý.
   - Cấu hình port: 1 RX queue, 1 TX queue.
   - rte_eth_dev_configure(port_id, 1, 1, &port_conf)
   - rte_eth_rx_queue_setup(port_id, 0, RX_DESC_DEFAULT,
                             socket_id, NULL, mempool)
   - rte_eth_tx_queue_setup(port_id, 0, TX_DESC_DEFAULT,
                             socket_id, NULL)
   - rte_eth_dev_start(port_id)
   - Khi có bất kỳ lỗi nào: lỗi fatal.

4. Tạo ba tầng ring
   /* Tầng 1: RX → Parser (SPSC) */
   parser_ring = rte_ring_create("parser_ring", PARSER_RING_SIZE,
                                  SOCKET_ID_ANY,
                                  RING_F_SP_ENQ | RING_F_SC_DEQ)

   /* Tầng 2: Parser → Worker[i] (SPSC per worker) */
   Với mỗi worker index i trong [0, num_workers):
     worker_rings[i] = rte_ring_create(name, RING_SIZE,
                                        SOCKET_ID_ANY,
                                        RING_F_SP_ENQ | RING_F_SC_DEQ)
     - RING_F_SP_ENQ: single producer (chỉ Parser lcore).
     - RING_F_SC_DEQ: single consumer (Worker lcore i).

   /* Tầng 3: Worker → TX (MPSC) */
   tx_ring = rte_ring_create("tx_ring", TX_RING_SIZE,
                               SOCKET_ID_ANY,
                               RING_F_SC_DEQ)
     - RING_F_SC_DEQ: single consumer (chỉ TX lcore).

   Khi có bất kỳ lỗi tạo ring nào: lỗi fatal.

5. Phân công vai trò lcore
   - main lcore   = rte_get_main_lcore()         → stats + logging + tắt máy
   - rx lcore     = lcore có sẵn đầu tiên sau main
   - parser lcore = lcore có sẵn tiếp theo
   - worker lcore = num_workers lcore có sẵn tiếp theo
   - tx lcore     = lcore có sẵn tiếp theo
   - Tổng lcore yêu cầu: num_workers + 4
   - Kiểm tra tổng lcore yêu cầu ≤ rte_lcore_count().
```

**Giao tiếp với các module khác:**
- Truyền con trỏ `mempool` và `port_id` cho module `rx`.
- Truyền `parser_ring` cho module `rx` (enqueue) và `parser` (dequeue).
- Truyền `worker_rings[]` cho module `parser` (enqueue) và `worker` (dequeue).
- Truyền `tx_ring` cho module `worker` (enqueue) và `tx` (dequeue).
- Truyền `port_id` và `tx_queue_id` cho module `tx`.
- Truyền lcore ID cho `main` để khởi chạy lcore.

---

### 2.2 Module Nhận Gói Tin (`packet/rx`)

**Trách nhiệm:** Liên tục poll NIC hoặc virtual port `net_pcap` ở chế độ burst; thực hiện lightweight hash để phân phối tải; enqueue mbuf pointer vào `parser_ring`; phát hiện kết thúc PCAP và phát tín hiệu tắt máy.

**Đầu vào:** `port_id`, `mempool`, `parser_ring`.

**Đầu ra:** mbuf pointer được enqueue vào `parser_ring`. Cập nhật `rx_lcore_stats`.

**Xử lý nội bộ — Vòng lặp chính của RX lcore:**

```
rx_lcore_func(void *arg):

  trong khi !g_shutdown_flag:
    handle = pcap_open_offline(ctx->pcap_path, errbuf)
    nb_batch = 0

    trong khi !g_shutdown_flag:
      ret = pcap_next_ex(handle, &pkt_hdr, &pkt_data)

      nếu ret == -2:   /* EOF */
        /* Flush batch còn lại */
        nếu nb_batch > 0:
          nb_enq = rte_ring_enqueue_burst(parser_ring, rx_pkts, nb_batch, NULL)
          /* free các mbuf không enqueue được */
          với mỗi i trong [nb_enq, nb_batch):
            rte_pktmbuf_free(rx_pkts[i])
            rx_lcore_stats.parser_ring_drop++
          rx_lcore_stats.rx_packets += nb_enq
          nb_batch = 0
        pcap_close(handle)
        rx_lcore_stats.pcap_loops++
        /* Mở lại file — continuous replay; KHÔNG đặt g_shutdown_flag */
        break

      nếu ret <= 0: tiếp tục   /* lỗi đọc, bỏ qua */

      caplen = pkt_hdr->caplen
      m = rte_pktmbuf_alloc(ctx->mempool)
      nếu m == NULL:
        rx_lcore_stats.alloc_fail++
        tiếp tục

      rte_memcpy(rte_pktmbuf_mtod(m, void *), pkt_data, caplen)
      m->data_len = caplen
      m->pkt_len  = caplen
      rx_lcore_stats.rx_bytes += caplen
      rx_pkts[nb_batch++] = m

      nếu nb_batch == SPIFAST_BURST_SIZE:
        nb_enq = rte_ring_enqueue_burst(parser_ring, rx_pkts, nb_batch, NULL)
        với mỗi i trong [nb_enq, nb_batch):
          rte_pktmbuf_free(rx_pkts[i])
          rx_lcore_stats.parser_ring_drop++
        rx_lcore_stats.rx_packets += nb_enq
        nb_batch = 0

  return 0
```

**Continuous replay:** Sau mỗi EOF (`ret == -2`), `pcap_close()` rồi mở lại file từ đầu. `g_shutdown_flag` **không bao giờ được đặt** bởi RX lcore. Chỉ SIGINT/SIGTERM handler mới đặt `g_shutdown_flag = 1`.

**Quyền sở hữu mbuf:** RX lcore sở hữu mỗi mbuf từ thời điểm `rte_pktmbuf_alloc` trả về cho đến khi:
- `rte_ring_enqueue_burst` thành công → quyền sở hữu chuyển sang Parser lcore.
- `rte_pktmbuf_free` được gọi (parser_ring đầy hoặc alloc_fail) → mbuf trả về mempool.

---

### 2.3 Module Phân Tích Gói Tin (`packet/parser`)

**Trách nhiệm:** Thực thi hàm Parser lcore: dequeue mbuf từ `parser_ring`; prefetch dữ liệu mbuf để ẩn cache miss; parse header L2/VLAN/L3/L4; chuẩn hóa luồng hai chiều; ghi five-tuple metadata vào mbuf headroom; thực hiện hash dispatch để chọn `worker_ring[i]`; enqueue mbuf pointer vào worker ring tương ứng.

**Đầu vào:** `parser_ring`, `worker_rings[]`, `N_workers`.

**Đầu ra:** mbuf với metadata đã ghi vào headroom, enqueue vào `worker_ring[worker_idx]`. Cập nhật `parser_lcore_stats`.

**Vòng lặp chính của Parser lcore:**

```
parser_lcore_func(void *arg):
  ctx = (parser_ctx_t *) arg

  trong khi shutdown_flag chưa được đặt HOẶC parser_ring chưa rỗng:
    nb = rte_ring_dequeue_burst(parser_ring, pkts[], BURST_SIZE, NULL)
    nếu nb == 0: tiếp tục

    /* Prefetch dữ liệu mbuf của các packet phía trước để ẩn cache miss */
    với mỗi i trong [0, min(PREFETCH_AHEAD, nb)):
      rte_prefetch0(rte_pktmbuf_mtod(pkts[i], void*))

    với mỗi i trong [0, nb):
      /* Prefetch packet i+PREFETCH_AHEAD trong khi xử lý packet i */
      nếu i + PREFETCH_AHEAD < nb:
        rte_prefetch0(rte_pktmbuf_mtod(pkts[i + PREFETCH_AHEAD], void*))

      /* Parse và dispatch */
      ok = parse_and_dispatch(pkts[i], ctx)
      nếu không ok:
        parser_lcore_stats.invalid_packets++

  return 0
```

**parse_and_dispatch(mbuf, ctx):**

```
  data     = rte_pktmbuf_mtod(mbuf, uint8_t *)
  data_len = mbuf->data_len
  meta     = (pkt_meta_t *)(data - sizeof(pkt_meta_t))  /* headroom area */

  /* --- Bước 1: Ethernet --- */
  nếu data_len < sizeof(eth_hdr): goto drop_invalid
  eth   = (struct rte_ether_hdr *) data
  etype = rte_be_to_cpu_16(eth->ether_type)
  offset = sizeof(struct rte_ether_hdr)   /* 14 bytes */

  /* --- Bước 2: VLAN (tùy chọn) --- */
  meta->vlan_id    = 0
  meta->vlan_valid = 0
  nếu etype == RTE_ETHER_TYPE_VLAN:
    nếu data_len < offset + 4: goto drop_invalid
    vlan_hdr = (struct rte_vlan_hdr *)(data + offset)
    meta->vlan_id    = rte_be_to_cpu_16(vlan_hdr->vlan_tci) & 0x0FFF
    meta->vlan_valid = 1
    etype  = rte_be_to_cpu_16(vlan_hdr->eth_proto)
    offset += 4

  /* --- Bước 3: Chỉ IPv4 --- */
  nếu etype != RTE_ETHER_TYPE_IPV4: goto drop_invalid
  nếu data_len < offset + sizeof(rte_ipv4_hdr): goto drop_invalid
  ip4 = (struct rte_ipv4_hdr *)(data + offset)
  ihl_bytes = (ip4->version_ihl & 0x0F) * 4
  nếu ihl_bytes < 20: goto drop_invalid
  meta->src_ip   = ip4->src_addr
  meta->dst_ip   = ip4->dst_addr
  meta->protocol = ip4->next_proto_id
  offset += ihl_bytes

  /* --- Bước 4: TCP hoặc UDP --- */
  nếu meta->protocol == IPPROTO_TCP:
    nếu data_len < offset + sizeof(rte_tcp_hdr): goto drop_invalid
    tcp = (struct rte_tcp_hdr *)(data + offset)
    meta->src_port = rte_be_to_cpu_16(tcp->src_port)
    meta->dst_port = rte_be_to_cpu_16(tcp->dst_port)
  ngược lại nếu meta->protocol == IPPROTO_UDP:
    nếu data_len < offset + sizeof(rte_udp_hdr): goto drop_invalid
    udp = (struct rte_udp_hdr *)(data + offset)
    meta->src_port = rte_be_to_cpu_16(udp->src_port)
    meta->dst_port = rte_be_to_cpu_16(udp->dst_port)
  ngược lại: goto drop_invalid

  /* --- Bước 5: Flow normalization --- */
  normalize_flow(meta)

  /* Metadata đã được ghi vào mbuf headroom — không cần truyền qua ring */

  /* --- Bước 6: Hash dispatch → chọn worker --- */
  worker_idx = rte_hash_crc(meta, sizeof(pkt_meta_t), 0) % ctx->N_workers
  rc = rte_ring_enqueue(ctx->worker_rings[worker_idx], mbuf)
  nếu rc != 0:   /* worker_ring đầy */
    rte_pktmbuf_free(mbuf)
    parser_lcore_stats.worker_ring_drop++
    return false

  return true

drop_invalid:
  rte_pktmbuf_free(mbuf)
  return false
```

**Ghi metadata vào mbuf headroom:**

`pkt_meta_t` (16 bytes) được ghi vào vùng headroom của chính mbuf tại địa chỉ `rte_pktmbuf_mtod(mbuf) - sizeof(pkt_meta_t)`. Mbuf headroom mặc định là 128 byte (`RTE_PKTMBUF_HEADROOM`), đủ chỗ cho metadata struct mà không cần cấp phát thêm bộ nhớ. Ring chỉ truyền mbuf pointer (8 byte) — Worker lcore đọc lại metadata từ headroom, đảm bảo metadata và packet data nằm gần nhau trong bộ nhớ (cache locality tốt).

**Hash dispatch — five-tuple hash (DD-14):**

`worker_idx = rte_hash_crc(&meta, sizeof(pkt_meta_t), seed) % N_workers`

Hàm hash sử dụng five-tuple đã chuẩn hóa (sau `normalize_flow`) làm input. Cùng một flow (cùng five-tuple) luôn được điều phối về cùng một Worker lcore, đảm bảo flow affinity và cache locality của `flat_acl_ctx` per-worker sau warm-up. Parser lcore là điểm duy nhất trong pipeline có đủ five-tuple đã parse để thực hiện hash chính xác (DD-14).

**Thuật toán chuẩn hóa luồng (`normalize_flow`):**

```
normalize_flow(meta):
  nếu meta->src_ip > meta->dst_ip:
    swap(meta->src_ip, meta->dst_ip)
    swap(meta->src_port, meta->dst_port)
  ngược lại nếu meta->src_ip == meta->dst_ip và meta->src_port > meta->dst_port:
    swap(meta->src_port, meta->dst_port)
```

Phép biến đổi thuần túy, thời gian hằng số, phi trạng thái. Đáp ứng DD-10, FR-012, FR-013.

---

### 2.4 Module Nạp Rule (`rule/rule_loader`)

**Trách nhiệm:** Đọc, phân tích và kiểm tra hợp lệ file cấu hình rule; xây dựng `flat_rule_table_t` với action (FORWARD/DROP) và `group_idx` đã được nhúng trực tiếp vào mỗi entry; gọi `acl_engine_build()` để biên dịch `flat_acl_ctx`.

**Đầu vào:** Chuỗi đường dẫn file từ `spifast_config_t`; `match_mode_t` từ `--mode`.

**Đầu ra:** `flat_rule_table_t` đã điền đầy đủ (rules[] + group_names[]) và `flat_acl_ctx` đã biên dịch (thông qua `acl_engine_build`). Trả về 0 khi thành công, -1 khi có bất kỳ lỗi nào.

**Xử lý nội bộ — xem Mục 5 để biết ngữ pháp đầy đủ.**

**Giao tiếp:** Gọi `acl_engine_build(flat_rule_table, match_mode)` sau khi tất cả rule đã được kiểm tra hợp lệ và `flat_rule_table` đã điền xong. Không còn truyền `filter_group_table` riêng — action đã nhúng sẵn trong mỗi `flat_rule_entry_t`.

---

### 2.5 Module ACL Engine (`rule/acl_engine`)

**Trách nhiệm:** Build `flat_acl_ctx` duy nhất từ `flat_rule_table_t` đã được rule_loader xây dựng; cung cấp single-stage batch lookup interface (đọc-chỉ, không trạng thái) cho Worker lcore.

**Đầu vào (giai đoạn build):** `const flat_rule_table_t *`, `match_mode_t`.

**Đầu vào (giai đoạn lookup — gọi từ Worker):** Mảng `const uint8_t *keys_ptr[]`, số lượng `nb`, mảng kết quả `uint32_t results[]`.

**Đầu ra (giai đoạn lookup):** `results[i]` = `file_order + 1` của rule khớp có priority cao nhất; `0` nếu không khớp (không xảy ra khi DEFAULT catch-all được thêm đúng cách). Worker tra cứu `flat_rule_table.rules[results[i]-1].action` để lấy action.

**Flat single-stage build:**

- `acl_engine_build(flat_rule_table, match_mode)`: Build một `rte_acl_ctx` duy nhất (`flat_acl_ctx`) chứa tất cả rule từ `flat_rule_table`. Priority được gán theo `match_mode` (xem Mục 4.4). Hoàn thành trước khi Worker lcore khởi chạy — không có lazy build.
- `acl_get_flat_ctx()`: Trả về `flat_acl_ctx` (read-only) để Worker gọi `rte_acl_classify`.
- `acl_get_flat_rule_table()`: Trả về `flat_rule_table` (read-only) để Worker tra cứu action sau classify.
- `acl_engine_destroy()`: Giải phóng `flat_acl_ctx`. Gọi từ main lcore sau khi tất cả Worker dừng.

**Xem Mục 4 để biết thiết kế ACL engine đầy đủ bao gồm ACL field definitions, priority encoding, build sequence và matching algorithm.**

---

### 2.6 Module Worker (`worker/worker`)

**Trách nhiệm:** Thực thi hàm Worker lcore: dequeue burst mbuf từ `worker_ring`; đọc five-tuple metadata từ mbuf headroom; thực hiện single-stage flat ACL classify; tra cứu action từ `flat_rule_table`; áp dụng hành động FORWARD (enqueue `tx_ring`) hoặc DROP (free mbuf).

**Đầu vào:** `rte_ring *worker_ring`, `rte_ring *tx_ring`, `struct rte_acl_ctx *flat_acl_ctx`, `const flat_rule_table_t *flat_rule_table`, con trỏ đến `worker_lcore_stats_t`.

**Đầu ra:** FORWARD mbufs được enqueue vào `tx_ring`. DROP mbufs được giải phóng về mempool. Counter `worker_lcore_stats_t` đã cập nhật.

**Vòng lặp chính của Worker lcore:**

```
worker_lcore_func(void *arg):
  ctx            = (worker_ctx_t *) arg
  ring           = ctx->ring
  tx             = ctx->tx_ring
  flat_acl_ctx   = ctx->flat_acl_ctx
  flat_rule_tbl  = ctx->flat_rule_table
  stats          = ctx->stats

  trong khi shutdown_flag chưa được đặt HOẶC ring chưa rỗng:
    nb = rte_ring_dequeue_burst(ring, pkts[], WORKER_BURST_SIZE, NULL)
    nếu nb == 0: tiếp tục

    /* Đọc metadata từ headroom và build key array */
    với mỗi i trong [0, nb):
      meta = (pkt_meta_t *)(rte_pktmbuf_mtod(pkts[i], uint8_t*)
                             - sizeof(pkt_meta_t))
      keys[i].protocol = meta->protocol
      keys[i].src_ip   = rte_be_to_cpu_32(meta->src_ip)   /* NBO → HBO cho ACL */
      keys[i].dst_ip   = rte_be_to_cpu_32(meta->dst_ip)
      keys[i].src_port = meta->src_port
      keys[i].dst_port = meta->dst_port

    /* Flat single-stage ACL classify — toàn bộ burst trong 1 lần gọi */
    memset(results, 0, nb * sizeof(uint32_t))
    rte_acl_classify(flat_acl_ctx, keys_ptr, results, nb, 1)

    /* Per-packet: tra cứu action và dispatch */
    nb_tx = 0
    với mỗi i trong [0, nb):
      ud = results[i]
      nếu ud == 0:
        /* Không rule nào khớp — fallback DROP (không xảy ra nếu DEFAULT tồn tại) */
        action    = ACTION_DROP
        group_idx = DEFAULT_GROUP_IDX
      ngược lại:
        entry     = &flat_rule_tbl->rules[ud - 1]   /* O(1) lookup */
        action    = entry->action
        group_idx = entry->group_idx

      /* Per-group hit counter — không trên mbuf critical path */
      ctx->group_hits[group_idx]++

      nếu action == ACTION_FORWARD:
        tx_burst[nb_tx++] = pkts[i]
        stats->forwarded++
      ngược lại:
        rte_pktmbuf_free(pkts[i])
        stats->dropped++

    /* Enqueue FORWARD batch vào tx_ring */
    nếu nb_tx > 0:
      nb_sent = rte_ring_enqueue_burst(tx, tx_burst, nb_tx, NULL)
      nếu nb_sent < nb_tx:
        với mỗi i trong [nb_sent, nb_tx):
          rte_pktmbuf_free(tx_burst[i])
          stats->tx_ring_drop++

  return 0
```

**Quyền sở hữu mbuf:** Worker sở hữu mbuf từ thời điểm `rte_ring_dequeue_burst` trả về cho đến khi:
- `rte_ring_enqueue_burst(tx_ring)` thành công → quyền sở hữu chuyển sang TX lcore.
- `rte_pktmbuf_free` được gọi (DROP hoặc tx_ring đầy) → mbuf trả về mempool.

---

### 2.7 Module TX (`tx/tx`)

**Trách nhiệm:** Thực thi hàm TX lcore: drain `tx_ring` (MPSC); gọi `rte_eth_tx_burst()` để truyền batch mbuf ra NIC TX queue; sở hữu TX queue duy nhất; xử lý mbuf chưa gửi được; cập nhật `tx_lcore_stats`.

**Đầu vào:** `rte_ring *tx_ring`, `port_id`, `tx_queue_id`.

**Đầu ra:** mbuf được truyền ra NIC TX. Mbuf chưa gửi được giải phóng về mempool. Counter `tx_lcore_stats` đã cập nhật.

**Vòng lặp chính của TX lcore:**

```
tx_lcore_func(void *arg):
  ctx   = (tx_ctx_t *) arg
  ring  = ctx->tx_ring
  stats = &ctx->stats

  trong khi shutdown_flag chưa được đặt HOẶC ring chưa rỗng:
    nb = rte_ring_dequeue_burst(ring, pkts[], TX_BURST_SIZE, NULL)
    nếu nb == 0: tiếp tục

    nb_sent = rte_eth_tx_burst(ctx->port_id, ctx->tx_queue_id, pkts, nb)

    stats->tx_packets += nb_sent
    với mỗi i trong [0, nb_sent):
      stats->tx_bytes += pkts[i]->pkt_len

    /* Giải phóng mbuf chưa gửi được (TX queue đầy) */
    nếu nb_sent < nb:
      với mỗi i trong [nb_sent, nb):
        rte_pktmbuf_free(pkts[i])
        stats->tx_drop_packets++

  return 0
```

**TX queue ownership:** TX lcore là thành phần duy nhất gọi `rte_eth_tx_burst()`. Không có Worker lcore hay lcore nào khác truy cập TX queue trực tiếp. Thiết kế này tránh tranh chấp TX queue và đơn giản hóa vòng đời mbuf trên đường FORWARD.

---

### 2.8 Module Thống Kê (`stats/stats`)

**Trách nhiệm:** Tổng hợp counter per-lcore thành tổng cộng cấp phiên; tính Throughput (Mbps) và PPS theo chu kỳ; cung cấp dữ liệu snapshot cho module logging.

**Đầu vào:** Con trỏ đến `rx_lcore_stats_t`, `parser_lcore_stats_t`, tất cả instance `worker_lcore_stats_t`, `tx_lcore_stats_t`; mảng hit counter ACL per-worker.

**Đầu ra:** `stats_snapshot_t` được module logging tiêu thụ.

**Xem Mục 8 để biết thiết kế thống kê đầy đủ.**

---

### 2.9 Module Logging (`logging/log`)

**Trách nhiệm:** Xuất thống kê định kỳ, sự kiện khởi động/tắt máy và tóm tắt phiên cuối cùng ra stdout và tùy chọn ra file log ở chế độ append. Toàn bộ I/O được thực hiện riêng trên main lcore.

**Đầu vào:** `stats_snapshot_t`, loại sự kiện vòng đời, đường dẫn file log (có thể là NULL).

**Đầu ra:** Văn bản được định dạng ra stdout và/hoặc file log.

**Xem Mục 8 để biết thiết kế logging đầy đủ.**

---

## 3. Thiết Kế Cấu Trúc Dữ Liệu

### 3.1 Cấu Trúc Metadata Gói Tin (`pkt_meta_t`)

Lưu trữ five-tuple đã phân tích và chuẩn hóa cho một gói tin đơn lẻ. Được **ghi vào mbuf headroom** bởi Parser lcore tại địa chỉ `rte_pktmbuf_mtod(mbuf) - sizeof(pkt_meta_t)`; được Worker lcore đọc lại từ headroom của cùng mbuf đó. Không heap-allocated; không stack-allocated; tồn tại suốt vòng đời mbuf trong pipeline.

```c
typedef struct {
    uint32_t src_ip;       /* Địa chỉ nguồn IPv4, network byte order,
                              đã chuẩn hóa (IP nhỏ hơn luôn ở đây)    */
    uint32_t dst_ip;       /* Địa chỉ đích IPv4, network byte order    */
    uint16_t src_port;     /* Cổng nguồn transport, host byte order    */
    uint16_t dst_port;     /* Cổng đích transport, host byte order     */
    uint8_t  protocol;     /* IP protocol: IPPROTO_TCP(6) hoặc IPPROTO_UDP(17) */
    uint8_t  vlan_valid;   /* 1 nếu frame mang VLAN tag, ngược lại 0  */
    uint16_t vlan_id;      /* 802.1Q VLAN ID [0..4095], hợp lệ khi vlan_valid=1 */
} pkt_meta_t;
```

**Ghi chú:**
- Các trường ở dạng host byte order sau khi trích xuất (ngoại trừ `src_ip`/`dst_ip` giữ nguyên network byte order vì ACL engine sử dụng trực tiếp cho prefix matching).
- Tổng kích thước: **16 bytes** (4+4+2+2+1+1+2, không có padding nội bộ nhờ căn chỉnh tự nhiên). `_Static_assert(sizeof(pkt_meta_t) == 16)` được đặt trong `pkt_ctx.h` để đảm bảo tại compile time.
- 16 bytes nằm trong ngưỡng 128-byte headroom mặc định của DPDK mbuf (`RTE_PKTMBUF_HEADROOM`).
- Hash dispatch dùng toàn bộ 16 bytes: `rte_hash_crc(meta, sizeof(pkt_meta_t), 0)` — bao gồm cả `vlan_valid` và `vlan_id`.

### 3.2 Cấu Trúc Rule (`spi_rule_t`)

Biểu diễn một mục rule đã phân tích trước khi được biên dịch vào cấu trúc ACL.

```c
#define SPIFAST_RULE_NAME_LEN   64
#define SPIFAST_GROUP_NAME_LEN  64

typedef enum {
    PROTO_MATCH_TCP  = 6,
    PROTO_MATCH_UDP  = 17,
    PROTO_MATCH_ANY  = 0    /* wildcard */
} proto_match_t;

typedef struct {
    char     rule_name[SPIFAST_RULE_NAME_LEN]; /* định danh rule duy nhất   */
    char     group_name[SPIFAST_GROUP_NAME_LEN];/* tư cách thành viên group */

    /* Điều kiện khớp five-tuple */
    uint32_t src_ip;         /* địa chỉ host hoặc địa chỉ mạng            */
    uint32_t src_prefix_len; /* độ dài CIDR prefix 0-32; 32 = host chính xác */
    uint32_t dst_ip;
    uint32_t dst_prefix_len;
    uint16_t src_port_lo;    /* giới hạn dưới port range; 0 nếu wildcard   */
    uint16_t src_port_hi;    /* giới hạn trên port range; 65535 nếu wildcard */
    uint16_t dst_port_lo;
    uint16_t dst_port_hi;
    proto_match_t protocol;  /* TCP, UDP, hoặc ANY(wildcard)               */

    uint32_t precedence;     /* từ khai báo group; cao hơn = ưu tiên cao hơn */
    uint32_t group_idx;      /* chỉ số trong flat_rule_table.group_names[]
                                — gán bởi rule_loader, dùng cho stats       */
} spi_rule_t;
```

### 3.3 Cấu Trúc Flat Rule Table (`flat_rule_entry_t` và `flat_rule_table_t`)

`filter_group_t` và `filter_group_table_t` đã bị loại bỏ khỏi mô hình runtime. Thay thế bằng bảng rule phẳng, trong đó action và group_idx được nhúng trực tiếp vào mỗi entry — không cần tra cứu group riêng biệt.

```c
typedef enum {
    ACTION_FORWARD = 0,
    ACTION_DROP    = 1
} group_action_t;

#define SPIFAST_MAX_GROUPS  4096

typedef struct {
    /* Định danh — dùng cho logging và stats */
    char           rule_name[SPIFAST_RULE_NAME_LEN];
    char           group_name[SPIFAST_GROUP_NAME_LEN];
    uint32_t       group_idx;       /* chỉ số vào flat_rule_table.group_names[] */

    /* Điều kiện khớp five-tuple */
    uint32_t       src_ip;
    uint8_t        src_prefix_len;
    uint32_t       dst_ip;
    uint8_t        dst_prefix_len;
    uint16_t       src_port_lo;
    uint16_t       src_port_hi;
    uint16_t       dst_port_lo;
    uint16_t       dst_port_hi;
    uint8_t        protocol;        /* IPPROTO_TCP(6), IPPROTO_UDP(17), 0=any */

    /* Action nhúng trực tiếp — không cần tra cứu group table runtime */
    group_action_t action;          /* ACTION_FORWARD hoặc ACTION_DROP        */

    /* Metadata thứ tự — dùng bởi acl_engine_build */
    uint32_t       precedence;      /* từ khai báo group; cao hơn = ưu tiên cao hơn */
    uint32_t       file_order;      /* chỉ số 0-based theo thứ tự xuất hiện trong file */
} flat_rule_entry_t;

typedef struct {
    flat_rule_entry_t rules[SPIFAST_MAX_RULES]; /* indexed by file_order        */
    uint32_t          num_rules;

    /* Bảng tên group — chỉ dùng cho stats/logging, không dùng cho matching */
    char     group_names[SPIFAST_MAX_GROUPS][SPIFAST_GROUP_NAME_LEN];
    uint32_t num_groups;
} flat_rule_table_t;
```

**Mã hóa ACL userdata:** `data.userdata = rule.file_order + 1`. Kết quả classify `== 0` nghĩa là không khớp; `!= 0` → `file_order = result - 1` → `flat_rule_table.rules[file_order]` cho action trực tiếp trong O(1).

### 3.4 Cấu Trúc Kết Quả Tra Cứu ACL

> **Đã loại bỏ.** `acl_result_t` không còn cần thiết. Kết quả tra cứu từ `rte_acl_classify` là `uint32_t results[]`; action được lấy trực tiếp bằng `flat_rule_table.rules[results[i]-1].action` — không cần struct trung gian.

### 3.5 Cấu Trúc Counter Thống Kê Per-lcore

Tồn tại bốn cấu trúc counter riêng biệt tương ứng với bốn loại data path lcore. Tất cả được khai báo với padding cache-line để ngăn false sharing.

```c
#define CACHE_LINE_SIZE  64

/* RX lcore — đọc libpcap, alloc mbuf, enqueue parser_ring */
typedef struct {
    uint64_t rx_packets;          /* tổng mbuf nhận được (qua tất cả pcap loops)   */
    uint64_t rx_bytes;            /* tổng byte (pkt_len) nhận được                 */
    uint64_t alloc_fail;          /* rte_pktmbuf_alloc() trả về NULL (pool cạn)    */
    uint64_t parser_ring_drop;    /* mbuf bị hủy do parser_ring đầy               */
    uint64_t pcap_loops;          /* số lần đã replay xong toàn bộ file pcap       */
    uint8_t  _pad[CACHE_LINE_SIZE - 5 * sizeof(uint64_t)];
} __rte_cache_aligned rx_lcore_stats_t;

/* Parser lcore — parse, headroom write, hash dispatch */
typedef struct {
    uint64_t parsed_packets;      /* mbuf đã parse thành công                */
    uint64_t invalid_packets;     /* mbuf bị hủy do parse failure            */
    uint64_t worker_ring_drop;    /* mbuf bị hủy do worker_ring đầy          */
    uint8_t  _pad[CACHE_LINE_SIZE
                  - (3 * sizeof(uint64_t)) % CACHE_LINE_SIZE];
} __rte_cache_aligned parser_lcore_stats_t;

/* Worker lcore — batch ACL classify, FORWARD/DROP */
typedef struct {
    uint64_t forwarded;           /* mbuf được enqueue vào tx_ring           */
    uint64_t dropped;             /* mbuf bị hủy bởi hành động rule DROP     */
    uint64_t tx_ring_drop;        /* mbuf bị hủy do tx_ring đầy              */
    uint64_t received;            /* mbuf dequeue được từ worker_ring         */
    uint8_t  _pad[CACHE_LINE_SIZE - 4 * sizeof(uint64_t)];
} __rte_cache_aligned worker_lcore_stats_t;

/* Per-group hit counter nằm trong worker_ctx_t (không phải worker_lcore_stats_t)
 * để tránh làm struct stats quá lớn (4096 × 8 = 32 KB per worker).
 * Stats module đọc hit counts từ worker_ctxs[i].group_hits[], không từ worker_stats[]. */
typedef struct {
    /* ... (các trường context khác) ... */
    uint64_t group_hits[SPIFAST_MAX_GROUPS]; /* per-group match count, per Worker */
} worker_ctx_t;   /* được khai báo đầy đủ trong worker/worker.h */

/* TX lcore — drain tx_ring, rte_eth_tx_burst */
typedef struct {
    uint64_t tx_packets;          /* mbuf đã truyền ra NIC TX thành công     */
    uint64_t tx_bytes;            /* byte đã truyền ra NIC TX                */
    uint64_t tx_drop_packets;     /* mbuf bị hủy do TX queue đầy             */
    uint8_t  _pad[CACHE_LINE_SIZE
                  - (3 * sizeof(uint64_t)) % CACHE_LINE_SIZE];
} __rte_cache_aligned tx_lcore_stats_t;
```

**Hit counter per-worker:** Mỗi Worker lcore duy trì `group_hits[SPIFAST_MAX_GROUPS]` riêng trong `worker_ctx_t` (không phải `worker_lcore_stats_t` — tách biệt ACL hit accounting khỏi performance counters). Không chia sẻ array giữa các Worker, không cần atomic operation. Stats module aggregate từ `worker_ctxs[i].group_hits[]` theo chu kỳ.

### 3.6 Cấu Trúc Snapshot Thống Kê (`stats_snapshot_t`)

Được module stats tạo ra mỗi chu kỳ; được module logging tiêu thụ.

```c
typedef struct {
    /* Số liệu theo chu kỳ (delta kể từ snapshot trước) */
    uint64_t interval_rx_pkts;
    uint64_t interval_fwd_pkts;
    uint64_t interval_fwd_bytes;
    double   interval_mbps;
    double   interval_pps;
    double   interval_sec;      /* số giây thực tế đã trôi qua trong chu kỳ này */

    /* Tổng lũy kế của phiên */
    uint64_t total_rx_pkts;
    uint64_t total_parsed_pkts;
    uint64_t total_fwd_pkts;
    uint64_t total_drop_pkts;
    uint64_t total_invalid_pkts;
    uint64_t total_parser_ring_drop;  /* parser_ring overflow tại RX lcore   */
    uint64_t total_worker_ring_drop;  /* worker_ring overflow tại Parser lcore */
    uint64_t total_tx_pkts;
    uint64_t total_tx_drop_pkts;      /* TX queue đầy tại TX lcore            */
    uint64_t total_bytes;

    /* Hit count per-group (tổng hợp từ tất cả Worker lcore) */
    uint64_t group_hits[SPIFAST_MAX_GROUPS];
    uint32_t num_groups;

    /* Thời gian phiên */
    uint64_t elapsed_sec;       /* giây kể từ gói tin đầu tiên             */
} stats_snapshot_t;
```

### 3.7 Cấu Trúc Cấu Hình Ứng Dụng (`spifast_config_t`)

```c
#define SPIFAST_MAX_PATH  512

typedef enum {
    MATCH_MODE_FIRST = 0,   /* mặc định */
    MATCH_MODE_BEST  = 1
} match_mode_t;

typedef struct {
    char        pcap_path[SPIFAST_MAX_PATH];   /* tham số --pcap          */
    char        rules_path[SPIFAST_MAX_PATH];  /* tham số --rules         */
    char        log_path[SPIFAST_MAX_PATH];    /* tham số --log; rỗng=không có */
    uint32_t    num_workers;                   /* tham số --workers        */
    match_mode_t match_mode;                   /* tham số --mode first|best */
    int         stats_interval_sec;            /* mặc định: 1              */
} spifast_config_t;
```

---

## 4. Thiết Kế ACL Rule Engine

> **Phiên bản:** 2.0 — Flat Single-Stage ACL (thay thế Two-Stage từ SDD v1.1)

### 4.1 Lý Do Thiết Kế — Single-Stage Flat ACL

Mô hình two-stage trước đây (stage1_ctx + group_ctx[]) bị loại bỏ hoàn toàn. Mô hình mới sử dụng một `rte_acl_ctx` duy nhất (`flat_acl_ctx`) chứa **tất cả rule từ tất cả group** đã được làm phẳng (flattened) vào một bảng tuyến tính.

**Thay đổi cốt lõi:**

| Khái niệm cũ | Trạng thái | Thay thế |
|---|---|---|
| `stage1_ctx` | **Loại bỏ** | `flat_acl_ctx` (ACL context duy nhất) |
| `group_ctx[SPIFAST_MAX_GROUPS]` | **Loại bỏ** | Không tồn tại |
| `filter_group_table_t` | **Loại bỏ** (runtime) | `flat_rule_table_t` (bảng rule phẳng) |
| `filter_group_t` | **Loại bỏ** (runtime) | Trường `action` nhúng trực tiếp trong `flat_rule_entry_t` |
| `acl_result_t` | **Loại bỏ** | `flat_rule_entry_t` tra cứu bằng `file_order` |
| Lazy build từ Worker → Main | **Loại bỏ** | Không cần; build hoàn tất trước khi lcore khởi chạy |
| `atomic_store`/`atomic_load` cho `group_ctx[g]` | **Loại bỏ** | Không cần đồng bộ |
| 2 lần gọi `rte_acl_classify` mỗi burst | **Loại bỏ** | **1 lần gọi** duy nhất |

**Lợi ích của mô hình flat:**
- Worker critical path đơn giản hơn: 1 ACL call thay vì 2.
- Không cần lazy build, không race condition giữa Main và Worker lcore.
- Action (FORWARD/DROP) có sẵn trực tiếp từ kết quả lookup — không cần tra cứu group table.
- Build time xác định hoàn toàn trước khi pipeline khởi chạy.

**Đánh đổi:** ACL context lớn hơn (chứa tất cả rule thay vì chỉ rule đại diện). Với quy mô thực tế (vài chục đến vài trăm rule), context vẫn fit trong L2 cache.

### 4.2 Cấu Trúc Dữ Liệu Flat ACL

#### 4.2.1 `flat_rule_entry_t` — Mục Rule Phẳng

Mỗi mục biểu diễn một rule đầy đủ với điều kiện khớp và action đã được giải quyết trực tiếp (không cần tra cứu group).

```c
typedef struct {
    /* Định danh — dùng cho logging và debug */
    char           rule_name[SPIFAST_RULE_NAME_LEN];
    char           group_name[SPIFAST_GROUP_NAME_LEN];
    uint32_t       group_idx;       /* chỉ số trong flat_rule_table.group_names[]
                                       — dùng cho stats aggregation, không dùng
                                       cho matching                              */

    /* Điều kiện khớp five-tuple */
    uint32_t       src_ip;          /* địa chỉ mạng hoặc host, network byte order */
    uint8_t        src_prefix_len;  /* CIDR prefix [0-32]; 32 = host chính xác   */
    uint32_t       dst_ip;
    uint8_t        dst_prefix_len;
    uint16_t       src_port_lo;     /* giới hạn dưới range; 0 nếu wildcard       */
    uint16_t       src_port_hi;     /* giới hạn trên range; 65535 nếu wildcard   */
    uint16_t       dst_port_lo;
    uint16_t       dst_port_hi;
    uint8_t        protocol;        /* IPPROTO_TCP(6), IPPROTO_UDP(17), 0=any    */

    /* Action — nhúng trực tiếp từ group declaration, không cần tra cứu runtime */
    group_action_t action;          /* ACTION_FORWARD hoặc ACTION_DROP           */

    /* Metadata thứ tự */
    uint32_t       precedence;      /* từ khai báo group; cao hơn = ưu tiên cao hơn */
    uint32_t       file_order;      /* chỉ số 0-based theo thứ tự xuất hiện trong
                                       file rule; dùng làm ACL userdata (file_order+1) */
} flat_rule_entry_t;
```

**Ghi chú thiết kế:** `group_idx` và `group_name` được giữ lại chỉ cho mục đích thống kê và logging. Chúng **không** được sử dụng trong hot path matching — chỉ sau khi action đã xác định xong.

#### 4.2.2 `flat_rule_table_t` — Bảng Rule Phẳng

```c
#define SPIFAST_MAX_FLAT_RULES   SPIFAST_MAX_RULES   /* hằng số hiện có */

typedef struct {
    flat_rule_entry_t rules[SPIFAST_MAX_FLAT_RULES]; /* indexed by file_order      */
    uint32_t          num_rules;                      /* tổng số rule (bao gồm DEFAULT) */

    /* Bảng tên group — dùng cho stats reporting, không dùng cho matching */
    char     group_names[SPIFAST_MAX_GROUPS][SPIFAST_GROUP_NAME_LEN];
    uint32_t num_groups;
} flat_rule_table_t;
```

`rules[]` được lập chỉ mục bởi `file_order`: `rules[file_order]` là rule thứ `file_order` trong file cấu hình. Mảng này không được sort lại sau khi xây dựng — thứ tự file được bảo toàn để đảm bảo `file_order` làm chỉ số truy cập O(1).

#### 4.2.3 Mã Hóa ACL Userdata

```
data.userdata = rule.file_order + 1
```

- `userdata == 0`: không có rule nào khớp (không thể xảy ra nếu DEFAULT catch-all được thêm đúng cách).
- `userdata == 1..N`: `file_order = userdata - 1` → tra cứu `flat_rule_table.rules[file_order]` để lấy action.

Cách mã hóa này duy trì convention DPDK (`0 = no match`) đồng thời cho phép tra cứu O(1) sau khi classify.

### 4.3 Định Nghĩa Trường ACL

Bố cục key `acl_key_t` và mảng `spifast_acl_fields[]` được giữ nguyên không thay đổi — flat model sử dụng cùng cấu trúc key, chỉ có một context duy nhất thay vì hai:

```
Bố cục Key (13 bytes tổng, căn chỉnh đến 16 bytes):

Offset  Kích thước  Trường
------  ----------  ------
  0        1        protocol   (IP protocol: 6=TCP, 17=UDP, 0=wildcard)
  1        4        src_ip     (IPv4, network byte order)
  5        4        dst_ip     (IPv4, network byte order)
  9        2        src_port   (host byte order)
 11        2        dst_port   (host byte order)
 13        3        padding
```

```c
static const struct rte_acl_field_def spifast_acl_fields[] = {
    {   /* protocol — bitmask match */
        .type        = RTE_ACL_FIELD_TYPE_BITMASK,
        .size        = sizeof(uint8_t),
        .field_index = 0,
        .input_index = 0,
        .offset      = offsetof(acl_key_t, protocol),
    },
    {   /* src_ip — prefix match */
        .type        = RTE_ACL_FIELD_TYPE_MASK,
        .size        = sizeof(uint32_t),
        .field_index = 1,
        .input_index = 1,
        .offset      = offsetof(acl_key_t, src_ip),
    },
    {   /* dst_ip — prefix match */
        .type        = RTE_ACL_FIELD_TYPE_MASK,
        .size        = sizeof(uint32_t),
        .field_index = 2,
        .input_index = 2,
        .offset      = offsetof(acl_key_t, dst_ip),
    },
    {   /* src_port — range match */
        .type        = RTE_ACL_FIELD_TYPE_RANGE,
        .size        = sizeof(uint16_t),
        .field_index = 3,
        .input_index = 3,
        .offset      = offsetof(acl_key_t, src_port),
    },
    {   /* dst_port — range match */
        .type        = RTE_ACL_FIELD_TYPE_RANGE,
        .size        = sizeof(uint16_t),
        .field_index = 4,
        .input_index = 4,
        .offset      = offsetof(acl_key_t, dst_port),
    },
};
```

**Mã hóa wildcard** (không thay đổi):
- Protocol `any`: bitmask value=0x00, mask=0x00 → khớp mọi giá trị byte.
- IP `any`: prefix length 0 → khớp 0.0.0.0/0.
- Port `any`: range [0, 65535].
- IP host chính xác: prefix length 32.
- Port chính xác: range [port, port].

### 4.4 Priority Encoding — Ánh Xạ Sang `rte_acl`

`rte_acl_classify` với `categories=1` trả về rule có `data.priority` **cao nhất** trong số tất cả rule khớp. SPIFast tận dụng hành vi này để triển khai cả hai chế độ khớp bằng cách điều chỉnh cách gán priority khi build, không cần thay đổi hot path.

#### Quy tắc gán priority

**Precedence semantics:** Giá trị `precedence` trong file rule là số nguyên dương, **cao hơn = ưu tiên cao hơn**. Rule DEFAULT được khai báo với precedence thấp nhất (thường là 1).

```
Chế độ best-match (--mode best):
  data.priority = rule.precedence
  → rule có precedence cao nhất thắng khi nhiều rule khớp
  → ví dụ: fg_facebook(100) < fg_youtube(101) < fg_http(102) < fg_dns(104)

Chế độ first-match (--mode first):
  data.priority = num_explicit_rules - rule.file_order
  → file_order=0 nhận priority=N (cao nhất)
  → file_order=N-1 nhận priority=1 (thấp nhất nhưng > 0)
  → rule xuất hiện sớm hơn trong file luôn thắng

DEFAULT rule (cả hai chế độ):
  data.priority = 0
  → luôn bị đánh bại bởi bất kỳ explicit rule nào có priority ≥ 1
```

**Ví dụ với file rule tham chiếu (7 explicit rules + DEFAULT):**

| Rule | file_order | precedence | priority (best) | priority (first) |
|---|---|---|---|---|
| f_l34_facebook_1 | 0 | 100 | 100 | 7 |
| f_l34_facebook_4 | 1 | 100 | 100 | 6 |
| f_l34_youtube_1  | 2 | 101 | 101 | 5 |
| f_l34_youtube_4  | 3 | 101 | 101 | 4 |
| f_l34_http_all   | 4 | 102 | 102 | 3 |
| f_l34_dns_udp    | 5 | 104 | 104 | 2 |
| f_l34_dns_tcp    | 6 | 104 | 104 | 1 |
| DEFAULT (catch-all) | 7 | 1 | **0** | **0** |

*num_explicit_rules = 7; DEFAULT priority = 0 cố định trong cả hai chế độ.*

**Trường hợp packet khớp nhiều rule (ví dụ: TCP dst=31.13.64.1 dport=80):**
- Best-match: f_l34_http_all (precedence=102) thắng vì 102 > 100.
- First-match: f_l34_facebook_1 (file_order=0, priority=7) thắng vì 7 > 3.

### 4.5 Phân Kỳ Giai Đoạn Triển Khai — Phase 3 và Phase 4

| Khía cạnh | Phase 3 (triển khai hiện tại) | Phase 4 (kế hoạch tương lai) |
|---|---|---|
| Matching engine | Custom linear scan: `flat_acl_match_burst()` duyệt `g_sorted_idx[]` và gọi `rule_matches()` per-packet | `rte_acl_classify(flat_acl_ctx, keys_ptr, results, nb, 1)` — SIMD/AVX2 |
| `g_flat_ctx` | `NULL` — không được tạo | `rte_acl_create()` → `rte_acl_build()` |
| `g_sorted_idx[]` | Được build bởi `qsort()` theo `match_mode` | Không cần (rte_acl tự quản lý ordering) |
| Kết quả lookup | `const flat_rule_entry_t *` (con trỏ trực tiếp) | `uint32_t results[]` → tra cứu O(1) qua `file_order - 1` |
| `s_acl_fields[]` | Được khai báo nhưng `(void)s_acl_fields` — giữ cho Phase 4 | Dùng làm `rte_acl_field_def[]` để build context |
| Complexity | O(N_rules) per-packet | O(log N) với trie; SIMD batch |

**Cảnh báo tích hợp Phase 4:** Khi migrate, cần đổi `flat_acl_match_burst()` interface: Worker hiện nhận `const flat_rule_entry_t *results[]`; Phase 4 sẽ nhận `uint32_t results[]` và tra cứu thêm một bước `flat_rule_table.rules[results[i]-1]`. Cần unit test lại toàn bộ matching logic.

### 4.6 Trình Tự Build `flat_acl_ctx` (Phase 4)

```
acl_engine_build(flat_rule_table, match_mode):

  Bước 1 — Tạo ACL context
    ctx = rte_acl_create("spifast_flat")
    acl_param.max_rule_num = flat_rule_table.num_rules   /* bao gồm DEFAULT */
    acl_param.rule_size    = RTE_ACL_RULE_SZ(5)          /* 5 trường */

  Bước 2 — Thêm tất cả explicit rule vào context
    với mỗi entry trong flat_rule_table.rules[0..num_rules-2]:
      /* Điền các trường khớp */
      acl_rule.field[0] = {protocol, protocol_mask}
      acl_rule.field[1] = {src_ip,   src_prefix_mask}
      acl_rule.field[2] = {dst_ip,   dst_prefix_mask}
      acl_rule.field[3] = {src_port_lo, src_port_hi}
      acl_rule.field[4] = {dst_port_lo, dst_port_hi}

      /* Gán userdata và priority theo chế độ */
      acl_rule.data.userdata = entry.file_order + 1

      nếu match_mode == MATCH_MODE_BEST:
        acl_rule.data.priority = entry.precedence
      ngược lại:   /* MATCH_MODE_FIRST */
        acl_rule.data.priority = (flat_rule_table.num_rules - 1) - entry.file_order
        /* Đảm bảo priority ≥ 1 cho mọi explicit rule */

      rte_acl_add_rules(ctx, &acl_rule, 1)

  Bước 3 — Thêm DEFAULT catch-all rule
    acl_rule.field[0] = {0x00, 0x00}      /* protocol = any */
    acl_rule.field[1] = {0,    0}          /* src_ip = 0.0.0.0/0 */
    acl_rule.field[2] = {0,    0}          /* dst_ip = 0.0.0.0/0 */
    acl_rule.field[3] = {0,    65535}      /* src_port = any */
    acl_rule.field[4] = {0,    65535}      /* dst_port = any */
    acl_rule.data.userdata = default_entry.file_order + 1
    acl_rule.data.priority = 0             /* luôn bị đánh bại bởi explicit rules */
    rte_acl_add_rules(ctx, &acl_rule, 1)

  Bước 4 — Compile
    rte_acl_build(ctx, &acl_build_cfg)
    nếu lỗi: rte_acl_free(ctx); return -1

  Bước 5 — Lưu context (read-only sau đây)
    flat_acl_ctx = ctx
    return 0
```

Toàn bộ build được thực hiện một lần trên main lcore trong bước khởi động, trước khi bất kỳ Worker lcore nào được khởi chạy. Không có lazy build, không có đồng bộ hóa runtime.

### 4.7 Luồng Khớp Trong Worker Lcore (Phase 3)

Sau khi dequeue burst và build `acl_key_t[]` từ mbuf headroom (không thay đổi so với trước):

```
/* ── Flat single-stage ACL classify — toàn bộ burst trong 1 lần gọi ─────── */

memset(results, 0, nb * sizeof(uint32_t))
rte_acl_classify(flat_acl_ctx, keys_ptr, results, nb, 1)

/* ── Per-packet dispatch ─────────────────────────────────────────────────── */

nb_tx = 0
với mỗi i trong [0, nb):
    ud = results[i]

    nếu ud == 0:
        /* Không rule nào khớp — lỗi hệ thống nếu DEFAULT được thêm đúng cách.
         * Fallback an toàn: DROP và đếm vào DEFAULT group. */
        action    = ACTION_DROP
        group_idx = DEFAULT_GROUP_IDX

    ngược lại:
        /* Tra cứu O(1): ud - 1 = file_order = chỉ số trong flat_rule_table */
        entry     = &flat_rule_table.rules[ud - 1]
        action    = entry.action        /* ACTION_FORWARD hoặc ACTION_DROP */
        group_idx = entry.group_idx     /* cho stats */

    /* Cập nhật per-group hit counter (không trên critical path của mbuf) */
    nếu group_idx < SPIFAST_MAX_GROUPS:
        worker_ctx.group_hits[group_idx]++

    /* Dispatch mbuf */
    nếu action == ACTION_FORWARD:
        tx_burst[nb_tx++] = pkts[i]
        stats.forwarded++
    ngược lại:
        rte_pktmbuf_free(pkts[i])
        stats.dropped++

/* ── Enqueue FORWARD batch vào tx_ring ───────────────────────────────────── */
nếu nb_tx > 0:
    nb_sent = rte_ring_enqueue_burst(tx_ring, tx_burst, nb_tx, NULL)
    nếu nb_sent < nb_tx:
        với mỗi i trong [nb_sent, nb_tx):
            rte_pktmbuf_free(tx_burst[i])
            stats.tx_ring_drop++
```

Không có lần gọi `rte_acl_classify` thứ hai. Không kiểm tra NULL cho context. Không trigger lazy build. Không cần đồng bộ hóa con trỏ giữa Main và Worker.

### 4.8 Sơ Đồ Luồng Runtime

```
packet → worker_ring
         │
         ▼
  rte_ring_dequeue_burst(worker_ring, pkts[], WORKER_BURST_SIZE)
         │
         ▼
  đọc pkt_meta_t từ mbuf headroom → build acl_key_t[]
         │
         ▼
  rte_acl_classify(flat_acl_ctx, keys_ptr, results, nb, 1)
         │
         ├── results[i] == 0
         │     → ACTION_DROP (lỗi hệ thống, DEFAULT không được thêm)
         │
         ├── rules[results[i]-1].action == ACTION_DROP
         │     → rte_pktmbuf_free(pkts[i])
         │     → stats.dropped++
         │
         └── rules[results[i]-1].action == ACTION_FORWARD
               → tx_burst[nb_tx++] = pkts[i]
               → stats.forwarded++
                    │
                    ▼
             rte_ring_enqueue_burst(tx_ring, tx_burst, nb_tx)
```

### 4.9 Hành Vi Khi Nhiều Rule Khớp

`rte_acl_classify` với `categories=1` trả về đúng 1 kết quả mỗi packet — rule có `data.priority` cao nhất. Đây là hành vi xác định, không ambiguous:

| Tình huống | Best-match | First-match |
|---|---|---|
| Đúng 1 rule tường minh khớp | Trả về rule đó | Trả về rule đó |
| N > 1 rule tường minh khớp | Rule có `precedence` cao nhất thắng (số cao hơn thắng) | Rule có `file_order` thấp nhất thắng (xuất hiện trước thắng) |
| Chỉ DEFAULT khớp | DEFAULT action (DROP) | DEFAULT action (DROP) |
| Không rule nào khớp (lỗi) | ACTION_DROP (fallback) | ACTION_DROP (fallback) |

**Tính quyết định:** Với cùng một file rule và cùng `--mode`, mọi packet luôn nhận cùng một action — không phụ thuộc vào thứ tự xử lý, số lượng Worker, hay thứ tự build.

### 4.10 Xử Lý Rule DEFAULT

Rule DEFAULT (`[group: DEFAULT] action=DROP`) được rule_loader kiểm tra là bắt buộc (FR-017). Nó được thêm vào `flat_rule_table` như một entry bình thường với:
- Điều kiện khớp: toàn wildcard (protocol=any, src_ip=0/0, dst_ip=0/0, port=[0,65535]).
- `action = ACTION_DROP` (theo khai báo group).
- `data.priority = 0` — cứng, không phụ thuộc `match_mode`.

Việc thêm DEFAULT vào flat context đảm bảo `results[i]` luôn khác 0 cho mọi gói tin IPv4 hợp lệ, bảo đảm FR-023.

### 4.11 Đếm Lượt Khớp — Per-Group Hit Counter

`worker_ctx_t.group_hits[SPIFAST_MAX_GROUPS]` được giữ nguyên từ thiết kế cũ, nhưng cơ chế cập nhật đơn giản hơn: sau khi `rte_acl_classify` trả về kết quả, `group_idx = flat_rule_table.rules[ud-1].group_idx` được sử dụng trực tiếp để tăng counter. Không cần thêm bước lookup group table.

Stats module aggregate tất cả per-worker `group_hits[]` arrays mỗi chu kỳ 1 giây theo cơ chế không thay đổi (xem Mục 8).

### 4.12 Public API của `acl_engine`

```c
/* Build sorted index (Phase 3) hoặc flat_acl_ctx (Phase 4) từ flat_rule_table.
 * Phải gọi sau rule_loader_load() và trước khi khởi chạy bất kỳ Worker lcore nào.
 * match_mode xác định thứ tự sort: BEST → cao precedence trước; FIRST → thấp file_order trước.
 * Trả về 0 khi thành công, -1 khi lỗi. */
int acl_engine_build(const flat_rule_table_t *tbl, match_mode_t match_mode);

/* Phase 3: Linear scan burst match. Trả về con trỏ trực tiếp đến rule khớp đầu tiên,
 * hoặc NULL nếu không khớp (không xảy ra khi DEFAULT tồn tại). */
void flat_acl_match_burst(const flat_rule_table_t *tbl,
                          const acl_key_t *keys[],
                          const flat_rule_entry_t *results[],
                          uint32_t nb);

/* Trả về con trỏ flat_rule_table (read-only) để Worker lcore tra cứu action.
 * Hợp lệ chỉ sau khi acl_engine_build() trả về 0. */
const flat_rule_table_t *acl_get_flat_rule_table(void);

/* Phase 4 (kế hoạch): Trả về flat_acl_ctx (hiện tại trả về NULL ở Phase 3). */
struct rte_acl_ctx *acl_get_flat_ctx(void);

/* Giải phóng tài nguyên ACL engine. Gọi từ main lcore sau khi tất cả Worker đã dừng. */
void acl_engine_destroy(void);

---

## 5. Thiết Kế Cấu Hình Rule

### 5.1 Ngữ Pháp File Rule

File rule là file văn bản thuần mã hóa UTF-8. Parser xử lý từng dòng một.

**Các loại dòng:**

| Loại dòng | Nhận dạng | Hành động |
|---|---|---|
| Chú thích | Bắt đầu bằng `#` | Bỏ qua hoàn toàn |
| Dòng trống | Không có ký tự nào khác khoảng trắng | Bỏ qua hoàn toàn |
| Khai báo group | Bắt đầu bằng `[group:` | Phân tích định nghĩa group |
| Mục rule | Phân tách bằng dấu phẩy, không bắt đầu bằng `[` hoặc `#` | Phân tích các trường rule |

**Cú pháp khai báo group:**

```
[group: <group_name>]  precedence=<uint32>  action=<FORWARD|DROP>
```

Ví dụ:
```
[group: fg_l34_facebook]     precedence=100  action=FORWARD
[group: DEFAULT]             precedence=1  action=DROP
```

Các trường được phân tách bằng khoảng trắng tùy ý. Tên group là chữ-số với dấu gạch dưới (regex: `[a-zA-Z0-9_]+`). Độ dài tối đa: 63 ký tự.

**Cú pháp mục rule:**

```
<rule_name>, <group_name>, <protocol>, <src_ip_cond>, <dst_ip_cond>, <src_port_cond>, <dst_port_cond>
```

- `<rule_name>`: chữ-số với dấu gạch dưới, duy nhất trên tất cả rule.
- `<group_name>`: phải khớp với tên group đã được khai báo trước đó.
- `<protocol>`: `tcp` | `udp` | `any`
- `<src_ip_cond>` và `<dst_ip_cond>`: một trong các giá trị:
  - `any` → wildcard (0.0.0.0/0)
  - `src_prefix=A.B.C.D/N` → CIDR subnet match
  - `src_address=A.B.C.D` → khớp host chính xác (prefix/32)
  - `dst_prefix=A.B.C.D/N`
  - `dst_address=A.B.C.D`
- `<src_port_cond>` và `<dst_port_cond>`: một trong các giá trị:
  - `any` → wildcard [0, 65535]
  - `<uint16>` → port chính xác [port, port]
  - `<uint16>-<uint16>` → range [lo, hi]

**Ví dụ đầy đủ (từ SRS RC-004):**

```
# Định Nghĩa Filter Group
[group: fg_l34_facebook]     precedence=100  action=FORWARD
[group: fg_l34_youtube]      precedence=101  action=FORWARD
[group: fg_l34_http_sdf1003] precedence=102  action=FORWARD
[group: fg_l34_dns_sdf1005]  precedence=104  action=FORWARD
[group: DEFAULT]             precedence=1  action=DROP

# Định Nghĩa Rule
f_l34_facebook_1, fg_l34_facebook,      any, dst_prefix=31.13.64.0/18,  any, any
f_l34_facebook_4, fg_l34_facebook,      any, dst_address=69.220.144.5,  any, any
f_l34_youtube_1,  fg_l34_youtube,       tcp, dst_prefix=142.250.0.0/15, 443, any
f_l34_youtube_4,  fg_l34_youtube,       tcp, dst_address=74.125.0.1,    443, any
f_l34_http_all,   fg_l34_http_sdf1003,  tcp, any,                        80, any
f_l34_dns_udp,    fg_l34_dns_sdf1005,   udp, any,                        53, any
f_l34_dns_tcp,    fg_l34_dns_sdf1005,   tcp, any,                        53, any
```

### 5.2 Trình Tự Nạp Khi Khởi Động

```
rule_loader_load(path, match_mode, flat_rule_table *out):

  Bước 1 — Mở file
    fp = fopen(path, "r")
    nếu fp == NULL:  LOG_ERROR("Cannot open rule file: %s", path); return -1

  Bước 2 — Phân tích từng dòng
    line_no    = 0
    file_order = 0   /* gán tăng dần cho mỗi rule entry */

    với mỗi dòng trong file:
      line_no++
      xóa khoảng trắng đầu/cuối
      nếu dòng trống hoặc bắt đầu bằng '#':  tiếp tục

      nếu dòng bắt đầu bằng '[group:':
        parse_group_declaration(line, line_no, out)
        /* Kiểm tra: độ dài tên, tính duy nhất, phạm vi precedence [1..999],
           action là FORWARD hoặc DROP */
        /* Gán out->group_names[out->num_groups] và tăng num_groups */
        khi lỗi: LOG_ERROR(line_no, reason); fclose(fp); return -1

      ngược lại:
        /* Điền flat_rule_entry_t, nhúng action từ group declaration đã parse */
        parse_rule_entry(line, line_no, out, file_order)
        /* Kiểm tra các trường theo Mục 5.3 */
        /* Gán entry.action = group.action; entry.file_order = file_order++ */
        khi lỗi: LOG_ERROR(line_no, reason); fclose(fp); return -1

      nếu out->num_groups > SPIFAST_MAX_GROUPS (4096):
        LOG_ERROR("Group count exceeds maximum (4096)"); return -1

  Bước 3 — Kiểm tra sau khi phân tích
    kiểm tra: out->num_rules >= 1
    kiểm tra: DEFAULT group tồn tại (group có action=DROP và wildcard conditions)
    kiểm tra: không có tên rule trùng lặp
    khi có bất kỳ lỗi nào: return -1

  Bước 4 — Build flat ACL context
    rc = acl_engine_build(out, match_mode)
    /* acl_engine_build thêm DEFAULT catch-all với priority=0 */
    nếu rc != 0:  return -1

  Bước 5 — Ghi log các rule đã nạp
    log_startup_rules(out)

  return 0
```

### 5.3 Quy Tắc Kiểm Tra Hợp Lệ Trường

| Trường | Kiểm tra |
|---|---|
| Tên rule | Không rỗng; `[a-zA-Z0-9_]`; ≤ 63 ký tự; duy nhất trên tất cả rule |
| Tên group (trong rule) | Phải khớp với tên group đã khai báo trước đó |
| Protocol | Không phân biệt hoa thường: `tcp`, `udp`, hoặc `any` |
| Từ khóa điều kiện IP | Phải là `any`, `src_prefix=`, `src_address=`, `dst_prefix=`, hoặc `dst_address=` |
| Địa chỉ IP (A.B.C.D) | Mỗi octet trong [0, 255]; đúng 4 octet |
| Độ dài CIDR prefix | Số nguyên trong [0, 32] |
| Port (chính xác) | Số nguyên trong [0, 65535] |
| Port range (lo-hi) | Cả hai số nguyên trong [0, 65535]; lo ≤ hi |
| Precedence | Số nguyên trong [1, 999] |
| Action | Không phân biệt hoa thường: `FORWARD` hoặc `DROP` |
| Số lượng group | Tổng số group ≤ 4096 (`SPIFAST_MAX_GROUPS`) |
| Tổng số rule | Tổng số rule (tất cả group) ≤ `SPIFAST_MAX_RULES` |

---

## 6. Thiết Kế Đa Lõi và Luồng

### 6.1 Phân Công Vai Trò lcore

SPIFast v1.1 sử dụng topology lcore pipeline 5 giai đoạn cố định. Ánh xạ như sau:

```
lcore ID   Vai trò                   Module
---------  ------------------------  ----------------------------
0          Main / Stats / Logging    main, stats, logging
1          RX lcore                  rx
2          Parser lcore              parser
3          Worker 0                  worker (worker_ring[0])
4          Worker 1                  worker (worker_ring[1])...
...        Worker N-1                worker (worker_ring[N-1])
N+3        TX lcore                  tx
```

**lcore ID được gán theo thứ tự tăng dần** từ tập hợp lcore có sẵn do DPDK trả về.

**Tổng lcore yêu cầu: `N + 4`** (1 Main + 1 RX + 1 Parser + N Worker + 1 TX).

Tham số `--lcores` của EAL phải bao gồm ít nhất N+4 lcore. Ví dụ cho 2 Worker:

```
./spifast --lcores 0-5 -- --pcap traffic.pcap --rules spi_rules.conf --workers 2
```

### 6.2 Trách Nhiệm RX lcore

RX lcore đọc packet trực tiếp từ file pcap qua libpcap (không dùng `rte_eth_rx_burst`), replay liên tục cho đến khi nhận SIGINT/SIGTERM. Net_pcap DPDK port vẫn được giữ active để TX lcore gọi `rte_eth_tx_burst()` bình thường.

RX lcore thực hiện các bước sau:

1. Gọi `pcap_open_offline(ctx->pcap_path, ...)` để mở file pcap.
2. Đọc từng packet bằng `pcap_next_ex(handle, &pkt_hdr, &pkt_data)`.
3. Gọi `rte_pktmbuf_alloc(ctx->mempool)` để lấy mbuf; nếu NULL tăng `alloc_fail` và tiếp tục.
4. Copy dữ liệu packet vào mbuf bằng `rte_memcpy(rte_pktmbuf_mtod(m), pkt_data, caplen)`.
5. Tích lũy batch đến `SPIFAST_BURST_SIZE`, rồi flush bằng `rte_ring_enqueue_burst(parser_ring, ...)`.
6. Xử lý parser_ring đầy: free mbuf, tăng `parser_ring_drop`.
7. Cập nhật `rx_lcore_stats.rx_packets` và `rx_lcore_stats.rx_bytes`.
8. Khi EOF (`pcap_next_ex` trả về -2): đóng handle, tăng `pcap_loops`, mở lại từ đầu.
9. Thoát khi `g_shutdown_flag == 1` (được đặt bởi SIGINT/SIGTERM handler).

RX lcore không gọi `printf` hay bất kỳ blocking system call nào trên data path (ngoài libpcap I/O là thiết kế có chủ ý — pcap-bound, không phải CPU-bound).

### 6.3 Trách Nhiệm Parser lcore

Parser lcore thực hiện các bước sau theo từng burst:

1. Dequeue burst từ `parser_ring`.
2. Prefetch dữ liệu mbuf (`rte_prefetch0`) PREFETCH_AHEAD packets ahead.
3. Parse L2/VLAN/L3/L4 cho từng mbuf.
4. Ghi `pkt_meta_t` vào mbuf headroom.
5. Tính `worker_idx = rte_hash_crc(&meta, ...) % N_workers`.
6. `rte_ring_enqueue(worker_rings[worker_idx], mbuf)`.
7. Xử lý worker_ring đầy: free mbuf, tăng `worker_ring_drop`.
8. Cập nhật `parser_lcore_stats`.

Parser lcore là điểm duy nhất trong pipeline thực hiện parse và hash dispatch. Không thực hiện ACL lookup.

### 6.4 Trách Nhiệm Worker lcore

Mỗi Worker lcore thực thi `worker_lcore_func` thực hiện:

1. Dequeue burst từ `worker_ring[i]` (ring chuyên biệt của mình).
2. Đọc `pkt_meta_t` từ mbuf headroom của từng mbuf.
3. Build `keys[]` từ five-tuple metadata (NBO → HBO cho IP).
4. **Single-stage flat ACL classify (Phase 3):** `flat_acl_match_burst(flat_rule_tbl, key_ptrs, results, nb)` → `results[]` là mảng `const flat_rule_entry_t *`.
5. Per-packet: `action = results[i]->action`; `group_idx = results[i]->group_idx`.
6. Tăng `worker_ctx.group_hits[group_idx]` (trong `worker_ctx_t`, không phải `worker_lcore_stats_t`).
7. FORWARD → `rte_ring_enqueue_burst(tx_ring, tx_burst, nb_tx)`.
8. DROP → `rte_pktmbuf_free(mbuf)`.
9. Cập nhật `worker_lcore_stats[i]` (forwarded, dropped, tx_ring_drop).

Worker không bao giờ gọi `rte_eth_tx_burst()` trực tiếp. Không có gọi ACL thứ hai, không kiểm tra NULL context, không trigger lazy build.

### 6.5 Trách Nhiệm TX lcore

TX lcore thực hiện:

1. Dequeue burst từ `tx_ring` (MPSC, nhận từ tất cả Worker).
2. `rte_eth_tx_burst(port_id, tx_queue_id, pkts, nb)`.
3. Free mbuf chưa gửi được (TX queue đầy).
4. Cập nhật `tx_lcore_stats`.
5. Tiếp tục drain cho đến khi `tx_ring` rỗng sau khi shutdown.

TX lcore là thành phần duy nhất sở hữu và truy cập TX queue.

### 6.6 Ngữ Cảnh Thực Thi Thống Kê và Logging

Main lcore điều khiển bộ đếm thời gian thống kê bằng kiểm tra wall-clock đơn giản:

```
main_lcore_func():
  khởi chạy rx lcore
  khởi chạy parser lcore
  khởi chạy worker lcore (×N)
  khởi chạy tx lcore

  last_ts = rte_get_timer_cycles()

  trong khi chưa hoàn thành tất cả lcore:
    now = rte_get_timer_cycles()
    nếu (now - last_ts) >= stats_interval_cycles:
      snapshot = stats_collect()   /* đọc tất cả counter per-lcore */
      log_periodic(snapshot)       /* ghi ra stdout + file          */
      last_ts = now

    rte_delay_us_block(STATS_POLL_US)   /* sleep 100 µs — không trên data path */

  /* Tất cả lcore đã trả về */
  snapshot = stats_collect_final()
  log_final_summary(snapshot)
  log_close()
```

`rte_delay_us_block` chỉ được gọi trên main lcore, không bao giờ trên các data path lcore.

### 6.7 Tóm Tắt Quyền Sở Hữu mbuf

| Giai đoạn | Chủ sở hữu mbuf | Cơ chế chuyển giao |
|---|---|---|
| PMD → RX lcore | PMD cấp phát từ mempool; RX lcore nhận qua `rte_eth_rx_burst` | Burst RX API |
| RX lcore → Parser lcore | RX enqueue; Parser dequeue | `rte_ring_enqueue_burst` / `rte_ring_dequeue_burst` (parser_ring, SPSC) |
| RX lcore → mempool (parser_ring đầy) | RX lcore gọi `rte_pktmbuf_free` | Giải phóng trực tiếp |
| Parser lcore → Worker lcore i | Parser enqueue; Worker dequeue | `rte_ring_enqueue` / `rte_ring_dequeue_burst` (worker_ring[i], SPSC) |
| Parser lcore → mempool (parse fail / worker_ring đầy) | Parser lcore gọi `rte_pktmbuf_free` | Giải phóng trực tiếp |
| Worker lcore → TX lcore | Worker enqueue; TX dequeue | `rte_ring_enqueue_burst` / `rte_ring_dequeue_burst` (tx_ring, MPSC) |
| Worker lcore → mempool (DROP / tx_ring đầy) | Worker lcore gọi `rte_pktmbuf_free` | Giải phóng trực tiếp |
| TX lcore → NIC TX | TX gọi `rte_eth_tx_burst` | TX API (NIC giải phóng mbuf sau khi gửi xong) |
| TX lcore → mempool (TX queue đầy) | TX lcore gọi `rte_pktmbuf_free` | Giải phóng trực tiếp |

Không có thời điểm nào một mbuf được chia sẻ giữa hai lcore đồng thời. Quyền sở hữu luôn được nắm giữ bởi đúng một lcore.

### 6.8 Yêu Cầu Đồng Bộ Hóa

| Tài nguyên | Người ghi | Người đọc | Đồng bộ hóa |
|---|---|---|---|
| `rx_lcore_stats` | RX lcore | Main lcore (stats) | Không có; đọc torn 64-bit chấp nhận được cho stats display |
| `parser_lcore_stats` | Parser lcore | Main lcore (stats) | Không có; cùng lý do |
| `worker_lcore_stats[i]` | Worker lcore i | Main lcore (stats) | Không có; per-worker riêng biệt, không share |
| `tx_lcore_stats` | TX lcore | Main lcore (stats) | Không có; cùng lý do |
| `parser_ring` | RX lcore (SP) | Parser lcore (SC) | SPSC ring: lock-free theo thiết kế |
| `worker_rings[i]` | Parser lcore (SP) | Worker lcore i (SC) | SPSC ring: lock-free theo thiết kế |
| `tx_ring` | Worker lcore × N (MP) | TX lcore (SC) | MPSC ring: `RING_F_MP_ENQ` — CAS lock-free |
| `shutdown_flag` | SIGINT/SIGTERM handler trong main lcore (người ghi duy nhất; RX lcore **không** ghi) | RX, Parser, Worker, TX (người đọc) | `volatile int`; single writer; platform memory model đủ |
| `flat_acl_ctx` | rule_loader / acl_engine (build một lần, trước khi lcore khởi chạy) | Worker lcore × N (read-only) | Không cần đồng bộ; `rte_acl_build` hoàn tất trước khi Worker bắt đầu |
| `flat_rule_table` | rule_loader (init một lần, trước khi lcore khởi chạy) | Worker lcore × N (read-only) | Không cần đồng bộ; bất biến sau khi khởi tạo xong |

### 6.9 Xem Xét Thứ Tự Gói Tin

Không có đảm bảo thứ tự gói tin trên các Worker lcore. Hash dispatch tại Parser đảm bảo cùng flow đến cùng Worker (flow affinity), nhưng không đảm bảo thứ tự global giữa các flow khác nhau. Trong mỗi `worker_ring[i]`, gói tin được xử lý theo thứ tự FIFO. Tổng hợp thống kê không phụ thuộc thứ tự; tất cả counter đều có tính cộng dồn.

---

## 7. Thiết Kế Tài Nguyên DPDK

### 7.1 Thiết Kế Mempool

Một `rte_mempool` duy nhất được tạo và dùng chung trên tất cả lcore.

| Tham số | Giá trị | Lý do |
|---|---|---|
| `nb_mbufs` | `SPIFAST_MEMPOOL_SIZE` = 32768 | Phải vượt số mbuf đang in-flight tối đa: `BURST_SIZE + num_workers × (RING_SIZE + WORKER_BURST_SIZE)`. 32768 cung cấp headroom lớn cho multi-worker với ring size lớn, ngăn `alloc_fail` dưới tải cao. |
| `cache_size` | 256 | Cache mbuf per-lcore. Giảm tranh chấp mempool khi alloc/free. DPDK khuyến nghị `cache_size < nb_mbufs/1.5` và là lũy thừa của hai. |
| `priv_size` | 0 | Không cần vùng dữ liệu mbuf private. |
| `data_room_size` | `RTE_MBUF_DEFAULT_BUF_SIZE` (2176 bytes) | Đủ cho Ethernet MTU tiêu chuẩn (1518 bytes) cộng headroom. |
| `socket_id` | `SOCKET_ID_ANY` | Triển khai single-socket; tối ưu NUMA được trì hoãn đến phần mở rộng hỗ trợ NIC. |

`SPIFAST_MEMPOOL_SIZE` là hằng số compile-time trong `dpdk_init.h`. Có thể override qua `make CFLAGS="-DSPIFAST_MEMPOOL_SIZE=16384"` để kiểm thử với tải cao hơn.

### 7.2 Kích Thước RX Burst

| Tham số | Giá trị | Lý do |
|---|---|---|
| `BURST_SIZE` | 64 | Kích thước burst RX. Cân bằng giữa khấu hao overhead per-packet và cache locality. Có thể cấu hình tại compile time. |
| `RX_DESC_DEFAULT` | 512 | Số lượng RX descriptor trong hardware ring của PMD. Phải ≥ `BURST_SIZE`. |
| `EOI_THRESHOLD` | 100 | Số lần poll burst trống liên tiếp trước khi tuyên bố kết thúc PCAP. |

### 7.3 Cấu Hình Ring — Ba Tầng

**Tầng 1: parser_ring (RX → Parser, SPSC)**

| Tham số | Giá trị | Lý do |
|---|---|---|
| `PARSER_RING_SIZE` | 65536 | Lũy thừa của hai. Buffer lớn để hấp thụ burst imbalance giữa RX libpcap và Parser. |
| `RING_F_SP_ENQ` | Đặt | Single producer (RX lcore) → không có MP enqueue overhead. |
| `RING_F_SC_DEQ` | Đặt | Single consumer (Parser lcore) → không có MC dequeue overhead. |

**Tầng 2: worker_ring[i] (Parser → Worker i, SPSC)**

| Tham số | Giá trị | Lý do |
|---|---|---|
| `RING_SIZE` | 4096 | Lũy thừa của hai. Buffer cho hash imbalance giữa Parser và Worker. |
| `RING_F_SP_ENQ` | Đặt | Single producer (Parser lcore) → lock-free tối ưu. |
| `RING_F_SC_DEQ` | Đặt | Single consumer (Worker lcore i riêng biệt) → lock-free tối ưu. |
| `WORKER_BURST_SIZE` | 32 | Kích thước dequeue burst để batch flat ACL classify. |

**Tầng 3: tx_ring (Worker → TX, MPSC)**

| Tham số | Giá trị | Lý do |
|---|---|---|
| `TX_RING_SIZE` | 65536 | Lớn hơn worker_ring vì N Worker enqueue đồng thời vào 1 ring; cần đủ lớn để không làm bottleneck khi nhiều worker. |
| `RING_F_MP_ENQ` | Đặt | Multi-producer (tất cả N Worker lcore enqueue đồng thời) — bắt buộc. |
| `RING_F_SC_DEQ` | Đặt | Single consumer (TX lcore) → lock-free dequeue. |
| `TX_BURST_SIZE` | 64 | Kích thước dequeue burst của TX lcore. |

**Xử lý ring đầy:** Mọi ring overflow đều dẫn đến free mbuf ngay lập tức và tăng counter tương ứng (`parser_ring_drop`, `worker_ring_drop`, `tx_ring_drop`). Kích thước ring phải đảm bảo tỷ lệ drop tổng cộng ≤ 0,1% (PR-005).

### 7.4 Tóm Tắt Bố Cục Bộ Nhớ

```
Hugepage memory (được EAL cấp phát khi khởi động)
│
├── rte_mempool (32768 mbufs × 2176 bytes ≈ 69 MB)
│    └── cache per-lcore (256 entry mỗi cái)
│
├── parser_ring     (65536 × 8 bytes = 512 KB, SPSC)
├── worker_ring[0]  (4096 × 8 bytes = 32 KB, SPSC)
├── worker_ring[1]  ...
├── worker_ring[N-1]
├── tx_ring         (65536 × 8 bytes = 512 KB, MPSC)
│
└── flat_acl_ctx    (rte_acl context duy nhất chứa tất cả rule, ~vài MB)
```

```
Stack / BSS (không phải hugepage)
│
└── flat_rule_table  (flat_rule_entry_t[SPIFAST_MAX_RULES] + group_names[])
     — kích thước tĩnh, cấp phát tại compile time
     — read-only sau khi rule_loader hoàn tất
```

Tất cả cấu trúc DPDK (mempool, ring, acl_ctx) đều nằm trong hugepage memory. `flat_rule_table` là cấu trúc C tĩnh không yêu cầu hugepage. Không có lazy allocation trong runtime — toàn bộ ACL được biên dịch một lần tại khởi động.

### 7.5 Tham Số Tài Nguyên Có Thể Cấu Hình

Các hằng số compile-time sau được định nghĩa trong `src/dpdk/dpdk_init.h` và có thể được override tại build time:

```c
#define SPIFAST_MEMPOOL_SIZE              32768  /* tăng từ 8192 để tránh alloc_fail dưới tải cao */
#define SPIFAST_MEMPOOL_CACHE             256
#define SPIFAST_BURST_SIZE                64     /* tăng từ 32 để cải thiện throughput */
#define SPIFAST_RX_DESC                   512
#define SPIFAST_TX_DESC                   512
#define SPIFAST_PARSER_RING_SIZE          65536  /* tăng từ 1024 để hấp thụ burst libpcap */
#define SPIFAST_RING_SIZE                 4096   /* tăng từ 1024 (worker_ring per worker) */
#define SPIFAST_TX_RING_SIZE              65536  /* tăng từ 4096 để tránh bottleneck multi-worker */
#define SPIFAST_WORKER_BURST              32
#define SPIFAST_TX_BURST_SIZE             64     /* tăng từ 32 */
#define SPIFAST_EOI_THRESHOLD             100
#define SPIFAST_PREFETCH_AHEAD            4
#define SPIFAST_MAX_GROUPS                4096
#define SPIFAST_MAX_RULES                 65536  /* tổng rule tối đa trong flat_rule_table */
/* SPIFAST_MAX_FILTERS_PER_GROUP đã bị loại bỏ cùng với two-stage ACL model */
```

---

## 8. Thiết Kế Thống Kê và Logging

### 8.1 Thiết Kế Thu Thập Thống Kê

Module stats đọc tất cả counter per-lcore một lần mỗi giây trên main lcore. Việc đọc là non-blocking và không cần lock (xem Mục 6.6). Module duy trì snapshot trước để tính delta theo chu kỳ.

**Hàm thu thập (`stats_collect`):**

```
stats_collect(prev_snapshot) → stats_snapshot_t:

  now_cycles = rte_get_timer_cycles()
  hz         = rte_get_timer_hz()

  /* Tổng hợp counter RX lcore */
  cur.total_rx_pkts          = rx_stats.rx_packets
  cur.total_alloc_fail       = rx_stats.alloc_fail
  cur.total_parser_ring_drop = rx_stats.parser_ring_drop
  cur.total_pcap_loops       = rx_stats.pcap_loops

  /* Tổng hợp counter Parser lcore */
  cur.total_parsed_pkts      = parser_stats.parsed_packets
  cur.total_invalid_pkts     = parser_stats.invalid_packets
  cur.total_worker_ring_drop = parser_stats.worker_ring_drop

  /* Tổng hợp counter tất cả Worker lcore */
  cur.total_fwd_pkts  = 0
  cur.total_drop_pkts = 0
  cur.total_tx_ring_drop = 0
  memset(cur.group_hits, 0, sizeof(cur.group_hits))

  với mỗi i trong [0, num_workers):
    cur.total_fwd_pkts     += worker_stats[i].forwarded
    cur.total_drop_pkts    += worker_stats[i].dropped
    cur.total_tx_ring_drop += worker_stats[i].tx_ring_drop
    /* Aggregate per-group hit counts từ worker_ctxs (không phải worker_stats) */
    với mỗi g trong [0, num_groups):
      cur.group_hits[g] += worker_ctxs[i].group_hits[g]

  /* Tổng hợp counter TX lcore */
  cur.total_tx_pkts      = tx_stats.tx_packets
  cur.total_tx_drop_pkts = tx_stats.tx_drop_packets
  /* total_bytes = tx_bytes (forwarded bytes tại TX), không phải worker fwd_bytes */
  cur.total_bytes        = tx_stats.tx_bytes

  /* Delta theo chu kỳ */
  snap.interval_sec      = (double)(now_cycles - prev_cycles) / hz
  snap.interval_rx_pkts  = cur.total_rx_pkts  - prev.total_rx_pkts
  snap.interval_fwd_pkts = cur.total_fwd_pkts - prev.total_fwd_pkts
  snap.interval_fwd_bytes= cur.total_bytes    - prev.total_bytes

  /* Throughput và PPS — chỉ forwarded (tx_bytes delta), không bao gồm DROP bytes */
  snap.interval_mbps = (snap.interval_fwd_bytes * 8.0)
                       / snap.interval_sec / 1e6
  snap.interval_pps  = snap.interval_fwd_pkts / snap.interval_sec

  /* Sao chép hit counter đã aggregate */
  memcpy(snap.group_hits, cur.group_hits, num_groups * sizeof(uint64_t))
  snap.num_groups = num_groups

  /* Thời gian đã trôi qua */
  snap.elapsed_sec = (now_cycles - session_start_cycles) / hz

  /* Sao chép tổng lũy kế */
  snap.total_rx_pkts         = cur.total_rx_pkts
  snap.total_alloc_fail      = cur.total_alloc_fail
  snap.total_pcap_loops      = cur.total_pcap_loops
  snap.total_parsed_pkts     = cur.total_parsed_pkts
  snap.total_fwd_pkts        = cur.total_fwd_pkts
  snap.total_drop_pkts       = cur.total_drop_pkts
  snap.total_invalid_pkts    = cur.total_invalid_pkts
  snap.total_parser_ring_drop= cur.total_parser_ring_drop
  snap.total_worker_ring_drop= cur.total_worker_ring_drop
  snap.total_tx_pkts         = cur.total_tx_pkts
  snap.total_tx_drop_pkts    = cur.total_tx_drop_pkts
  snap.total_bytes           = cur.total_bytes

  return snap
```

**Xác nhận mất gói tin (FR-032) — thực hiện cuối phiên:**

`parser_ring_drop` được **loại trừ khỏi công thức** vì với continuous replay, giá trị này tích lũy qua nhiều vòng loop và không phản ánh "packet lost" cần hạch toán. PASS condition dùng ngưỡng 0,1% thay vì delta == 0 để chấp nhận một tỷ lệ nhỏ ring overflow bình thường.

```
validate_packet_accounting(final_snap):
  accounted = final_snap.total_invalid_pkts
            + final_snap.total_worker_ring_drop
            + final_snap.total_drop_pkts        /* ACL DROP rule */
            + final_snap.total_tx_ring_drop
            + final_snap.total_tx_drop_pkts     /* TX queue đầy */
            + final_snap.total_tx_pkts

  /* parser_ring_drop không tính — tích lũy qua nhiều pcap loops */

  delta = final_snap.total_rx_pkts - accounted

  nếu final_snap.total_rx_pkts == 0:
    result = PASS
  ngược lại:
    ratio = (double)delta / (double)final_snap.total_rx_pkts
    nếu ratio <= 0.001:                 /* PERF_SUCCESS = 0.1% */
      log_info("Packet accounting: PASS (delta=%lu, ratio=%.4f%%)", delta, ratio*100)
    ngược lại:
      log_error("Packet accounting: FAIL (delta=%lu, ratio=%.4f%%)", delta, ratio*100)
```

### 8.2 Thiết Kế Logging

Module logging cung cấp các hàm sau được gọi riêng từ main lcore:

| Hàm | Khi được gọi | Nội dung |
|---|---|---|
| `log_open(path)` | Khởi động | Mở file log ở append mode nếu path khác NULL |
| `log_startup_event(config, rules, groups)` | Sau khi nạp rule | Tóm tắt config ứng dụng; danh sách rule đã nạp |
| `log_periodic(snapshot)` | Mỗi 1 giây | Thống kê theo chu kỳ và lũy kế (xem định dạng bên dưới) |
| `log_final_summary(snapshot)` | Trước khi thoát | Tổng cộng phiên; bảng hit per-group; kết quả xác nhận mất gói tin |
| `log_close()` | Sau tóm tắt cuối | Flush và đóng file log |

**Triển khai dual-output:**

```c
static void log_write(const char *msg) {
    fputs(msg, stdout);
    if (log_file != NULL) {
        fputs(msg, log_file);
    }
}
```

`log_file` là `FILE *` được mở bằng `fopen(path, "a")` (append mode). Một lệnh gọi `log_write` duy nhất ghi vào cả hai đích một cách nguyên tử đối với luồng gọi (tất cả lệnh gọi đều từ main lcore; không có ghi đồng thời).

**Chính sách flush:** `fflush` được gọi trên cả `stdout` và `log_file` mỗi lần gọi `log_periodic` (mỗi giây một lần). Điều này tránh overhead `fflush` per-dòng trong khi vẫn đảm bảo dữ liệu log đến đĩa trong vòng một giây sau khi được tạo.

**Xử lý lỗi file log:** Nếu `fopen` thất bại, một cảnh báo được in ra `stderr` và `log_file` vẫn là NULL. Các lệnh gọi `log_write` tiếp theo bỏ qua đầu ra file một cách im lặng. Xử lý gói tin không bị gián đoạn.

### 8.3 Định Dạng Đầu Ra Log

**Dòng thống kê định kỳ (LOG-002, LOG-003):**

```
[2025-06-26T14:32:05+0700] elapsed=10s  loops=3  rx=500000  fwd=489800  drop=9800  inv=200  alloc_fail=0  p_drop=0  w_drop=0  tx_drop=0  mbps=823.40  pps=489800
```

Định nghĩa trường:

| Token | Trường | Đơn vị |
|---|---|---|
| `[timestamp]` | Thời gian địa phương ISO 8601 | — |
| `elapsed=Ns` | Giây kể từ gói tin đầu tiên | giây |
| `loops=N` | Số lần đã replay hết file pcap lũy kế | lần |
| `rx=N` | Gói tin RX lũy kế | gói tin |
| `fwd=N` | Gói tin được forward lũy kế (enqueue tx_ring) | gói tin |
| `drop=N` | Gói tin bị DROP theo rule lũy kế | gói tin |
| `inv=N` | Gói tin không hợp lệ lũy kế | gói tin |
| `alloc_fail=N` | Lần rte_pktmbuf_alloc() trả về NULL lũy kế | lần |
| `p_drop=N` | Gói tin bị hủy do parser_ring overflow lũy kế | gói tin |
| `w_drop=N` | Gói tin bị hủy do worker_ring overflow lũy kế | gói tin |
| `tx_drop=N` | Tổng mbuf bị hủy ở TX (tx_ring overflow + TX queue đầy) lũy kế | gói tin |
| `mbps=F` | Throughput theo chu kỳ | Mbps (2 chữ số thập phân) |
| `pps=N` | PPS theo chu kỳ | gói tin/giây |

**Sự kiện khởi động (LOG-004):**

```
[2025-06-26T14:32:00+0700] STARTUP  pcap=traffic.pcap  rules=spi_rules.conf  workers=2  mode=first-match
[2025-06-26T14:32:00+0700] RULES_LOADED  count=7  groups=5
[2025-06-26T14:32:00+0700] RULE  f_l34_facebook_1  group=fg_l34_facebook  action=FORWARD  precedence=100
...
[2025-06-26T14:32:00+0700] FIRST_PACKET
```

**Tóm tắt phiên cuối cùng (FR-031, LOG-004):**

```
[2025-06-26T14:32:15+0700] SESSION_END
[2025-06-26T14:32:15+0700] SUMMARY  elapsed=15s  pcap_loops=5  total_rx=750000  total_parsed=749700  total_fwd=734700  total_drop=14700  total_inv=300  total_alloc_fail=0  total_p_ring_drop=0  total_w_ring_drop=0  total_tx_ring_drop=0  total_tx_drop=0  total_tx=734700
[2025-06-26T14:32:15+0700] THROUGHPUT_AVG  mbps=817.33
[2025-06-26T14:32:15+0700] PPS_AVG  pps=489800
[2025-06-26T14:32:15+0700] GROUP_HITS  fg_l34_facebook=180000 fg_l34_youtube=127500 fg_l34_http_sdf1003=300000 fg_l34_dns_sdf1005=127500 DEFAULT=14700
[2025-06-26T14:32:15+0700] PACKET_ACCOUNTING  rx=750000  p_ring_drop=0  inv=300  w_ring_drop=0  acl_drop=14700  tx_ring_drop=0  tx_drop=0  tx_pkts=734700  lost=0  result=PASS
```

### 8.4 Đo Hiệu Năng Per-Stage (`perf/perf_stats`)

Module `perf_stats` cung cấp cơ chế đo cycles per-stage không ảnh hưởng đến data path. Được dùng để chẩn đoán bottleneck theo từng giai đoạn pipeline.

**Cấu trúc dữ liệu:**

```c
#define SPIFAST_PERF_SAMPLE_RATE  1000   /* đo 1 trong 1000 burst/packet */

typedef struct {
    uint64_t total_cycles;    /* tổng cycles tích lũy trong các mẫu */
    uint64_t total_packets;   /* tổng số packet trong các mẫu       */
    uint64_t total_samples;   /* số lần lấy mẫu                     */
    uint8_t  _pad[CACHE_LINE_SIZE - 3 * sizeof(uint64_t)];
} __rte_cache_aligned perf_stage_t;

typedef struct {
    perf_stage_t rx;
    perf_stage_t parser;
    perf_stage_t worker[SPIFAST_MAX_WORKERS];  /* tổng cycles Worker (bao gồm ACL) */
    perf_stage_t acl[SPIFAST_MAX_WORKERS];     /* chỉ ACL cycles trong Worker       */
    perf_stage_t tx;
    uint32_t     num_workers;
} perf_ctx_t;
```

**Cơ chế sampling:**

Mỗi lcore kiểm tra `burst_count % SPIFAST_PERF_SAMPLE_RATE == 0`. Nếu đúng:
```c
uint64_t t0 = rte_rdtsc();
/* ... tác vụ chính của stage ... */
perf->total_cycles  += rte_rdtsc() - t0;
perf->total_packets += nb;
perf->total_samples++;
```

Overhead `rte_rdtsc()` < 0,1% tổng thời gian xử lý với sampling rate 1/1000.

**Xuất kết quả:**

`log_perf_report(perf_ctx, hz, pps, mbps, ...)` được gọi từ main lcore mỗi 1 giây, xuất:
- cycles/packet và nanoseconds/packet cho từng stage: RX, Parser, Worker (total), Flat ACL, TX
- Tổng cycles/packet toàn pipeline
- Per-worker: số packet dispatched, ACL cycles, total cycles
- Tóm tắt PPS và Mbps hiện tại

`perf_ctx_t g_perf_ctx` là global, được khởi tạo trong main lcore trước khi khởi chạy các data path lcore. Mỗi lcore nhận con trỏ đến `perf_stage_t` tương ứng của mình.

---

## 9. Thiết Kế Cấu Hình

### 9.1 Giao Diện Dòng Lệnh

Ứng dụng chấp nhận tham số EAL theo sau bởi `--` và sau đó là các tham số dành riêng cho ứng dụng:

```
./spifast [EAL options] -- [application options]
```

**Tùy chọn ứng dụng:**

| Tùy chọn | Kiểu | Bắt buộc | Mặc định | Mô tả |
|---|---|---|---|---|
| `--pcap <path>` | string | Có | — | Đường dẫn đến file PCAP đầu vào |
| `--rules <path>` | string | Không | `spi_rules.conf` | Đường dẫn đến file cấu hình rule |
| `--workers <N>` | integer | Không | `1` | Số lượng worker lcore (≥ 1) |
| `--log <path>` | string | Không | (không có) | Đường dẫn đến file log đầu ra (append mode) |
| `--mode <first\|best>` | enum | Không | `first` | Chế độ khớp ACL |

**Ví dụ gọi lệnh:**

```bash
# Tối giản: 1 worker (N+4 = 5 lcore), rule từ file mặc định, log chỉ ra stdout
./spifast -l 0-4 -n 4 -- --pcap tests/tp01_small.pcap

# Đầy đủ: 4 worker (N+4 = 8 lcore), rule tường minh, file log, chế độ best-match
./spifast -l 0-7 -n 4 -- \
  --pcap tests/tp02_medium.pcap \
  --rules config/spi_rules.conf \
  --workers 4 \
  --log /var/log/spifast/run_$(date +%Y%m%d_%H%M%S).log \
  --mode best
```

### 9.2 Trình Tự Nạp Cấu Hình

```
main(argc, argv):

  Bước 1: Tách tham số EAL và tham số ứng dụng
    Tách argv tại dấu phân tách '--'.
    eal_argc / eal_argv → truyền cho rte_eal_init.
    app_argc / app_argv → được getopt_long phân tích.

  Bước 2: Phân tích tham số ứng dụng (getopt_long)
    Điền vào spifast_config_t.
    Kiểm tra:
      - đường dẫn --pcap: file tồn tại và có thể đọc được
      - --workers N: N >= 1
      - --mode: giá trị là "first" hoặc "best"
    Khi kiểm tra thất bại: in hướng dẫn sử dụng; exit(EXIT_FAILURE).

  Bước 3: Khởi tạo DPDK (dpdk_init)
    dpdk_init(&config) → thiết lập mempool, port, ring.

  Bước 4: Mở file log (nếu --log được chỉ định)
    log_open(config.log_path)

  Bước 5: Nạp rule
    rule_loader_load(config.rules_path, ...) → build ACL.

  Bước 6: Ghi log sự kiện khởi động
    log_startup_event(&config, rules, groups)

  Bước 7: Khởi chạy lcore
    rte_eal_remote_launch(rx_lcore_func,     &rx_ctx,     rx_lcore_id)
    rte_eal_remote_launch(parser_lcore_func, &parser_ctx, parser_lcore_id)
    với mỗi i trong workers:
      rte_eal_remote_launch(worker_lcore_func, &worker_ctx[i], worker_lcore_id[i])
    rte_eal_remote_launch(tx_lcore_func,     &tx_ctx,     tx_lcore_id)

  Bước 8: Vòng lặp stats của main lcore (xem Mục 6.4)

  Bước 9: Chờ tất cả lcore
    rte_eal_mp_wait_lcore()

  Bước 10: Tóm tắt cuối, dọn dẹp
    log_final_summary(final_snapshot)
    log_close()
    rte_eal_cleanup()
    exit(EXIT_SUCCESS)
```

---

## 10. Thiết Kế Xử Lý Lỗi

### 10.1 Triết Lý Xử Lý Lỗi

Tất cả điều kiện lỗi thuộc hai loại:

- **Lỗi fatal (giai đoạn khởi động):** Bất kỳ lỗi nào trong quá trình khởi tạo, nạp rule hay build ACL đều gây ra thoát ngay lập tức có trật tự với thông báo mô tả ra `stderr`. Không cho phép trạng thái một phần.
- **Lỗi runtime (data path):** Các lỗi xảy ra trong quá trình xử lý gói tin (lỗi phân tích, ring đầy) được xử lý im lặng tại chỗ bằng cách hủy gói tin bị lỗi và tăng counter thích hợp. Hệ thống không bao giờ hủy hoạt động do một gói tin xấu.

### 10.2 Xử Lý Lỗi Khởi Động

| Điều kiện | Điểm phát hiện | Phản hồi |
|---|---|---|
| File `--pcap` không tìm thấy hoặc không đọc được | `main` (kiểm tra tham số) | `fprintf(stderr, ...)` ; `exit(EXIT_FAILURE)` |
| File `--rules` không tìm thấy hoặc không đọc được | `rule_loader_load` | Ghi log lỗi kèm đường dẫn file; `return -1` → `main` thoát |
| Lỗi cú pháp rule | `rule_loader_load` (parser dòng) | Ghi log lỗi kèm đường dẫn file, số dòng và nội dung bị lỗi; `return -1` |
| Tên rule trùng lặp | `rule_loader_load` | Ghi log lỗi xác định cả hai lần xuất hiện; `return -1` |
| Số lượng group > 4096 | `rule_loader_load` | Ghi log lỗi kèm số lượng; `return -1` |
| Tổng số rule > `SPIFAST_MAX_RULES` | `rule_loader_load` | Ghi log lỗi kèm tổng số rule; `return -1` |
| Thiếu rule DEFAULT | `rule_loader_load` (kiểm tra sau phân tích) | Ghi log lỗi; `return -1` |
| Định dạng IP/prefix không hợp lệ | `rule_loader_load` (validator trường) | Ghi log lỗi kèm giá trị trường và số dòng; `return -1` |
| Port range lo > hi | `rule_loader_load` | Ghi log lỗi; `return -1` |
| Lỗi `rte_acl_build` | `acl_engine_build` | Ghi log `rte_strerror(rte_errno)`; `return -1` |
| Lỗi khởi tạo EAL | `dpdk_init` | Ghi log `rte_strerror`; `exit(EXIT_FAILURE)` |
| Lỗi tạo mempool | `dpdk_init` | Ghi log lỗi; `exit(EXIT_FAILURE)` |
| Lỗi cấu hình port | `dpdk_init` | Ghi log lỗi; `exit(EXIT_FAILURE)` |
| Lỗi tạo ring | `dpdk_init` | Ghi log lỗi; `exit(EXIT_FAILURE)` |
| Không đủ lcore | `main` (kiểm tra sau EAL) | Ghi log số lcore yêu cầu vs. có sẵn; `exit(EXIT_FAILURE)` |
| Lỗi mở file log | `log_open` | `fprintf(stderr, "WARNING: cannot open log file %s: %s\n", path, strerror(errno))`; tiếp tục chỉ với stdout |

### 10.3 Xử Lý Lỗi Runtime (Data Path)

| Điều kiện | Điểm phát hiện | Phản hồi | Counter được cập nhật |
|---|---|---|---|
| Ethernet header quá ngắn | `parser` | Giải phóng mbuf; bỏ qua | `invalid_packets` |
| EtherType không được hỗ trợ (không phải IPv4 sau khi bóc VLAN) | `parser` | Giải phóng mbuf; bỏ qua | `invalid_packets` |
| IPv4 header quá ngắn hoặc IHL bị lỗi | `parser` | Giải phóng mbuf; bỏ qua | `invalid_packets` |
| IP protocol không được hỗ trợ (không phải TCP/UDP) | `parser` | Giải phóng mbuf; bỏ qua | `invalid_packets` |
| Transport header quá ngắn | `parser` | Giải phóng mbuf; bỏ qua | `invalid_packets` |
| parser_ring đầy (`rte_ring_enqueue_burst` thiếu slot) | `rx` (enqueue parser_ring) | Giải phóng mbuf ngay lập tức | `parser_ring_drop` |
| worker_ring đầy (`rte_ring_enqueue` trả về -ENOBUFS) | `parser` (hash dispatch) | Giải phóng mbuf ngay lập tức | `worker_ring_drop` |
| tx_ring đầy (`rte_ring_enqueue_burst` thiếu slot) | `worker` (enqueue tx_ring) | Giải phóng mbuf ngay lập tức | `tx_ring_drop` |
| TX queue đầy (`rte_eth_tx_burst` gửi ít hơn nb) | `tx` (tx_burst) | Giải phóng mbuf chưa gửi | `tx_drop_packets` |
| Flat ACL không khớp explicit rule nào (results[i]==0) | `worker` (sau rte_acl_classify) | Áp dụng ACTION_DROP; tăng group_hits[DEFAULT_GROUP_IDX] | `group_hits[DEFAULT_GROUP_IDX]` |

Không có điều kiện lỗi nào trên data path dẫn đến ghi log, `fprintf`, hoặc bất kỳ system call nào. Tất cả đường lỗi kết thúc bằng `rte_pktmbuf_free` và tăng counter.

### 10.4 Định Dạng Thông Báo Lỗi

Tất cả thông báo lỗi khởi động tuân theo định dạng:

```
[SPIFAST ERROR] <module>: <mô tả>. <gợi ý khắc phục nếu có>
```

Ví dụ:
```
[SPIFAST ERROR] rule_loader: line 15: invalid CIDR prefix length '33' in field dst_prefix (must be 0-32).
[SPIFAST ERROR] rule_loader: duplicate rule name 'f_l34_facebook_1' at line 22 (first defined at line 8).
[SPIFAST ERROR] rule_loader: no DEFAULT group defined. Add '[group: DEFAULT] precedence=1 action=DROP'.
```

---

## 11. Trình Tự Triển Khai

Trình tự build được khuyến nghị tiến hành theo từng giai đoạn, mỗi giai đoạn có thể được biên dịch và kiểm thử độc lập trước khi tiến hành.

### Giai đoạn 1 — Nền Tảng DPDK

**Mục tiêu:** Xác nhận môi trường DPDK hoạt động trước khi viết bất kỳ logic ứng dụng nào.

1. Thiết lập build system (`Makefile` hoặc `CMakeLists.txt`) với liên kết DPDK pkg-config.
2. Triển khai skeleton `main.c`: phân tích tham số EAL, `rte_eal_init`, `rte_eal_cleanup`.
3. Triển khai `dpdk_init`: tạo mempool; cấu hình port với 1 RX queue và 1 TX queue; tạo `parser_ring`, `worker_ring[]`, `tx_ring`.
4. Kiểm tra: ứng dụng khởi động, mở port và thoát sạch. Xác nhận N+4 lcore được gán đúng vai trò.

### Giai đoạn 2 — RX lcore và Logging Thô

**Mục tiêu:** Xác nhận nhận gói tin thô từ file PCAP và cơ chế pipeline ring cơ bản.

5. Triển khai `rx.c`: vòng lặp RX burst; enqueue toàn bộ burst vào `parser_ring`; phát hiện kết thúc PCAP; xử lý `parser_ring` đầy.
6. Triển khai stub Parser lcore: chỉ dequeue từ `parser_ring` rồi free mbuf ngay; đếm số gói tin.
7. Triển khai `logging/log.c` tối giản và `stats/stats.c` cơ bản.
8. Khởi chạy RX, Parser (stub), và main stats loop.
9. Kiểm tra: số gói tin khớp với `tcpdump -r <pcap> | wc -l`. Xác nhận `parser_ring` hoạt động đúng.

### Giai đoạn 3 — Packet Parser lcore

**Mục tiêu:** Giải mã chính xác tất cả kiểu gói tin và hash dispatch.

10. Triển khai `packet/parser.c` với `parser_lcore_func`: dequeue, prefetch, parse L2/VLAN/L3/L4.
11. Triển khai `normalize_flow` và ghi metadata vào mbuf headroom.
12. Triển khai hash dispatch: `rte_hash_crc(&meta, ...) % N_workers` → enqueue `worker_ring[i]`.
13. Unit test parse path (độc lập, không cần DPDK).
14. Kiểm tra với TP-04 (PCAP hai chiều): cùng five-tuple từ cả hai chiều.
15. Kiểm tra với TP-05 (PCAP VLAN): VLAN parsing và headroom metadata đúng.

### Giai đoạn 4 — Rule Loader và Flat ACL Engine

**Mục tiêu:** Nạp rule, xây dựng `flat_rule_table_t` và build `flat_acl_ctx`.

16. Triển khai `rule/rule_loader.c`: parser file, validator (≤4096 group, tổng rule ≤ `SPIFAST_MAX_RULES`); điền `flat_rule_entry_t` với action và group_idx nhúng trực tiếp; gán `file_order` tăng dần.
17. Unit test rule loader: kiểm tra tất cả trường hợp hợp lệ, invalid IP, port range, thiếu DEFAULT, tên trùng; kiểm tra `flat_rule_table` output đúng `file_order`, `action`, `group_idx`.
18. Triển khai `rule/acl_engine.c`: `acl_engine_build(flat_rule_table, match_mode)` — gán `data.priority` theo mode (best: `precedence`; first: `N - file_order`); DEFAULT rule với `priority=0`; `rte_acl_build` một lần.
19. Unit test ACL engine: verify `rte_acl_classify` trả về `file_order+1` cho các packet khớp; verify priority ordering đúng cho cả `--mode best` và `--mode first`; verify DEFAULT catch-all hoạt động.

### Giai đoạn 5 — Worker lcore với Single-Stage Flat ACL

**Mục tiêu:** Hoàn thành pipeline Worker với single-stage ACL classify và tx_ring enqueue.

20. Triển khai `worker/worker.c` với `worker_lcore_func`: dequeue, đọc headroom, **một lần** `rte_acl_classify(flat_acl_ctx, ...)`, tra cứu O(1) `flat_rule_table.rules[ud-1].action`, FORWARD → `tx_ring`, DROP → free, tăng `group_hits[group_idx]`.
21. Triển khai stub TX lcore: chỉ dequeue từ `tx_ring` rồi free mbuf ngay; đếm counter.
22. Khởi chạy toàn bộ pipeline: RX → Parser → Worker → TX (stub).
23. Kiểm tra: tổng `worker_stats[i].forwarded` khớp số FORWARD packet dự kiến. Không có mbuf leak.
24. Kiểm tra với PCAP tham chiếu: mọi gói tin được phân loại đúng action theo rule file (RC-004). Kiểm tra `GROUP_HITS` khớp phân phối lưu lượng.

### Giai đoạn 6 — TX lcore

**Mục tiêu:** Hoàn thiện TX path — truyền gói tin ra NIC TX.

25. Triển khai `tx/tx.c` với `tx_lcore_func`: drain `tx_ring`, `rte_eth_tx_burst`, xử lý mbuf chưa gửi, cập nhật `tx_lcore_stats`.
26. Thay stub TX bằng TX lcore thật.
27. Kiểm tra: `tx_stats.tx_packets` bằng `worker_stats.fwd_packets` (không có tx_drop).

### Giai đoạn 7 — Thống Kê và Logging

**Mục tiêu:** Tạo ra đầu ra thống kê đầy đủ từ tất cả lcore.

28. Hoàn thiện `stats/stats.c`: aggregate từ tất cả 4 loại lcore counter; công thức Mbps/PPS; packet accounting mới (5 thành phần).
29. Hoàn thiện `logging/log.c`: định dạng định kỳ mới với `tx`, `p_ring_drop`, `w_ring_drop`, `tx_drop`; sự kiện khởi động; tóm tắt cuối.
30. Triển khai log file output (dual-output, append mode, flush policy).
31. Kiểm tra với TP-01: PPS output ≥ 500.000. Kiểm tra `PACKET_ACCOUNTING result=PASS`.

### Giai đoạn 8 — Kiểm Thử Tích Hợp và Hiệu Năng

**Mục tiêu:** Đáp ứng tất cả yêu cầu hiệu năng SRS.

32. Chạy TP-01 (frame 64 byte): đo PPS duy trì. Mục tiêu: PASS ≥ 500 Kpps; EXCELLENT ≥ 1.488 Mpps.
33. Chạy TP-02 (frame ~1024 byte): đo Mbps duy trì. Mục tiêu: PASS ≥ 700 Mbps; EXCELLENT ≥ 950 Mbps.
34. Chạy TP-03 (full rule coverage): xác nhận tất cả group hit counter ≥ 1 cuối phiên.
35. Chạy TP-04 (bidirectional flow): xác nhận cả hai chiều tăng cùng group counter.
36. Chạy TP-05 (VLAN tagged): xác nhận phân loại giống hệt như gói tương đương không có thẻ.
37. Đo tỷ lệ drop tổng cộng (PR-005): `(p_ring_drop + w_ring_drop + tx_ring_drop + tx_drop) / total_rx × 100 ≤ 0,1%`.
38. Kiểm tra hạch toán mất gói tin (PR-006): `PACKET_ACCOUNTING result=PASS` cho tất cả profile.
39. Thu thập và lưu trữ bằng chứng kiểm thử.

### Giai đoạn 9 — Xử Lý Lỗi và Edge Case

**Mục tiêu:** Làm cứng ứng dụng trước tất cả điều kiện lỗi.

40. Kiểm thử từng đường lỗi khởi động: file thiếu, cú pháp sai, >4096 group, tổng rule > `SPIFAST_MAX_RULES`, không có DEFAULT, IP sai, port range sai. Xác nhận thông báo lỗi đúng format.
41. Kiểm thử lỗi đường dẫn file log: xác nhận cảnh báo trên stderr; xử lý tiếp tục.
42. Kiểm thử ring overflow bằng cách giảm ring size để kích hoạt `p_ring_drop` và `w_ring_drop`.
43. Kiểm thử với PCAP chứa frame không phải IPv4: xác nhận `invalid_packets` tăng; không crash.
44. Kiểm thử với frame bị lỗi (header bị cắt ngắn): xác nhận xử lý graceful; không crash.

---

*Kết thúc tài liệu — SPIFAST-SDD-001-VI v1.4*
