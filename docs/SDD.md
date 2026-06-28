# Thiết Kế Chi Tiết Phần Mềm

---

**Tiêu đề tài liệu:** Thiết Kế Chi Tiết Phần Mềm — SPIFast: Hệ Thống Kiểm Tra Gói Tin Hiệu Năng Cao Sử Dụng DPDK

**Mã tài liệu:** SPIFAST-SDD-001

**Phiên bản:** 1.1

**Trạng thái:** Draft

**Người soạn thảo:** Nhóm Kỹ Thuật Hệ Thống

**Ngày:** 2025-06-28

**HLD áp dụng:** SPIFAST-HLD-001 v1.3

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
│   │   ├── acl_engine.c   # Build two-stage ACL (stage1_ctx + group_ctx[]); batch lookup
│   │   └── acl_engine.h
│   ├── worker/
│   │   ├── worker.c       # Worker lcore: dequeue, đọc headroom, batch two-stage ACL, FORWARD/DROP
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
| `rule/rule_loader` | ACL Rule Engine (giai đoạn nạp) | Phân tích file rule; kiểm tra hợp lệ trường; xây dựng bảng filter-group |
| `rule/acl_engine` | ACL Rule Engine (giai đoạn build + lookup) | Build stage1_ctx (group representative rules) và group_ctx[i] (per-group filter rules, lazy); batch two-stage lookup được gọi từ Worker lcore |
| `worker/worker` | Worker lcore | Dequeue burst từ worker_ring; đọc metadata từ mbuf headroom; batch two-stage ACL classify; FORWARD → enqueue tx_ring; DROP → rte_pktmbuf_free |
| `tx/tx` | TX lcore | Drain tx_ring (MPSC); rte_eth_tx_burst(); sở hữu TX queue duy nhất; xử lý mbuf chưa gửi được |
| `stats/stats` | Statistics Component | Tổng hợp counter lock-free từ tất cả lcore (RX, Parser, Worker×N, TX); tính Mbps và PPS |
| `logging/log` | Logging Component | Xuất log định kỳ và cuối phiên ra stdout và file log tùy chọn; quản lý dual-output |

### 1.3 Đồ Thị Phụ Thuộc Liên Module

```
main
 ├── dpdk_init        (gọi đầu tiên; tạo parser_ring, worker_ring[], tx_ring)
 ├── rule_loader      (gọi sau EAL; tạo ra bảng rule và group table)
 │    └── acl_engine  (build stage1_ctx + khởi tạo group_ctx[] lazy array)
 ├── log              (mở sau khi config đã biết)
 ├── rx               (khởi chạy trên RX lcore; poll NIC → enqueue parser_ring)
 ├── parser           (khởi chạy trên Parser lcore; dequeue parser_ring →
 │                     parse → write headroom → hash dispatch → worker_ring[i])
 ├── worker×N         (khởi chạy trên N Worker lcore; dequeue worker_ring →
 │                     batch two-stage ACL → FORWARD→tx_ring | DROP→free)
 │    └── acl_engine  (batch lookup, read-only stage1_ctx + group_ctx[])
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
                               RING_F_MP_ENQ | RING_F_SC_DEQ)
     - RING_F_MP_ENQ: multi-producer (tất cả N Worker lcore enqueue đồng thời).
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

  zero_consecutive_empty = 0

  vòng lặp:
    nb_rx = rte_eth_rx_burst(port_id, queue_id=0,
                              rx_pkts[], burst_size=BURST_SIZE)

    nếu nb_rx == 0:
      zero_consecutive_empty++
      nếu zero_consecutive_empty >= EOI_THRESHOLD:
        signal_shutdown()   /* đặt global volatile shutdown_flag = 1 */
        thoát vòng lặp
      tiếp tục

    zero_consecutive_empty = 0
    rx_lcore_stats.rx_packets += nb_rx

    /* Enqueue toàn bộ burst vào parser_ring */
    nb_enqueued = rte_ring_enqueue_burst(parser_ring, rx_pkts, nb_rx, NULL)

    nếu nb_enqueued < nb_rx:
      /* parser_ring đầy: hủy các mbuf không enqueue được */
      với mỗi i trong [nb_enqueued, nb_rx):
        rte_pktmbuf_free(rx_pkts[i])
        rx_lcore_stats.parser_ring_drop++

  /* Chờ pipeline downstream drain trước khi trả về */
  wait_pipeline_drain()
  return 0
```

**Lightweight hash (placeholder cho future scale):**

Ở cấu hình hiện tại với 1 Parser lcore, toàn bộ burst được enqueue vào `parser_ring` duy nhất mà không cần hash. Nếu trong tương lai scale lên nhiều Parser lcore, RX lcore đọc IP src tại fixed byte offset trong frame data (offset 26 với untagged Ethernet, offset 30 với VLAN tagged) để tính lightweight hash phân phối vào `parser_ring[p]` tương ứng. Thao tác này không yêu cầu parse đầy đủ header.

**Phát hiện kết thúc đầu vào:**

PMD `net_pcap` trả về 0 mbuf khi file PCAP đã được tiêu thụ hết. Counter liên tiếp bằng không `EOI_THRESHOLD` (mặc định: 100 lần poll liên tiếp) ngăn false positive. Khi phát hiện kết thúc, RX lcore đặt `shutdown_flag = 1` và chờ tất cả lcore downstream hoàn tất drain trước khi trả về.

**Quyền sở hữu mbuf:** RX lcore sở hữu mỗi mbuf từ thời điểm `rte_eth_rx_burst` trả về cho đến khi:
- `rte_ring_enqueue_burst` thành công → quyền sở hữu chuyển sang Parser lcore.
- `rte_pktmbuf_free` được gọi (parser_ring đầy) → mbuf trả về mempool.

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

Hàm hash sử dụng five-tuple đã chuẩn hóa (sau `normalize_flow`) làm input. Cùng một flow (cùng five-tuple) luôn được điều phối về cùng một Worker lcore, đảm bảo flow affinity và warm cache ACL Stage-2 context per-worker. Parser lcore là điểm duy nhất trong pipeline có đủ five-tuple đã parse để thực hiện hash chính xác (DD-14).

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

**Trách nhiệm:** Đọc, phân tích và kiểm tra hợp lệ file cấu hình rule; xây dựng bảng filter-group trong bộ nhớ; gọi `acl_engine` để biên dịch cấu trúc tra cứu ACL.

**Đầu vào:** Chuỗi đường dẫn file từ `spifast_config_t`.

**Đầu ra:** `filter_group_table_t` đã điền và ACL context đã biên dịch (thông qua `acl_engine`). Trả về 0 khi thành công, -1 khi có bất kỳ lỗi nào.

**Xử lý nội bộ — xem Mục 5 để biết ngữ pháp đầy đủ.**

**Giao tiếp:** Gọi `acl_engine_build()` sau khi tất cả rule đã được kiểm tra hợp lệ. Cung cấp `filter_group_table` cho `acl_engine` để giải quyết action.

---

### 2.5 Module ACL Engine (`rule/acl_engine`)

**Trách nhiệm:** Build two-stage ACL structure từ các rule đã kiểm tra hợp lệ; cung cấp batch lookup interface được gọi từ Worker lcore; duy trì per-worker hit counter.

**Đầu vào (giai đoạn build):** Mảng các struct `spi_rule_t`, số lượng, `filter_group_table_t *`.

**Đầu vào (giai đoạn lookup):** Mảng `acl_key_t keys[]`, số lượng `nb`, con trỏ đến kết quả.

**Đầu ra (giai đoạn lookup):** Mảng `uint32_t group_ids[]` (Stage-1) và `acl_result_t results[]` (Stage-2), được gọi từ worker_lcore_func.

**Two-stage build:**

- `acl_engine_build_stage1(rules[], num_rules)`: Build `stage1_ctx` chứa 1 rule đại diện cho mỗi group (tối đa 4096 rules). Stage-1 context nhỏ gọn, fit trong L1/L2 cache của Worker lcore sau warm-up.
- `acl_engine_init_stage2()`: Khởi tạo mảng `group_ctx[SPIFAST_MAX_GROUPS]` = NULL. Stage-2 context được build lazy — chỉ build khi group được hit lần đầu.
- `acl_engine_build_group(group_id, filters[], n)`: Build `group_ctx[group_id]` chứa tối đa `SPIFAST_MAX_FILTERS_PER_GROUP` (2048) filter rules cho group đó. Được gọi từ Main lcore khi group hit lần đầu, không block fast path.

**Xem Mục 4 để biết thiết kế ACL engine đầy đủ bao gồm ACL field definitions, build sequence và batch lookup.**

---

### 2.6 Module Worker (`worker/worker`)

**Trách nhiệm:** Thực thi hàm Worker lcore: dequeue burst mbuf từ `worker_ring`; đọc five-tuple metadata từ mbuf headroom; thực hiện batch two-stage ACL classify; áp dụng hành động FORWARD (enqueue `tx_ring`) hoặc DROP (free mbuf).

**Đầu vào:** `rte_ring *worker_ring`, `rte_ring *tx_ring`, `struct rte_acl_ctx *stage1_ctx`, `struct rte_acl_ctx **group_ctx`, con trỏ đến `worker_lcore_stats_t`.

**Đầu ra:** FORWARD mbufs được enqueue vào `tx_ring`. DROP mbufs được giải phóng về mempool. Counter `worker_lcore_stats_t` đã cập nhật.

**Vòng lặp chính của Worker lcore:**

```
worker_lcore_func(void *arg):
  ctx   = (worker_ctx_t *) arg
  ring  = ctx->worker_ring
  tx    = ctx->tx_ring
  stats = &ctx->stats

  trong khi shutdown_flag chưa được đặt HOẶC ring chưa rỗng:
    nb = rte_ring_dequeue_burst(ring, pkts[], WORKER_BURST_SIZE, NULL)
    nếu nb == 0: tiếp tục

    /* Đọc metadata từ headroom và build key array */
    với mỗi i trong [0, nb):
      meta = (pkt_meta_t *)(rte_pktmbuf_mtod(pkts[i], uint8_t*)
                             - sizeof(pkt_meta_t))
      keys[i].protocol = meta->protocol
      keys[i].src_ip   = meta->src_ip
      keys[i].dst_ip   = meta->dst_ip
      keys[i].src_port = meta->src_port
      keys[i].dst_port = meta->dst_port

    /* Stage-1: Batch ACL classify → xác định group_id */
    rte_acl_classify(ctx->stage1_ctx, keys_ptr, group_results, nb, 1)

    /* Stage-2: Batch ACL classify theo từng group (gộp batch per group) */
    với mỗi i trong [0, nb):
      userdata = group_results[i]
      nếu userdata == 0:
        group_id = default_group_id
      ngược lại:
        group_id = userdata - 1

      /* Lookup stage2 context của group này */
      g_ctx = ctx->group_ctx[group_id]
      nếu g_ctx == NULL:
        /* Group chưa được build — áp dụng default action tạm thời */
        action_results[i] = default_action
        trigger_lazy_build(group_id)   /* báo Main lcore build async */
      ngược lại:
        rte_acl_classify(g_ctx, &keys_ptr[i], &filter_result, 1, 1)
        action_results[i] = filter_group_table.groups[
                              filter_result ? filter_result - 1 : group_id
                            ].action

      stats->hit_count[group_id]++

    /* Áp dụng action */
    nb_tx = 0
    với mỗi i trong [0, nb):
      nếu action_results[i] == ACTION_FORWARD:
        tx_burst[nb_tx++] = pkts[i]
        stats->fwd_packets++
        stats->fwd_bytes += pkts[i]->pkt_len
      ngược lại:
        rte_pktmbuf_free(pkts[i])
        stats->drop_packets++

    /* Enqueue vào tx_ring */
    nếu nb_tx > 0:
      nb_enqueued = rte_ring_enqueue_burst(tx, tx_burst, nb_tx, NULL)
      nếu nb_enqueued < nb_tx:
        với mỗi i trong [nb_enqueued, nb_tx):
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
- Các trường ở dạng host byte order sau khi trích xuất (ngoại trừ `src_ip`/`dst_ip` giữ nguyên network byte order vì ACL engine sử dụng trực tiếp cho prefix matching qua DPDK `rte_acl`).
- Tổng kích thước: 12 bytes. Vừa trong một cache line cùng với các biến cục bộ.

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

    uint32_t precedence;     /* từ khai báo group; thấp hơn = ưu tiên cao hơn */
    uint32_t group_id;       /* chỉ số trong filter_group_table            */
} spi_rule_t;
```

### 3.3 Cấu Trúc Filter Group (`filter_group_t` và `filter_group_table_t`)

```c
typedef enum {
    ACTION_FORWARD = 0,
    ACTION_DROP    = 1
} group_action_t;

typedef struct {
    char          name[SPIFAST_GROUP_NAME_LEN];
    group_action_t action;
    uint32_t      precedence;   /* số nguyên precedence nhỏ nhất trong các rule
                                   thuộc group này (dùng để tie-breaking)    */
    uint32_t      group_id;     /* chỉ số trong bảng; cũng dùng làm ACL userdata */
} filter_group_t;

#define SPIFAST_MAX_GROUPS  4096

typedef struct {
    filter_group_t groups[SPIFAST_MAX_GROUPS];
    uint32_t       num_groups;
} filter_group_table_t;
```

**Mã hóa ACL userdata:** ACL engine lưu `group_id + 1` làm trường `userdata` trong mỗi mục ACL rule. Kết quả lookup bằng `0` nghĩa là không khớp (hành vi ACL mặc định); khác không nghĩa là `group_id = result - 1`. Cách này tránh nhầm lẫn giữa "không khớp" và group index 0.

### 3.4 Cấu Trúc Kết Quả Tra Cứu ACL (`acl_result_t`)

```c
typedef struct {
    uint32_t       group_id;   /* chỉ số trong filter_group_table              */
    group_action_t action;     /* ACTION_FORWARD hoặc ACTION_DROP              */
    uint32_t       rule_id;    /* chỉ số rule nội bộ ACL để đếm lượt khớp     */
} acl_result_t;
```

### 3.5 Cấu Trúc Counter Thống Kê Per-lcore

Tồn tại bốn cấu trúc counter riêng biệt tương ứng với bốn loại data path lcore. Tất cả được khai báo với padding cache-line để ngăn false sharing.

```c
#define CACHE_LINE_SIZE  64

/* RX lcore — chỉ poll và enqueue parser_ring */
typedef struct {
    uint64_t rx_packets;          /* tổng mbuf nhận được từ PMD              */
    uint64_t parser_ring_drop;    /* mbuf bị hủy do parser_ring đầy          */
    uint8_t  _pad[CACHE_LINE_SIZE
                  - (2 * sizeof(uint64_t)) % CACHE_LINE_SIZE];
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
    uint64_t fwd_packets;         /* mbuf được enqueue vào tx_ring           */
    uint64_t fwd_bytes;           /* byte của gói tin được forward (pkt_len) */
    uint64_t drop_packets;        /* mbuf bị hủy bởi hành động rule DROP     */
    uint64_t tx_ring_drop;        /* mbuf bị hủy do tx_ring đầy              */
    uint64_t hit_count[SPIFAST_MAX_GROUPS]; /* per-group match count         */
    uint8_t  _pad[CACHE_LINE_SIZE
                  - (4 * sizeof(uint64_t)) % CACHE_LINE_SIZE];
} __rte_cache_aligned worker_lcore_stats_t;

/* TX lcore — drain tx_ring, rte_eth_tx_burst */
typedef struct {
    uint64_t tx_packets;          /* mbuf đã truyền ra NIC TX thành công     */
    uint64_t tx_bytes;            /* byte đã truyền ra NIC TX                */
    uint64_t tx_drop_packets;     /* mbuf bị hủy do TX queue đầy             */
    uint8_t  _pad[CACHE_LINE_SIZE
                  - (3 * sizeof(uint64_t)) % CACHE_LINE_SIZE];
} __rte_cache_aligned tx_lcore_stats_t;
```

**Hit counter per-worker:** Mỗi Worker lcore duy trì `hit_count[SPIFAST_MAX_GROUPS]` riêng trong `worker_lcore_stats_t`. Không chia sẻ array giữa các Worker, không cần atomic operation. Stats module aggregate tất cả per-worker arrays theo chu kỳ.

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

### 4.1 Lý Do Thiết Kế — DPDK `rte_acl` Two-Stage

ACL engine được xây dựng trên thư viện `librte_acl` của DPDK theo mô hình two-stage để đáp ứng quy mô 4096 group × 2048 filter/group mà không làm một ACL context đơn khổng lồ không fit cache.

- **Stage-1 context (`stage1_ctx`):** Chứa tối đa 4096 rule đại diện (1 rule/group). Nhỏ gọn, fit trong L1/L2 cache của Worker lcore sau warm-up. Lookup Stage-1 xác định `group_id` cho gói tin.
- **Stage-2 context (`group_ctx[group_id]`):** Mỗi group có một `rte_acl_ctx` riêng chứa tối đa 2048 filter rules. Được build lazy khi group được hit lần đầu. Fit trong L1 cache khi đang active. Lookup Stage-2 xác định filter cụ thể và action trong group.

Cả hai stage đều sử dụng batch `rte_acl_classify` được gọi từ Worker lcore, không phải từ RX lcore.

### 4.2 Định Nghĩa Trường ACL

Bố cục key và `rte_acl_field_def` giống nhau cho cả Stage-1 và Stage-2:

```
Bố cục Key (13 bytes tổng, được căn chỉnh đến 16 bytes):

Offset  Kích thước  Trường
------  ----------  ------
  0        1        protocol   (IP protocol number: 6=TCP, 17=UDP, 0=wildcard)
  1        4        src_ip     (IPv4, network byte order)
  5        4        dst_ip     (IPv4, network byte order)
  9        2        src_port   (host byte order)
 11        2        dst_port   (host byte order)
 13        3        padding
```

```c
static const struct rte_acl_field_def spifast_acl_fields[] = {
    /* Trường 0: protocol — byte range */
    {
        .type        = RTE_ACL_FIELD_TYPE_BITMASK,
        .size        = sizeof(uint8_t),
        .field_index = 0,
        .input_index = 0,
        .offset      = offsetof(acl_key_t, protocol),
    },
    /* Trường 1: source IPv4 — prefix match */
    {
        .type        = RTE_ACL_FIELD_TYPE_MASK,
        .size        = sizeof(uint32_t),
        .field_index = 1,
        .input_index = 1,
        .offset      = offsetof(acl_key_t, src_ip),
    },
    /* Trường 2: destination IPv4 — prefix match */
    {
        .type        = RTE_ACL_FIELD_TYPE_MASK,
        .size        = sizeof(uint32_t),
        .field_index = 2,
        .input_index = 2,
        .offset      = offsetof(acl_key_t, dst_ip),
    },
    /* Trường 3: source port — range match */
    {
        .type        = RTE_ACL_FIELD_TYPE_RANGE,
        .size        = sizeof(uint16_t),
        .field_index = 3,
        .input_index = 3,
        .offset      = offsetof(acl_key_t, src_port),
    },
    /* Trường 4: destination port — range match */
    {
        .type        = RTE_ACL_FIELD_TYPE_RANGE,
        .size        = sizeof(uint16_t),
        .field_index = 4,
        .input_index = 4,
        .offset      = offsetof(acl_key_t, dst_port),
    },
};
```

**Mã hóa wildcard:**
- Protocol wildcard (`any`): mask = 0x00 với value 0x00 (khớp với bất kỳ byte value nào).
- IP wildcard (`any`): prefix length 0 → khớp với tất cả IP.
- Port wildcard (`any`): range [0, 65535].
- Khớp chính xác IP host: prefix length 32.
- Khớp chính xác port: range [port, port].

### 4.3 Trình Tự Build Bảng ACL Two-Stage

```
acl_engine_build_stage1(rules[], num_rules, filter_group_table):
  /* Mỗi group đóng góp đúng 1 rule đại diện vào Stage-1 */

  1. ctx = rte_acl_create("spifast_stage1")
     acl_param.max_rule_num = SPIFAST_MAX_GROUPS   /* tối đa 4096 */

  2. Với mỗi group g trong filter_group_table:
       Lấy rule đại diện của group g (rule có precedence thấp nhất trong group)
       Điền fields và masks từ rule đó
       data.userdata = g.group_id + 1
       data.priority = UINT32_MAX - g.precedence
       rte_acl_add_rules(ctx, &acl_rule, 1)

  3. rte_acl_build(ctx, &cfg)
  4. stage1_ctx = ctx
  5. Trả về 0 khi thành công; -1 khi có lỗi rte_acl.

acl_engine_init_stage2():
  /* Khởi tạo tất cả group_ctx[] = NULL (lazy build) */
  memset(group_ctx, 0, sizeof(group_ctx))
  Khởi tạo per-worker hit_count[] = 0

acl_engine_build_group(group_id, filters[], n_filters):
  /* Được gọi từ Main lcore khi group được hit lần đầu */
  1. ctx = rte_acl_create("spifast_group_%u", group_id)
     acl_param.max_rule_num = SPIFAST_MAX_FILTERS_PER_GROUP   /* 2048 */

  2. Với mỗi filter f trong filters[]:
       Điền fields và masks từ f
       data.userdata = f.filter_id + 1
       data.priority = UINT32_MAX - f.precedence
       rte_acl_add_rules(ctx, &acl_rule, 1)

  3. Thêm default filter (wildcard, priority thấp nhất)
  4. rte_acl_build(ctx, &cfg)
  5. atomic_store(group_ctx[group_id], ctx)   /* Worker đọc ngay sau đó */
  6. Trả về 0 khi thành công; -1 khi có lỗi rte_acl.
```

### 4.4 Batch ACL Lookup Trong Worker Lcore

ACL lookup không còn thực hiện theo từng gói tin riêng lẻ trên RX lcore. Thay vào đó, Worker lcore gọi `rte_acl_classify` theo batch cho cả hai stage sau khi dequeue toàn bộ burst:

```
/* Stage-1 batch: xác định group_id cho tất cả packet trong burst */
keys_ptr[nb] = array of (const uint8_t*) trỏ vào keys[]
rte_acl_classify(stage1_ctx, keys_ptr, group_results, nb, 1)
/* group_results[i] = group_id + 1, hoặc 0 nếu không khớp → default group */

/* Stage-2: với mỗi packet, lookup group_ctx của group đã xác định */
nếu group_ctx[group_id] != NULL:
  rte_acl_classify(group_ctx[group_id], &keys_ptr[i], &filter_result, 1, 1)
  action = filter_group_table.groups[filter_result ? filter_result-1 : group_id].action
ngược lại:
  action = default_action   /* group chưa build, áp dụng default tạm thời */
  trigger_lazy_build(group_id)
```

Batch classify với n=32 cho phép CPU prefetch và SIMD pipeline che giấu cache miss latency của ACL structure — đặc biệt quan trọng với 64-byte frames có budget per-packet rất nhỏ.

### 4.5 Xử Lý Priority

`rte_acl` chọn rule khớp có giá trị `data.priority` cao nhất khi nhiều rule khớp. SPIFast ánh xạ `precedence` (thấp hơn = ưu tiên cao hơn) sang priority của `rte_acl`:

```
acl_priority = UINT32_MAX - rule.precedence
```

**Chế độ first-match vs. best-match (FR-016):**

- **Chế độ Best-match:** Sử dụng `rte_acl_classify` trực tiếp. Thư viện ACL trả về kết quả khớp priority cao nhất theo thiết kế.
- **Chế độ First-match:** Sắp xếp các rule theo `precedence` tăng dần trước khi gọi `rte_acl_add_rules`, gán priority tăng dần nghiêm ngặt để xấp xỉ first-match semantics.

Chế độ khớp được chọn khi khởi động qua `--mode` và không thay đổi trong runtime.

### 4.6 Xử Lý Rule Mặc Định

Rule loader kiểm tra rằng rule DEFAULT group tồn tại (FR-017). Default rule được thêm vào Stage-1 context với `precedence` cao nhất và key toàn wildcard:

```
protocol = ANY (mask 0x00)
src_ip   = 0.0.0.0/0
dst_ip   = 0.0.0.0/0
src_port = [0, 65535]
dst_port = [0, 65535]
```

Điều này đảm bảo mọi gói tin đến Stage-1 lookup đều trả về `userdata` khác không, bảo đảm FR-023.

### 4.7 Đếm Lượt Khớp Rule

Hit counter được duy trì per-worker trong `worker_lcore_stats_t.hit_count[group_id]`. Mỗi Worker lcore chỉ ghi vào array của chính nó — không có tranh chấp, không cần atomic operation. Stats module aggregate tất cả per-worker `hit_count[]` arrays theo chu kỳ 1 giây từ Main lcore.

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
[group: DEFAULT]             precedence=999  action=DROP
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
[group: DEFAULT]             precedence=999  action=DROP

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
rule_loader_load(path, config, group_table, rules[], &num_rules):

  Bước 1 — Mở file
    fp = fopen(path, "r")
    nếu fp == NULL:  LOG_ERROR("Cannot open rule file: %s", path); return -1

  Bước 2 — Phân tích từng dòng
    line_no = 0
    với mỗi dòng trong file:
      line_no++
      xóa khoảng trắng đầu/cuối
      nếu dòng trống hoặc bắt đầu bằng '#':  tiếp tục

      nếu dòng bắt đầu bằng '[group:':
        parse_group_declaration(line, line_no, group_table)
        /* Kiểm tra: độ dài tên, tính duy nhất, phạm vi precedence [1..999],
           action là FORWARD hoặc DROP */
        khi lỗi: LOG_ERROR(line_no, reason); fclose(fp); return -1

      ngược lại:
        parse_rule_entry(line, line_no, rules[], group_table)
        /* Kiểm tra các trường theo Mục 5.3 */
        khi lỗi: LOG_ERROR(line_no, reason); fclose(fp); return -1

      nếu num_groups > SPIFAST_MAX_GROUPS (4096):
        LOG_ERROR("Group count exceeds maximum (4096)"); return -1

      nếu filter_count_in_group > SPIFAST_MAX_FILTERS_PER_GROUP (2048):
        LOG_ERROR("Filter count in group exceeds maximum (2048)"); return -1

  Bước 3 — Kiểm tra sau khi phân tích
    kiểm tra: num_rules >= 1
    kiểm tra: DEFAULT group tồn tại (group có precedence cao nhất)
    kiểm tra: không có tên rule trùng lặp
    khi có bất kỳ lỗi nào: return -1

  Bước 4 — Build bảng ACL
    rc = acl_engine_build(rules[], num_rules, group_table)
    nếu rc != 0:  return -1

  Bước 5 — Ghi log các rule đã nạp
    log_startup_rules(group_table, rules[], num_rules)

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
| Số lượng filter-group | Tổng số group ≤ 4096 |
| Số lượng filter mỗi group | Số filter trong một group ≤ 2048 |

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

RX lcore thực hiện các bước sau theo từng burst:

1. Nhận mbuf qua `rte_eth_rx_burst`.
2. Thực hiện lightweight hash (placeholder cho future multi-parser scale).
3. Gọi `rte_ring_enqueue_burst(parser_ring, pkts, nb_rx)`.
4. Xử lý parser_ring đầy: free mbuf, tăng `parser_ring_drop`.
5. Cập nhật `rx_lcore_stats.rx_packets`.

RX lcore không gọi bất kỳ hàm I/O nào, `malloc`, `free`, `printf`, hoặc blocking system call.

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
3. Build `keys[]` từ five-tuple metadata.
4. Batch Stage-1 ACL classify: `rte_acl_classify(stage1_ctx, ...)` → `group_ids[]`.
5. Per-packet Stage-2 ACL classify: `rte_acl_classify(group_ctx[group_id], ...)` → action.
6. FORWARD → `rte_ring_enqueue(tx_ring, mbuf)`.
7. DROP → `rte_pktmbuf_free(mbuf)`.
8. Cập nhật `worker_lcore_stats[i]` (fwd, drop, hit_count).

Worker không bao giờ gọi `rte_eth_tx_burst()` trực tiếp.

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
| `shutdown_flag` | RX lcore (người ghi) | Parser, Worker, TX (người đọc) | `volatile int`; single writer; platform memory model đủ |
| `stage1_ctx` | rule_loader (build, một lần) | Worker lcore × N (read-only) | Không cần đồng bộ sau khi `rte_acl_build` hoàn tất trước khi lcore khởi chạy |
| `group_ctx[g]` | Main lcore (lazy build) | Worker lcore × N (read) | `atomic_store` / `atomic_load`; Worker đọc NULL → dùng default; Main ghi ctx mới |
| `filter_group_table` | rule_loader (init, một lần) | Worker lcore (read-only) | Không cần đồng bộ; được build trước khi lcore khởi chạy |

### 6.9 Xem Xét Thứ Tự Gói Tin

Không có đảm bảo thứ tự gói tin trên các Worker lcore. Hash dispatch tại Parser đảm bảo cùng flow đến cùng Worker (flow affinity), nhưng không đảm bảo thứ tự global giữa các flow khác nhau. Trong mỗi `worker_ring[i]`, gói tin được xử lý theo thứ tự FIFO. Tổng hợp thống kê không phụ thuộc thứ tự; tất cả counter đều có tính cộng dồn.

---

## 7. Thiết Kế Tài Nguyên DPDK

### 7.1 Thiết Kế Mempool

Một `rte_mempool` duy nhất được tạo và dùng chung trên tất cả lcore.

| Tham số | Giá trị | Lý do |
|---|---|---|
| `nb_mbufs` | `SPIFAST_MEMPOOL_SIZE` = 8192 | Phải vượt số mbuf đang in-flight tối đa: `BURST_SIZE + num_workers × (RING_SIZE + WORKER_BURST_SIZE)`. 8192 cung cấp headroom thoải mái cho đến 4 worker với kích thước ring mặc định. |
| `cache_size` | 256 | Cache mbuf per-lcore. Giảm tranh chấp mempool khi alloc/free. DPDK khuyến nghị `cache_size < nb_mbufs/1.5` và là lũy thừa của hai. |
| `priv_size` | 0 | Không cần vùng dữ liệu mbuf private. |
| `data_room_size` | `RTE_MBUF_DEFAULT_BUF_SIZE` (2176 bytes) | Đủ cho Ethernet MTU tiêu chuẩn (1518 bytes) cộng headroom. |
| `socket_id` | `SOCKET_ID_ANY` | Triển khai single-socket; tối ưu NUMA được trì hoãn đến phần mở rộng hỗ trợ NIC. |

`SPIFAST_MEMPOOL_SIZE` là hằng số compile-time trong `dpdk_init.h`. Có thể override qua `make CFLAGS="-DSPIFAST_MEMPOOL_SIZE=16384"` để kiểm thử với tải cao hơn.

### 7.2 Kích Thước RX Burst

| Tham số | Giá trị | Lý do |
|---|---|---|
| `BURST_SIZE` | 32 | Kích thước DPDK burst tiêu chuẩn. Cân bằng giữa khấu hao overhead per-packet và cache locality. Có thể cấu hình tại compile time. |
| `RX_DESC_DEFAULT` | 512 | Số lượng RX descriptor trong hardware ring của PMD. Phải ≥ `BURST_SIZE`. |
| `EOI_THRESHOLD` | 100 | Số lần poll burst trống liên tiếp trước khi tuyên bố kết thúc PCAP. |

### 7.3 Cấu Hình Ring — Ba Tầng

**Tầng 1: parser_ring (RX → Parser, SPSC)**

| Tham số | Giá trị | Lý do |
|---|---|---|
| `PARSER_RING_SIZE` | 1024 | Lũy thừa của hai. Buffer cho burst imbalance giữa RX và Parser. |
| `RING_F_SP_ENQ` | Đặt | Single producer (RX lcore) → không có MP enqueue overhead. |
| `RING_F_SC_DEQ` | Đặt | Single consumer (Parser lcore) → không có MC dequeue overhead. |

**Tầng 2: worker_ring[i] (Parser → Worker i, SPSC)**

| Tham số | Giá trị | Lý do |
|---|---|---|
| `RING_SIZE` | 1024 | Lũy thừa của hai. Buffer cho hash imbalance giữa Parser và Worker. |
| `RING_F_SP_ENQ` | Đặt | Single producer (Parser lcore) → lock-free tối ưu. |
| `RING_F_SC_DEQ` | Đặt | Single consumer (Worker lcore i riêng biệt) → lock-free tối ưu. |
| `WORKER_BURST_SIZE` | 32 | Kích thước dequeue burst để batch ACL classify. |

**Tầng 3: tx_ring (Worker → TX, MPSC)**

| Tham số | Giá trị | Lý do |
|---|---|---|
| `TX_RING_SIZE` | 4096 | Lớn hơn worker_ring vì N Worker enqueue đồng thời vào 1 ring. |
| `RING_F_MP_ENQ` | Đặt | Multi-producer (tất cả N Worker lcore enqueue đồng thời) — bắt buộc. |
| `RING_F_SC_DEQ` | Đặt | Single consumer (TX lcore) → lock-free dequeue. |
| `TX_BURST_SIZE` | 32 | Kích thước dequeue burst của TX lcore. |

**Xử lý ring đầy:** Mọi ring overflow đều dẫn đến free mbuf ngay lập tức và tăng counter tương ứng (`parser_ring_drop`, `worker_ring_drop`, `tx_ring_drop`). Kích thước ring phải đảm bảo tỷ lệ drop tổng cộng ≤ 0,1% (PR-005).

### 7.4 Tóm Tắt Bố Cục Bộ Nhớ

```
Hugepage memory (được EAL cấp phát khi khởi động)
│
├── rte_mempool (8192 mbufs × 2176 bytes ≈ 17 MB)
│    └── cache per-lcore (256 entry mỗi cái)
│
├── parser_ring  (1024 × 8 bytes = 8 KB, SPSC)
├── worker_ring[0]  (1024 × 8 bytes = 8 KB, SPSC)
├── worker_ring[1]  ...
├── worker_ring[N-1]
├── tx_ring      (4096 × 8 bytes = 32 KB, MPSC)
│
├── stage1_ctx   (rte_acl context, tối đa 4096 group rules, ~vài MB)
│
└── group_ctx[0..4095]  (lazy built, mỗi ctx ≤ 2048 filter rules, ~10-20 KB)
     ├── group_ctx[0]   → built khi group 0 được hit lần đầu
     ├── group_ctx[1]   → NULL (chưa build)
     └── ...
```

Tất cả cấu trúc được DPDK quản lý đều nằm trong hugepage memory. `group_ctx[]` lazy build từ hugepage thông qua `rte_acl_create` trên Main lcore.

### 7.5 Tham Số Tài Nguyên Có Thể Cấu Hình

Các hằng số compile-time sau được định nghĩa trong `src/dpdk/dpdk_init.h` và có thể được override tại build time:

```c
#define SPIFAST_MEMPOOL_SIZE              8192
#define SPIFAST_MEMPOOL_CACHE             256
#define SPIFAST_BURST_SIZE                32
#define SPIFAST_RX_DESC                   512
#define SPIFAST_TX_DESC                   512
#define SPIFAST_PARSER_RING_SIZE          1024
#define SPIFAST_RING_SIZE                 1024   /* worker_ring per worker */
#define SPIFAST_TX_RING_SIZE              4096
#define SPIFAST_WORKER_BURST              32
#define SPIFAST_TX_BURST_SIZE             32
#define SPIFAST_EOI_THRESHOLD             100
#define SPIFAST_PREFETCH_AHEAD            4
#define SPIFAST_MAX_GROUPS                4096
#define SPIFAST_MAX_FILTERS_PER_GROUP     2048
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
  cur.total_parser_ring_drop = rx_stats.parser_ring_drop

  /* Tổng hợp counter Parser lcore */
  cur.total_parsed_pkts      = parser_stats.parsed_packets
  cur.total_invalid_pkts     = parser_stats.invalid_packets
  cur.total_worker_ring_drop = parser_stats.worker_ring_drop

  /* Tổng hợp counter tất cả Worker lcore */
  cur.total_fwd_pkts  = 0
  cur.total_drop_pkts = 0
  cur.total_bytes     = 0
  memset(cur.group_hits, 0, sizeof(cur.group_hits))

  với mỗi i trong [0, num_workers):
    cur.total_fwd_pkts  += worker_stats[i].fwd_packets
    cur.total_drop_pkts += worker_stats[i].drop_packets
    cur.total_bytes     += worker_stats[i].fwd_bytes
    cur.total_tx_ring_drop += worker_stats[i].tx_ring_drop
    /* Aggregate per-group hit counts từ tất cả Worker */
    với mỗi g trong [0, num_groups):
      cur.group_hits[g] += worker_stats[i].hit_count[g]

  /* Tổng hợp counter TX lcore */
  cur.total_tx_pkts      = tx_stats.tx_packets
  cur.total_tx_drop_pkts = tx_stats.tx_drop_packets

  /* Delta theo chu kỳ */
  snap.interval_sec      = (double)(now_cycles - prev_cycles) / hz
  snap.interval_rx_pkts  = cur.total_rx_pkts  - prev.total_rx_pkts
  snap.interval_fwd_pkts = cur.total_fwd_pkts - prev.total_fwd_pkts
  snap.interval_fwd_bytes= cur.total_bytes    - prev.total_bytes

  /* Throughput và PPS */
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

```
validate_packet_accounting(final_snap):
  accounted = final_snap.total_fwd_pkts
            + final_snap.total_drop_pkts
            + final_snap.total_invalid_pkts
            + final_snap.total_parser_ring_drop
            + final_snap.total_worker_ring_drop
            + final_snap.total_tx_drop_pkts

  nếu accounted == final_snap.total_rx_pkts:
    log_info("Packet accounting: PASS — zero unaccounted packets")
  ngược lại:
    lost = final_snap.total_rx_pkts - accounted
    log_error("Packet accounting: FAIL — %lu unaccounted packets", lost)
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
[2025-06-26T14:32:05+0700] elapsed=10s  rx=500000  parsed=499800  fwd=489800  drop=9800  inv=200  p_ring_drop=0  w_ring_drop=0  tx=489800  tx_drop=0  mbps=823.40  pps=489800  | fg_l34_facebook=120000 fg_l34_youtube=85000 fg_l34_http_sdf1003=200000 fg_l34_dns_sdf1005=85000 DEFAULT=9800
```

Định nghĩa trường:

| Token | Trường | Đơn vị |
|---|---|---|
| `[timestamp]` | Thời gian địa phương ISO 8601 | — |
| `elapsed=Ns` | Giây kể từ gói tin đầu tiên | giây |
| `rx=N` | Gói tin RX lũy kế | gói tin |
| `parsed=N` | Gói tin đã parse thành công lũy kế | gói tin |
| `fwd=N` | Gói tin được forward lũy kế (enqueue tx_ring) | gói tin |
| `drop=N` | Gói tin bị DROP theo rule lũy kế | gói tin |
| `inv=N` | Gói tin không hợp lệ lũy kế | gói tin |
| `p_ring_drop=N` | Gói tin bị hủy do parser_ring overflow lũy kế | gói tin |
| `w_ring_drop=N` | Gói tin bị hủy do worker_ring overflow lũy kế | gói tin |
| `tx=N` | Gói tin đã truyền ra NIC TX lũy kế | gói tin |
| `tx_drop=N` | Gói tin bị hủy do TX queue đầy lũy kế | gói tin |
| `mbps=F` | Throughput theo chu kỳ | Mbps (2 chữ số thập phân) |
| `pps=N` | PPS theo chu kỳ | gói tin/giây |
| `\| group=N ...` | Hit lũy kế per-group (aggregate từ tất cả Worker) | gói tin |

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
[2025-06-26T14:32:15+0700] SUMMARY  elapsed=15s  total_rx=750000  total_parsed=749700  total_fwd=734700  total_drop=14700  total_inv=300  total_p_ring_drop=0  total_w_ring_drop=0  total_tx=734700  total_tx_drop=0
[2025-06-26T14:32:15+0700] THROUGHPUT_AVG  mbps=817.33
[2025-06-26T14:32:15+0700] PPS_AVG  pps=489800
[2025-06-26T14:32:15+0700] GROUP_HITS  fg_l34_facebook=180000 fg_l34_youtube=127500 fg_l34_http_sdf1003=300000 fg_l34_dns_sdf1005=127500 DEFAULT=14700
[2025-06-26T14:32:15+0700] PACKET_ACCOUNTING  rx=750000  accounted=750000  lost=0  result=PASS
```

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
| Số lượng filter trong group > 2048 | `rule_loader_load` | Ghi log lỗi kèm tên group và số lượng; `return -1` |
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
| ACL không khớp Stage-1 | `acl_engine` (trong worker) | Áp dụng hành động DEFAULT group | `hit_count[default_group]` |
| Stage-2 ctx chưa build (NULL) | `worker` (group_ctx lookup) | Áp dụng default action tạm thời; trigger lazy build | `hit_count[default_group]` |

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
[SPIFAST ERROR] rule_loader: no DEFAULT group defined. Add '[group: DEFAULT] precedence=999 action=DROP'.
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

### Giai đoạn 4 — Rule Loader và Two-Stage ACL Engine

**Mục tiêu:** Nạp rule và build two-stage ACL structure.

16. Triển khai `rule/rule_loader.c`: parser file, validator (≤4096 group, ≤2048 filter/group), builder bảng group.
17. Unit test rule loader: kiểm tra tất cả trường hợp kiểm tra hợp lệ bao gồm giới hạn group và filter.
18. Triển khai `rule/acl_engine.c`: `acl_engine_build_stage1`, `acl_engine_init_stage2`, `acl_engine_build_group` (lazy).
19. Unit test ACL engine: stage1 classify đúng group_id; stage2 classify đúng action.

### Giai đoạn 5 — Worker lcore với Batch Two-Stage ACL

**Mục tiêu:** Hoàn thành pipeline Worker với batch ACL classify và tx_ring enqueue.

20. Triển khai `worker/worker.c` với `worker_lcore_func`: dequeue, đọc headroom, batch Stage-1 classify, per-packet Stage-2 classify, FORWARD → `tx_ring`, DROP → free.
21. Triển khai stub TX lcore: chỉ dequeue từ `tx_ring` rồi free mbuf ngay; đếm counter.
22. Khởi chạy toàn bộ pipeline: RX → Parser → Worker → TX (stub).
23. Kiểm tra: tổng `worker_stats[i].fwd_packets` khớp số FORWARD packet dự kiến. Không có mbuf leak.
24. Kiểm tra với PCAP tham chiếu: mọi gói tin được phân loại vào group mong đợi (RC-004).

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

40. Kiểm thử từng đường lỗi khởi động: file thiếu, cú pháp sai, >4096 group, >2048 filter/group, không có DEFAULT, IP sai, port range sai. Xác nhận thông báo lỗi đúng format.
41. Kiểm thử lỗi đường dẫn file log: xác nhận cảnh báo trên stderr; xử lý tiếp tục.
42. Kiểm thử ring overflow bằng cách giảm ring size để kích hoạt `p_ring_drop` và `w_ring_drop`.
43. Kiểm thử với PCAP chứa frame không phải IPv4: xác nhận `invalid_packets` tăng; không crash.
44. Kiểm thử với frame bị lỗi (header bị cắt ngắn): xác nhận xử lý graceful; không crash.

---

*Kết thúc tài liệu — SPIFAST-SDD-001-VI v1.1*
