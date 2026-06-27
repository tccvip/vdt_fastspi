# Thiết Kế Chi Tiết Phần Mềm

---

**Tiêu đề tài liệu:** Thiết Kế Chi Tiết Phần Mềm — SPIFast: Hệ Thống Kiểm Tra Gói Tin Hiệu Năng Cao Sử Dụng DPDK

**Mã tài liệu:** SPIFAST-SDD-001

**Phiên bản:** 1.0

**Trạng thái:** Draft

**Người soạn thảo:** Nhóm Kỹ Thuật Hệ Thống

**Ngày:** 2025-06-26

**HLD áp dụng:** SPIFAST-HLD-001 v1.1

**SRS áp dụng:** SPIFAST-SRS-001 v1.0

**Phiên bản DPDK mục tiêu:** 23.11 LTS (tối thiểu 21.11 LTS)

**Công cụ build:** GCC 10+, GNU Make hoặc CMake 3.16+, Linux kernel 5.4+

---

## Lịch Sử Sửa Đổi

| Phiên bản | Ngày | Tác giả | Mô tả |
|---|---|---|---|
| 0.1 | 2025-06-26 | Kỹ thuật hệ thống | Bản thảo SDD ban đầu |
| 1.0 | 2025-06-26 | Kỹ thuật hệ thống | Baseline SDD căn chỉnh với HLD v1.1 và SRS v1.0 |

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

HLD định nghĩa sáu thành phần xử lý. Mỗi thành phần ánh xạ trực tiếp sang một module phần mềm trong cây thư mục `src/`. Điểm vào `main` đóng vai trò bộ điều phối (orchestrator) khởi tạo tất cả module theo thứ tự phụ thuộc và khởi chạy các DPDK lcore.

```
spifast/
├── Makefile               # File build cấp cao nhất (hoặc CMakeLists.txt)
├── config/
│   └── spi_rules.conf     # File cấu hình rule tham chiếu
├── src/
│   ├── main.c             # Điểm vào: phân tích tham số, trình tự khởi tạo, khởi chạy lcore
│   ├── dpdk/
│   │   ├── dpdk_init.c    # EAL init, mempool, port, tạo ring
│   │   └── dpdk_init.h
│   ├── packet/
│   │   ├── rx.c           # Vòng lặp RX burst, phát hiện kết thúc PCAP
│   │   ├── rx.h
│   │   ├── parser.c       # Phân tích Ethernet/VLAN/IPv4/TCP/UDP, chuẩn hóa luồng
│   │   └── parser.h
│   ├── rule/
│   │   ├── rule_loader.c  # Phân tích file rule, kiểm tra hợp lệ, bảng filter-group
│   │   ├── rule_loader.h
│   │   ├── acl_engine.c   # Build bảng ACL, lookup, đếm lượt khớp
│   │   └── acl_engine.h
│   ├── worker/
│   │   ├── worker.c       # Hàm worker lcore: drain ring, hạch toán, giải phóng mbuf
│   │   └── worker.h
│   ├── stats/
│   │   ├── stats.c        # Tổng hợp counter per-lcore, tính Mbps/PPS
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
| `dpdk/dpdk_init` | Khởi tạo DPDK | EAL init; cấp phát mempool; cấu hình virtual port net_pcap; tạo ring |
| `packet/rx` | Nhận gói tin | Vòng lặp RX burst poll-mode; phát hiện kết thúc PCAP; tín hiệu tắt máy |
| `packet/parser` | Packet Parser | Giải mã header L2–L4; trích xuất five-tuple; chuẩn hóa luồng hai chiều |
| `rule/rule_loader` | ACL Rule Engine (giai đoạn nạp) | Phân tích file rule; kiểm tra hợp lệ trường; xây dựng bảng filter-group |
| `rule/acl_engine` | ACL Rule Engine (giai đoạn lookup) | Build cấu trúc ACL; lookup theo từng gói tin; thực thi precedence; đếm lượt khớp |
| `worker/worker` | Worker Core | Drain ring; hạch toán byte/gói tin theo từng gói; giải phóng mbuf về mempool |
| `stats/stats` | Statistics Component | Tổng hợp counter lock-free từ tất cả lcore; tính Mbps và PPS |
| `logging/log` | Logging Component | Xuất log định kỳ và cuối phiên ra stdout và file log tùy chọn; quản lý dual-output |

### 1.3 Đồ Thị Phụ Thuộc Liên Module

```
main
 ├── dpdk_init        (gọi đầu tiên; tất cả module phụ thuộc DPDK đã sẵn sàng)
 ├── rule_loader      (gọi sau EAL; tạo ra bảng rule)
 │    └── acl_engine  (được rule_loader gọi để build cấu trúc ACL)
 ├── log              (mở sau khi config đã biết)
 ├── rx               (khởi chạy trên RX lcore; gọi parser và acl_engine inline)
 │    ├── parser
 │    └── acl_engine  (chỉ lookup; read-only sau khi build)
 ├── worker           (khởi chạy trên N worker lcore; drain ring)
 └── stats            (chạy trên timer của main lcore; đọc tất cả counter per-lcore)
      └── log         (stats kích hoạt xuất log)
```

---

## 2. Thiết Kế Chi Tiết Module

### 2.1 Module Khởi Tạo DPDK (`dpdk/dpdk_init`)

**Trách nhiệm:** Đưa môi trường runtime DPDK vào trạng thái hoạt động đầy đủ trước khi bắt đầu bất kỳ quá trình xử lý gói tin nào.

**Đầu vào:** Cấu hình ứng dụng đã phân tích (`spifast_config_t`), bao gồm số lượng worker và đường dẫn file PCAP.

**Đầu ra:** Các tài nguyên toàn cục đã khởi tạo: `rte_mempool`, `uint16_t port_id`, `rte_ring *worker_rings[]`, phân công vai trò lcore.

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

3. Cấu hình net_pcap virtual device
   - Build chuỗi tham số thiết bị:
       "eth_pcap0,rx_pcap=<pcap_path>"
   - rte_eal_hotplug_add("vdev", "net_pcap0", devargs)
   - rte_eth_dev_get_port_by_name("net_pcap0", &port_id)
   - Cấu hình port: 1 RX queue, 0 TX queue.
   - rte_eth_dev_configure(port_id, 1, 0, &port_conf)
   - rte_eth_rx_queue_setup(port_id, 0, RX_DESC_DEFAULT,
                             socket_id, NULL, mempool)
   - rte_eth_dev_start(port_id)
   - Khi có bất kỳ lỗi nào: lỗi fatal.

4. Tạo worker ring
   - Với mỗi worker index i trong [0, num_workers):
       worker_rings[i] = rte_ring_create(name, RING_SIZE,
                                          SOCKET_ID_ANY,
                                          RING_F_SP_ENQ | RING_F_SC_DEQ)
   - RING_F_SP_ENQ: single producer (chỉ classifier lcore).
   - RING_F_SC_DEQ: single consumer (worker lcore được dành riêng).
   - Khi thất bại: lỗi fatal.

5. Phân công vai trò lcore
   - main lcore  = rte_get_main_lcore()  → stats + logging + tắt máy
   - rx lcore    = lcore có sẵn đầu tiên sau main
   - worker lcore = num_workers lcore có sẵn tiếp theo
   - Kiểm tra tổng lcore yêu cầu ≤ rte_lcore_count().
```

**Giao tiếp với các module khác:**
- Truyền con trỏ `mempool` cho module `rx`.
- Truyền `port_id` cho module `rx`.
- Truyền mảng `worker_rings[]` cho cả `rx` (phía enqueue) và `worker` (phía dequeue).
- Truyền lcore ID cho `main` để khởi chạy lcore.

---

### 2.2 Module Nhận Gói Tin (`packet/rx`)

**Trách nhiệm:** Liên tục poll virtual port net_pcap ở chế độ burst; chuyển các mbuf đã nhận đến pipeline parser/classifier; phát hiện kết thúc PCAP và phát tín hiệu tắt máy.

**Đầu vào:** `port_id`, `mempool`, `worker_rings[]`, con trỏ ACL context (chỉ đọc).

**Đầu ra:** Các hành động phân loại đã thực hiện theo từng gói tin (FORWARD hoặc DROP). Cập nhật `rx_lcore_stats`.

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

    với mỗi i trong [0, nb_rx):
      process_packet(rx_pkts[i])

  /* drain các mbuf đang in-flight từ worker ring trước khi trả về */
  wait_workers_drain()
  return 0
```

**process_packet(mbuf):**

```
  meta = parse_packet(mbuf)          /* module parser */
  nếu meta == NULL:                  /* phân tích thất bại */
    rte_pktmbuf_free(mbuf)
    rx_lcore_stats.invalid_packets++
    return

  result = acl_lookup(meta)          /* module acl_engine */
  acl_engine_increment_hit(result.rule_id)

  nếu result.action == ACTION_FORWARD:
    worker_idx = select_worker()     /* round-robin */
    rc = rte_ring_enqueue(worker_rings[worker_idx], mbuf)
    nếu rc != 0:                     /* ring đầy: unintended drop */
      rte_pktmbuf_free(mbuf)
      rx_lcore_stats.ring_drop_packets++
    ngược lại:
      rx_lcore_stats.forward_packets++
      rx_lcore_stats.forward_bytes += mbuf->pkt_len

  ngược lại:  /* ACTION_DROP */
    rte_pktmbuf_free(mbuf)
    rx_lcore_stats.drop_packets++
```

**Chọn worker — round-robin:**

```
  static uint32_t rr_counter = 0
  worker_idx = rr_counter % num_workers
  rr_counter++
```

Round-robin là phi trạng thái theo từng gói tin. Không cần trạng thái chia sẻ giữa lcore và các worker.

**Phát hiện kết thúc đầu vào:**

PMD `net_pcap` trả về 0 mbuf khi file PCAP đã được tiêu thụ hết. Counter liên tiếp bằng không `EOI_THRESHOLD` (mặc định: 100 lần poll liên tiếp) ngăn false positive từ các burst trống thoáng qua trong quá trình vận hành bình thường. Ngưỡng này đủ vì PMD sẽ liên tục trả về 0 cho tất cả các lần poll tiếp theo sau khi file được tiêu thụ hoàn toàn.

**Quyền sở hữu mbuf:** RX lcore sở hữu mỗi mbuf từ thời điểm `rte_eth_rx_burst` trả về cho đến khi:
- `rte_ring_enqueue` thành công → quyền sở hữu chuyển sang worker lcore mục tiêu.
- `rte_pktmbuf_free` được gọi (đường DROP hoặc ring đầy) → mbuf trả về mempool.

---

### 2.3 Module Phân Tích Gói Tin (`packet/parser`)

**Trách nhiệm:** Giải mã header gói tin theo từng lớp; ghép five-tuple; thực hiện chuẩn hóa luồng hai chiều; trả về bản ghi metadata hoặc NULL khi phân tích thất bại.

**Đầu vào:** Con trỏ `rte_mbuf *` đơn lẻ.

**Đầu ra:** Con trỏ đến `pkt_meta_t` (được cấp phát trên stack trong hàm gọi, hợp lệ trong suốt thời gian gọi phân loại) hoặc NULL.

**Luồng phân tích:**

```
parse_packet(mbuf) → pkt_meta_t *:

  data     = rte_pktmbuf_mtod(mbuf, uint8_t *)
  data_len = mbuf->data_len

  /* --- Bước 1: Ethernet --- */
  nếu data_len < sizeof(eth_hdr):  return NULL
  eth  = (struct rte_ether_hdr *) data
  etype = rte_be_to_cpu_16(eth->ether_type)
  offset = sizeof(struct rte_ether_hdr)        /* 14 bytes */

  /* --- Bước 2: VLAN (tùy chọn, có thể double-tagged) --- */
  meta.vlan_id    = 0
  meta.vlan_valid = 0
  nếu etype == RTE_ETHER_TYPE_VLAN:             /* 0x8100 */
    nếu data_len < offset + 4:  return NULL
    vlan_hdr = (struct rte_vlan_hdr *)(data + offset)
    meta.vlan_id    = rte_be_to_cpu_16(vlan_hdr->vlan_tci) & 0x0FFF
    meta.vlan_valid = 1
    etype  = rte_be_to_cpu_16(vlan_hdr->eth_proto)
    offset += 4

  /* --- Bước 3: Chỉ IPv4 --- */
  nếu etype != RTE_ETHER_TYPE_IPV4:            /* 0x0800 */
    return NULL   /* EtherType không được hỗ trợ */

  nếu data_len < offset + sizeof(struct rte_ipv4_hdr):  return NULL
  ip4 = (struct rte_ipv4_hdr *)(data + offset)

  ihl_bytes = (ip4->version_ihl & 0x0F) * 4
  nếu ihl_bytes < 20:  return NULL            /* IHL bị lỗi */

  meta.src_ip   = ip4->src_addr              /* network byte order */
  meta.dst_ip   = ip4->dst_addr
  meta.protocol = ip4->next_proto_id
  offset       += ihl_bytes

  /* --- Bước 4: TCP hoặc UDP --- */
  nếu meta.protocol == IPPROTO_TCP:           /* 6 */
    nếu data_len < offset + sizeof(struct rte_tcp_hdr):  return NULL
    tcp = (struct rte_tcp_hdr *)(data + offset)
    meta.src_port = rte_be_to_cpu_16(tcp->src_port)
    meta.dst_port = rte_be_to_cpu_16(tcp->dst_port)

  ngược lại nếu meta.protocol == IPPROTO_UDP: /* 17 */
    nếu data_len < offset + sizeof(struct rte_udp_hdr):  return NULL
    udp = (struct rte_udp_hdr *)(data + offset)
    meta.src_port = rte_be_to_cpu_16(udp->src_port)
    meta.dst_port = rte_be_to_cpu_16(udp->dst_port)

  ngược lại:
    return NULL   /* giao thức transport không được hỗ trợ */

  /* --- Bước 5: Five-tuple đã ghép --- */
  /* --- Bước 6: Chuẩn hóa luồng hai chiều (DD-10) --- */
  normalize_flow(&meta)

  return &meta
```

**Thuật toán chuẩn hóa luồng (`normalize_flow`):**

```
normalize_flow(meta):
  /* Dạng chuẩn tắc: IP nhỏ hơn luôn ở vị trí src.
     Nếu IP bằng nhau, cổng nhỏ hơn vào vị trí src.
     Trường protocol và VLAN không được sắp xếp lại.  */

  nếu meta.src_ip > meta.dst_ip:
    swap(meta.src_ip, meta.dst_ip)
    swap(meta.src_port, meta.dst_port)

  ngược lại nếu meta.src_ip == meta.dst_ip và meta.src_port > meta.dst_port:
    swap(meta.src_port, meta.dst_port)
```

Đây là phép biến đổi thuần túy, thời gian hằng số, phi trạng thái. Không cấp phát bộ nhớ. Cùng hàm áp dụng cho gói tin chiều đi và gói tin ngược chiều tạo ra kết quả giống hệt nhau (DD-10, FR-012, FR-013).

**Toàn bộ quá trình phân tích được thực hiện trực tiếp trên dữ liệu mbuf (zero-copy).** Không có heap allocation theo từng gói tin trên đường phân tích.

---

### 2.4 Module Nạp Rule (`rule/rule_loader`)

**Trách nhiệm:** Đọc, phân tích và kiểm tra hợp lệ file cấu hình rule; xây dựng bảng filter-group trong bộ nhớ; gọi `acl_engine` để biên dịch cấu trúc tra cứu ACL.

**Đầu vào:** Chuỗi đường dẫn file từ `spifast_config_t`.

**Đầu ra:** `filter_group_table_t` đã điền và ACL context đã biên dịch (thông qua `acl_engine`). Trả về 0 khi thành công, -1 khi có bất kỳ lỗi nào.

**Xử lý nội bộ — xem Mục 5 để biết ngữ pháp đầy đủ.**

**Giao tiếp:** Gọi `acl_engine_build()` sau khi tất cả rule đã được kiểm tra hợp lệ. Cung cấp `filter_group_table` cho `acl_engine` để giải quyết action.

---

### 2.5 Module ACL Engine (`rule/acl_engine`)

**Trách nhiệm:** Build cấu trúc tra cứu DPDK ACL từ các rule đã kiểm tra hợp lệ; thực hiện lookup five-tuple theo từng gói tin; trả về filter-group ID và action đã khớp; duy trì hit counter.

**Đầu vào (giai đoạn build):** Mảng các struct `spi_rule_t`, số lượng.

**Đầu vào (giai đoạn lookup):** `pkt_meta_t *` theo từng gói tin.

**Đầu ra (giai đoạn lookup):** `acl_result_t` chứa `{group_id, action, rule_id}`.

**Xem Mục 4 để biết thiết kế ACL engine đầy đủ.**

---

### 2.6 Module Worker (`worker/worker`)

**Trách nhiệm:** Thực thi hàm worker lcore: drain ring được gán, thực hiện hạch toán theo từng gói tin, giải phóng mbuf về mempool.

**Đầu vào:** `rte_ring *ring`, chỉ số worker, con trỏ đến `worker_lcore_stats_t`.

**Đầu ra:** Counter `worker_lcore_stats_t` đã cập nhật. Tất cả mbuf được giải phóng về mempool.

**Vòng lặp chính của worker lcore:**

```
worker_lcore_func(void *arg):
  ctx = (worker_ctx_t *) arg
  ring  = ctx->ring
  stats = &ctx->stats

  trong khi shutdown_flag chưa được đặt HOẶC ring chưa rỗng:
    nb_rx = rte_ring_dequeue_burst(ring, pkts[], WORKER_BURST_SIZE, NULL)

    với mỗi i trong [0, nb_rx):
      stats->pkt_count++
      stats->byte_count += pkts[i]->pkt_len
      rte_pktmbuf_free(pkts[i])

  return 0
```

**Drain khi tắt máy:** Khi `shutdown_flag` được đặt, worker tiếp tục drain ring cho đến khi rỗng trước khi trả về. Điều này đảm bảo không có mbuf nào bị kẹt trong ring khi ứng dụng thoát, đáp ứng yêu cầu hạch toán zero-loss (FR-032).

**Quyền sở hữu mbuf:** Worker sở hữu mbuf từ thời điểm `rte_ring_dequeue_burst` trả về cho đến khi `rte_pktmbuf_free` được gọi. Không thể xảy ra mbuf leak hay double-free trên đường này.

---

### 2.7 Module Thống Kê (`stats/stats`)

**Trách nhiệm:** Tổng hợp counter per-lcore thành tổng cộng cấp phiên; tính Throughput (Mbps) và PPS theo chu kỳ; cung cấp dữ liệu snapshot cho module logging.

**Đầu vào:** Con trỏ đến tất cả instance `rx_lcore_stats_t` và `worker_lcore_stats_t`; mảng hit counter ACL.

**Đầu ra:** `stats_snapshot_t` được module logging tiêu thụ.

**Xem Mục 8 để biết thiết kế thống kê đầy đủ.**

---

### 2.8 Module Logging (`logging/log`)

**Trách nhiệm:** Xuất thống kê định kỳ, sự kiện khởi động/tắt máy và tóm tắt phiên cuối cùng ra stdout và tùy chọn ra file log ở chế độ append. Toàn bộ I/O được thực hiện riêng trên main lcore.

**Đầu vào:** `stats_snapshot_t`, loại sự kiện vòng đời, đường dẫn file log (có thể là NULL).

**Đầu ra:** Văn bản được định dạng ra stdout và/hoặc file log.

**Xem Mục 8 để biết thiết kế logging đầy đủ.**

---

## 3. Thiết Kế Cấu Trúc Dữ Liệu

### 3.1 Cấu Trúc Metadata Gói Tin (`pkt_meta_t`)

Lưu trữ five-tuple đã phân tích và chuẩn hóa cho một gói tin đơn lẻ. Được cấp phát trên stack của RX/classifier lcore theo từng gói tin; không được heap-allocated.

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

#define SPIFAST_MAX_GROUPS  32

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

Tồn tại hai cấu trúc counter riêng biệt: một cho RX/classifier lcore, một cho mỗi worker lcore. Cả hai được khai báo với padding cache-line để ngăn false sharing.

```c
#define CACHE_LINE_SIZE  64

typedef struct {
    /* Chỉ được ghi bởi RX lcore */
    uint64_t rx_packets;        /* tổng mbuf nhận được từ PMD              */
    uint64_t forward_packets;   /* mbuf enqueue vào worker ring            */
    uint64_t forward_bytes;     /* byte của gói tin được forward (pkt_len) */
    uint64_t drop_packets;      /* mbuf bị hủy bởi hành động rule DROP     */
    uint64_t invalid_packets;   /* mbuf bị hủy do lỗi phân tích            */
    uint64_t ring_drop_packets; /* mbuf bị hủy do worker ring đầy          */
    /* Padding đến cache line đầy đủ */
    uint8_t  _pad[CACHE_LINE_SIZE
                  - (6 * sizeof(uint64_t)) % CACHE_LINE_SIZE];
} __rte_cache_aligned rx_lcore_stats_t;

typedef struct {
    uint64_t pkt_count;         /* gói tin nhận được từ ring               */
    uint64_t byte_count;        /* byte của gói tin nhận được              */
    uint8_t  _pad[CACHE_LINE_SIZE
                  - (2 * sizeof(uint64_t)) % CACHE_LINE_SIZE];
} __rte_cache_aligned worker_lcore_stats_t;
```

**Hit counter rule/group** được duy trì riêng trong module ACL engine dưới dạng mảng được đánh chỉ số bởi `group_id`:

```c
typedef struct {
    uint64_t hit_count[SPIFAST_MAX_GROUPS]; /* số lượt khớp per-group */
} acl_hit_counters_t;
```

Hit counter chỉ được ghi bởi RX/classifier lcore, do đó không cần atomic operation.

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
    uint64_t total_fwd_pkts;
    uint64_t total_drop_pkts;
    uint64_t total_invalid_pkts;
    uint64_t total_ring_drop_pkts;
    uint64_t total_bytes;

    /* Hit count per-group (bản sao snapshot) */
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

### 4.1 Lý Do Thiết Kế — DPDK `rte_acl`

ACL engine được xây dựng trên thư viện `librte_acl` của DPDK, triển khai thuật toán phân loại đa trường (dựa trên Bit-Vector Trie hoặc DFA tùy thuộc kích thước bộ rule). Thư viện này hỗ trợ tự nhiên:

- IPv4 prefix matching (CIDR) trên trường src/dst IP.
- Khớp giá trị chính xác và range trên trường port và protocol.
- Chọn kết quả dựa trên priority trong số nhiều rule khớp.
- Batch lookup trên mảng các packet key để tận dụng hiệu quả SIMD.

`rte_acl` biên dịch các rule thành cấu trúc nội bộ được tối ưu hóa tại thời điểm build. Cấu trúc kết quả là read-only trong quá trình xử lý gói tin, đáp ứng yêu cầu nạp tĩnh (DD-04) và cho phép đọc đồng thời lock-free nếu cần trong các mở rộng tương lai.

### 4.2 Định Nghĩa Trường ACL

Thư viện DPDK ACL yêu cầu mỗi rule được biểu diễn dưới dạng tập hợp các trường byte-range trên một mảng byte phẳng (gọi là "key"). Với SPIFast, bố cục key là:

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

Điều này ánh xạ sang mảng `rte_acl_field_def` sau (định nghĩa tại build time):

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

### 4.3 Trình Tự Build Bảng ACL

```
acl_engine_build(rules[], num_rules, filter_group_table):

  1. Tạo ACL context:
       ctx = rte_acl_create(&acl_param)
       acl_param.name       = "spifast_acl"
       acl_param.socket_id  = SOCKET_ID_ANY
       acl_param.rule_size  = RTE_ACL_RULE_SZ(NUM_ACL_FIELDS)
       acl_param.max_rule_num = SPIFAST_MAX_RULES

  2. Với mỗi spi_rule_t rule trong rules[]:
       a. Cấp phát struct acl_rule (stack)
       b. Điền giá trị và mask trường từ các trường rule:
            - protocol: value=rule.protocol, mask=(rule.protocol==ANY ? 0 : 0xFF)
            - src_ip:   value=rule.src_ip (network order),
                        mask = prefix_to_mask(rule.src_prefix_len)
            - dst_ip:   tương tự
            - src_port: lo=rule.src_port_lo, hi=rule.src_port_hi
            - dst_port: lo=rule.dst_port_lo, hi=rule.dst_port_hi
       c. Đặt data.priority = UINT32_MAX - rule.precedence
            /* rte_acl chọn người thắng có priority cao nhất (số nguyên lớn nhất);
               SPIFast precedence là thấp hơn=ưu tiên cao hơn, nên phải đảo ngược. */
       d. Đặt data.userdata = rule.group_id + 1   /* 0 dành cho no-match */
       e. rte_acl_add_rules(ctx, &acl_rule, 1)

  3. Build cấu trúc lookup:
       cfg.num_categories = 1   /* single-category: một kết quả mỗi gói tin */
       rte_acl_build(ctx, &cfg)

  4. Lưu ctx vào con trỏ acl_ctx toàn cục của module.
  5. Khởi tạo hit_counters[] về zero.
  6. Trả về 0 khi thành công; -1 khi có bất kỳ lỗi rte_acl nào.
```

### 4.4 Tra Cứu ACL Theo Từng Gói Tin

Tra cứu ACL được thực hiện trên từng gói tin một trên RX/classifier lcore. Mặc dù `rte_acl_classify` hỗ trợ batch lookup, gọi đơn gói tin được sử dụng cho đơn giản; batch lookup có thể được áp dụng như một tối ưu hóa trong vòng lặp tương lai.

```
acl_lookup(meta) → acl_result_t:

  /* Build key từ metadata đã chuẩn hóa */
  key.protocol = meta->protocol
  key.src_ip   = meta->src_ip
  key.dst_ip   = meta->dst_ip
  key.src_port = meta->src_port
  key.dst_port = meta->dst_port

  keys_ptr[0] = (const uint8_t *) &key
  rte_acl_classify(acl_ctx, keys_ptr, results, 1, 1)

  userdata = results[0]
  nếu userdata == 0:
    /* Không khớp: áp dụng default group (phải luôn tồn tại) */
    group_id = default_group_id
  ngược lại:
    group_id = userdata - 1

  result.group_id = group_id
  result.action   = filter_group_table.groups[group_id].action
  result.rule_id  = group_id   /* đếm lượt khớp theo per-group */

  return result
```

### 4.5 Xử Lý Priority

`rte_acl` chọn rule khớp có giá trị `data.priority` cao nhất khi nhiều rule khớp (ngữ nghĩa best-match trong thư viện ACL). SPIFast ánh xạ số nguyên `precedence` (thấp hơn = ưu tiên cao hơn) sang priority của `rte_acl` thông qua:

```
acl_priority = UINT32_MAX - rule.precedence
```

Điều này đảm bảo rule có `precedence` nhỏ nhất về số học (ưu tiên SPIFast cao nhất) ánh xạ sang `acl_priority` lớn nhất và được `rte_acl` chọn.

**Chế độ first-match vs. best-match (FR-016):**

- **Chế độ Best-match:** Sử dụng `rte_acl_classify` trực tiếp. Thư viện ACL trả về kết quả khớp priority cao nhất theo thiết kế.
- **Chế độ First-match:** Sắp xếp các rule theo `precedence` tăng dần trước khi gọi `rte_acl_add_rules`. Chèn rule theo từng cái một; rule đầu tiên theo thứ tự precedence mà khớp sẽ thắng. Trong thực tế, vì `rte_acl` với một priority category đơn luôn trả về kết quả khớp tốt nhất duy nhất, hành vi first-match được xấp xỉ bằng cách gán các giá trị priority tăng dần nghiêm ngặt, duy nhất, suy ra từ thứ tự chèn rule trong từng cấp độ precedence. Các rule có cùng giá trị precedence đã khai báo giữ nguyên thứ tự trong file.

Chế độ khớp được chọn khi khởi động qua `--mode` và không thay đổi trong runtime.

### 4.6 Xử Lý Rule Mặc Định

Rule loader kiểm tra rằng rule DEFAULT group tồn tại (FR-017). Rule mặc định được thêm vào ACL context với `precedence = 999` (hoặc giá trị tối đa đã cấu hình) và key toàn wildcard:

```
protocol = ANY (mask 0x00)
src_ip   = 0.0.0.0/0
dst_ip   = 0.0.0.0/0
src_port = [0, 65535]
dst_port = [0, 65535]
```

Điều này đảm bảo mọi gói tin đến ACL lookup đều trả về `userdata` khác không, bảo đảm FR-023 (mọi gói tin nhận được một action).

### 4.7 Đếm Lượt Khớp Rule

Hit counter được duy trì per filter-group trong `acl_hit_counters_t.hit_count[group_id]`. Sau mỗi `acl_lookup`, RX lcore tăng:

```c
acl_hit_counters.hit_count[result.group_id]++;
```

Vì RX lcore là người ghi duy nhất, không cần atomic operation hay lock. Module stats đọc mảng này từ main lcore theo chu kỳ 1 giây; việc đọc torn thỉnh thoảng của counter 64-bit là chấp nhận được cho mục đích hiển thị thống kê phi quan trọng và không ảnh hưởng đến tính đúng đắn.

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

      nếu num_rules >= SPIFAST_MAX_RULES (99):
        LOG_ERROR("Rule count exceeds maximum (99)"); return -1

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
| Số lượng rule | Tổng số mục rule < 100 |

---

## 6. Thiết Kế Đa Lõi và Luồng

### 6.1 Phân Công Vai Trò lcore

SPIFast sử dụng topology lcore cố định được thiết lập khi khởi động. Ánh xạ như sau:

```
lcore ID   Vai trò                   Module
---------  ------------------------  ----------------------------
0          Main / Stats / Logging    main, stats, logging
1          RX / Classifier           rx, parser, acl_engine
2          Worker 0                  worker (ring[0])
3          Worker 1                  worker (ring[1])...
...        Worker N-1                worker (ring[N-1])
```

**lcore ID được gán theo thứ tự tăng dần** từ tập hợp lcore có sẵn do DPDK trả về. Main lcore luôn là `rte_get_main_lcore()`. RX lcore là lcore có sẵn tiếp theo sau main. Các worker chiếm `num_workers` lcore tiếp theo.

**Tổng lcore yêu cầu: `2 + num_workers`.**

Tham số `--lcores` của EAL hoặc core mask được cung cấp trên dòng lệnh phải bao gồm ít nhất số lcore này. Ví dụ cho 2 worker:

```
./spifast --lcores 0-3 -- --pcap traffic.pcap --rules spi_rules.conf --workers 2
```

### 6.2 Trách Nhiệm Dispatcher (RX/Classifier lcore)

RX/classifier lcore là dispatcher duy nhất. Trách nhiệm của nó theo từng gói tin:

1. Nhận mbuf qua `rte_eth_rx_burst`.
2. Gọi parser → tạo ra `pkt_meta_t`.
3. Gọi ACL lookup → tạo ra `acl_result_t`.
4. Khi FORWARD: chọn target worker ring (round-robin); gọi `rte_ring_enqueue`.
5. Khi DROP hoặc lỗi phân tích: gọi `rte_pktmbuf_free`; tăng counter.
6. Cập nhật counter `rx_lcore_stats` (ghi cục bộ, không cần lock).

Dispatcher không bao giờ gọi bất kỳ hàm I/O nào, `malloc`, `free`, `printf`, hoặc bất kỳ blocking system call nào. Tất cả thao tác đều là tính toán trong register hoặc userspace memory operation.

### 6.3 Trách Nhiệm Worker

Mỗi worker lcore thực thi `worker_lcore_func` thực hiện:

1. Gọi `rte_ring_dequeue_burst` trên ring được dành riêng.
2. Với mỗi mbuf đã dequeue: tăng counter packet và byte per-worker; gọi `rte_pktmbuf_free`.
3. Lặp cho đến khi `shutdown_flag == 1` VÀ ring của nó rỗng.

Các worker không bao giờ tương tác với nhau, với ring của dispatcher dành cho worker khác, hoặc trực tiếp với module stats/logging.

### 6.4 Ngữ Cảnh Thực Thi Thống Kê và Logging

Main lcore điều khiển bộ đếm thời gian thống kê bằng kiểm tra wall-clock đơn giản:

```
main_lcore_func():
  khởi chạy rx lcore
  khởi chạy worker lcore

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

`rte_delay_us_block` chỉ được gọi trên main lcore, không bao giờ trên RX hay worker lcore. Sleep 100 µs này không ảnh hưởng đến hiệu năng xử lý gói tin.

### 6.5 Tóm Tắt Quyền Sở Hữu mbuf

| Giai đoạn | Chủ sở hữu mbuf | Cơ chế chuyển giao |
|---|---|---|
| PMD → RX lcore | PMD cấp phát từ mempool; RX lcore nhận qua `rte_eth_rx_burst` | Burst RX API |
| RX lcore → worker lcore | RX lcore enqueue; worker lcore dequeue | `rte_ring_enqueue` / `rte_ring_dequeue_burst` |
| Worker lcore → mempool | Worker gọi `rte_pktmbuf_free` | Giải phóng trực tiếp |
| RX lcore → mempool (DROP) | RX lcore gọi `rte_pktmbuf_free` | Giải phóng trực tiếp |

Không có thời điểm nào một mbuf được chia sẻ giữa hai lcore đồng thời. Quyền sở hữu luôn được nắm giữ bởi đúng một lcore.

### 6.6 Yêu Cầu Đồng Bộ Hóa

| Tài nguyên | Người ghi | Người đọc | Đồng bộ hóa |
|---|---|---|---|
| `rx_lcore_stats` | RX lcore | Main lcore (stats) | Không có; việc đọc torn 64-bit thỉnh thoảng là chấp nhận được cho hiển thị stats |
| `worker_lcore_stats[i]` | Worker lcore i | Main lcore (stats) | Không có; cùng lý do |
| `acl_hit_counters` | RX lcore | Main lcore (stats) | Không có |
| `worker_rings[i]` | RX lcore (SP) | Worker lcore i (SC) | SPSC ring: lock-free theo thiết kế |
| `shutdown_flag` | RX lcore (người ghi) | Worker lcore (người đọc) | `volatile int`; một người ghi, nhiều người đọc; memory model nền tảng đủ cho cờ đơn giản |
| ACL context (`acl_ctx`) | rule_loader (build, một lần) | RX lcore (lookup, chỉ đọc) | Không cần đồng bộ sau khi `rte_acl_build` hoàn tất trước khi lcore khởi chạy |
| `filter_group_table` | rule_loader (init, một lần) | RX lcore (lookup, chỉ đọc) | Không cần đồng bộ; được build trước khi lcore khởi chạy |

### 6.7 Xem Xét Thứ Tự Gói Tin

Không có đảm bảo thứ tự gói tin trên các worker lcore (HLD §4.5). Trong mỗi worker ring, gói tin được xử lý theo thứ tự FIFO. Tổng hợp thống kê không phụ thuộc thứ tự; tất cả counter đều có tính cộng dồn.

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

### 7.3 Cấu Hình Worker Ring

Mỗi worker ring được tạo với:

| Tham số | Giá trị | Lý do |
|---|---|---|
| `RING_SIZE` | 1024 | Phải là lũy thừa của hai (yêu cầu DPDK). Cung cấp buffer cho sự mất cân bằng burst giữa classifier và worker. Tại 1 Mpps và 1 worker, tốc độ lấp ring ≈ tốc độ drain; 1024 entry cung cấp ~1 ms buffer. |
| `RING_F_SP_ENQ` | Đặt | Single-producer enqueue (chỉ classifier lcore) → tránh overhead MP enqueue. |
| `RING_F_SC_DEQ` | Đặt | Single-consumer dequeue (worker chuyên dụng) → tránh overhead MC dequeue. |
| `WORKER_BURST_SIZE` | 32 | Kích thước dequeue burst ở phía worker. |

**Xử lý ring đầy:** Nếu `rte_ring_enqueue` trả về `-ENOBUFS` (ring đầy), gói tin bị hủy ngay lập tức và `rx_lcore_stats.ring_drop_packets` được tăng. Đây là unintended drop được theo dõi bởi PR-005. Kích thước ring phải đảm bảo tỷ lệ này không vượt quá 0,1% dưới tải mục tiêu.

### 7.4 Tóm Tắt Bố Cục Bộ Nhớ

```
Hugepage memory (được EAL cấp phát khi khởi động)
│
├── rte_mempool (8192 mbufs × 2176 bytes ≈ 17 MB)
│    └── cache per-lcore (256 entry mỗi cái)
│
├── rte_ring[0]  (1024 × 8 bytes = 8 KB)
├── rte_ring[1]  ...
├── ...
├── rte_ring[N-1]
│
└── rte_acl context (cấu trúc rule đã biên dịch, ~KB với ≤99 rule)
```

Tất cả cấu trúc được DPDK quản lý đều nằm trong hugepage memory. Không có lệnh gọi `malloc`/`free` nào được thực hiện sau khi khởi tạo hoàn tất.

### 7.5 Tham Số Tài Nguyên Có Thể Cấu Hình

Các hằng số compile-time sau được định nghĩa trong `src/dpdk/dpdk_init.h` và có thể được override tại build time:

```c
#define SPIFAST_MEMPOOL_SIZE     8192
#define SPIFAST_MEMPOOL_CACHE    256
#define SPIFAST_BURST_SIZE       32
#define SPIFAST_RX_DESC          512
#define SPIFAST_RING_SIZE        1024
#define SPIFAST_WORKER_BURST     32
#define SPIFAST_EOI_THRESHOLD    100
#define SPIFAST_MAX_RULES        99
#define SPIFAST_MAX_GROUPS       32
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
  cur.total_rx_pkts       = rx_stats.rx_packets
  cur.total_fwd_pkts      = rx_stats.forward_packets
  cur.total_drop_pkts     = rx_stats.drop_packets
  cur.total_invalid_pkts  = rx_stats.invalid_packets
  cur.total_ring_drop_pkts= rx_stats.ring_drop_packets
  cur.total_bytes         = rx_stats.forward_bytes

  /* Tổng hợp counter worker (hạch toán byte bổ sung) */
  với mỗi i trong [0, num_workers):
    cur.total_bytes += worker_stats[i].byte_count  /* kiểm tra chéo tùy chọn */

  /* Delta theo chu kỳ */
  snap.interval_sec      = (double)(now_cycles - prev_cycles) / hz
  snap.interval_rx_pkts  = cur.total_rx_pkts  - prev.total_rx_pkts
  snap.interval_fwd_pkts = cur.total_fwd_pkts - prev.total_fwd_pkts
  snap.interval_fwd_bytes= cur.total_bytes    - prev.total_bytes

  /* Throughput và PPS */
  snap.interval_mbps = (snap.interval_fwd_bytes * 8.0)
                       / snap.interval_sec / 1e6
  snap.interval_pps  = snap.interval_fwd_pkts / snap.interval_sec

  /* Sao chép hit counter */
  memcpy(snap.group_hits, acl_hit_counters.hit_count,
         num_groups * sizeof(uint64_t))
  snap.num_groups = num_groups

  /* Thời gian đã trôi qua */
  snap.elapsed_sec = (now_cycles - session_start_cycles) / hz

  /* Sao chép tổng lũy kế */
  snap.total_rx_pkts      = cur.total_rx_pkts
  ... (tất cả trường lũy kế)

  return snap
```

**Xác nhận mất gói tin (FR-032) — thực hiện cuối phiên:**

```
validate_packet_accounting(final_snap):
  accounted = final_snap.total_fwd_pkts
            + final_snap.total_drop_pkts
            + final_snap.total_invalid_pkts

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
[2025-06-26T14:32:05+0700] elapsed=10s  rx=500000  fwd=490000  drop=9800  inv=200  ring_drop=0  mbps=823.40  pps=490000  | fg_l34_facebook=120000 fg_l34_youtube=85000 fg_l34_http_sdf1003=200000 fg_l34_dns_sdf1005=85000 DEFAULT=9800
```

Định nghĩa trường:

| Token | Trường | Đơn vị |
|---|---|---|
| `[timestamp]` | Thời gian địa phương ISO 8601 | — |
| `elapsed=Ns` | Giây kể từ gói tin đầu tiên | giây |
| `rx=N` | Gói tin RX lũy kế | gói tin |
| `fwd=N` | Gói tin được forward lũy kế | gói tin |
| `drop=N` | Gói tin bị DROP theo rule lũy kế | gói tin |
| `inv=N` | Gói tin không hợp lệ lũy kế | gói tin |
| `ring_drop=N` | Gói tin bị hủy do ring overflow lũy kế | gói tin |
| `mbps=F` | Throughput theo chu kỳ | Mbps (2 chữ số thập phân) |
| `pps=N` | PPS theo chu kỳ | gói tin/giây |
| `\| group=N ...` | Hit lũy kế per-group | gói tin |

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
[2025-06-26T14:32:15+0700] SUMMARY  elapsed=15s  total_rx=750000  total_fwd=735000  total_drop=14700  total_inv=300  total_ring_drop=0
[2025-06-26T14:32:15+0700] THROUGHPUT_AVG  mbps=817.33
[2025-06-26T14:32:15+0700] PPS_AVG  pps=490000
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
# Tối giản: 1 worker, rule từ file mặc định, log chỉ ra stdout
./spifast -l 0-2 -n 4 -- --pcap tests/tp01_small.pcap

# Đầy đủ: 4 worker, rule tường minh, file log, chế độ best-match
./spifast -l 0-6 -n 4 -- \
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
    rte_eal_remote_launch(rx_lcore_func,   &rx_ctx,     rx_lcore_id)
    với mỗi i trong workers:
      rte_eal_remote_launch(worker_lcore_func, &worker_ctx[i], worker_lcore_id[i])

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
| Số lượng rule > 99 | `rule_loader_load` | Ghi log lỗi kèm số lượng; `return -1` |
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
| Ethernet header quá ngắn | `parser` | Giải phóng mbuf; return NULL | `invalid_packets` |
| EtherType không được hỗ trợ (không phải IPv4 sau khi bóc VLAN) | `parser` | Giải phóng mbuf; return NULL | `invalid_packets` |
| IPv4 header quá ngắn hoặc IHL bị lỗi | `parser` | Giải phóng mbuf; return NULL | `invalid_packets` |
| IP protocol không được hỗ trợ (không phải TCP/UDP) | `parser` | Giải phóng mbuf; return NULL | `invalid_packets` |
| Transport header quá ngắn | `parser` | Giải phóng mbuf; return NULL | `invalid_packets` |
| Worker ring đầy (`rte_ring_enqueue` trả về -ENOBUFS) | `rx` (dispatch) | Giải phóng mbuf ngay lập tức | `ring_drop_packets` |
| ACL không khớp | `acl_engine` | Áp dụng hành động DEFAULT group (luôn được định nghĩa) | `hit_count` của default group |

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
3. Triển khai `dpdk_init`: tạo mempool, cấu hình và khởi động port net_pcap.
4. Kiểm tra: ứng dụng khởi động, mở PCAP port và thoát sạch. Sử dụng `rte_eth_stats_get` để xác nhận port đang hoạt động.

### Giai đoạn 2 — Nhận Gói Tin và Logging Thô

**Mục tiêu:** Xác nhận nhận gói tin thô từ file PCAP.

5. Triển khai vòng lặp RX burst `rx.c` (gọi `rte_eth_rx_burst`; giải phóng tất cả mbuf ngay lập tức; đếm).
6. Triển khai `logging/log.c` tối giản: `log_write` chỉ ra stdout; in counter định kỳ.
7. Triển khai `stats/stats.c`: đọc `rx_lcore_stats`; tính PPS theo chu kỳ.
8. Khởi chạy RX lcore và vòng lặp stats của main lcore.
9. Kiểm tra: số gói tin được in ra khớp với `tcpdump -r <pcap> | wc -l`. Xác nhận phát hiện kết thúc PCAP hoạt động.

### Giai đoạn 3 — Packet Parser

**Mục tiêu:** Giải mã chính xác tất cả kiểu gói tin được hỗ trợ.

10. Triển khai `packet/parser.c`: Ethernet → VLAN → IPv4 → TCP/UDP → ghép five-tuple.
11. Triển khai chuẩn hóa luồng (`normalize_flow`).
12. Unit test (độc lập, không cần DPDK): nạp mảng byte tổng hợp biểu diễn các gói tin đã biết; assert đầu ra `pkt_meta_t` mong đợi.
13. Tích hợp parser vào vòng lặp RX (thay thế giải phóng-tất-cả bằng phân tích → ghi log five-tuple → giải phóng).
14. Kiểm tra với TP-04 (PCAP hai chiều): cả hai chiều của mỗi luồng tạo ra five-tuple đã chuẩn hóa giống hệt nhau.
15. Kiểm tra với TP-05 (PCAP VLAN): gói tin VLAN tạo ra cùng five-tuple như các gói tin tương đương không có thẻ.

### Giai đoạn 4 — Rule Loader và ACL Engine

**Mục tiêu:** Nạp rule và thực hiện phân loại.

16. Triển khai `rule/rule_loader.c`: parser file, validator, builder bảng group.
17. Unit test rule loader: kiểm tra tất cả trường hợp kiểm tra hợp lệ (IP bị lỗi, port range sai, thiếu DEFAULT, tên trùng lặp, >99 rule).
18. Triển khai `rule/acl_engine.c`: định nghĩa trường ACL, `acl_engine_build`, `acl_lookup`.
19. Tích hợp ACL vào vòng lặp RX: phân tích → lookup → in kết quả (action, tên group) → giải phóng.
20. Kiểm tra với PCAP tham chiếu và file rule: mọi gói tin được phân loại vào group mong đợi theo ví dụ SRS (RC-004).
21. Kiểm thử chế độ first-match vs. best-match với bộ rule có precedence chồng nhau.

### Giai đoạn 5 — Xử Lý Worker

**Mục tiêu:** Hoàn thành pipeline dispatcher-worker end-to-end.

22. Triển khai `worker/worker.c`: vòng lặp drain ring, cập nhật counter, `rte_pktmbuf_free`.
23. Tạo worker ring trong `dpdk_init`.
24. Triển khai chọn worker round-robin trong `rx.c`.
25. Khởi chạy worker lcore.
26. Kiểm tra: tổng `rx_lcore_stats.forward_packets` bằng tổng tất cả `worker_lcore_stats[i].pkt_count` cuối phiên. Không có mbuf leak (số lượng in-use của mempool trở về không sau phiên).

### Giai đoạn 6 — Thống Kê và Logging

**Mục tiêu:** Tạo ra đầu ra thống kê định kỳ và cuối phiên chính xác.

27. Hoàn thiện `stats/stats.c`: tính delta theo chu kỳ, công thức Mbps/PPS, xác nhận mất gói tin.
28. Hoàn thiện `logging/log.c`: định dạng định kỳ (Mục 8.3), sự kiện khởi động, tóm tắt cuối.
29. Triển khai đầu ra file log (dual-output, append mode, chính sách flush, fallback khi lỗi).
30. Kiểm tra với TP-01 (small packet stress): đầu ra PPS ≥ 500.000. Kiểm tra công thức Mbps khớp với tính toán thủ công từ byte count.
31. Kiểm tra xác nhận mất gói tin: chạy với PCAP đã biết; xác nhận `PACKET_ACCOUNTING result=PASS`.

### Giai đoạn 7 — Kiểm Thử Tích Hợp và Hiệu Năng

**Mục tiêu:** Đáp ứng tất cả yêu cầu hiệu năng SRS và tạo ra bằng chứng kiểm thử.

32. Chạy TP-01 (small packet stress, frame 64 byte): đo PPS duy trì. Mục tiêu: PASS ≥ 500 Kpps; EXCELLENT ≥ 1.488 Mpps.
33. Chạy TP-02 (medium Throughput, frame ~1024 byte): đo Mbps duy trì. Mục tiêu: PASS ≥ 700 Mbps; EXCELLENT ≥ 950 Mbps.
34. Chạy TP-03 (full rule coverage): xác nhận tất cả group hit counter ≥ 1 cuối phiên.
35. Chạy TP-04 (bidirectional flow): xác nhận cả hai chiều tăng cùng group counter.
36. Chạy TP-05 (VLAN tagged): xác nhận phân loại giống hệt như các gói tương đương không có thẻ.
37. Đo tỷ lệ drop ngoài ý muốn (PR-005): `ring_drop_packets / total_rx_packets × 100 ≤ 0,1%`.
38. Kiểm tra hạch toán mất gói tin (PR-006): `PACKET_ACCOUNTING result=PASS` cho tất cả profile.
39. Thu thập và lưu trữ: log stdout, file log, file PCAP, tóm tắt kết quả kiểm thử.

### Giai đoạn 8 — Xử Lý Lỗi và Edge Case

**Mục tiêu:** Làm cứng ứng dụng trước tất cả điều kiện lỗi đã định nghĩa.

40. Kiểm thử từng đường lỗi khởi động (file thiếu, cú pháp sai, >99 rule, không có DEFAULT, IP sai, port range sai). Xác nhận thông báo lỗi bao gồm đường dẫn file, số dòng và gợi ý khắc phục.
41. Kiểm thử lỗi đường dẫn file log (thư mục không ghi được): xác nhận cảnh báo trên stderr; xử lý tiếp tục.
42. Kiểm thử điều kiện ring đầy bằng cách tạm thời giảm `RING_SIZE` xuống giá trị rất nhỏ và xác nhận `ring_drop_packets` tăng đúng.
43. Kiểm thử với PCAP chứa frame không phải IPv4: xác nhận counter `invalid_packets` tăng; không bị crash.
44. Kiểm thử với frame bị lỗi (header bị cắt ngắn): xác nhận xử lý graceful; không bị crash.

---

*Kết thúc tài liệu — SPIFAST-SDD-001-VI v1.0*
