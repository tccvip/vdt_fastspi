# Thiết Kế Mức Cao

---

**Tiêu đề tài liệu:** Thiết Kế Mức Cao — SPIFast: Hệ Thống Kiểm Tra Gói Tin Hiệu Năng Cao Sử Dụng DPDK

**Mã tài liệu:** SPIFAST-HLD-001

**Phiên bản:** 1.1

**Trạng thái:** Draft

**Người soạn thảo:** Nhóm Kỹ Thuật Hệ Thống

**Ngày:** 2025-06-26

**SRS áp dụng:** SPIFAST-SRS-001 v1.0

---

## Lịch Sử Sửa Đổi

| Phiên bản | Ngày | Tác giả | Mô tả |
|---|---|---|---|
| 0.1 | 2025-06-26 | Kỹ thuật hệ thống | Bản thảo HLD ban đầu, căn chỉnh theo SRS baseline |
| 1.0 | 2025-06-26 | Kỹ thuật hệ thống | Baseline HLD để rà soát thiết kế |
| 1.1 | 2025-06-26 | Kỹ thuật hệ thống | Dịch sang tiếng Việt; bổ sung thành phần Statistics and Logging Component tách biệt |

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

SPIFast là hệ thống Shallow Packet Inspection (SPI) chạy trong userspace, bỏ qua kernel (kernel-bypass), được xây dựng trên nền tảng Data Plane Development Kit (DPDK). Hệ thống vận hành như một instance ứng dụng đơn lẻ trên máy chủ Linux, tiêu thụ lưu lượng gói tin được replay từ các file PCAP thông qua DPDK `net_pcap` Poll Mode Driver (PMD). Hệ thống phân loại gói tin theo bộ ACL rule được nạp tĩnh và điều phối gói tin đã phân loại đến các Worker Core xử lý song song.

Thiết kế được xây dựng trên ba nguyên tắc kiến trúc cốt lõi:

- **Kernel bypass:** Toàn bộ I/O gói tin và xử lý đều diễn ra trong userspace thông qua DPDK, loại bỏ overhead của kernel network stack trên data path.
- **Giao tiếp liên lõi lock-free:** Giao tiếp data path giữa giai đoạn RX/phân loại và Worker Core sử dụng cấu trúc ring lock-free của DPDK, ngăn ngừa suy giảm Throughput do tranh chấp tài nguyên.
- **Phân loại gói tin phi trạng thái theo từng gói:** Mỗi gói tin được phân loại độc lập bằng cách tra cứu five-tuple đã chuẩn hóa, không duy trì trạng thái theo từng luồng, cho phép vận hành với Throughput cao và ổn định.

### 1.2 Mô Hình Triển Khai

SPIFast được triển khai dưới dạng ứng dụng đơn tiến trình trên máy Linux tiêu chuẩn. Không yêu cầu phần cứng NIC vật lý. Các điều kiện tiên quyết triển khai bao gồm:

- Hệ điều hành Linux (khuyến nghị Ubuntu 20.04 LTS trở lên)
- DPDK đã được cài đặt và cấu hình (phiên bản cụ thể được chỉ định trong SDD)
- Hugepages được cấp phát trước khi khởi chạy ứng dụng (khuyến nghị trang 2 MB)
- Đủ lõi CPU để gán độc quyền cho DPDK lcore (tối thiểu: 1 lõi RX/phân loại + N Worker Core theo cấu hình)
- Không có ứng dụng DPDK nào khác chạy đồng thời trên cùng máy trong quá trình thực thi kiểm thử

Người vận hành cung cấp hai đầu vào khi khởi chạy: đường dẫn file PCAP và đường dẫn file cấu hình rule. Hệ thống xử lý PCAP đúng một lần và kết thúc khi hoàn tất, xuất tóm tắt thống kê cuối phiên.

### 1.3 Các Giai Đoạn Xử Lý Chính

Pipeline xử lý của SPIFast gồm các giai đoạn tuần tự sau:

```
+---------------------------+
|        File PCAP          |
|  (do người vận hành cung  |
|   cấp)                    |
+-------------+-------------+
              |
              v
+---------------------------+
|   DPDK PCAP PMD           |
|  (net_pcap virtual device)|
|  Replay frame thành mbufs |
+-------------+-------------+
              |
              v
+---------------------------+
|   Packet Receive          |
|  Nhận burst poll-mode     |
|  từ virtual port          |
+-------------+-------------+
              |
              v
+---------------------------+
|   Packet Parser           |
|  Phân tích L2/VLAN/L3/L4 |
|  Trích xuất five-tuple    |
|  Chuẩn hóa luồng         |
+-------------+-------------+
              |
              v
+---------------------------+
|   ACL Rule Engine         |
|  Phân loại ACL ưu tiên   |
|  Khớp subnet, port range, |
|  protocol, wildcard       |
+-------------+-------------+
              |
         +----+----+
         |         |
         v         v
   [FORWARD]     [DROP]
         |         |
         v         v
+-------------+  Giải phóng mbuf
|  Worker     |  Tăng drop counter
|  Dispatch   |
|  (DPDK Ring)|
+------+------+
       |
       v
+---------------------------+
|   Worker Cores            |
|  (N lcore cấu hình được) |
|  Nhận, hạch toán, giải   |
|  phóng mbuf               |
+-------------+-------------+
              |
              v
+------------------------------------------+
|   Statistics and Logging Component       |
|  Thu thập counter theo chu kỳ từ các    |
|  lcore; tính Mbps, PPS; ghi log         |
|  runtime; xuất thống kê định kỳ 1 giây  |
|  và tóm tắt cuối phiên ra stdout        |
+------------------------------------------+
```

**Mô tả các giai đoạn:**

| Giai đoạn | Mục đích |
|---|---|
| File PCAP | Nguồn lưu lượng mạng đã bắt sẵn; cung cấp đầu vào kiểm thử xác định và có thể tái hiện |
| DPDK PCAP PMD | Virtual device net_pcap trình bày file PCAP như một DPDK port logic; mbuf được điền dữ liệu từ frame PCAP |
| Packet Receive | RX burst poll-mode từ virtual port; chuyển batch mbuf đến parser để xử lý hiệu quả CPU |
| Packet Parser | Giải mã tuần tự header Ethernet, VLAN tùy chọn, IPv4 và TCP/UDP; trích xuất five-tuple; thực hiện chuẩn hóa luồng hai chiều |
| ACL Rule Engine | Khớp five-tuple đã chuẩn hóa với bộ ACL rule đã nạp bằng cơ chế chọn theo ưu tiên; xác định hành động filter-group tương ứng |
| Filter Group Action | Áp dụng hành động (FORWARD hoặc DROP) cho nhóm đã khớp; với DROP, giải phóng mbuf ngay lập tức; với FORWARD, enqueue vào worker ring |
| Worker Cores | Drain ring được gán; thực hiện hạch toán theo từng gói tin; giải phóng mbuf về mempool |
| Statistics and Logging Component | Thu thập counter từ tất cả lcore theo chu kỳ; tính toán Throughput và PPS; ghi log runtime theo khoảng thời gian 1 giây; xuất tóm tắt cuối phiên ra stdout |

---

## 2. Thiết Kế Thành Phần

### 2.1 Thành Phần Khởi Tạo DPDK

**Trách nhiệm:**

Thành phần Khởi Tạo DPDK là hệ thống con đầu tiên thực thi khi ứng dụng khởi động. Thành phần này chịu trách nhiệm đưa môi trường runtime DPDK vào trạng thái hoạt động đầy đủ trước khi bất kỳ gói tin nào được nhận hoặc bất kỳ rule nào được đánh giá.

Các trách nhiệm cụ thể bao gồm:

- Phân tích tham số EAL từ dòng lệnh và khởi tạo DPDK Environment Abstraction Layer (EAL), thiết lập ánh xạ lcore-to-CPU affinity, memory channel mapping và hugepage backing.
- Cấp phát và cấu hình một hoặc nhiều DPDK mempool từ bộ nhớ hugepage để làm nguồn cung cấp đối tượng mbuf trong suốt vòng đời ứng dụng. Kích thước mempool phải tính đến số lượng mbuf đang in-flight tối đa trên tất cả giai đoạn pipeline và ring buffer.
- Cấu hình PMD virtual device `net_pcap`, liên kết với đường dẫn file PCAP được cung cấp qua dòng lệnh. Virtual port được cấu hình với một RX queue.
- Khởi tạo các cấu trúc ring lock-free của DPDK dùng cho giao tiếp liên lõi giữa classifier và từng worker lcore.
- Ghim các lcore vào vai trò được chỉ định (RX/classifier lcore và worker lcore) theo số lượng Worker Core đã cấu hình.

Nếu bất kỳ bước khởi tạo nào thất bại, thành phần này phát ra thông báo lỗi mô tả rõ hệ thống con bị lỗi và kết thúc ứng dụng. Trạng thái khởi tạo một phần không được phép; ứng dụng không tiến hành xử lý gói tin trừ khi tất cả tài nguyên đã được cấp phát và cấu hình đầy đủ.

### 2.2 Thành Phần Nhận Gói Tin (Packet Receive)

**Trách nhiệm:**

Thành phần Nhận Gói Tin vận hành trên RX lcore được dành riêng. Thành phần này liên tục poll virtual port `net_pcap` bằng DPDK burst receive API (`rte_eth_rx_burst`) để drain các mbuf có sẵn từ PMD vào local burst buffer.

Các trách nhiệm cụ thể bao gồm:

- Phát lệnh burst receive đến RX queue của virtual port đã cấu hình. Burst size có thể cấu hình tại build time để cân bằng giữa độ trễ và hiệu quả CPU.
- Phát hiện kết thúc đầu vào: khi PMD `net_pcap` báo hiệu rằng tất cả frame PCAP đã được tiêu thụ (burst count trả về bằng không trong khoảng thời gian nhất định), thành phần này khởi tạo chuỗi tắt máy có trật tự cho pipeline.
- Chuyển các burst mbuf đã nhận trực tiếp đến Thành Phần Packet Parser. Không thực hiện sao chép; xử lý là zero-copy từ PMD vào giai đoạn parsing.
- Duy trì bộ đếm chạy cho số mbuf đã nhận phục vụ hạch toán thống kê.

Thành phần Nhận Gói Tin không thực hiện bất kỳ thao tác lọc, phân loại hay quản lý bộ nhớ nào ngoài việc nhận mbuf. Chức năng duy nhất của nó là chuyển mbuf hiệu quả theo batch từ PMD đến parser.

### 2.3 Thành Phần Phân Tích Gói Tin (Packet Parser)

**Trách nhiệm:**

Thành phần Packet Parser xử lý từng mbuf theo thứ tự, giải mã cấu trúc header từng lớp của gói tin để trích xuất metadata phân loại. Toàn bộ parsing được thực hiện in-place trên dữ liệu mbuf; không cấp phát thêm bộ nhớ cho mỗi gói tin trong trạng thái hoạt động ổn định.

**Chuỗi parsing:**

1. **Phân tích Ethernet header (FR-005):** Đọc 14-byte Ethernet II header. Trích xuất trường EtherType để xác định giao thức lớp tiếp theo.

2. **Xử lý VLAN header (FR-006):** Nếu EtherType bằng `0x8100` (IEEE 802.1Q), parser bóc VLAN tag 4 byte và đọc lại inner EtherType. VLAN ID được giữ lại như metadata chẩn đoán tùy chọn. Cả frame có thẻ lẫn không có thẻ đều được xử lý trên một đường mã thống nhất sau khi bóc thẻ.

3. **Phân tích IPv4 header (FR-007):** Nếu EtherType bằng `0x0800`, parser giải mã IPv4 header, trích xuất IP nguồn, IP đích, số giao thức IP và IHL (để tính offset L4). Các gói tin có EtherType khác được phân loại là không được hỗ trợ và bị hủy; counter giao thức không hỗ trợ được tăng lên và mbuf được giải phóng.

4. **Phân tích header tầng giao vận (FR-008):** Với giao thức 6 (TCP) hoặc 17 (UDP), parser giải mã transport header bằng offset tính từ IHL và trích xuất số cổng nguồn và đích. Các gói tin mang giao thức IP khác bị hủy là không được hỗ trợ.

5. **Ghép five-tuple (FR-009):** Parser ghép các trường đã trích xuất thành bản ghi metadata five-tuple: `{src_ip, dst_ip, src_port, dst_port, protocol}`.

6. **Chuẩn hóa luồng hai chiều (FR-012, FR-013):** Parser biến đổi five-tuple thành canonical flow key sao cho gói tin chiều đi và chiều về của cùng một luồng hai chiều tạo ra cùng một khóa. Thuật toán chuẩn hóa có tính xác định và phi trạng thái: nó sắp xếp lại cặp (IP, port) endpoint sao cho endpoint có địa chỉ IP số học nhỏ hơn (hoặc cổng nhỏ hơn làm tiebreaker) luôn được đặt ở vị trí "source". Không có flow table hay trạng thái theo từng luồng nào được cấp phát hay tham chiếu.

**Xử lý gói tin không hợp lệ (FR-010, FR-011):** Bất kỳ gói tin nào không thể phân tích đầy đủ (header bị lỗi, frame bị cắt ngắn, EtherType không phải IPv4 sau khi bóc VLAN, giao thức IP không được hỗ trợ) đều bị hủy một cách im lặng. mbuf được giải phóng ngay lập tức. Counter gói tin không hợp lệ được tăng lên. Lỗi parsing không ảnh hưởng đến xử lý các gói tin tiếp theo.

### 2.4 Thành Phần ACL Rule Engine

**Trách nhiệm:**

Thành phần ACL Rule Engine là lõi phân loại của SPIFast. Nó nhận bản ghi metadata five-tuple đã chuẩn hóa từ parser và xác định rule đã nạp nào — nếu có — khớp với gói tin, cùng với hành động filter-group và precedence tương ứng.

**Nạp rule:**

Khi khởi động, sau khi DPDK khởi tạo xong, rule engine đọc và phân tích file cấu hình rule. Với mỗi mục rule, engine trích xuất:

- Điều kiện khớp cho từng trường five-tuple: giá trị chính xác, wildcard, tiền tố CIDR subnet IPv4, port range (min–max), hoặc địa chỉ IP host.
- Tên filter-group liên kết cùng với action và số nguyên precedence đã khai báo của group.

Các rule đã phân tích được biên dịch vào cấu trúc phân loại ACL nội bộ, được tối ưu hóa cho việc tra cứu lặp lại. Tất cả rule phải được biên dịch và cấu trúc phải được làm bất biến trước khi gói tin đầu tiên được nhận. Không hỗ trợ chỉnh sửa rule trong runtime.

**ACL matching:**

Với mỗi gói tin đã phân tích, engine thực hiện tra cứu bằng normalized five-tuple key so với cấu trúc ACL đã biên dịch. Logic khớp đánh giá các kiểu điều kiện sau cho mỗi trường:

| Kiểu điều kiện | Trường áp dụng | Ngữ nghĩa khớp |
|---|---|---|
| Exact match | Tất cả trường | Giá trị trường phải bằng chính xác giá trị được chỉ định trong rule |
| Wildcard | Tất cả trường | Bất kỳ giá trị trường nào đều được chấp nhận |
| IPv4 subnet match | src_ip, dst_ip | Giá trị trường phải nằm trong tiền tố CIDR (network/mask) |
| IPv4 host address match | src_ip, dst_ip | Giá trị trường phải bằng chính xác địa chỉ host được chỉ định |
| Port range match | src_port, dst_port | Giá trị trường phải nằm trong phạm vi bao gồm [min, max] |
| Protocol match | protocol | Giá trị trường phải khớp với số giao thức được chỉ định |

Nhiều điều kiện trong một rule duy nhất được kết hợp theo ngữ nghĩa logic AND. Một gói tin khớp với một rule chỉ khi tất cả điều kiện được chỉ định trong rule đó đều được thỏa mãn đồng thời.

**Xử lý precedence và chế độ khớp:**

Rule engine hỗ trợ hai chế độ khớp có thể cấu hình, chọn qua tham số dòng lệnh khi khởi động (mặc định: first-match):

- **Chế độ First-match:** Các rule được đánh giá theo thứ tự precedence tăng dần. Rule đầu tiên có điều kiện được thỏa mãn bởi gói tin sẽ được chọn. Không đánh giá thêm rule nào nữa.
- **Chế độ Best-match:** Tất cả rule có điều kiện được thỏa mãn bởi gói tin đều là ứng viên. Ứng viên có số precedence nhỏ nhất (ưu tiên cao nhất) được chọn.

Một rule mặc định (catch-all) bắt buộc với số precedence cao nhất (ưu tiên thấp nhất) phải có mặt trong bộ rule. Rule này khớp với tất cả gói tin không được khớp bởi bất kỳ rule đặc hiệu hơn nào, đảm bảo mọi gói tin đều nhận được một hành động (FR-017, FR-023).

**Đếm lượt khớp rule (FR-020):**

Engine duy trì counter hit atomic theo từng rule hoặc từng filter-group. Counter cho rule hoặc group đã khớp được tăng lên với mỗi gói tin được phân loại. Các counter này được xuất đến thành phần Statistics and Logging.

**Giới hạn số lượng rule (FR-019):**

Rule engine hỗ trợ tối đa 99 rule. Các file rule chứa từ 100 rule trở lên sẽ bị từ chối trong quá trình kiểm tra khi khởi động.

### 2.5 Thành Phần Filter Group

**Trách nhiệm:**

Thành phần Filter Group là một phần logic của giai đoạn đầu ra phân loại. Nó ánh xạ kết quả phân loại của rule engine (tên filter-group đã khớp và hành động) sang hành động xử lý gói tin phù hợp.

**Ánh xạ group-to-action:**

Mỗi filter group trong cấu hình có một hành động đã khai báo:

| Hành động | Xử lý |
|---|---|
| FORWARD / ALLOW | mbuf được enqueue vào DPDK ring được chỉ định cho một trong các worker lcore có sẵn. Dispatcher chọn target worker ring theo chiến lược phân phối (xem Mục 4). |
| DROP | mbuf được giải phóng ngay lập tức về mempool. Drop counter được tăng lên. Gói tin không đến bất kỳ Worker Core nào. |

Mỗi gói tin đi vào giai đoạn này nhận đúng một hành động. Rule mặc định đảm bảo không có gói tin nào thoát khỏi pipeline phân loại mà không có hành động được gán (FR-023).

**Vòng đời mbuf khi DROP:** Khi một gói tin bị hủy, mbuf phải được giải phóng về mempool trên cùng code path, không có deferred release. Điều này đảm bảo không có rò rỉ mbuf trên đường DROP (FR-004, FR-027).

### 2.6 Thành Phần Statistics and Logging

**Trách nhiệm:**

Thành phần Statistics and Logging được tách biệt thành hai chức năng phối hợp với nhau: thu thập số liệu runtime (Statistics) và xuất log thực thi (Logging). Thành phần này vận hành trên main lcore hoặc một lcore thống kê riêng biệt, độc lập với các lcore xử lý data path.

**Quyết định kiến trúc quan trọng — Tách biệt fast path và logging path:**

Logging không được đưa overhead xử lý nặng vào packet fast path. Các Worker Core và thành phần data path chỉ cập nhật counter nội bộ cục bộ theo từng lcore (local per-lcore counters) mà không thực hiện bất kỳ thao tác I/O hay đồng bộ hóa nặng nào. Thành phần Statistics and Logging đọc các counter đó theo định kỳ, tổng hợp kết quả và ghi log ra stdout. Cách tiếp cận này đảm bảo fast path luôn lock-free và không bị tác động bởi hoạt động ghi log.

#### 2.6.1 Statistics Component

**Thu thập và duy trì số liệu:**

Statistics Component chịu trách nhiệm thu thập, tổng hợp và duy trì các số liệu hiệu năng và hạch toán runtime. Thành phần đọc counter từ tất cả lcore theo chu kỳ 1 giây. Tất cả counter được cập nhật bởi các thành phần data path (Packet Receive, Packet Parser, ACL Rule Engine, Worker Cores) dưới dạng biến cục bộ per-lcore; Statistics Component đọc và tổng hợp chúng theo chu kỳ mà không cần khóa (lock-free aggregation).

**Số liệu được theo dõi:**

| Số liệu | Phạm vi | Mô tả |
|---|---|---|
| RX packets (theo chu kỳ) | Chu kỳ | Gói tin nhận được từ PMD trong khoảng 1 giây vừa qua |
| RX packets (lũy kế) | Phiên | Tổng gói tin nhận được từ khi ứng dụng khởi động |
| Processed packets (lũy kế) | Phiên | Tổng gói tin được chuyển tiếp đến Worker Core |
| Dropped packets (lũy kế) | Phiên | Tổng gói tin bị hủy do hành động DROP của rule |
| Invalid packets (lũy kế) | Phiên | Tổng gói tin bị hủy do lỗi parsing |
| Throughput | Chu kỳ | Tốc độ dữ liệu tính bằng Mbps trong khoảng 1 giây vừa qua |
| PPS | Chu kỳ | Tốc độ gói tin trong khoảng 1 giây vừa qua |
| Rule / group hit counts | Lũy kế | Số lượt khớp theo từng rule hoặc từng group từ khi khởi động |

**Tính toán số liệu:**

Statistics Component tính các số liệu sau từ giá trị delta giữa hai lần lấy mẫu:

```
Throughput (Mbps) = (Delta bytes × 8) / Khoảng thời gian lấy mẫu (giây) / 1.000.000

PPS = Delta packets / Khoảng thời gian lấy mẫu (giây)
```

**Xác nhận gói tin bị mất (FR-032):**

Cuối phiên, Statistics Component xác minh:

```
RX_total == FORWARD_total + DROP_total + Invalid_total
```

Bất kỳ sai lệch nào được báo cáo là lỗi gói tin bị mất. Một phiên sạch báo cáo zero gói tin không được hạch toán.

#### 2.6.2 Logging Component

**Trách nhiệm xuất log:**

Logging Component chịu trách nhiệm xuất số liệu thống kê đã tổng hợp ra đầu ra tiêu chuẩn (stdout) và ghi log thực thi phục vụ xác nhận và đo hiệu năng. Toàn bộ hoạt động ghi I/O được thực hiện ngoài fast path, trên lcore thống kê riêng biệt.

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
| Processed packets (tổng) | Gói tin được điều phối đến Worker từ khi khởi động |
| Dropped packets (tổng) | Gói tin bị hủy do hành động rule từ khi khởi động |
| Invalid packets (tổng) | Gói tin bị hủy do lỗi parsing từ khi khởi động |
| Throughput | Throughput đo được tính bằng Mbps cho chu kỳ hiện tại |
| PPS | Tốc độ gói tin đo được cho chu kỳ hiện tại |
| Lượt khớp theo nhóm | Số lượt khớp theo từng filter group từ khi khởi động |

---

## 3. Luồng Xử Lý Gói Tin

### 3.1 Trường Hợp Bình Thường — Gói Tin Khớp Rule FORWARD

Mô tả dưới đây trình bày vòng đời đầy đủ của một gói tin được phân tích thành công và khớp với rule FORWARD.

```
Bước 1: PCAP PMD RX
  - net_pcap PMD đọc frame tiếp theo từ file PCAP.
  - Một mbuf được cấp phát từ mempool và điền dữ liệu frame.
  - mbuf được đặt vào RX queue của PMD.

Bước 2: Burst Receive
  - RX lcore phát lệnh rte_eth_rx_burst() đến virtual port.
  - Một burst tối đa [burst_size] mbuf được trả về.
  - RX counter được tăng theo số lượng burst.

Bước 3: Phân Tích Ethernet
  - Với mỗi mbuf trong burst:
    - Ethernet header được đọc từ offset 0 của dữ liệu mbuf.
    - EtherType được trích xuất.

Bước 4: Bóc VLAN (có điều kiện)
  - Nếu EtherType == 0x8100:
    - VLAN tag được phân tích; VLAN ID được giữ lại như metadata.
    - Inner EtherType được đọc.

Bước 5: Phân Tích IPv4 Header
  - Nếu EtherType == 0x0800:
    - src_ip, dst_ip, protocol và IHL được trích xuất.
  - Ngược lại: hủy mbuf, tăng invalid counter, chuyển sang mbuf tiếp theo.

Bước 6: Phân Tích Transport Header
  - Nếu protocol == 6 (TCP) hoặc 17 (UDP):
    - src_port và dst_port được trích xuất từ L4 header tại offset tính từ IHL.
  - Ngược lại: hủy mbuf, tăng invalid counter, tiếp tục.

Bước 7: Ghép Five-Tuple
  - Bản ghi five-tuple {src_ip, dst_ip, src_port, dst_port, protocol} được ghép lại.

Bước 8: Flow Normalization
  - Five-tuple được chuẩn hóa thành canonical form sao cho luồng chiều đi
    và chiều về dùng chung một khóa.
  - Không cấp phát trạng thái; chuẩn hóa là hàm thuần túy của five-tuple.

Bước 9: ACL Lookup
  - Five-tuple đã chuẩn hóa được gửi đến ACL rule engine.
  - Engine đánh giá rule theo thứ tự precedence (first-match hoặc best-match
    theo cấu hình).
  - Tên filter-group và hành động của rule đã khớp được trả về.
  - Rule/group hit counter được tăng nguyên tử.

Bước 10: Action Dispatch — FORWARD
  - Hành động là FORWARD.
  - Target worker ring được chọn (chiến lược dispatcher — xem Mục 4).
  - mbuf được enqueue vào worker ring đã chọn bằng rte_ring_enqueue().
  - FORWARD counter được tăng.

Bước 11: Xử Lý Tại Worker
  - Target worker lcore drain ring bằng rte_ring_dequeue_burst().
  - Với mỗi mbuf đã dequeue:
    - Worker packet counter được tăng.
    - Worker byte counter được cập nhật.
    - mbuf được giải phóng về mempool qua rte_pktmbuf_free().

Bước 12: Cập Nhật Thống Kê
  - Statistics Component đọc per-core counter theo chu kỳ 1 giây của nó.
  - Throughput (Mbps) và PPS được tính từ giá trị delta.
  - Logging Component xuất bản ghi thống kê ra stdout.
```

### 3.2 Trường Hợp Hủy — Gói Tin Khớp Rule DROP

Bước 1–9 giống với trường hợp bình thường. Luồng phân kỳ tại Bước 10:

```
Bước 10 (đường DROP): Action Dispatch — DROP
  - Hành động là DROP.
  - rte_pktmbuf_free() được gọi ngay lập tức trên mbuf.
  - DROP counter được tăng.
  - mbuf được trả về mempool.
  - Không thực hiện ring enqueue.
  - Không có worker lcore nào tham gia.
```

### 3.3 Trường Hợp Không Khớp Rule — Rule Mặc Định

Nếu không có rule nào được cấu hình tường minh khớp với five-tuple đã chuẩn hóa của gói tin, rule catch-all mặc định (ưu tiên thấp nhất, số precedence cao nhất) được chọn. Hành động liên kết với default filter group (thường là DROP theo cấu hình tham chiếu trong SRS) được áp dụng. Trường hợp này đi theo đường DROP ở Bước 10. Default rule hit counter được tăng lên.

### 3.4 Trường Hợp Gói Tin Không Hợp Lệ

Nếu parsing thất bại ở bất kỳ giai đoạn nào (EtherType không được hỗ trợ, giao thức IP không được hỗ trợ, header bị cắt ngắn), mbuf được giải phóng ngay tại điểm xảy ra lỗi. Invalid-packet counter được tăng lên. Quá trình xử lý tiếp tục với mbuf tiếp theo trong burst. Không thực hiện ACL lookup cho gói tin không hợp lệ.

### 3.5 Xử Lý Kết Thúc PCAP

Khi PMD `net_pcap` đã replay hết tất cả frame, các lệnh `rte_eth_rx_burst()` tiếp theo trả về không mbuf. Thành phần RX phát hiện điều kiện này và khởi tạo quá trình tắt máy có trật tự: báo hiệu các worker lcore drain ring của chúng và thoát, chờ tất cả worker hoàn tất, sau đó Statistics and Logging Component xuất tóm tắt phiên cuối cùng và kết quả xác nhận gói tin bị mất trước khi ứng dụng thoát.

---

## 4. Thiết Kế Kiến Trúc Đa Lõi

### 4.1 Mô Hình Kiến Trúc

SPIFast áp dụng mô hình đa lõi **dispatcher-worker**. Mô hình này tách biệt chức năng nhận, phân tích và phân loại (thực hiện trên một lcore dành riêng) khỏi chức năng xử lý sau phân loại (thực hiện trên N worker lcore cấu hình được).

```
  CPU Core 0 (Main / Stats lcore)
  ┌────────────────────────────────────┐
  │  Khởi tạo ứng dụng                │
  │  Nạp rule                          │
  │  Statistics Timer (thu thập định  │
  │  kỳ từ tất cả lcore)              │
  │  Logging (xuất log ra stdout)     │
  │  Điều phối tắt máy                │
  └────────────────────────────────────┘

  CPU Core 1 (RX / Classifier lcore)
  ┌────────────────────────────────────┐
  │  net_pcap PMD Poll                 │
  │  Packet Parser                     │
  │  Flow Normalizer                   │
  │  ACL Rule Engine                   │
  │  Action Dispatcher                 │
  │    → Ring[0] (Worker 0)            │
  │    → Ring[1] (Worker 1)            │
  │    → Ring[N-1] (Worker N-1)        │
  └────────────────────────────────────┘
        |           |
        v           v
  ┌──────────┐  ┌──────────┐
  │ Worker 0 │  │ Worker 1 │  ... Worker N-1
  │ Ring[0]  │  │ Ring[1]  │
  │ Drain    │  │ Drain    │
  │ Account  │  │ Account  │
  │ Free     │  │ Free     │
  └──────────┘  └──────────┘
        |           |
        +-----+-----+
              |  (per-lcore counters được đọc theo chu kỳ)
              v
  ┌────────────────────────────────────┐
  │  Statistics and Logging Component  │
  │  (chạy trên Main lcore)            │
  │  Tổng hợp counter, tính Mbps/PPS  │
  │  Ghi log ra stdout mỗi 1 giây     │
  └────────────────────────────────────┘
```

### 4.2 Mô Hình Giao Tiếp Ring

Giao tiếp liên lõi giữa classifier lcore và từng worker lcore sử dụng `rte_ring` của DPDK — ring buffer lock-free theo mô hình SPSC (single-producer, single-consumer) hoặc SPMC. Mỗi worker lcore có ring riêng của mình, loại bỏ tranh chấp giữa các worker ở phía consumer. Classifier lcore đóng vai trò là producer duy nhất cho mỗi ring.

Các thuộc tính chính của mô hình giao tiếp này:

- **Hoạt động lock-free trên data path:** `rte_ring_enqueue()` và `rte_ring_dequeue_burst()` là các thao tác lock-free, đáp ứng NFR-003.
- **Không có system call trên data path:** Tất cả thao tác ring là userspace memory operation, nhất quán với nguyên tắc kernel-bypass của DPDK (NFR-002).
- **Xử lý backpressure:** Nếu worker ring đầy (điều kiện quá tải thoáng qua), classifier có thể hủy gói tin thay vì block. Điều này tạo thành unintended drop và được tính vào ngân sách drop rate ≤0,1% (PR-005). Kích thước ring phải được chọn để giảm thiểu tình huống này dưới tải dự kiến.

### 4.3 Chiến Lược Phân Phối Worker

Classifier lcore chọn destination worker ring cho mỗi gói tin được phân loại là FORWARD. Ý định kiến trúc là phân phối cân bằng trên tất cả worker có sẵn. Thuật toán cụ thể (ví dụ: round-robin theo số gói tin, hash theo flow key, hoặc lựa chọn ngẫu nhiên) là chi tiết triển khai được để lại cho SDD. Chiến lược được chọn không được yêu cầu trạng thái chia sẻ giữa các lõi mà sẽ đưa locking vào data path.

Với các kịch bản chỉ có một worker lcore được cấu hình, tất cả gói tin FORWARD được điều phối đến worker ring duy nhất đó.

### 4.4 Cấu Hình Số Lượng Worker

Số lượng worker lcore được chỉ định thông qua tham số dòng lệnh khi khởi động ứng dụng (FR-025). Hệ thống không hardcode số lượng Worker Core. Cấu hình tối thiểu được hỗ trợ là một worker lcore. Giới hạn thực tế tối đa bị ràng buộc bởi số lõi CPU có sẵn trừ đi số lõi cần cho main/stats lcore và RX/classifier lcore.

EAL lcore mask hoặc tham số `--lcores` ánh xạ lcore ID logic sang lõi CPU vật lý. Việc gán CPU vật lý cho lcore là mối quan tâm vận hành được ghi trong hướng dẫn triển khai; cô lập CPU (tham số kernel `isolcpus`) được khuyến nghị cho các phép đo hiệu năng gần với môi trường sản xuất (điều kiện PR-005).

### 4.5 Xem Xét Thứ Tự Gói Tin

SPIFast không cung cấp đảm bảo về thứ tự gói tin trên các Worker Core. Khi N > 1 worker đang hoạt động, các gói tin được điều phối đến các worker ring khác nhau có thể được xử lý theo thứ tự khác với chuỗi PCAP gốc. Điều này được chấp nhận về mặt kiến trúc cho trường hợp sử dụng SPIFast vì:

- Worker chỉ thực hiện hạch toán và giải phóng mbuf; không tạo ra luồng đầu ra có thứ tự.
- Thống kê được tổng hợp trên tất cả worker; thứ tự trong ring của từng worker được bảo toàn (ngữ nghĩa ring FIFO).

Nếu yêu cầu thứ tự nghiêm ngặt trong một mở rộng tương lai, cần đưa reorder buffer vào, làm tăng độ trễ và overhead bộ nhớ — không nhất quán với mục tiêu Throughput cao hiện tại.

### 4.6 Xem Xét Cân Bằng Tải

Trong kiến trúc hiện tại, giai đoạn phân loại là đơn luồng (một RX/classifier lcore). Throughput phân loại tối đa của hệ thống bị giới hạn bởi năng lực của lõi đơn đó. Đây là quyết định đơn giản hóa thiết kế có chủ ý, nhất quán với quy mô mục tiêu của hệ thống (tốc độ liên kết mô phỏng ≤1 Gbps). Tại giới hạn hiệu năng mục tiêu (≥700 Mbps, ≥500 Kpps), một lõi CPU hiện đại chạy DPDK poll-mode hoàn toàn có khả năng duy trì tốc độ phân loại yêu cầu.

Nếu Throughput phân loại trở thành bottleneck ở quy mô cao hơn, kiến trúc có thể được mở rộng sang mô hình RSS (Receive-Side Scaling) đối xứng với nhiều classifier core, mỗi core sở hữu một tập con của không gian luồng. Điều này được xác định là hướng mở rộng tương lai (Mục 9).

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
  - Kiểm tra giới hạn số lượng rule (< 100)
  - Phát hiện tên rule trùng lặp
       |
       v
  Xây Dựng Bảng Filter Group
  - Phân tích khai báo group
  - Liên kết tên group với giá trị action và precedence
       |
       v
  Biên Dịch ACL Rules
  - Ánh xạ từng mục rule thành ACL classification entry nội bộ
  - Gán ưu tiên dựa trên số nguyên precedence đã khai báo
  - Biên dịch các entry vào cấu trúc tra cứu ACL
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
  Sẵn Sàng Phân Loại Gói Tin
```

Nếu bất kỳ bước kiểm tra nào thất bại, ứng dụng phát ra thông báo lỗi mô tả rõ mục bị lỗi và kết thúc. Nạp rule một phần khi có lỗi không được phép (RC-006).

### 5.2 Bảng Kiểm Tra Hợp Lệ

| Kiểm tra | Rule | Hành vi khi lỗi |
|---|---|---|
| Định dạng địa chỉ IP (dotted-decimal) | RC-002 | Lỗi + kết thúc |
| Định dạng tiền tố CIDR (a.b.c.d/len, len 0–32) | RC-002 | Lỗi + kết thúc |
| Tính hợp lệ port range (min ≤ max, giá trị 0–65535) | RC-002 | Lỗi + kết thúc |
| Giá trị giao thức (tcp, udp, hoặc wildcard) | RC-002 | Lỗi + kết thúc |
| Giới hạn số lượng rule (< 100 rule) | FR-019 | Lỗi + kết thúc |
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

Mỗi rule đã được kiểm tra hợp lệ được dịch thành ACL entry nội bộ mã hóa điều kiện khớp theo từng trường và ưu tiên liên kết (suy ra từ số nguyên precedence của group). ACL engine sắp xếp các entry theo ưu tiên để tra cứu. Khi hai rule có cùng giá trị precedence nhưng khác nhau ở các trường khác (ví dụ: điều kiện giao thức khác nhau trong cùng một group), engine coi chúng là các entry riêng biệt với ưu tiên bằng nhau; hành vi tie-breaking trong trường hợp này được định nghĩa trong SDD.

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

**Tính tái hiện (TR-007):** Công cụ sinh phải tạo ra đầu ra PCAP bit-identical khi được gọi với cùng file cấu hình profile. Điều này cho phép thực thi kiểm thử lặp lại trên các phiên khác nhau và giữa các kỹ sư khác nhau.

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
  Đầu Ra Thống Kê Runtime (stdout)
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

Throughput được đo là tốc độ dữ liệu được xử lý qua giai đoạn phân loại, bao gồm cả gói tin FORWARD lẫn DROP (tức là tất cả gói tin mà quá trình parsing thành công và một hành động phân loại đã được thực hiện).

**Công thức (SRS PR-001):**

```
Throughput (Mbps) = (Tổng byte đã xử lý × 8) / Thời gian runtime (giây) / 1.000.000
```

Byte đã xử lý được tích lũy theo từng mbuf từ trường `pkt_len` của mbuf. Thời gian runtime là thời gian wall-clock từ khi gói tin đầu tiên được nhận đến khi gói tin cuối cùng được xử lý.

**Tiêu chí chấp nhận:**

| Kết quả | Tiêu chí |
|---|---|
| PASS | ≥ 700 Mbps duy trì |
| EXCELLENT | ≥ 950 Mbps duy trì |
| FAIL | < 700 Mbps |

### 7.3 Tốc Độ Gói Tin (PPS)

PPS được đo là số gói tin mà giai đoạn phân loại hoàn tất một hành động (FORWARD hoặc DROP) trong một đơn vị thời gian.

**Công thức (SRS PR-003):**

```
PPS = Tổng gói tin đã phân loại / Thời gian runtime (giây)
```

**Tiêu chí chấp nhận:**

| Kết quả | Tiêu chí |
|---|---|
| PASS | ≥ 500.000 pps duy trì |
| EXCELLENT | ≥ 1.488.000 pps duy trì |
| FAIL | < 500.000 pps |

Mục tiêu EXCELLENT 1.488.000 pps tương ứng với tốc độ gói tin line-rate lý thuyết cho frame Ethernet 64 byte trên liên kết 1 Gbps.

### 7.4 Tỷ Lệ Rơi Gói Tin (Unintended)

Tỷ lệ rơi gói tin ngoài ý muốn đo lường sự mất gói tin do các ràng buộc năng lực hệ thống (ví dụ: ring overflow), không phải do hành động DROP được cấu hình trong rule.

**Công thức (SRS PR-005):**

```
Tỷ lệ rơi (%) = (Gói tin rơi ngoài ý muốn / Tổng gói tin RX) × 100
```

Gói tin rơi ngoài ý muốn phải được phân biệt với gói tin bị hủy do hành động rule trong thiết kế counter. DROP theo rule là hành vi mong đợi và không được tính vào giới hạn tỷ lệ rơi.

**Tiêu chí chấp nhận:** Tỷ lệ rơi ngoài ý muốn ≤ 0,1% dưới tải duy trì với bất kỳ traffic profile nào đã định nghĩa.

### 7.5 Xác Nhận Gói Tin Bị Mất (Yêu Cầu Zero Loss)

Cuối phiên, hệ thống xác nhận rằng mọi gói tin trong PCAP đầu vào đã được hạch toán (PR-006, FR-032):

```
Điều kiện PASS:
  RX_total == FORWARD_total + DROP_total + Invalid_total

Điều kiện FAIL:
  Bất kỳ sai lệch dương nào giữa RX_total và tổng các disposition
```

Xác nhận này được báo cáo trong log tóm tắt phiên cuối cùng.

### 7.6 Điều Kiện Đo

Theo SRS Mục 5.5, các phép đo hiệu năng phải được thực hiện trong các điều kiện sau:

- Hugepages được cấp phát trước và xác nhận có sẵn trước khi chạy kiểm thử
- Không có ứng dụng xử lý gói tin nào khác chạy đồng thời trên máy chủ
- DPDK lcore được ghim vào các lõi CPU cô lập khi có thể (khuyến nghị `isolcpus`)
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
| DD-04 | Mô hình nạp rule | Nạp tĩnh khi khởi động; không cập nhật runtime | Loại bỏ nhu cầu đồng bộ hóa truy cập đồng thời giữa rule engine và code phân loại data path. Nhất quán với CON-06. Biên dịch rule vào cấu trúc ACL khi khởi động cho phép classification engine vận hành với dữ liệu chỉ đọc, cải thiện hành vi cache. |
| DD-05 | Khớp rule dựa trên ưu tiên | Số nguyên precedence gán cho từng group; giá trị thấp hơn = ưu tiên cao hơn | Cung cấp thứ tự đánh giá rule xác định và do người vận hành kiểm soát. Cho phép rule catch-all mặc định luôn được đánh giá cuối cùng (số precedence cao nhất). Đáp ứng FR-016 và FR-017. |
| DD-06 | Cơ chế I/O gói tin | DPDK net_pcap PMD; không dùng NIC vật lý | Loại bỏ yêu cầu phần cứng NIC chuyên dụng, cho phép phát triển và xác nhận trên bất kỳ máy Linux nào. Đáp ứng CON-04 và OBJ-01. PCAP replay cung cấp đầu vào kiểm thử xác định và tái hiện được, đáp ứng NFR-007 và NFR-008. |
| DD-07 | Mô hình đa lõi | Dispatcher-worker (1 RX/classifier lcore + N worker lcore) | Tách rời critical path phân loại khỏi xử lý sau phân loại. Classifier lcore đơn tránh nhu cầu về cấu trúc tra cứu ACL thread-safe. Worker lcore vận hành trên các ring độc lập, loại bỏ tranh chấp inter-worker. Đáp ứng NFR-003. |
| DD-08 | Giao tiếp liên lõi | DPDK rte_ring (lock-free ring buffer) | Cung cấp hàng đợi SPSC/SPMC lock-free, cache-efficient giữa classifier và worker. Không có system call trên data path. Đáp ứng NFR-002 và NFR-003. |
| DD-09 | Thu thập thống kê và logging | Per-lcore software counter; Statistics Component tổng hợp định kỳ; Logging Component xuất ra stdout tách biệt khỏi fast path | Tránh phụ thuộc vào hardware performance counter. Cập nhật counter bởi các thành phần data path là thao tác cục bộ không cần khóa. Logging định kỳ bởi thành phần riêng biệt ngăn I/O xâm nhập vào fast path. Đáp ứng NFR-002, NFR-003, LOG-003 và FR-028. |
| DD-10 | Chuẩn hóa luồng hai chiều | Sắp xếp five-tuple chuẩn tắc phi trạng thái (IP/cổng nhỏ hơn luôn ở vị trí source) | Đạt FR-012 mà không cần flow table. Hàm chuẩn hóa là phép biến đổi thuần túy với thời gian hằng số, thêm độ trễ không đáng kể cho mỗi gói tin. Đáp ứng FR-013. |

---

## 9. Hướng Mở Rộng Tương Lai

Thiết kế SPIFast v1.0 hiện tại được phạm vi hóa có chủ ý theo mô hình phân loại SPI xác định rõ ràng. Các mở rộng kiến trúc sau đây được xác định là các hướng phát triển tự nhiên cho các phiên bản tương lai.

### 9.1 Flow Table và Stateful Inspection

Một bảng trạng thái theo từng luồng (hash map được khóa bởi five-tuple đã chuẩn hóa) có thể được đưa vào để cho phép stateful packet inspection. Điều này sẽ cho phép hệ thống theo dõi trạng thái kết nối (máy trạng thái phiên TCP, liên kết dựa trên timeout UDP), tạo điều kiện cho hành vi tường lửa có trạng thái, giới hạn tốc độ kết nối và phát hiện bất thường dựa trên lịch sử theo từng luồng.

Tác động kiến trúc: flow table sẽ yêu cầu thiết kế an toàn truy cập đồng thời (per-flow locking hoặc hash table lock-free), quản lý bộ nhớ cho flow expiry và cơ chế timeout/aging trên một lcore riêng. Đường phân loại phi trạng thái sẽ được giữ lại như fast path cho các lần tra cứu flow table.

### 9.2 Hỗ Trợ NIC Vật Lý

Hỗ trợ NIC vật lý thông qua DPDK hardware PMD (ví dụ: Intel ixgbe, Mellanox mlx5) sẽ cho phép SPIFast vận hành như một packet classifier inline cấp sản xuất ở tốc độ line-rate thực sự (10 GbE, 25 GbE, 100 GbE). Điều này sẽ yêu cầu:

- RX đa hàng đợi dựa trên RSS để phân phối luồng trên nhiều classifier lcore.
- Cấu hình TX queue cho hành động FORWARD (truyền gói tin đến egress port thay vì giải phóng sau xử lý worker).
- Cấp phát bộ nhớ NUMA-aware căn chỉnh với NUMA node của NIC.

### 9.3 Hỗ Trợ IPv6

Mở rộng parser và ACL engine để hỗ trợ IPv6 (RFC 8200) sẽ mở rộng phạm vi bao phủ lưu lượng. Điều này yêu cầu trường địa chỉ 128-bit trong five-tuple, mở rộng định nghĩa trường ACL và parsing chuỗi extension header để xác định vị trí transport layer header. Thuật toán chuẩn hóa sẽ cần thích ứng cho ngữ nghĩa sắp xếp địa chỉ IPv6.

### 9.4 Cập Nhật Rule Động

Chỉnh sửa rule runtime sẽ cho phép người vận hành thêm, xóa hoặc sửa đổi rule mà không cần khởi động lại ứng dụng. Điều này yêu cầu mô hình Read-Copy-Update (RCU) hoặc versioned double-buffer cho cấu trúc phân loại ACL, cho phép data path đọc bộ rule hiện tại mà không cần khóa trong khi một control-plane thread chuẩn bị và cài đặt nguyên tử một phiên bản cập nhật.

### 9.5 Deep Packet Inspection (DPI)

Khả năng DPI sẽ mở rộng phân loại vượt ra ngoài header L2–L4 vào nội dung payload tầng ứng dụng, cho phép nhận dạng giao thức (HTTP, TLS, DNS, QUIC) và thực thi chính sách dựa trên nội dung. Điều này sẽ yêu cầu một payload inspection engine (dựa trên regex, signature hoặc ML) được tích hợp như giai đoạn xử lý sau phân loại trên Worker Core, với reassembly có chọn lọc cho payload bị phân mảnh hoặc đa segment.

### 9.6 Giao Diện Quản Lý

Một giao diện quản lý (gRPC, NETCONF hoặc REST API) sẽ cho phép các hệ thống bên ngoài truy vấn thống kê runtime, lấy rule hit counter và (với hỗ trợ cập nhật rule động) sửa đổi bộ rule đang hoạt động. Điều này sẽ yêu cầu một management lcore riêng và một API contract được định nghĩa rõ ràng, giữ cho lưu lượng quản lý được cô lập khỏi các data path lcore.

---

*Kết thúc tài liệu — SPIFAST-HLD-001-VI v1.1*
