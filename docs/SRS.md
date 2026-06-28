# Đặc Tả Yêu Cầu Phần Mềm

---

**Tiêu đề tài liệu:** Đặc Tả Yêu Cầu Phần Mềm — SPIFast: Hệ Thống Kiểm Tra Gói Tin Hiệu Năng Cao Sử Dụng DPDK

**Mã tài liệu:** SPIFAST-SRS-001

**Phiên bản:** 1.1

**Trạng thái:** Baseline

**Người soạn thảo:** Nhóm Kỹ Thuật Hệ Thống

**Ngày:** 2025-06-26

---

## Lịch Sử Sửa Đổi

| Phiên bản | Ngày | Tác giả | Mô tả |
|---|---|---|---|
| 0.1 | 2025-06-20 | Kỹ thuật hệ thống | Bản thảo ban đầu |
| 0.2 | 2025-06-24 | Kỹ thuật hệ thống | Cập nhật theo kết quả rà soát căn chỉnh kiến trúc |
| 1.0 | 2025-06-26 | Kỹ thuật hệ thống | Baseline sau khi làm rõ yêu cầu |
| 1.1 | 2026-06-27 | Kỹ thuật hệ thống | Thay thế giới hạn "100 rule" bằng mô hình phân cấp filter-group / filter (FR-019, CON-07) |

---

## Mục Lục

1. Giới thiệu
2. Tổng quan hệ thống
3. Yêu cầu chức năng
4. Yêu cầu đầu vào lưu lượng
5. Yêu cầu hiệu năng
6. Yêu cầu cấu hình rule
7. Yêu cầu ghi log runtime
8. Yêu cầu kiểm thử và xác nhận
9. Yêu cầu phi chức năng
10. Ràng buộc và giả định
11. Ma trận truy vết yêu cầu

---

## 1. Giới Thiệu

### 1.1 Mục Đích

Tài liệu này định nghĩa Đặc Tả Yêu Cầu Phần Mềm (SRS) cho **SPIFast** — hệ thống Kiểm Tra Gói Tin Nông (Shallow Packet Inspection) hiệu năng cao được xây dựng trên nền tảng tăng tốc data-plane DPDK. SRS xác lập tập hợp đầy đủ các yêu cầu chức năng, yêu cầu hiệu năng, ràng buộc vận hành và tiêu chí xác nhận chi phối quá trình phát triển và nghiệm thu hệ thống.

Tài liệu này được sử dụng bởi:

- Kiến trúc sư hệ thống và kỹ sư phần mềm chịu trách nhiệm thiết kế và triển khai
- Kỹ sư kiểm thử chịu trách nhiệm lập kế hoạch và thực hiện xác nhận
- Giám sát dự án và cán bộ đánh giá chịu trách nhiệm thẩm định bàn giao

Tài liệu này định nghĩa **những gì** hệ thống phải thực hiện. Các quyết định thiết kế chi tiết bao gồm kiến trúc nội tại, cấu trúc dữ liệu, lập lịch đa lõi và tổ chức bộ nhớ được dành cho tài liệu Thiết Kế Mức Cao (HLD) và Thiết Kế Chi Tiết Phần Mềm (SDD).

### 1.2 Phạm Vi

SPIFast là hệ thống kiểm tra gói tin chạy hoàn toàn trong userspace, không phụ thuộc phần cứng, được thiết kế để vận hành trên một máy tính cá nhân Linux duy nhất. Hệ thống nhận dữ liệu gói tin được replay từ các file Packet Capture (PCAP) thông qua cơ chế DPDK PCAP Virtual Device, thực hiện phân tích cú pháp header từ tầng L2 đến L4, phân loại từng gói tin theo bộ rule cấu hình được, điều phối gói tin đã phân loại đến các đơn vị xử lý Worker song song, và xuất thống kê hiệu năng runtime.

**Trong phạm vi:**

- Nhận gói tin từ DPDK PCAP virtual device
- Phân tích cú pháp header Ethernet, VLAN, IPv4, TCP và UDP
- Trích xuất Five-Tuple và chuẩn hóa luồng hai chiều (bidirectional flow normalization)
- Phân loại gói tin theo kiểu ACL với hành vi so khớp cấu hình được
- Chính sách hành động ở cấp độ filter-group (FORWARD / DROP)
- Xử lý gói tin song song đa lõi với số lượng Worker cấu hình được
- Thu thập và báo cáo thống kê runtime
- Công cụ sinh lưu lượng PCAP cho các traffic profile kiểm thử
- Xác nhận kiểm thử chức năng và hiệu năng

**Ngoài phạm vi:**

- Hỗ trợ phần cứng NIC vật lý
- Phân tích cú pháp và phân loại IPv6
- Deep Packet Inspection (DPI) hoặc phân tích payload tầng ứng dụng
- Theo dõi luồng có trạng thái (stateful flow tracking) hoặc quản lý bảng phiên (session table)
- Cập nhật rule động trong thời gian runtime
- Giao diện quản lý mạng (SNMP, NETCONF, gRPC)

### 1.3 Động Lực Dự Án

Các hàm mạng carrier-grade hiện đại — bao gồm tường lửa (firewall), User Plane Function (UPF) trong mạng 5G và bộ cân bằng tải phần mềm — phụ thuộc vào phân loại gói tin tốc độ cao tại lớp data-plane của mạng. Shallow Packet Inspection (SPI) cho phép các hệ thống này kiểm tra các trường header L2/L3/L4 và áp dụng chính sách chuyển tiếp ở tốc độ line-rate mà không tốn chi phí tính toán cho việc phân tích payload.

DPDK cung cấp framework I/O userspace bỏ qua (bypass) kernel network stack của Linux, cho phép đạt tốc độ xử lý gói tin hàng triệu gói mỗi giây trên phần cứng máy chủ thông thường.

SPIFast được thiết kế nhằm trình bày và xác nhận các nguyên tắc kiến trúc cốt lõi của một hệ thống SPI dựa trên DPDK trong một môi trường đơn máy có thể tái hiện, không yêu cầu phần cứng giao tiếp mạng chuyên dụng, giúp hệ thống có thể tiếp cận để phát triển và đánh giá trên các máy tính cá nhân tiêu chuẩn.

### 1.4 Mục Tiêu

Hệ thống phải đạt được các mục tiêu sau:

| ID | Mục tiêu |
|---|---|
| OBJ-01 | Nhận và xử lý gói tin mạng từ file PCAP sử dụng DPDK net_pcap virtual device |
| OBJ-02 | Phân tích cú pháp header Ethernet, VLAN, IPv4, TCP và UDP với hiệu quả zero-copy |
| OBJ-03 | Phân loại gói tin theo bộ rule cấu hình được hỗ trợ: exact match, wildcard, subnet và port range |
| OBJ-04 | Chuẩn hóa luồng lưu lượng hai chiều để đảm bảo gói tin chiều đi và chiều về khớp cùng một rule mà không cần duy trì trạng thái luồng |
| OBJ-05 | Phân phối gói tin đã phân loại đến các lõi xử lý Worker song song cấu hình được |
| OBJ-06 | Đạt Throughput duy trì tối thiểu 700 Mbps trong các traffic profile kiểm thử tiêu chuẩn |
| OBJ-07 | Đạt tốc độ xử lý gói tin duy trì tối thiểu 500.000 gói tin mỗi giây |
| OBJ-08 | Duy trì tỷ lệ rơi gói tin (packet drop rate) không vượt quá 0,1% dưới tải dự kiến |
| OBJ-09 | Đảm bảo không có gói tin bị mất: tất cả gói tin đọc từ file PCAP phải được hạch toán đầy đủ |
| OBJ-10 | Cung cấp bộ dữ liệu kiểm thử tái hiện được và bằng chứng runtime để đánh giá PASS/FAIL |

### 1.5 Định Nghĩa và Thuật Ngữ

| Thuật ngữ | Định nghĩa |
|---|---|
| ACL | Access Control List. Cơ chế so khớp rule hỗ trợ phân loại đa trường với sắp xếp ưu tiên. |
| Bidirectional Flow | Trao đổi thông tin giữa hai đầu cuối trong đó gói tin có thể đi theo cả hai chiều và phải được coi là thuộc cùng một luồng logic. |
| DPDK | Data Plane Development Kit. Tập hợp thư viện và driver userspace dành cho xử lý gói tin tốc độ cao. |
| EAL | Environment Abstraction Layer. Hệ thống con quản lý khởi tạo và runtime của DPDK. |
| Five-Tuple | Tổ hợp gồm địa chỉ IP nguồn, địa chỉ IP đích, cổng nguồn, cổng đích và số giao thức IP dùng để nhận dạng một luồng mạng. |
| Filter Group | Tập hợp rule có tên dùng chung một chính sách hành động. |
| Flow Normalization | Quá trình tạo ra biểu diễn chuẩn tắc (canonical form) của một five-tuple sao cho gói tin chiều đi và chiều về cho cùng một khóa tra cứu. |
| Hugepages | Trang bộ nhớ ảo lớn (thường 2 MB) được cấp phát trước cho DPDK để quản lý bộ đệm gói tin. |
| lcore | Lõi logic (Logical core). Khái niệm trừu tượng của DPDK cho một luồng CPU được ghim vào lõi CPU vật lý. |
| mbuf | Cấu trúc bộ đệm gói tin của DPDK dùng để biểu diễn một gói tin mạng trong bộ nhớ. |
| Mempool | Vùng bộ nhớ được cấp phát trước của DPDK dùng để cấp phát và giải phóng mbuf hiệu quả. |
| net_pcap PMD | DPDK PCAP Poll Mode Driver. Thiết bị mạng ảo replay gói tin từ file PCAP vào bộ đệm gói tin DPDK. |
| PCAP | Định dạng file Packet Capture (.pcap). Định dạng nhị phân chuẩn để lưu trữ gói tin mạng đã bắt. |
| PMD | Poll Mode Driver. Driver DPDK sử dụng cơ chế polling thay vì ngắt (interrupt) để nhận và truyền gói tin. |
| PPS | Packets Per Second — Gói tin trên mỗi giây. Đơn vị đo Throughput xử lý gói tin. |
| SPI | Shallow Packet Inspection — Kiểm tra gói tin nông. Phân loại gói tin chỉ dựa trên header mà không phân tích payload. |
| Throughput | Tốc độ xử lý dữ liệu gói tin của hệ thống, đo bằng Megabits trên giây (Mbps). |
| VLAN | Virtual Local Area Network. Phần mở rộng IEEE 802.1Q cho header Ethernet cung cấp khả năng phân đoạn mạng. |
| Worker Core | Lõi CPU lcore được dành riêng cho các tác vụ xử lý gói tin ở giai đoạn sau phân loại. |

### 1.6 Tài Liệu Áp Dụng và Tham Chiếu

| Tham chiếu | Tài liệu |
|---|---|
| REF-01 | DPDK Programmer's Guide, https://doc.dpdk.org/guides/ |
| REF-02 | Tiêu chuẩn Ethernet IEEE 802.3 |
| REF-03 | Tiêu chuẩn VLAN IEEE 802.1Q |
| REF-04 | RFC 791 — Internet Protocol (IPv4) |
| REF-05 | RFC 793 — Transmission Control Protocol (TCP) |
| REF-06 | RFC 768 — User Datagram Protocol (UDP) |
| REF-07 | SPIFAST-HLD-001 — Thiết Kế Mức Cao (sẽ ban hành) |
| REF-08 | SPIFAST-SDD-001 — Thiết Kế Chi Tiết Phần Mềm (sẽ ban hành) |
| REF-09 | SPIFAST-TSP-001 — Đặc Tả Kiểm Thử (sẽ ban hành) |

---

## 2. Tổng Quan Hệ Thống

### 2.1 Môi Trường Triển Khai

SPIFast được triển khai dưới dạng một instance ứng dụng đơn lẻ trên một máy tính cá nhân hoặc laptop chạy Linux. Hệ thống không yêu cầu phần cứng card giao tiếp mạng chuyên dụng. Toàn bộ đầu vào gói tin được cung cấp thông qua cơ chế DPDK PCAP Virtual Device, cơ chế này trình bày một file PCAP như một giao tiếp mạng logic với DPDK runtime.

Môi trường triển khai phải đáp ứng các điều kiện sau:

- Hệ điều hành: Linux (khuyến nghị Ubuntu 20.04 LTS trở lên)
- Framework DPDK đã được cài đặt và cấu hình
- Bộ nhớ Hugepage đã được cấp phát trước khi khởi chạy ứng dụng
- Các lõi CPU có sẵn để gán độc quyền cho DPDK lcore

### 2.2 Ngữ Cảnh Hệ Thống

Hệ thống vận hành trong ngữ cảnh sau:

```
+-------------------------------+
|         Người vận hành        |
|  - cung cấp file PCAP         |
|  - cung cấp cấu hình rule     |
|  - quan sát thống kê          |
+---------------+---------------+
                |
                v
+-------------------------------+
|         SPIFast               |
|  Hệ thống xử lý gói tin SPI  |
+-------------------------------+
         |           |
         v           v
   [File PCAP]  [Cấu hình Rule]
   [spi_rules.conf]
```

Đầu vào từ bên ngoài vào hệ thống:

- **File lưu lượng PCAP:** File packet capture được sinh trước, replay làm đầu vào gói tin
- **File cấu hình rule:** Bộ rule do người vận hành định nghĩa, xác định chính sách phân loại và hành động
- **Tham số dòng lệnh:** Số lượng Worker, đường dẫn file rule, đường dẫn file PCAP, chế độ so khớp

Đầu ra từ hệ thống ra bên ngoài:

- **Thống kê runtime:** Đầu ra console định kỳ báo cáo Throughput, PPS, số lượng gói tin và thống kê rule hit
- **Log runtime:** Bản ghi sự kiện và thống kê có dấu thời gian

### 2.3 Pipeline Xử Lý Mức Cao

Hệ thống xử lý gói tin qua các giai đoạn pipeline tuần tự sau:

```
  [File PCAP]
       |
       v
  [DPDK PCAP Virtual Device]
       |
       v
  [Nhận gói tin - Packet Reception]
       |
       v
  [Phân tích cú pháp gói tin - Packet Parsing]
  (L2 / VLAN / L3 / L4)
       |
       v
  [Trích xuất Five-Tuple]
       |
       v
  [Chuẩn hóa luồng - Flow Normalization]
       |
       v
  [Phân loại rule - Rule Classification]
       |
       v
  [Điều phối hành động - Action Dispatch]
  (FORWARD → Worker Processing)
  (DROP    → Giải phóng + Đếm)
       |
       v
  [Worker xử lý gói tin]
       |
       v
  [Thu thập thống kê - Statistics Collection]
```

Kiến trúc nội tại chi tiết của từng giai đoạn pipeline, bao gồm phân công lcore, cơ chế giao tiếp giữa các giai đoạn và quản lý bộ nhớ, sẽ được định nghĩa trong tài liệu Thiết Kế Mức Cao (SPIFAST-HLD-001).

### 2.4 Mô Hình Xử Lý Đa Lõi

Hệ thống sử dụng nhiều lõi CPU để xử lý gói tin song song. Việc phân bổ trách nhiệm xử lý giữa các lõi CPU và cơ chế truyền gói tin giữa các giai đoạn xử lý sẽ được định nghĩa trong HLD. Từ góc độ yêu cầu, các thuộc tính hành vi sau phải được thỏa mãn:

- Hệ thống phải vận hành mà không có sự tham gia của kernel network stack trên đường dẫn dữ liệu (data path) gói tin
- Hệ thống phải sử dụng cơ chế giao tiếp liên lõi không khóa (lock-free) trên data path
- Hệ thống không được yêu cầu người vận hành can thiệp để quản lý việc gán lõi cho tác vụ ngoài cấu hình ban đầu

---

## 3. Yêu Cầu Chức Năng

### 3.1 Khởi Tạo DPDK và Nhận Gói Tin

**FR-001 — Khởi tạo DPDK Runtime**

Hệ thống phải khởi tạo DPDK Environment Abstraction Layer (EAL) trước khi bắt đầu bất kỳ hoạt động xử lý gói tin nào. Quá trình khởi tạo phải bao gồm cấp phát các vùng nhớ bộ đệm gói tin (Mempool) sử dụng Hugepages và cấu hình tất cả virtual network device cần thiết.

Nếu quá trình khởi tạo thất bại vì bất kỳ lý do nào, hệ thống phải kết thúc với thông báo lỗi mô tả rõ nguyên nhân thất bại.

**FR-002 — Cấu Hình Virtual Device**

Hệ thống phải cấu hình một DPDK PCAP Virtual Device (net_pcap PMD) làm giao tiếp nhận gói tin. Virtual device phải được liên kết với file PCAP do người dùng chỉ định thông qua tham số dòng lệnh.

**FR-003 — Nhận Gói Tin**

Hệ thống phải nhận gói tin từ giao tiếp virtual device đã cấu hình bằng cách sử dụng API nhận gói tin chế độ poll (poll-mode) của DPDK. Hệ thống phải nhận gói tin theo chế độ burst để tối đa hóa hiệu quả CPU.

**FR-004 — Quản Lý Bộ Đệm Gói Tin**

Hệ thống phải quản lý bộ đệm gói tin sử dụng các hệ thống con mbuf và Mempool của DPDK. Mỗi gói tin nhận được phải được biểu diễn dưới dạng một DPDK mbuf. Bộ đệm gói tin phải được hoàn trả về Mempool sau khi xử lý hoàn tất.

Hệ thống không được để rò rỉ bộ đệm gói tin trên bất kỳ đường xử lý nào, kể cả đường xử lý hành động DROP.

---

### 3.2 Phân Tích Cú Pháp Gói Tin

**FR-005 — Phân Tích Cú Pháp Ethernet Header**

Hệ thống phải phân tích cú pháp IEEE 802.3 Ethernet header của từng gói tin nhận được. Bộ phân tích phải trích xuất trường EtherType để xác định giao thức được đóng gói bên trong.

**FR-006 — Phân Tích Cú Pháp VLAN Header**

Hệ thống phải phát hiện và phân tích cú pháp các khung Ethernet có gắn thẻ IEEE 802.1Q VLAN. Khi có thẻ VLAN (EtherType = 0x8100), hệ thống phải loại bỏ VLAN header và tiếp tục phân tích cú pháp sử dụng trường EtherType bên trong.

VLAN ID phải có sẵn như metadata tùy chọn phục vụ mục đích ghi log và chẩn đoán. Gói tin có thẻ VLAN và gói tin không có thẻ VLAN đều phải được xử lý minh bạch trên cùng một đường xử lý.

**FR-007 — Phân Tích Cú Pháp IPv4 Header**

Hệ thống phải phân tích cú pháp IPv4 header cho các gói tin mang payload IPv4 (EtherType = 0x0800). Bộ phân tích phải trích xuất:

- Địa chỉ IP nguồn (32-bit)
- Địa chỉ IP đích (32-bit)
- Số giao thức IP (IP Protocol number)
- Độ dài IPv4 header (để tính toán offset L4 chính xác)

**FR-008 — Phân Tích Cú Pháp Tầng Giao Vận**

Hệ thống phải phân tích cú pháp header tầng giao vận cho các gói tin mang payload TCP (Protocol = 6) hoặc UDP (Protocol = 17). Bộ phân tích phải trích xuất:

- Số cổng nguồn (16-bit)
- Số cổng đích (16-bit)

**FR-009 — Trích Xuất Metadata Five-Tuple**

Hệ thống phải tạo ra một bản ghi metadata five-tuple cho mỗi gói tin được phân tích cú pháp thành công, bao gồm:

| Trường | Kiểu | Mô tả |
|---|---|---|
| src_ip | uint32 | Địa chỉ nguồn IPv4 |
| dst_ip | uint32 | Địa chỉ đích IPv4 |
| src_port | uint16 | Cổng nguồn tầng giao vận |
| dst_port | uint16 | Cổng đích tầng giao vận |
| protocol | uint8 | Số giao thức IP (6=TCP, 17=UDP) |

**FR-010 — Xử Lý Gói Tin Không Hợp Lệ**

Hệ thống phải xử lý các gói tin không hợp lệ (malformed) hoặc không được hỗ trợ một cách an toàn mà không gây sập (crash) hoặc làm hỏng trạng thái hệ thống. Các gói tin không thể phân tích cú pháp (EtherType không phải IPv4 sau khi loại bỏ VLAN, giao thức không được hỗ trợ, header bị cắt ngắn) phải bị loại bỏ. Một bộ đếm phải được duy trì cho các gói tin không hợp lệ bị loại bỏ.

**FR-011 — Phạm Vi Chỉ IPv4**

Hệ thống phải chỉ hỗ trợ phân tích cú pháp gói tin IPv4. Các gói tin IPv6 nhận được qua virtual device phải bị loại bỏ và được tính là gói tin giao thức không được hỗ trợ. Hỗ trợ IPv6 bị loại trừ một cách tường minh khỏi phiên bản này.

---

### 3.3 Nhận Dạng Luồng Hai Chiều

**FR-012 — Chuẩn Hóa Luồng (Flow Normalization)**

Hệ thống phải chuẩn hóa five-tuple của mỗi gói tin thành một khóa luồng chuẩn tắc (canonical flow key) sao cho gói tin chiều đi và chiều về thuộc cùng một kết nối hai chiều tạo ra cùng một khóa.

Thuật toán chuẩn hóa phải có tính xác định (deterministic) và tạo ra đầu ra giống hệt nhau cho một cặp gói tin chiều đi và chiều về bất kể thứ tự nhận được của chúng.

**FR-013 — Vận Hành Phi Trạng Thái (Stateless Operation)**

Hệ thống phải triển khai nhận dạng luồng hai chiều mà không duy trì bảng luồng (flow table) hay bất kỳ trạng thái theo từng luồng nào. Mỗi gói tin phải được chuẩn hóa và phân loại độc lập. Không có bộ nhớ nào được cấp phát theo từng luồng trong thời gian runtime.

---

### 3.4 Rule Classification Engine

**FR-014 — Phân Loại Gói Tin Dựa Trên Rule**

Hệ thống phải phân loại từng gói tin đã phân tích cú pháp theo bộ rule đã nạp, sử dụng five-tuple đã chuẩn hóa làm khóa phân loại. Classification engine phải xác định rule khớp và hành động filter-group liên kết cho từng gói tin.

**FR-015 — Hỗ Trợ Điều Kiện Khớp**

Rule classification engine phải hỗ trợ các kiểu điều kiện khớp sau trên từng trường của five-tuple:

| Kiểu điều kiện | Mô tả | Ví dụ |
|---|---|---|
| Exact Match | Trường phải bằng chính xác giá trị đã chỉ định | dst_port = 80 |
| Wildcard | Trường khớp với bất kỳ giá trị nào | src_ip = * |
| IPv4 Subnet Match | IP nguồn hoặc đích khớp với tiền tố CIDR | src_ip = 10.0.0.0/24 |
| Port Range Match | Cổng nguồn hoặc đích nằm trong phạm vi | dst_port = 80–443 |
| Protocol Match | Giao thức IP khớp với giá trị chỉ định | protocol = TCP |
| IPv4 Exact Address Match | Source hoặc destination IP khớp với một địa chỉ IPv4 đơn cụ thể (host address, không phải prefix) | dst_ip = 69.220.144.5 |

Nhiều điều kiện trên các trường khác nhau trong một rule duy nhất phải được kết hợp theo ngữ nghĩa logic AND. Một gói tin khớp với một rule chỉ khi tất cả các điều kiện được chỉ định trong rule đó đều được thỏa mãn.

**FR-016 — Chế Độ So Khớp Rule Cấu Hình Được**

Hệ thống phải hỗ trợ hai chế độ so khớp rule, có thể lựa chọn qua cấu hình:

- **First-Match:** Rule đầu tiên trong bộ rule đã sắp xếp có điều kiện được thỏa mãn bởi gói tin sẽ được áp dụng. Các rule tiếp theo sẽ không được đánh giá.
- **Best-Match:** Rule khớp có độ đặc hiệu cao nhất, được xác định theo ưu tiên phân loại, sẽ được áp dụng.

Nếu không có chế độ so khớp nào được cấu hình tường minh, hệ thống phải mặc định theo hành vi first-match.
Một filter-group có thể có nhiều precedence khác nhau tương ứng với các rule con có điều kiện khác nhau (ví dụ: khác protocol).

**FR-017 — Rule Mặc Định (Default Rule)**

Bộ rule phải hỗ trợ một rule mặc định bắt-tất-cả (catch-all) khớp với tất cả gói tin không được khớp bởi bất kỳ rule nào trước đó. Rule mặc định phải là rule có ưu tiên thấp nhất trong bộ rule.

**FR-018 — Nạp Rule Tĩnh**

Hệ thống phải nạp toàn bộ bộ rule từ file cấu hình trong quá trình khởi tạo ứng dụng. Tất cả các rule phải được biên dịch vào classification engine trước khi bắt đầu xử lý gói tin.

Việc chỉnh sửa bộ rule đã nạp trong runtime không được yêu cầu và không được hỗ trợ.

**FR-019 — Giới Hạn Số Lượng Filter-Group và Filter**

Hệ thống phải hỗ trợ tối đa **4096 filter-group**, mỗi filter-group chứa tối đa **2048 filter**. Hành vi đối với cấu hình vượt quá các giới hạn này là không xác định và không cần được hỗ trợ.

**FR-020 — Đếm Lượt Khớp Rule (Rule Hit Counting)**

Hệ thống phải duy trì bộ đếm lượt khớp theo từng rule hoặc từng filter-group, ghi lại số lượng gói tin được khớp bởi từng rule hoặc nhóm. Các bộ đếm lượt khớp phải được đưa vào đầu ra thống kê runtime.

---

### 3.5 Chính Sách Hành Động

**FR-021 — Mô Hình Hành Động Filter-Group**

Các rule phải được tổ chức thành các filter group có tên. Mỗi filter group phải có một chính sách hành động liên kết áp dụng cho tất cả gói tin được khớp bởi bất kỳ rule nào trong nhóm đó.

**FR-022 — Các Hành Động Được Hỗ Trợ**

Hệ thống phải hỗ trợ các hành động sau:

| Hành động | Hành vi |
|---|---|
| FORWARD / ALLOW | Gói tin được chuyển tiếp đến một Worker Core để xử lý tiếp. |
| DROP | Gói tin bị loại bỏ ngay lập tức. Bộ đệm gói tin phải được giải phóng. Bộ đếm drop phải được tăng lên. |

**FR-023 — Tính Đầy Đủ Của Hành Động**

Mỗi gói tin đi vào giai đoạn phân loại phải dẫn đến đúng một hành động. Không có gói tin nào được phép thoát khỏi giai đoạn phân loại mà không có hành động được gán. Rule mặc định (FR-017) đảm bảo tất cả gói tin đều nhận được một hành động.

---

### 3.6 Điều Phối Gói Tin và Xử Lý Worker

**FR-024 — Điều Phối Gói Tin Đến Worker Core**

Các gói tin được gán hành động FORWARD phải được điều phối đến một Worker Core xử lý. Cơ chế điều phối phải truyền gói tin từ giai đoạn phân loại đến Worker Core sử dụng kênh giao tiếp liên lõi không khóa (lock-free).

**FR-025 — Số Lượng Worker Core Cấu Hình Được**

Số lượng Worker Core dành riêng cho xử lý gói tin phải có thể cấu hình được. Số Worker phải có thể chỉ định thông qua tham số dòng lệnh khi khởi động ứng dụng. Hệ thống không được hardcode số lượng Worker Core.

**FR-026 — Xử Lý Gói Tin Tại Worker**

Worker Core phải nhận các gói tin đã điều phối và thực hiện các thao tác sau:

- Lấy gói tin và metadata liên kết
- Cập nhật bộ đếm gói tin và byte theo từng Worker
- Giải phóng bộ đệm gói tin trả về Mempool

**FR-027 — Giải Phóng Bộ Đệm Gói Tin**

Mỗi gói tin đi vào hệ thống phải có bộ đệm của nó được giải phóng đúng một lần, trên đường DROP (giai đoạn phân loại) hoặc đường FORWARD (giai đoạn Worker). Điều kiện double-free và rò rỉ bộ đệm không được xảy ra.

---

### 3.7 Thống Kê Runtime

**FR-028 — Đầu Ra Thống Kê Định Kỳ**

Hệ thống phải tính toán và xuất thống kê runtime theo chu kỳ đều đặn một giây. Thống kê phải được in ra đầu ra console tiêu chuẩn.

**FR-029 — Nội Dung Thống Kê**

Mỗi bản ghi đầu ra thống kê phải bao gồm:

| Chỉ số | Mô tả | Đơn vị |
|---|---|---|
| Thời gian đã trôi qua | Thời gian từ khi ứng dụng khởi động | giây |
| Gói tin đã nhận | Tổng gói tin nhận được từ virtual device | số lượng |
| Gói tin đã xử lý | Tổng gói tin được phân loại và điều phối thành công | số lượng |
| Gói tin đã DROP | Tổng gói tin bị loại bỏ do hành động rule | số lượng |
| Gói tin không hợp lệ | Tổng gói tin bị loại bỏ do lỗi phân tích cú pháp | số lượng |
| Throughput | Tốc độ dữ liệu gói tin từ chu kỳ trước | Mbps |
| Tốc độ gói tin | Tốc độ xử lý gói tin từ chu kỳ trước | PPS |
| Lượt khớp theo nhóm | Số gói tin khớp theo từng filter group | số lượng |

**FR-030 — Thống Kê Lũy Kế và Theo Chu Kỳ**

Hệ thống phải báo cáo cả thống kê lũy kế từ khi ứng dụng khởi động và thống kê theo chu kỳ cho khoảng thời gian một giây gần nhất.

**FR-031 — Tóm Tắt Cuối Phiên Chạy**

Khi quá trình replay PCAP hoàn tất và tất cả gói tin đã được xử lý, hệ thống phải xuất một bản ghi tóm tắt thống kê cuối cùng trước khi kết thúc.

**FR-032 — Xác Nhận Gói Tin Bị Mất**

Hệ thống phải xác minh vào cuối phiên chạy rằng tổng số gói tin nhận được từ file PCAP bằng tổng của gói tin đã xử lý và gói tin đã DROP. Bất kỳ sự sai lệch nào phải được báo cáo là lỗi gói tin bị mất.

---

## 4. Yêu Cầu Đầu Vào Lưu Lượng

### 4.1 Hành Vi Replay PCAP

**TR-001 — File PCAP Là Nguồn Đầu Vào**

Hệ thống phải chấp nhận một file PCAP là nguồn đầu vào gói tin duy nhất. Đường dẫn file PCAP phải được chỉ định như một tham số dòng lệnh.

**TR-002 — Replay Một Lần Duy Nhất**

Hệ thống phải replay file PCAP đúng một lần. Khi tất cả gói tin trong file PCAP đã được nhận, virtual device phải báo hiệu kết thúc đầu vào và hệ thống phải hoàn thành xử lý các gói tin còn trong bộ đệm rồi kết thúc bình thường.

Chế độ replay lặp liên tục không được yêu cầu.

**TR-003 — Độ Trung Thực Replay**

Hệ thống phải xử lý tất cả gói tin có trong file PCAP. Nội dung gói tin và thứ tự trong file PCAP phải được bảo toàn trong quá trình replay. Hệ thống không được bỏ qua hoặc sắp xếp lại thứ tự gói tin trong quá trình nhận.

---

### 4.2 Công Cụ Sinh PCAP

**TR-004 — Sinh PCAP Tự Động**

Dự án phải cung cấp một công cụ hoặc script sinh file PCAP cho phép người vận hành tạo ra các file lưu lượng kiểm thử với các đặc tính được kiểm soát, có thể tái hiện. Công cụ sinh không được yêu cầu tạo gói tin thủ công.

**TR-005 — Cấu Hình Công Cụ Sinh**

Công cụ sinh PCAP phải chấp nhận các tham số cấu hình chỉ định:

- Tổng số gói tin cần sinh
- Phân phối giao thức (phần trăm TCP, phần trăm UDP)
- Phân phối cổng đích (ánh xạ đến các kiểu lưu lượng đã định nghĩa)
- Phân phối kích thước gói tin (kích thước cố định hoặc phân phối theo các nhóm kích thước)
- Dải địa chỉ IP nguồn và đích
- Sinh cặp gói tin luồng hai chiều (phục vụ kiểm thử flow normalization)

**TR-006 — Sinh Theo Profile**

Công cụ sinh PCAP phải hỗ trợ các traffic profile có tên. Mỗi profile phải được định nghĩa trong một file cấu hình tổng hợp tất cả tham số sinh cho profile đó. Các profile phải có thể lựa chọn độc lập tại thời điểm sinh.

---

### 4.3 Traffic Profile

Hệ thống phải định nghĩa và cung cấp tập hợp tối thiểu các traffic profile sau cho mục đích kiểm thử:

**TP-01 — Profile Kiểm Tra Tải Gói Tin Nhỏ (Small Packet Stress)**

| Tham số | Giá trị |
|---|---|
| Mục đích | Kiểm tra PPS tối đa (stress test) |
| Kích thước gói tin | 64 bytes (cố định) |
| Giao thức | 100% TCP |
| Cổng đích | 80 (HTTP) |
| Chỉ số kỳ vọng | ≥ 1.488.000 PPS (line-rate, mức Excellent) |

**TP-02 — Profile Throughput Hỗn Hợp Trung Bình (Medium Mixed Throughput)**

| Tham số | Giá trị |
|---|---|
| Mục đích | Kiểm tra Throughput Mbps tối đa |
| Kích thước gói tin | Phân phối đều: 512 B và 1024 B |
| Giao thức | Hỗn hợp TCP và UDP |
| Kiểu lưu lượng | HTTP (port 80), HTTPS (port 443), DNS (port 53), GTPU (port 2152) |
| Chỉ số kỳ vọng | ≥ 700 Mbps (mức Pass) |

**TP-03 — Profile Phủ Toàn Bộ Rule (Rule Coverage)**

| Tham số | Giá trị |
|---|---|
| Mục đích | Xác nhận tất cả rule đã cấu hình đều được kích hoạt |
| Kích thước gói tin | 256 bytes |
| Giao thức | Hỗn hợp để khớp từng rule đã định nghĩa ít nhất một lần |
| Kiểu lưu lượng | Một lớp gói tin cho mỗi rule đã định nghĩa |
| Kết quả kỳ vọng | Tất cả bộ đếm rule hit ≥ 1 |

**TP-04 — Profile Luồng Hai Chiều (Bidirectional Flow)**

| Tham số | Giá trị |
|---|---|
| Mục đích | Xác nhận flow normalization cho lưu lượng hai chiều |
| Kích thước gói tin | 128 bytes |
| Cấu trúc | Cặp gói tin: Client→Server theo sau là Server→Client |
| Kết quả kỳ vọng | Cả hai chiều đều khớp cùng một rule |

**TP-05 — Profile Gói Tin Có Thẻ VLAN (VLAN Tagged)**

| Tham số | Giá trị |
|---|---|
| Mục đích | Xác nhận đường phân tích cú pháp VLAN |
| Kích thước gói tin | 256 bytes |
| Đóng gói | Khung Ethernet có gắn thẻ IEEE 802.1Q VLAN |
| Giao thức | Hỗn hợp TCP và UDP |
| Kết quả kỳ vọng | Gói tin được phân loại giống hệt như các gói tương đương không có thẻ VLAN |

**TR-007 — Khả Năng Tái Hiện Profile**

Các traffic profile phải tạo ra các file PCAP giống hệt nhau khi được thực thi với cùng tham số cấu hình. Kết quả kiểm thử thu được bằng một profile nhất định phải có thể tái hiện qua các lần thực thi lặp lại trên cùng phần cứng.

---

## 5. Yêu Cầu Hiệu Năng

### 5.1 Throughput

**PR-001 — Throughput Duy Trì Tối Thiểu**

Hệ thống phải duy trì Throughput xử lý gói tin tối thiểu **700 Mbps** khi được kiểm thử sử dụng Traffic Profile TP-02 (Medium Mixed Throughput) trong điều kiện vận hành ổn định.

**PR-002 — Mục Tiêu Throughput Mức Excellent**

Hệ thống nên đạt Throughput **950–990 Mbps** khi được kiểm thử trong điều kiện tối ưu với kích thước gói tin lớn. Mục tiêu này đại diện cho hiệu năng gần line-rate đối với giao tiếp mạng 1 Gbps được mô phỏng.

Phương pháp đo:

```
Throughput (Mbps) = (Tổng byte đã xử lý × 8) / Thời gian runtime (giây) / 1.000.000
```

---

### 5.2 Tốc Độ Xử Lý Gói Tin

**PR-003 — Tốc Độ Gói Tin Duy Trì Tối Thiểu**

Hệ thống phải duy trì tốc độ xử lý gói tin tối thiểu **500.000 gói tin mỗi giây (0,5 Mpps)** trong điều kiện vận hành tiêu chuẩn.

**PR-004 — Mục Tiêu Tốc Độ Gói Tin Mức Excellent**

Hệ thống nên đạt tốc độ xử lý gói tin **1.488.000 gói tin mỗi giây** khi được kiểm thử sử dụng Traffic Profile TP-01 (Small Packet Stress). Mục tiêu này tương ứng với tốc độ gói tin line-rate lý thuyết cho khung 64 byte trên giao tiếp Ethernet 1 Gbps.

Phương pháp đo:

```
PPS = Tổng gói tin đã xử lý / Thời gian runtime (giây)
```

---

### 5.3 Tỷ Lệ Rơi Gói Tin

**PR-005 — Tỷ Lệ Rơi Gói Tin Tối Đa Cho Phép**

Hệ thống không được vượt quá tỷ lệ rơi gói tin **0,1%** do các ràng buộc năng lực nội tại (như tràn hàng đợi liên lõi) trong điều kiện tải dự kiến.

Lưu ý: Các gói tin bị loại bỏ do hành động DROP của rule đã cấu hình không được tính là vi phạm tỷ lệ rơi gói tin. Tỷ lệ rơi gói tin chỉ áp dụng cho việc mất gói tin ngoài ý muốn do cạn kiệt tài nguyên hệ thống.

Phương pháp đo:

```
Tỷ lệ rơi (%) = (Gói tin rơi ngoài ý muốn / Tổng gói tin đã nhận) × 100
```

---

### 5.4 Tỷ Lệ Gói Tin Bị Mất

**PR-006 — Yêu Cầu Không Có Gói Tin Bị Mất**

Hệ thống phải duy trì tỷ lệ gói tin bị mất **0%**. Mọi gói tin có trong file PCAP đầu vào phải được hạch toán trong đúng một trong các danh mục kết quả sau:

- Khớp với rule FORWARD và được xử lý bởi Worker Core
- Khớp với rule DROP và bị loại bỏ
- Bị loại bỏ do không hợp lệ (lỗi phân tích cú pháp)

Tổng của tất cả bộ đếm kết quả phải bằng tổng số gói tin có trong file PCAP đầu vào.

---

### 5.5 Điều Kiện Đo Hiệu Năng

Các phép đo hiệu năng phải được thực hiện trong các điều kiện sau:

- Hugepages được cấp phát và xác nhận có sẵn trước khi thực thi kiểm thử
- Không có ứng dụng xử lý gói tin nào khác chạy đồng thời
- Các lõi CPU được sử dụng bởi DPDK lcore phải được cô lập khỏi Linux scheduler khi có thể
- Hệ thống đang kiểm thử phải được phép có giai đoạn khởi động (warm-up) trước khi bắt đầu đo hiệu năng
- Phép đo phải được thực hiện trong suốt một phiên chạy ổn định sử dụng traffic profile đã định nghĩa

---

## 6. Yêu Cầu Cấu Hình Rule

### 6.1 File Cấu Hình Rule

**RC-001 — Cấu Hình Rule Dựa Trên File**

Hệ thống phải nạp rule từ một file cấu hình dạng văn bản thuần (plain-text). Đường dẫn file cấu hình phải được chỉ định như một tham số dòng lệnh. Tên file mặc định phải là `spi_rules.conf`.

**RC-002 — Định Dạng File Rule**

Mỗi mục rule trong file cấu hình phải chỉ định các trường sau:

| Trường | Bắt buộc | Mô tả |
|---|---|---|
| Tên Rule | Có | Mã định danh chữ-số duy nhất cho rule |
| Filter Group | Có | Tên nhóm mà rule này thuộc về |
| Giao thức | Có | TCP, UDP hoặc wildcard (*) |
| IP nguồn | Có | Địa chỉ IPv4 |
| IP nguồn prefix | Có | Tiền tố CIDR |
| IP đích | Có | Địa chỉ IPv4 |
| IP đích prefix | Có | Tiền tố CIDR |
| Cổng nguồn | Có | Số cổng, phạm vi cổng (min–max) hoặc wildcard (*) |
| Cổng đích | Có | Số cổng, phạm vi cổng (min–max) hoặc wildcard (*) |

**RC-003 — Khai Báo Hành Động Filter Group**

Mỗi filter group có khai báo action và precedence. Mỗi action liên kết chỉ định FORWARD hoặc DROP. Mỗi precedence khai báo số nguyên thứ tự ưu tiên của group. Giá trị thấp hơn = ưu tiên cao hơn. Trường Precedence cần được định nghĩa ở cấp rule, không phải chỉ ở cấp group declaration.

**RC-004 — Ví Dụ File Rule**

Ví dụ dưới đây minh họa định dạng cấu hình rule yêu cầu. Cú pháp chính xác sẽ được định nghĩa trong SDD.

```
# Filter Group Definitions (với Precedence)
[group: fg_l34_facebook]     precedence=100  action=FORWARD
[group: fg_l34_youtube]      precedence=101  action=FORWARD
[group: fg_l34_http_sdf1003] precedence=102  action=FORWARD
[group: fg_l34_dns_sdf1005]  precedence=104  action=FORWARD
[group: fg_l34_dns_sdf1005]  precedence=105  action=FORWARD
[group: DEFAULT]             precedence=999  action=DROP

# Rule Definitions (prefix = CIDR, address = exact host IP)
f_l34_facebook_1, fg_l34_facebook, any, dst_prefix=31.13.64.0/18,  any, any
f_l34_facebook_4, fg_l34_facebook, any, dst_address=69.220.144.5,  any, any
f_l34_youtube_1,  fg_l34_youtube,  tcp, dst_prefix=142.250.0.0/15, 443, any
f_l34_youtube_4,  fg_l34_youtube,  tcp, dst_address=74.125.0.1,    443, any
f_l34_http_all,   fg_l34_http_sdf1003, tcp, any, 80, any
f_l34_dns_udp,    fg_l34_dns_sdf1005,  udp, any, 53, any
f_l34_dns_tcp,    fg_l34_dns_sdf1005,  tcp, any, 53, any
```

**RC-005 — Hỗ Trợ Chú Thích**

File cấu hình rule phải hỗ trợ chú thích theo dòng bắt đầu bằng ký tự `#`. Các dòng chú thích và dòng trống phải được bỏ qua trong quá trình phân tích cú pháp.

**RC-006 — Xác Thực File Rule**

Hệ thống phải xác thực file cấu hình rule trong quá trình khởi động. Nếu file vắng mặt, không thể đọc hoặc chứa các mục không hợp lệ về cú pháp, hệ thống phải kết thúc với thông báo lỗi mô tả rõ ràng. Việc nạp rule một phần khi có lỗi không được phép.

---

## 7. Yêu Cầu Ghi Log Runtime

**LOG-001 — Sinh Log Runtime**

Hệ thống phải sinh đầu ra log runtime trong quá trình vận hành. Đầu ra log phải được ghi vào đầu ra tiêu chuẩn (standard output) và phải có thể chuyển hướng ra file để phân tích sau phiên chạy.

**LOG-002 — Nội Dung Mục Log**

Mỗi mục log định kỳ phải bao gồm các trường sau:

| Trường | Mô tả |
|---|---|
| Dấu thời gian | Thời gian thực tế của mục log |
| Thời gian đã trôi qua | Số giây từ khi ứng dụng khởi động |
| Gói tin RX (theo chu kỳ) | Gói tin nhận được trong chu kỳ hiện tại |
| Gói tin RX (tổng) | Gói tin nhận được từ khi khởi động |
| Gói tin đã xử lý (tổng) | Gói tin được điều phối đến Worker từ khi khởi động |
| Gói tin đã DROP (tổng) | Gói tin bị loại bỏ do hành động rule từ khi khởi động |
| Gói tin không hợp lệ (tổng) | Gói tin bị loại bỏ do lỗi phân tích cú pháp từ khi khởi động |
| Throughput | Throughput đo được theo Mbps cho chu kỳ hiện tại |
| PPS | Tốc độ gói tin đo được cho chu kỳ hiện tại |
| Lượt khớp theo nhóm | Số lượt khớp theo từng filter group từ khi khởi động |

**LOG-003 — Chu Kỳ Ghi Log**

Hệ thống phải tạo ra một mục log mỗi giây trong quá trình vận hành.

**LOG-004 — Ghi Log Khởi Động và Tắt Máy**

Hệ thống phải tạo mục log tại các sự kiện vòng đời sau:

- Khởi động ứng dụng: tóm tắt cấu hình, số lượng rule, số lượng Worker, đường dẫn file PCAP
- Nạp rule hoàn tất: danh sách các rule đã nạp kèm nhóm và hành động liên kết
- Bắt đầu xử lý gói tin: dấu thời gian của gói tin đầu tiên được nhận
- Kết thúc xử lý gói tin: dấu thời gian của gói tin cuối cùng được xử lý
- Tóm tắt cuối phiên: thống kê lũy kế cuối cùng và kết quả xác nhận gói tin bị mất

**LOG-005 — Tính Nhất Quán Định Dạng Log**

Các mục log phải sử dụng định dạng nhất quán, dễ đọc cho người. Các trường số phải bao gồm đơn vị. Dấu thời gian phải theo định dạng ISO 8601 hoặc biểu diễn không nhập nhằng tương đương.

---

## 8. Yêu Cầu Kiểm Thử và Xác Nhận

### 8.1 Sản Phẩm Bàn Giao Kiểm Thử

Bàn giao hệ thống phải bao gồm các tài liệu kiểm thử sau:

| Sản phẩm | Mô tả |
|---|---|
| Đặc tả kiểm thử (Test Specification) | Tài liệu định nghĩa tất cả test case, tiêu chí chấp nhận và quy trình thực thi |
| Script traffic profile | Script sinh PCAP cho từng traffic profile đã định nghĩa |
| File PCAP đã sinh | File PCAP được sinh trước cho từng traffic profile |
| Log thực thi kiểm thử | Log đầu ra console được thu thập trong quá trình thực thi kiểm thử |
| Tóm tắt kết quả kiểm thử | Bảng tính hoặc tài liệu ghi lại kết quả PASS/FAIL cho từng test case |

### 8.2 Yêu Cầu Kiểm Thử Chức Năng

**FT-001 — Kiểm Thử Phân Tích Cú Pháp Ethernet Header**

Hệ thống phải phân tích cú pháp chính xác Ethernet header của tất cả gói tin trong PCAP kiểm thử. Kiểm thử phải xác nhận rằng EtherType được nhận dạng đúng cho cả khung IPv4 không có thẻ (0x0800) và khung có thẻ VLAN (0x8100).

Tiêu chí chấp nhận: 100% khung Ethernet hợp lệ được phân tích cú pháp không có lỗi.

**FT-002 — Kiểm Thử Phân Tích Cú Pháp VLAN Header**

Sử dụng Traffic Profile TP-05, hệ thống phải nhận dạng đúng gói tin có thẻ VLAN, loại bỏ VLAN header và tiếp tục phân tích cú pháp payload IPv4 bên trong.

Tiêu chí chấp nhận: Gói tin có thẻ VLAN được phân loại giống hệt như các gói tương đương không có thẻ. Số lượt khớp rule khớp với giá trị kỳ vọng.

**FT-003 — Kiểm Thử Phân Tích Cú Pháp IPv4 Header**

Hệ thống phải trích xuất đúng IP nguồn, IP đích và số giao thức từ IPv4 header.

Tiêu chí chấp nhận: Các trường đã trích xuất khớp với giá trị kỳ vọng cho tất cả gói tin trong PCAP tham chiếu có nội dung đã biết.

**FT-004 — Kiểm Thử Phân Tích Cú Pháp TCP Header**

Hệ thống phải trích xuất đúng số cổng nguồn và cổng đích từ TCP header.

Tiêu chí chấp nhận: Các trường đã trích xuất khớp với giá trị kỳ vọng cho tất cả gói tin TCP trong PCAP tham chiếu.

**FT-005 — Kiểm Thử Phân Tích Cú Pháp UDP Header**

Hệ thống phải trích xuất đúng số cổng nguồn và cổng đích từ UDP header.

Tiêu chí chấp nhận: Các trường đã trích xuất khớp với giá trị kỳ vọng cho tất cả gói tin UDP trong PCAP tham chiếu.

**FT-006 — Kiểm Thử Trích Xuất Five-Tuple**

Hệ thống phải ghép đúng five-tuple hoàn chỉnh từ các header đã phân tích cú pháp.

Tiêu chí chấp nhận: Five-tuple đã trích xuất khớp với giá trị kỳ vọng cho tất cả gói tin trong PCAP tham chiếu.

**FT-007 — Kiểm Thử Flow Normalization**

Sử dụng Traffic Profile TP-04, hệ thống phải chuẩn hóa đúng gói tin chiều đi và chiều về của cùng một luồng hai chiều thành cùng một khóa chuẩn tắc.

Tiêu chí chấp nhận: Cả gói tin Client→Server và Server→Client của mỗi luồng đều khớp cùng một rule và tăng cùng một bộ đếm hit.

**FT-008 — Kiểm Thử Rule Exact Match**

Hệ thống phải khớp đúng các gói tin trong đó five-tuple thỏa mãn chính xác một rule với các giá trị trường tường minh.

Tiêu chí chấp nhận: Tất cả gói tin khớp được gán đúng hành động nhóm.

**FT-009 — Kiểm Thử Rule Wildcard Match**

Hệ thống phải khớp đúng các gói tin với các rule chứa trường wildcard (*).

Tiêu chí chấp nhận: Gói tin có các trường không phải wildcard khớp với rule được phân loại đúng, bất kể giá trị của trường wildcard.

**FT-010 — Kiểm Thử Rule IP Subnet Match**

Hệ thống phải khớp đúng các gói tin trong đó địa chỉ IP nguồn hoặc đích nằm trong tiền tố CIDR được chỉ định trong rule.

Tiêu chí chấp nhận: Tất cả gói tin có địa chỉ IP trong subnet chỉ định đều khớp rule. Gói tin ngoài subnet không khớp.

**FT-011 — Kiểm Thử Rule Port Range Match**

Hệ thống phải khớp đúng các gói tin trong đó cổng nguồn hoặc đích nằm trong phạm vi cổng được chỉ định trong rule.

Tiêu chí chấp nhận: Tất cả gói tin có cổng trong phạm vi đều khớp rule. Gói tin có cổng ngoài phạm vi không khớp.

**FT-012 — Kiểm Thử Rule Mặc Định**

Hệ thống phải áp dụng rule catch-all mặc định cho tất cả gói tin không được khớp bởi bất kỳ rule nào trước đó.

Tiêu chí chấp nhận: Gói tin không có rule tường minh nào khớp được gán hành động rule mặc định. Bộ đếm hit rule mặc định khác không.

**FT-013 — Kiểm Thử Bộ Đếm Lượt Khớp Rule**

Hệ thống phải tăng đúng bộ đếm lượt khớp theo từng rule hoặc từng nhóm cho mỗi gói tin khớp.

Tiêu chí chấp nhận: Tổng số lượt khớp trên tất cả rule bằng tổng số gói tin được phân tích cú pháp thành công. Không có đếm trùng hay đếm sót.

**FT-014 — Kiểm Thử Hành Động FORWARD**

Các gói tin được khớp bởi rule FORWARD phải được điều phối đến Worker Core và được xử lý.

Tiêu chí chấp nhận: Số gói tin Worker Core nhận được khớp với số gói tin được phân loại là FORWARD.

**FT-015 — Kiểm Thử Hành Động DROP**

Các gói tin được khớp bởi rule DROP phải bị loại bỏ ngay lập tức mà không được điều phối đến Worker Core.

Tiêu chí chấp nhận: Số gói tin đã DROP khớp với số gói tin được phân loại là DROP. Không có gói tin DROP nào xuất hiện trong thống kê Worker.

**FT-016 — Kiểm Thử Xử Lý Gói Tin Không Hợp Lệ**

Hệ thống phải loại bỏ các gói tin có EtherType không phải IPv4 (sau khi loại bỏ VLAN) mà không bị sập.

Tiêu chí chấp nhận: Bộ đếm gói tin không hợp lệ tăng đúng. Hệ thống tiếp tục xử lý các gói tin tiếp theo mà không có lỗi.

**FT-017 — Kiểm Thử Đầu Ra Thống Kê**

Hệ thống phải tạo ra đầu ra thống kê có định dạng đúng theo chu kỳ một giây.

Tiêu chí chấp nhận: Thống kê được in ra mỗi giây trong quá trình vận hành. Tất cả trường yêu cầu đều có mặt. Các số lượng lũy kế tăng đơn điệu.

**FT-018 — Kiểm Thử Tóm Tắt Cuối Phiên Chạy**

Hệ thống phải tạo ra tóm tắt thống kê cuối cùng khi quá trình replay PCAP hoàn tất.

Tiêu chí chấp nhận: Tóm tắt cuối cùng được in ra. Kết quả xác nhận gói tin bị mất được báo cáo. Tổng số lượng gói tin khớp với nội dung file PCAP.

**FT-019 — Kiểm Thử Cấu Hình Số Lượng Worker**

Hệ thống phải chấp nhận và áp dụng số Worker cấu hình được từ dòng lệnh.

Tiêu chí chấp nhận: Hệ thống khởi tạo đúng số lượng Worker Core đã chỉ định. Thống kê phản ánh hoạt động trên tất cả Worker đã cấu hình.

### 8.3 Yêu Cầu Kiểm Thử Hiệu Năng

**PT-001 — Kiểm Thử Throughput**

Sử dụng Traffic Profile TP-02, hệ thống phải được đo Throughput duy trì.

| Kết quả | Tiêu chí |
|---|---|
| PASS | Throughput đo được ≥ 700 Mbps duy trì |
| EXCELLENT | Throughput đo được ≥ 950 Mbps duy trì |
| FAIL | Throughput đo được < 700 Mbps |

**PT-002 — Kiểm Thử Tốc Độ PPS**

Sử dụng Traffic Profile TP-01, hệ thống phải được đo tốc độ xử lý gói tin duy trì.

| Kết quả | Tiêu chí |
|---|---|
| PASS | PPS đo được ≥ 500.000 pps duy trì |
| EXCELLENT | PPS đo được ≥ 1.488.000 pps duy trì |
| FAIL | PPS đo được < 500.000 pps |

**PT-003 — Kiểm Thử Tỷ Lệ Rơi Gói Tin**

Trong tải duy trì sử dụng bất kỳ profile hiệu năng nào, hệ thống phải được quan sát về rơi gói tin ngoài ý muốn.

| Kết quả | Tiêu chí |
|---|---|
| PASS | Tỷ lệ rơi ngoài ý muốn ≤ 0,1% |
| EXCELLENT | Tỷ lệ rơi ngoài ý muốn = 0% |
| FAIL | Tỷ lệ rơi ngoài ý muốn > 0,1% |

**PT-004 — Kiểm Thử Tỷ Lệ Gói Tin Bị Mất**

Vào cuối phiên chạy, hệ thống phải hạch toán tất cả gói tin có trong file PCAP đầu vào.

| Kết quả | Tiêu chí |
|---|---|
| PASS / EXCELLENT | Tỷ lệ mất = 0% (tất cả gói tin đều được hạch toán) |
| FAIL | Bất kỳ gói tin nào không được hạch toán |

**PT-005 — Kiểm Thử Hiệu Năng Phủ Toàn Bộ Rule**

Sử dụng Traffic Profile TP-03, hệ thống phải chứng minh rằng tất cả rule đã định nghĩa đều được kích hoạt trong một phiên chạy hiệu năng mà không có suy giảm.

Tiêu chí chấp nhận: Tất cả bộ đếm rule hit ≥ 1. Throughput và PPS đạt ngưỡng PASS.

---

## 9. Yêu Cầu Phi Chức Năng

### 9.1 Hiệu Năng

**NFR-001** — Hệ thống phải xử lý gói tin ở tốc độ nhất quán với các hệ thống data-plane hiệu năng cao, hướng tới vận hành gần line-rate cho giao tiếp mạng 1 Gbps được mô phỏng.

**NFR-002** — Hệ thống phải giảm thiểu độ trễ xử lý từng gói tin trên data path. Các thao tác blocking, system call và cấp phát bộ nhớ không được xảy ra trên data path xử lý gói tin trong trạng thái ổn định.

**NFR-003** — Hệ thống phải sử dụng giao tiếp liên lõi lock-free trên data path để ngăn tranh chấp giữa các lõi làm suy giảm Throughput hoặc PPS.

### 9.2 Độ Tin Cậy

**NFR-004** — Hệ thống phải vận hành liên tục không bị sập hay hỏng bộ nhớ trong suốt thời gian replay đầy đủ một file PCAP dưới bất kỳ traffic profile nào được hỗ trợ.

**NFR-005** — Hệ thống phải xử lý tất cả gói tin trong file PCAP đầu vào mà không có mất gói tin nào có thể quy cho lỗi triển khai. Tất cả mất gói tin phải quy cho hành động DROP rule tường minh hoặc các giới hạn năng lực đã ghi nhận.

**NFR-006** — Hệ thống không được biểu hiện hành vi không xác định, tham chiếu con trỏ null hay truy cập bộ nhớ ngoài biên với bất kỳ đầu vào nào thỏa mãn các ràng buộc đã định nghĩa (file PCAP hợp lệ, cấu hình rule hợp lệ, các kiểu gói tin được hỗ trợ).

### 9.3 Khả Năng Tái Hiện

**NFR-007** — Kết quả kiểm thử thu được với một traffic profile và cấu hình rule nhất định phải có thể tái hiện qua các lần thực thi lặp lại trên cùng phần cứng trong cùng điều kiện hệ thống.

**NFR-008** — Các traffic profile phải được chỉ định đầy đủ bởi các file cấu hình của chúng sao cho bất kỳ kỹ sư nào có quyền truy cập công cụ sinh và file profile đều có thể tái tạo đầu vào PCAP giống hệt nhau được sử dụng trong một phiên chạy kiểm thử trước đó.

### 9.4 Khả Năng Sử Dụng

**NFR-009** — Hệ thống phải cung cấp đủ đầu ra console trong quá trình vận hành để cho phép người vận hành đánh giá hệ thống có hoạt động đúng hay không mà không cần truy cập debugger.

**NFR-010** — Các thông báo lỗi do hệ thống tạo ra phải có tính mô tả, xác định thành phần phát hiện lỗi, bản chất của lỗi, và khi áp dụng được, hành động khắc phục được đề xuất.

### 9.5 Khả Năng Bảo Trì

**NFR-011** — Mã nguồn phải được tổ chức thành các module logic tương ứng với các giai đoạn xử lý chính của pipeline. Mỗi module phải có ranh giới giao tiếp và trách nhiệm được định nghĩa rõ ràng.

**NFR-012** — Định dạng file cấu hình rule phải có thể đọc và chỉnh sửa bởi người bằng trình soạn thảo văn bản tiêu chuẩn mà không cần công cụ chuyên dụng.

---

## 10. Ràng Buộc và Giả Định

### 10.1 Ràng Buộc Kỹ Thuật

| ID | Ràng buộc |
|---|---|
| CON-01 | Hệ thống phải được triển khai bằng ngôn ngữ lập trình C. |
| CON-02 | Hệ thống phải được xây dựng sử dụng framework DPDK. Phiên bản DPDK cụ thể phải được ghi lại trong HLD. |
| CON-03 | Hệ thống phải chạy trên hệ điều hành Linux. Ubuntu 20.04 LTS trở lên là nền tảng tham chiếu. |
| CON-04 | Hệ thống phải sử dụng DPDK PCAP Virtual Device (net_pcap PMD) là cơ chế đầu vào gói tin duy nhất. Phần cứng NIC vật lý không được yêu cầu và không được hỗ trợ. |
| CON-05 | Hệ thống phải chỉ hỗ trợ IPv4. IPv6 bị loại trừ tường minh. |
| CON-06 | Nạp rule là tĩnh. Chỉnh sửa rule trong runtime không được hỗ trợ. |
| CON-07 | Hệ thống hỗ trợ tối đa 4096 filter-group; mỗi filter-group hỗ trợ tối đa 2048 filter. |
| CON-08 | Hệ thống phải có thể triển khai trên một máy đơn lẻ mà không cần hạ tầng mạng bên ngoài. |
| CON-09 | Hệ thống build phải sử dụng Makefile hoặc CMake, có thể biên dịch bằng GCC trên Linux không có lỗi hay cảnh báo. |

### 10.2 Giả Định Vận Hành

| ID | Giả định |
|---|---|
| ASM-01 | Hugepages được cấu hình và có sẵn trên hệ thống máy chủ trước khi khởi chạy ứng dụng. |
| ASM-02 | File PCAP đầu vào là một file PCAP hợp lệ, đúng định dạng có thể phân tích bằng các công cụ tiêu chuẩn (ví dụ: Wireshark, tcpdump). |
| ASM-03 | File cấu hình rule có mặt và có thể truy cập tại đường dẫn được chỉ định trong dòng lệnh. |
| ASM-04 | Hệ thống máy chủ có đủ lõi CPU để hỗ trợ số lượng DPDK lcore đã cấu hình (tối thiểu: 1 lõi RX + số Worker đã cấu hình). |
| ASM-05 | Không có ứng dụng DPDK nào khác chạy đồng thời trên cùng hệ thống trong quá trình thực thi kiểm thử. |
| ASM-06 | Người vận hành có đặc quyền hệ thống thích hợp để cấp phát Hugepages và bind DPDK virtual device. |

---

## 11. Ma Trận Truy Vết Yêu Cầu

Ma trận dưới đây ánh xạ từng yêu cầu chức năng đến mục tài liệu thiết kế liên kết và test case tương ứng. Liên kết truy vết đầy đủ đến các mục HLD và SDD sẽ được hoàn thiện khi các tài liệu đó được baseline.

| ID Yêu cầu | Mô tả | Tham chiếu thiết kế | Test case |
|---|---|---|---|
| FR-001 | Khởi tạo DPDK EAL | HLD §3.1 | FT-018 (log khởi động) |
| FR-002 | Cấu hình virtual device | HLD §3.1 | FT-001, FT-002 |
| FR-003 | Nhận gói tin | HLD §3.2 | PT-001, PT-002 |
| FR-004 | Quản lý bộ đệm gói tin | HLD §3.2 | PT-004 (gói tin bị mất) |
| FR-005 | Phân tích cú pháp Ethernet header | SDD §2.1 | FT-001 |
| FR-006 | Phân tích cú pháp VLAN header | SDD §2.2 | FT-002 |
| FR-007 | Phân tích cú pháp IPv4 header | SDD §2.3 | FT-003 |
| FR-008 | Phân tích cú pháp tầng giao vận | SDD §2.4 | FT-004, FT-005 |
| FR-009 | Trích xuất Five-Tuple | SDD §2.5 | FT-006 |
| FR-010 | Xử lý gói tin không hợp lệ | SDD §2.6 | FT-016 |
| FR-011 | Phạm vi chỉ IPv4 | SDD §2.1 | FT-016 |
| FR-012 | Flow normalization | SDD §3.1 | FT-007 |
| FR-013 | Vận hành phi trạng thái | SDD §3.1 | FT-007 |
| FR-014 | Phân loại gói tin dựa trên rule | SDD §4.1 | FT-008 – FT-012 |
| FR-015 | Hỗ trợ điều kiện khớp | SDD §4.2 | FT-008, FT-009, FT-010, FT-011 |
| FR-016 | Chế độ so khớp rule cấu hình được | SDD §4.3 | FT-008 |
| FR-017 | Rule mặc định | SDD §4.4 | FT-012 |
| FR-018 | Nạp rule tĩnh | SDD §4.5 | FT-018 (log khởi động) |
| FR-019 | Giới hạn số lượng rule | SDD §4.5 | RC-006 (xác thực) |
| FR-020 | Đếm lượt khớp rule | SDD §4.6 | FT-013 |
| FR-021 | Mô hình hành động filter-group | SDD §5.1 | FT-014, FT-015 |
| FR-022 | Các hành động được hỗ trợ | SDD §5.2 | FT-014, FT-015 |
| FR-023 | Tính đầy đủ của hành động | SDD §5.2 | PT-004 |
| FR-024 | Điều phối gói tin | HLD §4.1 | FT-014 |
| FR-025 | Số Worker cấu hình được | HLD §4.2 | FT-019 |
| FR-026 | Xử lý gói tin tại Worker | SDD §6.1 | FT-014 |
| FR-027 | Giải phóng bộ đệm gói tin | SDD §6.2 | PT-004 |
| FR-028 | Đầu ra thống kê định kỳ | SDD §7.1 | FT-017 |
| FR-029 | Nội dung thống kê | SDD §7.2 | FT-017 |
| FR-030 | Thống kê lũy kế và theo chu kỳ | SDD §7.2 | FT-017 |
| FR-031 | Tóm tắt cuối phiên chạy | SDD §7.3 | FT-018 |
| FR-032 | Xác nhận gói tin bị mất | SDD §7.3 | PT-004 |
| TR-001 | Đầu vào file PCAP | HLD §3.1 | FT-001 |
| TR-002 | Replay một lần duy nhất | HLD §3.1 | FT-018 |
| TR-003 | Độ trung thực replay | HLD §3.1 | PT-004 |
| TR-004 | Sinh PCAP tự động | Công cụ | Tất cả PT |
| TR-005 | Cấu hình công cụ sinh | Công cụ | Tất cả PT |
| TR-006 | Sinh theo profile | Công cụ | TP-01 – TP-05 |
| TR-007 | Khả năng tái hiện profile | Công cụ | NFR-007, NFR-008 |
| PR-001 | Throughput ≥ 700 Mbps | Pipeline HLD | PT-001 |
| PR-002 | Mục tiêu Throughput Excellent | Pipeline HLD | PT-001 |
| PR-003 | PPS ≥ 500.000 | Pipeline HLD | PT-002 |
| PR-004 | Mục tiêu PPS Excellent | Pipeline HLD | PT-002 |
| PR-005 | Tỷ lệ rơi ≤ 0,1% | HLD §4.1 | PT-003 |
| PR-006 | Tỷ lệ gói tin bị mất = 0% | Tất cả giai đoạn | PT-004 |
| LOG-001 | Sinh log runtime | SDD §7.1 | FT-017 |
| LOG-002 | Nội dung mục log | SDD §7.2 | FT-017 |
| LOG-003 | Chu kỳ ghi log | SDD §7.1 | FT-017 |
| LOG-004 | Ghi log khởi động và tắt máy | SDD §7.3 | FT-018 |
| LOG-005 | Tính nhất quán định dạng log | SDD §7.2 | FT-017 |

---

*Kết thúc tài liệu — SPIFAST-SRS-001 v1.0*
