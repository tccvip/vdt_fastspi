# SPIFast Project Context

## 1. Project Overview

Project name:

SPIFast - High Performance Shallow Packet Inspection System using DPDK


## 2. Project Goal

SPIFast is a high-performance packet inspection system implemented using DPDK.

The goal is to build a software-based packet processing pipeline capable of:
- receiving packets
- parsing packet metadata
- applying ACL rules
- forwarding or dropping packets
- measuring processing performance


## 3. Main Technologies

Programming language:
- C

Framework:
- DPDK

Main components:
- rte_mbuf
- rte_ring
- rte_acl
- rte_mempool
- lcore


## 4. Final Architecture

Current implemented architecture:

RX
 |
 v
Parser
 |
 v
Worker
 |
 v
Flat ACL
 |
 v
TX


The previous group-based ACL architecture was replaced by flat ACL architecture.


## 5. Data Flow

Packet flow:

1. RX reads packet from pcap source
2. Packet is stored in rte_mbuf
3. Parser extracts:
   - IPv4
   - TCP/UDP
   - five tuple
   - VLAN information

4. Parser dispatches packet to worker
5. Worker executes ACL matching
6. Action:
   - FORWARD
   - DROP

7. TX transmits forwarded packets


## 6. Implemented Features

Implemented:

- DPDK initialization
- hugepage support
- mbuf pool
- pcap based RX
- packet parser
- flow normalization
- multi-worker pipeline
- flat ACL lookup
- rule configuration parser
- performance measurement
- runtime logging


## 7. Performance Metrics

The system measures:

- PPS
- Mbps
- cycles per packet
- nanoseconds per packet
- RX stage latency
- Parser latency
- Worker latency
- ACL latency
- TX latency


## 8. Testing

Testing includes:

- functional test cases
- generated pcap traffic
- rule matching validation
- single worker benchmark
- multi worker benchmark
- ACL rule scaling


## 9. Current Investigation

Current performance investigation:

Why adding workers does not always improve throughput.

Experiments:
- worker count change
- ring size tuning
- packet distribution analysis


## 10. Report Requirement

The report should be:

- engineering style
- based on actual implementation
- no fabricated benchmark data
- Vietnamese language
- keep technical terms:
  DPDK, ACL, PPS, Mbps, pipeline, worker, parser, lcore