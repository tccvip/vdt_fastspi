# SPIFast

High Performance Shallow Packet Inspection System using DPDK.

SPIFast replays a `.pcap` file through a DPDK `net_pcap` virtual port, classifies every IPv4/TCP/UDP packet against a set of configurable L3/L4 filter-group rules, and reports per-group hit counts, forwarded throughput (Mbps), and packet-per-second rates. All packet processing runs in kernel-bypass poll-mode on dedicated CPU cores.

---

## Architecture Overview

```
┌───────────────────────────────────────────────────────┐
│  main lcore  (stats / logging / lifecycle)            │
│   ├── rule_loader  →  acl_engine (compile-time build) │
│   └── stats  →  logging  (every 1 s, append-mode)    │
└──────────────────────┬────────────────────────────────┘
                       │ rte_eal_remote_launch
          ┌────────────┴───────────────┐
          │                            │ × N
   RX / classifier lcore        Worker lcore(s)
   (packet/rx.c)                (worker/worker.c)
   ├── parser.c                 drain ring →
   ├── acl_engine (lookup)      byte/pkt counter →
   └── rte_ring_enqueue ──────► rte_pktmbuf_free
```

**Multicore topology** (SDD §6.1):

| lcore | Role | Module |
|---|---|---|
| 0 | Main / Stats / Logging | `main`, `stats`, `logging` |
| 1 | RX / Classifier | `packet/rx`, `packet/parser`, `rule/acl_engine` |
| 2 … N+1 | Worker 0 … N-1 | `worker/worker` |

Each worker gets its own dedicated SPSC `rte_ring`; the RX lcore dispatches to workers round-robin.

---

## Directory Structure

```
spifast/
├── CMakeLists.txt          # CMake build (GCC, pkg-config DPDK discovery)
├── config/
│   └── spi_rules.conf      # Reference rule configuration
├── docs/
│   ├── SRS.md              # Software Requirements Specification
│   ├── HLD.md              # High-Level Design
│   ├── SDD.md              # Software Detailed Design  ← source of truth
│   └── BUILD.md            # Build and dependency guide
├── src/
│   ├── include/
│   │   └── config.h        # spifast_config_t (shared application config)
│   ├── main.c
│   ├── dpdk/
│   │   ├── dpdk_init.c/.h  # EAL init, mempool, net_pcap port, rings
│   ├── packet/
│   │   ├── rx.c/.h         # RX burst loop, EOI detection
│   │   └── parser.c/.h     # Ethernet/VLAN/IPv4/TCP/UDP parser
│   ├── rule/
│   │   ├── rule_loader.c/.h  # Rule file parser, filter-group table
│   │   └── acl_engine.c/.h   # rte_acl build, per-packet lookup
│   ├── worker/
│   │   └── worker.c/.h     # Ring drain, byte/packet accounting
│   ├── stats/
│   │   └── stats.c/.h      # Per-lcore counter aggregation, Mbps/PPS
│   └── logging/
│       └── log.c/.h        # Dual stdout+file output, log formats
└── tools/
    └── pcap_gen/           # (placeholder) PCAP traffic generator scripts
```

---

## Required Environment

| Component | Minimum | Recommended |
|---|---|---|
| OS | Ubuntu 22.04 LTS | Ubuntu 24.04 LTS |
| Kernel | 5.4 | 6.8 |
| GCC | 10 | 13 |
| CMake | 3.16 | 3.28 |
| DPDK | 21.11 LTS | 23.11 LTS |
| libpcap | 1.9 | 1.10 |
| Hugepages | 512 × 2 MB | 1024 × 2 MB |

### Development Workflow

All development, building, and benchmarking happen on the same Ubuntu bare-metal machine:

1. **Edit** — use any terminal editor (`vim`, `nano`) or a local VS Code window opened directly on the Ubuntu machine.
2. **Build** — run `cmake` and `make` from the repository root (see Build Instructions below).
3. **Run** — execute the binary with `sudo` on the same machine; hugepages and CPU pinning are available on bare-metal.
4. **Benchmark** — run performance tests immediately after a Release build without rebooting or switching machines.

---

## Dependency Installation

See [docs/BUILD.md](docs/BUILD.md) for the full guide. Quick start for Ubuntu 22.04 / 24.04:

```bash
sudo apt update
sudo apt install -y \
    build-essential cmake pkg-config \
    libdpdk-dev dpdk-dev \
    libpcap-dev \
    libnuma-dev \
    python3-pyelftools   # required by DPDK's own build system
```

Configure hugepages (required by DPDK EAL at runtime):

```bash
# Allocate 1024 × 2 MB hugepages (2 GB total)
echo 1024 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
sudo mkdir -p /mnt/huge
sudo mount -t hugetlbfs none /mnt/huge
```

---

## Build Instructions

```bash
# 1. Enter the repository directory
cd vdt_fastspi

# 2. Configure — Release by default (-O3 -march=native)
cmake -B build

# 3. Compile using all available cores
cmake --build build -j$(nproc)

# Binary is at: build/spifast
```

### Debug vs Release

| Mode | Flag | Use when |
|---|---|---|
| **Release** (default) | `-DCMAKE_BUILD_TYPE=Release` | Performance benchmarking, normal operation. Enables `-O3 -march=native`. |
| **Debug** | `-DCMAKE_BUILD_TYPE=Debug` | Step-through debugging with `gdb`, inspecting DPDK internal state. Disables optimisations; throughput will be significantly lower. |

Use Release for all benchmarks. Switch to Debug only to diagnose a specific crash or logic error — do not compare throughput numbers between the two modes.

```bash
# Debug build
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j$(nproc)

# Switch back to Release (clean reconfigure recommended)
rm -rf build
cmake -B build
cmake --build build -j$(nproc)
```

**Override compile-time DPDK resource constants** (SDD §7.5):

```bash
cmake -B build -DCMAKE_C_FLAGS="-DSPIFAST_MEMPOOL_SIZE=16384 -DSPIFAST_RING_SIZE=2048"
cmake --build build -j$(nproc)
```

---

## Run Instructions

SPIFast uses the standard DPDK EAL argument convention: EAL options come first, followed by `--`, followed by application options.

**Minimum required:** `--pcap <path>`

**Full option reference:**

| Option | Required | Default | Description |
|---|---|---|---|
| `--pcap <path>` | Yes | — | Input PCAP file |
| `--rules <path>` | No | `spi_rules.conf` | Rule configuration file |
| `--workers <N>` | No | `1` | Number of worker lcores (≥ 1) |
| `--log <path>` | No | (none) | Append-mode log file |
| `--mode first\|best` | No | `first` | ACL match mode |

The EAL options `-l` (lcore list) and `-n` (memory channels) must cover at least `2 + N` lcores where `N` is `--workers`.

---

## Example Commands

```bash
# Minimal: 1 worker, default rules, log to stdout only
sudo ./build/spifast -l 0-2 -n 4 -- \
    --pcap tests/tp01_small.pcap

# Full: 4 workers, explicit rules, log file, best-match mode
sudo ./build/spifast -l 0-6 -n 4 -- \
    --pcap tests/tp02_medium.pcap \
    --rules config/spi_rules.conf \
    --workers 4 \
    --log /var/log/spifast/run.log \
    --mode best
```

**Example output (one periodic line per second):**

```
[2025-06-26T14:32:05+0700] elapsed=10s  rx=500000  fwd=490000  drop=9800  inv=200  ring_drop=0  mbps=823.40  pps=490000  | fg_l34_facebook=120000 fg_l34_youtube=85000 fg_l34_http_sdf1003=200000 fg_l34_dns_sdf1005=85000 DEFAULT=9800
```

---

## Rule File Format

Rules are defined in a plain-text file. Filter groups declare the action; rules assign packets to groups.

```
# Group declarations
[group: fg_l34_facebook]     precedence=100  action=FORWARD
[group: DEFAULT]             precedence=999  action=DROP

# Rules: name, group, protocol, src_ip, dst_ip, src_port, dst_port
f_l34_facebook_1, fg_l34_facebook, any, dst_prefix=31.13.64.0/18, any, any
f_l34_http_all,   fg_l34_facebook, tcp, any, any, any, 80
```

See `config/spi_rules.conf` for the full reference configuration and `docs/SDD.md §5` for the grammar specification.

---

## Performance Targets (SRS)

| Metric | Target |
|---|---|
| Throughput | ≥ 700 Mbps (1024-byte frames) |
| PPS | ≥ 500 Kpps (64-byte frames) |
| Unintended drop rate | ≤ 0.1% |
| Packet accounting | Zero unaccounted packets (PASS) |

---

## References

- `docs/SRS.md` — Software Requirements Specification
- `docs/HLD.md` — High-Level Design
- `docs/SDD.md` — Software Detailed Design (architecture source of truth)
- `docs/BUILD.md` — Build and dependency guide
