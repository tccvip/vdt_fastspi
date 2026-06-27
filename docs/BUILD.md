# SPIFast — Build and Dependency Guide

---

## Supported Platform

SPIFast requires Ubuntu bare-metal. DPDK relies on Linux hugepages, CPU affinity, and poll-mode driver kernel modules; neither Windows nor macOS can provide these.

| OS | Status |
|---|---|
| Ubuntu 22.04 LTS (Jammy) | Supported |
| Ubuntu 24.04 LTS (Noble) | Supported (recommended) |

---

## 1. Required Packages

### 1.1 Build Tools

```bash
sudo apt update
sudo apt install -y \
    build-essential \   # GCC, binutils, libc-dev
    gcc \               # GCC 10+ required; GCC 13 recommended
    cmake \             # 3.16+ required
    pkg-config \        # used by CMakeLists.txt to find libdpdk
    git
```

Verify versions:

```bash
gcc --version        # expect: gcc 10.x or newer
cmake --version      # expect: cmake 3.16 or newer
pkg-config --version
```

### 1.2 DPDK

```bash
sudo apt install -y \
    dpdk \              # runtime: rte_eal, rte_mbuf, rte_ring, rte_acl, etc.
    dpdk-dev \          # headers and pkg-config file (libdpdk.pc)
    libdpdk-dev         # symlink package (Ubuntu 22.04+)
```

Verify that `pkg-config` can find the DPDK module:

```bash
pkg-config --modversion libdpdk   # expect: 21.11, 22.11, or 23.11
pkg-config --libs libdpdk         # must print -ldpdk or a list of -lrte_* libs
```

If `pkg-config` fails, DPDK may have been installed to a non-standard prefix. Set:

```bash
export PKG_CONFIG_PATH=/usr/local/lib/x86_64-linux-gnu/pkgconfig:$PKG_CONFIG_PATH
```

### 1.3 libpcap

Required for the `net_pcap` DPDK PMD that replays `.pcap` files.

```bash
sudo apt install -y libpcap-dev
```

### 1.4 NUMA and Threading

```bash
sudo apt install -y \
    libnuma-dev \       # DPDK NUMA-aware memory allocation
    libpthread-stubs0-dev   # usually already present with build-essential
```

### 1.5 Python (DPDK build dependency)

Only needed if you build DPDK from source. Not required when using the distro package.

```bash
sudo apt install -y python3-pyelftools meson ninja-build
```

---

## 2. Hugepage Configuration

DPDK requires hugepages for its mempool allocator. Configure before running `spifast`.

### 2.1 Allocate at runtime (does not survive reboot)

```bash
# 1024 × 2 MB hugepages = 2 GB total (adjust to available RAM)
echo 1024 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# Mount the hugetlbfs filesystem
sudo mkdir -p /mnt/huge
sudo mount -t hugetlbfs none /mnt/huge
```

### 2.2 Persist across reboots (grub)

Add to `/etc/default/grub`:

```
GRUB_CMDLINE_LINUX_DEFAULT="... hugepages=1024"
```

Then:

```bash
sudo update-grub
sudo reboot
```

### 2.3 Verify allocation

```bash
grep HugePages /proc/meminfo
# HugePages_Total:    1024
# HugePages_Free:     1024
```

---

## 3. Build

### 3.1 Configure and Compile

```bash
# From the repository root:
cmake -B build
cmake --build build -j$(nproc)
# Binary: build/spifast
```

### 3.2 Debug vs Release

The build type controls compiler optimisation flags and is the single most important build decision:

| Build type | CMake flag | C flags applied | When to use |
|---|---|---|---|
| **Release** (default) | `-DCMAKE_BUILD_TYPE=Release` | `-O3 -march=native` | All performance benchmarks and normal operation. |
| **Debug** | `-DCMAKE_BUILD_TYPE=Debug` | `-O0 -g` | Debugging with `gdb`, tracing DPDK internals, stepping through ACL logic. |

**Rule:** always benchmark with Release. Debug builds disable all optimisations; measured throughput will be an order of magnitude lower and is not representative.

```bash
# Release (default — use for benchmarks)
cmake -B build
cmake --build build -j$(nproc)

# Debug (use for gdb / development)
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j$(nproc)

# Switch between modes: always reconfigure from a clean build directory
rm -rf build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

### 3.3 Manual make (alternative)

```bash
mkdir build
cd build
cmake ..
make -j$(nproc)
```

### 3.4 Override compile-time constants

DPDK resource parameters defined in `src/dpdk/dpdk_init.h` (SDD §7.5) can be overridden without editing source:

```bash
cmake -B build -DCMAKE_C_FLAGS="\
    -DSPIFAST_MEMPOOL_SIZE=16384 \
    -DSPIFAST_RING_SIZE=2048 \
    -DSPIFAST_BURST_SIZE=64"
cmake --build build -j$(nproc)
```

### 3.5 Clean build

```bash
rm -rf build
cmake -B build
cmake --build build -j$(nproc)
```

---

## 4. Verifying the Build

```bash
# Check the binary links correctly and DPDK symbols are resolved
ldd build/spifast | grep -E "dpdk|pcap|numa"

# Print EAL help (does not process packets)
sudo ./build/spifast --help
```

---

## 5. Runtime Prerequisites

DPDK requires root or `CAP_SYS_ADMIN` to:
- Access hugepage memory
- Set CPU affinity via `rte_eal_init`

Run with `sudo` or grant the binary the necessary capabilities:

```bash
sudo setcap cap_sys_admin,cap_net_raw+ep build/spifast
```

Verify hugepages are allocated before running (see Section 2).

---

## 6. Building DPDK from Source (optional)

Use this path if the distro package is too old (< 21.11) or missing.

```bash
# Download DPDK 23.11 LTS
wget https://fast.dpdk.org/rel/dpdk-23.11.tar.xz
tar xf dpdk-23.11.tar.xz
cd dpdk-23.11

# Build and install to /usr/local
meson setup build --prefix=/usr/local
ninja -C build
sudo ninja -C build install
sudo ldconfig

# Make pkg-config find it
export PKG_CONFIG_PATH=/usr/local/lib/x86_64-linux-gnu/pkgconfig:$PKG_CONFIG_PATH
```

---

## 7. Common Build Errors

### `pkg-config: libdpdk not found`

```
CMake Error: pkg_check_modules: libdpdk: not found
```

**Fix:** Install `dpdk-dev` / `libdpdk-dev`, or set `PKG_CONFIG_PATH` to the directory containing `libdpdk.pc`.

---

### `cannot find -lnuma`

**Fix:** `sudo apt install libnuma-dev`

---

### `cannot find -lpcap`

**Fix:** `sudo apt install libpcap-dev`

---

### PMD `net_pcap` not found at runtime

```
EAL: No probed ethernet devices
```

DPDK's static PMD registration requires the linker to keep PMD constructor symbols. The `CMakeLists.txt` passes `${DPDK_LDFLAGS}` (which carries `--whole-archive`) as link options. If this message appears after a manual link invocation, ensure `--whole-archive`/`--no-whole-archive` wraps the DPDK static libraries.

---

### Hugepage allocation failure

```
EAL: Cannot get hugepage information.
```

**Fix:** Allocate hugepages before running (Section 2).
