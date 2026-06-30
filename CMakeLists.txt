cmake_minimum_required(VERSION 3.16)
project(spifast LANGUAGES C)

# ─────────────────────────────────────────────────────────────────────────────
# Compiler settings  (SRS CON-09: GCC on Linux, no errors / warnings)
# ─────────────────────────────────────────────────────────────────────────────
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(
    -Wall
    -Wextra
    -Wno-unused-parameter
    "$<$<CONFIG:Release>:-O3;-march=native>"
    "$<$<CONFIG:Debug>:-O0;-g>"
)

# ─────────────────────────────────────────────────────────────────────────────
# DPDK  (target: 23.11 LTS, minimum: 21.11 LTS — SDD cover page)
# Requires: dpdk-dev package or DPDK built/installed with meson.
# The libdpdk.pc shipped since DPDK 20.11 carries all needed link flags.
# ─────────────────────────────────────────────────────────────────────────────
find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED libdpdk)

# net_pcap PMD needs the system pcap library at link time.
find_library(PCAP_LIBRARY NAMES pcap REQUIRED)

# ─────────────────────────────────────────────────────────────────────────────
# Sources  (one .c per SDD §1.1 module; no extra translation units)
# ─────────────────────────────────────────────────────────────────────────────
set(SPIFAST_SOURCES
    src/main.c
    src/dpdk/dpdk_init.c
    src/packet/rx.c
    src/packet/parser.c
    src/rule/rule_loader.c
    src/rule/acl_engine.c
    src/worker/worker.c
    src/tx/tx.c
    src/stats/stats.c
    src/logging/log.c
    src/perf/perf_stats.c
)

add_executable(spifast ${SPIFAST_SOURCES})

target_include_directories(spifast PRIVATE
    src                   # enables #include "dpdk/dpdk_init.h" style
    ${DPDK_INCLUDE_DIRS}
)

target_compile_options(spifast PRIVATE ${DPDK_CFLAGS_OTHER})

# pkg-config emits -Wl,--whole-archive/-Wl,--no-whole-archive around static
# PMD objects so that driver registration constructors are not stripped.
# Pass those flags verbatim to the linker.
target_link_options(spifast PRIVATE ${DPDK_LDFLAGS})

target_link_libraries(spifast PRIVATE
    ${DPDK_LIBRARIES}
    ${PCAP_LIBRARY}
    m
    pthread
    dl
    numa
)

# ─────────────────────────────────────────────────────────────────────────────
# Unit tests  (no EAL init required — fake rte_mbuf via buf_addr/data_off)
# Build: cmake --build build --target test_parser
# Run:   build/test_parser
# ─────────────────────────────────────────────────────────────────────────────
add_executable(test_parser
    tests/test_parser.c
    src/packet/parser.c
)
target_include_directories(test_parser PRIVATE src ${DPDK_INCLUDE_DIRS})
target_compile_options(test_parser PRIVATE ${DPDK_CFLAGS_OTHER})
target_link_options(test_parser PRIVATE ${DPDK_LDFLAGS})
target_link_libraries(test_parser PRIVATE
    ${DPDK_LIBRARIES}
    ${PCAP_LIBRARY}
    m pthread dl numa
)

# ─────────────────────────────────────────────────────────────────────────────
# test_rule_loader — unit tests for flat rule parsing and validation (Phase 2)
# Uses rule_loader_parse() (Steps 1-3, no ACL build) so EAL init is not
# required.  acl_engine.c is linked to satisfy rule_loader_load()'s call to
# acl_engine_build() (Phase 3 — now a real implementation, not a stub).
# Build: cmake --build build --target test_rule_loader
# Run:   build/test_rule_loader
# ─────────────────────────────────────────────────────────────────────────────
add_executable(test_rule_loader
    tests/test_rule_loader.c
    src/rule/rule_loader.c
    src/rule/acl_engine.c
)
target_include_directories(test_rule_loader PRIVATE src ${DPDK_INCLUDE_DIRS})
target_compile_options(test_rule_loader PRIVATE ${DPDK_CFLAGS_OTHER})
target_link_options(test_rule_loader PRIVATE ${DPDK_LDFLAGS})
target_link_libraries(test_rule_loader PRIVATE
    ${DPDK_LIBRARIES}
    ${PCAP_LIBRARY}
    m pthread dl numa
)

# ─────────────────────────────────────────────────────────────────────────────
# test_acl — unit tests for flat single-stage ACL engine (Phase 3)
# flat_acl_match is pure C linear scan; no EAL init or hugepages required.
# acl_engine.c is included directly.
# Build: cmake --build build --target test_acl
# Run:   build/test_acl
# ─────────────────────────────────────────────────────────────────────────────
add_executable(test_acl
    tests/test_acl.c
    src/rule/rule_loader.c
    src/rule/acl_engine.c
)
target_include_directories(test_acl PRIVATE src ${DPDK_INCLUDE_DIRS})
target_compile_options(test_acl PRIVATE ${DPDK_CFLAGS_OTHER})
target_link_options(test_acl PRIVATE ${DPDK_LDFLAGS})
target_link_libraries(test_acl PRIVATE
    ${DPDK_LIBRARIES}
    ${PCAP_LIBRARY}
    m pthread dl numa
)

# ─────────────────────────────────────────────────────────────────────────────
# Install
# ─────────────────────────────────────────────────────────────────────────────
install(TARGETS spifast RUNTIME DESTINATION bin)
install(FILES config/spi_rules.conf DESTINATION etc/spifast)
