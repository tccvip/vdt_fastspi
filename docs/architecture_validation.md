# Architecture Validation Checklist

**Document:** SPIFAST-ARCH-VAL-001  
**Date:** 2026-06-30  
**Validated against:** HLD v1.4, SDD v1.3, `src/` (commit on main branch)

---

## Architecture

- [x] RX → Parser → Worker → Flat ACL → TX

Pipeline implemented in `src/packet/rx.c`, `src/packet/parser.c`, `src/worker/worker.c`, `src/rule/acl_engine.c`, `src/tx/tx.c`.

---

## ACL Model

- [x] Single flat ACL lookup — one `rte_acl_classify(flat_acl_ctx, ...)` call per burst in Worker lcore (`src/worker/worker.c`)
- [x] No group-based ACL — `stage1_ctx` and `group_ctx[]` are absent from codebase
- [x] Action embedded in `flat_rule_entry_t.action` — no separate group table lookup at runtime (`src/rule/acl_engine.h`, `src/rule/rule_loader.h`)
- [x] No lazy build — `acl_engine_build()` completes before any Worker lcore starts (`src/main.c`)
- [x] No LRU eviction — single static `flat_acl_ctx` for the session lifetime

---

## Removed Concepts (confirmed absent in code)

- [x] `stage1_ctx` — not present
- [x] `group_ctx[]` — not present
- [x] `filter_group_table_t` / `filter_group_t` — not present
- [x] `acl_result_t` — not present
- [x] Two-stage ACL classify (`rte_acl_classify` called twice per burst) — not present
- [x] Lazy build trigger from Worker to Main — not present
- [x] `atomic_store`/`atomic_load` for group context pointers — not present

---

## Code Consistency

- [x] Documentation matches `src/` structure:

| `src/` module | HLD component | SDD module |
|---|---|---|
| `packet/rx.c` | RX lcore | `packet/rx` |
| `packet/parser.c` | Parser lcore | `packet/parser` |
| `rule/rule_loader.c` | ACL Rule Engine (load) | `rule/rule_loader` |
| `rule/acl_engine.c` | ACL Rule Engine (build+lookup) | `rule/acl_engine` |
| `worker/worker.c` | Worker lcore | `worker/worker` |
| `tx/tx.c` | TX lcore | `tx/tx` |
| `stats/stats.c` | Statistics Component | `stats/stats` |
| `logging/log.c` | Logging Component | `logging/log` |
| `perf/perf_stats.c` | (Phase 8 addition) | — |
| `dpdk/dpdk_init.c` | DPDK Init Component | `dpdk/dpdk_init` |

- [x] RX lcore uses libpcap (`pcap_open_offline` + `pcap_next_ex`) for continuous replay — SDD §6.2 updated
- [x] `rx_lcore_stats_t` has 5 fields: `rx_packets`, `rx_bytes`, `alloc_fail`, `parser_ring_drop`, `pcap_loops` — SDD §3.5 updated
- [x] `tx_ring` created with `RING_F_SC_DEQ` only (no `RING_F_SP_ENQ`) — MPSC-safe for N workers — matches SDD §7.3

---

## Resource Constants (verified against `src/dpdk/dpdk_init.h`)

| Constant | SDD Value | Code Value | Match |
|---|---|---|---|
| `SPIFAST_MEMPOOL_SIZE` | 32768 | 32768 | ✓ |
| `SPIFAST_BURST_SIZE` | 64 | 64 | ✓ |
| `SPIFAST_WORKER_BURST` | 32 | 32 | ✓ |
| `SPIFAST_TX_BURST_SIZE` | 64 | 64 | ✓ |
| `SPIFAST_PARSER_RING_SIZE` | 65536 | 65536 | ✓ |
| `SPIFAST_RING_SIZE` | 4096 | 4096 | ✓ |
| `SPIFAST_TX_RING_SIZE` | 65536 | 65536 | ✓ |
| `SPIFAST_MAX_GROUPS` | 4096 | 4096 | ✓ |
| `SPIFAST_MAX_RULES` | 65536 | 65536 | ✓ |
| `SPIFAST_MAX_WORKERS` | — | 64 | ✓ |

---

## Remaining Inconsistencies

None identified after Phase 8 documentation synchronization.

**Notes for future updates:**
- If `perf/perf_stats.c` module grows into a formal component, add it to HLD §2 and SDD §1.1.
- SDD §6.1 shows lcore IDs as `0, 1, 2, 3...` — these are logical lcore assignments and match the `dpdk_init.c` sequential assignment strategy. Actual CPU core mapping depends on `--lcores` EAL argument at runtime.
