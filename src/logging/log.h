#ifndef SPIFAST_LOG_H
#define SPIFAST_LOG_H

#include "include/config.h"      /* spifast_config_t    */
#include "rule/rule_loader.h"    /* flat_rule_table_t   */
#include "stats/stats.h"         /* stats_snapshot_t    */

/* ─────────────────────────────────────────────────────────────────────────────
 * Logging component  (SDD §2.8, §8.2)
 *
 * All functions must be called exclusively from the main/stats lcore.
 * File I/O is never performed on the RX or worker lcores (HLD DD-09).
 *
 * Dual-output: every log_write() goes to stdout AND, if a path was supplied,
 * to an append-mode file (log.c maintains the static FILE * internally).
 * ───────────────────────────────────────────────────────────────────────────── */

/* Open the log file at path in append mode.  If path is NULL or empty the
 * file output is silently skipped; stdout output continues in all cases.
 * On fopen failure a warning is printed to stderr and file output is
 * disabled — packet processing is never interrupted.  SDD §8.2 */
void log_open(const char *path);

/* Emit a startup summary: application config, worker count, match mode,
 * PCAP path, rules path.  Then emit one RULE line per loaded rule.
 * Called after rule_loader_load() completes.  SDD §8.2, LOG-004 */
void log_startup_event(const spifast_config_t  *cfg,
                       const flat_rule_table_t *tbl);

/* Emit the periodic statistics line (once per second).
 * Format defined in SDD §8.3.  SDD §8.2, LOG-002, LOG-003 */
void log_periodic(const stats_snapshot_t  *snap,
                  const flat_rule_table_t *tbl);

/* Emit SESSION_END summary block including group hit table and packet
 * accounting validation result.  SDD §8.2, FR-031, LOG-004 */
void log_final_summary(const stats_snapshot_t  *snap,
                       const flat_rule_table_t *tbl);

/* Flush and close the log file.  No-op if file was never opened.
 * Called just before rte_eal_cleanup().  SDD §8.2 */
void log_close(void);

#endif /* SPIFAST_LOG_H */
