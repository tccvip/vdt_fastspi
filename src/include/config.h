#ifndef SPIFAST_CONFIG_H
#define SPIFAST_CONFIG_H

#include <stdint.h>

/* Maximum length for file path strings used in application config. */
#define SPIFAST_MAX_PATH  512

/* ─────────────────────────────────────────────────────────────────────────────
 * Application configuration  (SDD §3.7)
 * Populated in main() by getopt_long; passed read-only to all modules.
 * ───────────────────────────────────────────────────────────────────────────── */
typedef enum {
    MATCH_MODE_FIRST = 0,   /* default: first rule in precedence order wins */
    MATCH_MODE_BEST  = 1    /* best-match: highest-priority match wins       */
} match_mode_t;

typedef struct {
    char         pcap_path[SPIFAST_MAX_PATH];  /* --pcap <path>            */
    char         rules_path[SPIFAST_MAX_PATH]; /* --rules <path>           */
    char         log_path[SPIFAST_MAX_PATH];   /* --log <path>; empty=none */
    uint32_t     num_workers;                  /* --workers N (≥ 1)        */
    match_mode_t match_mode;                   /* --mode first|best        */
    int          stats_interval_sec;           /* default: 1               */
} spifast_config_t;

#endif /* SPIFAST_CONFIG_H */
