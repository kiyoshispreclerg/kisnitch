/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * nftables firewall: the interception table, chains and rules, and the
 * monitor that puts them back when they disappear. Port of upstream
 * daemon/firewall/nftables/{nftables,tables,chains,rules,monitor,utils}.go
 * and the rules checker of daemon/firewall/common/common.go, talking to the
 * kernel through libnftnl and libmnl (upstream uses google/nftables).
 *
 * What gets installed (byte for byte what upstream installs, so either
 * daemon cleans up after the other):
 *
 *   table inet opensnitch
 *     chain filter_input   { type filter hook input  priority filter; }
 *       udp sport 53 queue num N [bypass]            (DNS responses)
 *     chain mangle_output  { type route  hook output priority mangle; }
 *       meta l4proto != tcp ct state new,related queue num N [bypass]
 *       tcp flags & (fin|syn|rst|ack) == syn queue num N [bypass]
 *
 * Every rule carries the user data "opensnitch-key-interception" (raw
 * bytes), which is how they are found and deleted.
 *
 * The system firewall (system-fw.json: tables, chains and rules carrying the
 * user data "opensnitch-key-system") is in nft_sys.c and nft_exprs.c.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_nft owns its netlink socket, its stores of tables and
 * chains, and its timers on the event loop, which must outlive it.
 */
#ifndef KS_DAEMON_FW_NFT_H
#define KS_DAEMON_FW_NFT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define KS_NFT_NAME "nftables"
#define KS_NFT_KEY "opensnitch-key"
#define KS_NFT_INTERCEPTION_KEY KS_NFT_KEY "-interception"
#define KS_NFT_SYSTEM_KEY KS_NFT_KEY "-system"

#define KS_NFT_TABLE_OPENSNITCH "opensnitch"
#define KS_NFT_CHAIN_FILTER_INPUT "filter_input"
#define KS_NFT_CHAIN_MANGLE_OUTPUT "mangle_output"
#define KS_NFT_FAMILY_INET "inet"

/* common.DefaultCheckInterval */
#define KS_FW_DEFAULT_CHECK_INTERVAL_NS (10LL * 1000000000LL)

struct ks_arena;
struct ks_evloop;
struct ks_fw_errors;
struct ks_nft;
struct ks_sysfw;
struct _Protocol__SysFirewall;

/* Fw(): a stopped firewall. NULL on OOM. */
struct ks_nft *ks_nft_new(struct ks_evloop *loop);
/* Frees without touching the kernel; call ks_nft_stop() first to clean up. */
void ks_nft_free(struct ks_nft *n);

/* Init: loads system-fw.json from `config_path` (and watches it), cleans
 * up leftovers of a previous run, adds the system rules and the
 * interception rules, and starts the rules checker. Does nothing if
 * already running.
 * `monitor_interval` is a Go duration ("10s"; "0s" disables the checker;
 * invalid ones fall back to 10s). */
void ks_nft_init(struct ks_nft *n, uint16_t queue_num, const char *config_path,
                 const char *monitor_interval, bool bypass_queue);
/* Stop: deletes our rules, chains and (if nothing else uses them) tables. */
void ks_nft_stop(struct ks_nft *n);
bool ks_nft_is_running(const struct ks_nft *n);

void ks_nft_enable_interception(struct ks_nft *n);
void ks_nft_disable_interception(struct ks_nft *n, bool log_errors);
/* CleanRules */
void ks_nft_clean_rules(struct ks_nft *n, bool log_errors);

/* Serialize: the system firewall configuration, allocated in `a`. */
struct _Protocol__SysFirewall *ks_nft_serialize(struct ks_nft *n, struct ks_arena *a);
/* SaveConfiguration: writes system-fw.json (the watcher applies it). */
int ks_nft_save_configuration(struct ks_nft *n, const char *raw, size_t len);
/* ErrorsChan: errors adding system rules. */
struct ks_fw_errors *ks_nft_errors(struct ks_nft *n);
/* The loaded system firewall configuration (SysConfig). */
const struct ks_sysfw *ks_nft_sysfw(const struct ks_nft *n);

/* AreRulesLoaded: the three rules are there, the DNS one first in
 * filter_input and the other two last in mangle_output. */
bool ks_nft_are_rules_loaded(struct ks_nft *n);

/* The rules checker's interval in ns (0: disabled). */
int64_t ks_nft_check_interval(const struct ks_nft *n);

/* Low-level helpers, also for tests. */

/* The number of rules carrying user data `key` in every table, or -1 if
 * the ruleset can't be listed. */
int ks_nft_count_rules(struct ks_nft *n, const char *key);
/* Whether table `name` (any family) exists in the kernel. -1 on error. */
int ks_nft_table_exists(struct ks_nft *n, const char *name);

#endif
