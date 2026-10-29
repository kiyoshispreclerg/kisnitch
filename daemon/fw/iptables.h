/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * iptables firewall: port of upstream daemon/firewall/iptables/
 * {iptables,rules,system,monitor}.go. Like upstream, it runs the iptables
 * and ip6tables binaries (ip6tables only if /proc/sys/net/ipv6 exists).
 *
 * What gets installed:
 *   iptables -I INPUT --protocol udp --sport 53 -j NFQUEUE --queue-num N [--queue-bypass]
 *   iptables -A OUTPUT -t mangle -m conntrack --ctstate NEW,RELATED -j NFQUEUE ...
 * plus, for each legacy "Rule" of system-fw.json, a chain
 * "opensnitch-filter-<Chain>" jumped to from the top of <Chain>.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_ipt owns its configuration (and its watcher), the
 * table of chains it added and its timers on the event loop, which must
 * outlive it.
 */
#ifndef KS_DAEMON_FW_IPTABLES_H
#define KS_DAEMON_FW_IPTABLES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define KS_IPT_NAME "iptables"
#define KS_IPT_SYSTEM_RULE_PREFIX "opensnitch-filter"

struct ks_arena;
struct ks_evloop;
struct ks_fw_errors;
struct ks_ipt;
struct ks_sysfw;
struct _Protocol__SysFirewall;

/* IsAvailable: `iptables -V` runs. */
bool ks_ipt_is_available(void);

/* Fw(): a stopped firewall. NULL on OOM. */
struct ks_ipt *ks_ipt_new(struct ks_evloop *loop);
/* Frees without touching the system; call ks_ipt_stop() first. */
void ks_ipt_free(struct ks_ipt *ipt);

void ks_ipt_init(struct ks_ipt *ipt, uint16_t queue_num, const char *config_path,
                 const char *monitor_interval, bool bypass_queue);
void ks_ipt_stop(struct ks_ipt *ipt);
bool ks_ipt_is_running(const struct ks_ipt *ipt);

void ks_ipt_enable_interception(struct ks_ipt *ipt);
void ks_ipt_disable_interception(struct ks_ipt *ipt, bool log_errors);
void ks_ipt_clean_rules(struct ks_ipt *ipt, bool log_errors);
/* AreRulesLoaded */
bool ks_ipt_are_rules_loaded(struct ks_ipt *ipt);

struct _Protocol__SysFirewall *ks_ipt_serialize(struct ks_ipt *ipt, struct ks_arena *a);
int ks_ipt_save_configuration(struct ks_ipt *ipt, const char *raw, size_t len);
struct ks_fw_errors *ks_ipt_errors(struct ks_ipt *ipt);
const struct ks_sysfw *ks_ipt_sysfw(const struct ks_ipt *ipt);

/* The binaries, for tests (default "iptables" and "ip6tables"). */
void ks_ipt_set_binaries(struct ks_ipt *ipt, const char *bin, const char *bin6);

#endif
