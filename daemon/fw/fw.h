/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The firewall in use. Port of upstream daemon/firewall/rules.go.
 *
 * Only the nftables backend exists for now: a configuration asking for
 * iptables falls back to it with a warning, as upstream does when iptables
 * isn't available (the iptables backend is listed in docs/UPSTREAM.md).
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_fw owns the backend.
 */
#ifndef KS_DAEMON_FW_FW_H
#define KS_DAEMON_FW_FW_H

#include <stdbool.h>
#include <stdint.h>

/* firewall/config DefaultConfigFile */
#define KS_FW_DEFAULT_CONFIG_FILE "/etc/opensnitchd/system-fw.json"
#define KS_FW_IPTABLES "iptables"

struct ks_evloop;
struct ks_nft;

struct ks_fw {
    struct ks_nft *nft;
};

/* `loop` runs the rules checker. Returns -1 on OOM. */
int ks_fw_create(struct ks_fw *fw, struct ks_evloop *loop);
/* Frees without cleaning up the kernel (see ks_fw_stop). */
void ks_fw_destroy(struct ks_fw *fw);

/* Init: picks the firewall ("" = nftables, with a warning about an
 * outdated configuration), stops it, and starts it with these options. */
int ks_fw_init(struct ks_fw *fw, const char *fw_type, const char *config_path,
               const char *monitor_interval, bool bypass_queue, uint16_t queue_num);
/* Reload: Stop + Init. */
int ks_fw_reload(struct ks_fw *fw, const char *fw_type, const char *config_path,
                 const char *monitor_interval, bool bypass_queue, uint16_t queue_num);
/* Stop: deletes our rules, letting traffic through. */
void ks_fw_stop(struct ks_fw *fw);
bool ks_fw_is_running(const struct ks_fw *fw);
const char *ks_fw_name(const struct ks_fw *fw);

int ks_fw_enable_interception(struct ks_fw *fw);
int ks_fw_disable_interception(struct ks_fw *fw);
void ks_fw_clean_rules(struct ks_fw *fw, bool log_errors);

#endif
