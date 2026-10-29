/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The firewall in use. Port of upstream daemon/firewall/rules.go.
 *
 * "iptables" uses the iptables binaries when `iptables -V` works, and
 * nftables otherwise (with a warning), as upstream does.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_fw owns both backends.
 */
#ifndef KS_DAEMON_FW_FW_H
#define KS_DAEMON_FW_FW_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* firewall/config DefaultConfigFile */
#define KS_FW_DEFAULT_CONFIG_FILE "/etc/opensnitchd/system-fw.json"
#define KS_FW_IPTABLES "iptables"

struct ks_arena;
struct ks_evloop;
struct ks_fw_errors;
struct ks_ipt;
struct ks_nft;
struct ks_sysfw;
struct _Protocol__SysFirewall;

enum ks_fw_backend { KS_FW_NONE, KS_FW_BACKEND_NFT, KS_FW_BACKEND_IPT };

struct ks_fw {
    struct ks_nft *nft;
    struct ks_ipt *ipt;
    enum ks_fw_backend current; /* the `fw` global */
    /* tests: skip the `iptables -V` check */
    bool assume_iptables;
};

/* `loop` runs the rules checker and the configuration watcher. -1 on OOM. */
int ks_fw_create(struct ks_fw *fw, struct ks_evloop *loop);
/* Frees without cleaning up the kernel (see ks_fw_stop). */
void ks_fw_destroy(struct ks_fw *fw);

/* Init: picks the firewall ("" = nftables, with a warning about an
 * outdated configuration), stops it, and starts it with these options.
 * -1 if no firewall could be picked (an unknown type before any other). */
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

/* Serialize: system-fw.json as protobuf, allocated in `a`. NULL if the
 * firewall isn't initialized (or OOM). */
struct _Protocol__SysFirewall *ks_fw_serialize(struct ks_fw *fw, struct ks_arena *a);
/* Deserialize: the JSON text to save (malloc'd), or NULL. */
char *ks_fw_deserialize(struct ks_fw *fw, const struct _Protocol__SysFirewall *sysfw);
/* SaveConfiguration. 0 or -1. */
int ks_fw_save_configuration(struct ks_fw *fw, const char *raw);
/* ErrorsChan, or NULL if not initialized. */
struct ks_fw_errors *ks_fw_errors(struct ks_fw *fw);
/* The loaded configuration, or NULL if not initialized. */
const struct ks_sysfw *ks_fw_sysfw(const struct ks_fw *fw);

#endif
