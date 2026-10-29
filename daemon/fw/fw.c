/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/firewall/rules.go.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "daemon/fw/fw.h"

#include <string.h>

#include "common/log.h"
#include "daemon/fw/iptables.h"
#include "daemon/fw/nft.h"
#include "daemon/fw/sysfw.h"

int ks_fw_create(struct ks_fw *fw, struct ks_evloop *loop)
{
    memset(fw, 0, sizeof(*fw));
    fw->nft = ks_nft_new(loop);
    fw->ipt = ks_ipt_new(loop);
    if (fw->nft == NULL || fw->ipt == NULL) {
        ks_fw_destroy(fw);
        return -1;
    }
    return 0;
}

void ks_fw_destroy(struct ks_fw *fw)
{
    ks_nft_free(fw->nft);
    ks_ipt_free(fw->ipt);
    fw->nft = NULL;
    fw->ipt = NULL;
    fw->current = KS_FW_NONE;
}

int ks_fw_init(struct ks_fw *fw, const char *fw_type, const char *config_path,
               const char *monitor_interval, bool bypass_queue, uint16_t queue_num)
{
    bool conf_error = false;
    if (fw_type == NULL || fw_type[0] == '\0') {
        conf_error = true;
        fw_type = KS_NFT_NAME;
    }
    if (config_path == NULL || config_path[0] == '\0') {
        conf_error = true;
        config_path = KS_FW_DEFAULT_CONFIG_FILE;
    }
    bool err = false;
    if (strcmp(fw_type, KS_FW_IPTABLES) == 0) {
        if (fw->assume_iptables || ks_ipt_is_available()) {
            fw->current = KS_FW_BACKEND_IPT;
        } else {
            ks_warning("iptables not available: exec: \"iptables\": executable file not "
                       "found in $PATH");
            err = true;
        }
    }
    if (strcmp(fw_type, KS_NFT_NAME) == 0 || err)
        fw->current = KS_FW_BACKEND_NFT;
    /* any other type keeps the previous firewall, if there's one */
    if (fw->current == KS_FW_NONE) {
        ks_error("Firewall not initialized. Be sure that you're using latest configuration "
                 "file. Report it on github if needed.");
        return -1;
    }

    const char *path = config_path;
    const char *ival = monitor_interval ? monitor_interval : "";
    if (fw->current == KS_FW_BACKEND_IPT) {
        ks_ipt_stop(fw->ipt);
        ks_ipt_init(fw->ipt, queue_num, path, ival, bypass_queue);
    } else {
        ks_nft_stop(fw->nft);
        ks_nft_init(fw->nft, queue_num, path, ival, bypass_queue);
    }
    if (conf_error)
        ks_error("Firewall error: the default configuration seem to be outdated "
                 "(default-config.json). Get latest configuration from github.");
    ks_info("Using %s firewall", ks_fw_name(fw));
    return 0;
}

int ks_fw_reload(struct ks_fw *fw, const char *fw_type, const char *config_path,
                 const char *monitor_interval, bool bypass_queue, uint16_t queue_num)
{
    ks_fw_stop(fw);
    return ks_fw_init(fw, fw_type, config_path, monitor_interval, bypass_queue, queue_num);
}

void ks_fw_stop(struct ks_fw *fw)
{
    if (fw->current == KS_FW_BACKEND_IPT)
        ks_ipt_stop(fw->ipt);
    else if (fw->current == KS_FW_BACKEND_NFT)
        ks_nft_stop(fw->nft);
}

bool ks_fw_is_running(const struct ks_fw *fw)
{
    if (fw->current == KS_FW_BACKEND_IPT)
        return ks_ipt_is_running(fw->ipt);
    if (fw->current == KS_FW_BACKEND_NFT)
        return ks_nft_is_running(fw->nft);
    return false;
}

const char *ks_fw_name(const struct ks_fw *fw)
{
    return fw->current == KS_FW_BACKEND_IPT ? KS_IPT_NAME : KS_NFT_NAME;
}

int ks_fw_enable_interception(struct ks_fw *fw)
{
    if (fw->current == KS_FW_NONE) {
        ks_error("firewall not initialized when trying to enable interception, report please");
        return -1;
    }
    if (fw->current == KS_FW_BACKEND_IPT)
        ks_ipt_enable_interception(fw->ipt);
    else
        ks_nft_enable_interception(fw->nft);
    return 0;
}

int ks_fw_disable_interception(struct ks_fw *fw)
{
    if (fw->current == KS_FW_NONE) {
        ks_error("firewall not initialized when trying to disable interception, report please");
        return -1;
    }
    if (fw->current == KS_FW_BACKEND_IPT)
        ks_ipt_disable_interception(fw->ipt, true);
    else
        ks_nft_disable_interception(fw->nft, true);
    return 0;
}

void ks_fw_clean_rules(struct ks_fw *fw, bool log_errors)
{
    if (fw->current == KS_FW_BACKEND_IPT)
        ks_ipt_clean_rules(fw->ipt, log_errors);
    else if (fw->current == KS_FW_BACKEND_NFT)
        ks_nft_clean_rules(fw->nft, log_errors);
}

struct _Protocol__SysFirewall *ks_fw_serialize(struct ks_fw *fw, struct ks_arena *a)
{
    if (fw->current == KS_FW_BACKEND_IPT)
        return ks_ipt_serialize(fw->ipt, a);
    if (fw->current == KS_FW_BACKEND_NFT)
        return ks_nft_serialize(fw->nft, a);
    ks_warning("firewall.Serialize() error: firewall not initialized, report please");
    return NULL;
}

char *ks_fw_deserialize(struct ks_fw *fw, const struct _Protocol__SysFirewall *sysfw)
{
    if (fw->current == KS_FW_NONE || sysfw == NULL)
        return NULL;
    /* nftables: EmitDefaults true; iptables: false */
    return ks_sysfw_pb_to_json(sysfw, fw->current == KS_FW_BACKEND_NFT);
}

int ks_fw_save_configuration(struct ks_fw *fw, const char *raw)
{
    if (fw->current == KS_FW_BACKEND_IPT)
        return ks_ipt_save_configuration(fw->ipt, raw, strlen(raw));
    if (fw->current == KS_FW_BACKEND_NFT)
        return ks_nft_save_configuration(fw->nft, raw, strlen(raw));
    return -1;
}

struct ks_fw_errors *ks_fw_errors(struct ks_fw *fw)
{
    if (fw->current == KS_FW_BACKEND_IPT)
        return ks_ipt_errors(fw->ipt);
    if (fw->current == KS_FW_BACKEND_NFT)
        return ks_nft_errors(fw->nft);
    return NULL;
}

const struct ks_sysfw *ks_fw_sysfw(const struct ks_fw *fw)
{
    if (fw->current == KS_FW_BACKEND_IPT)
        return ks_ipt_sysfw(fw->ipt);
    if (fw->current == KS_FW_BACKEND_NFT)
        return ks_nft_sysfw(fw->nft);
    return NULL;
}
