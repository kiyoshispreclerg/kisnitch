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
#include "daemon/fw/nft.h"

int ks_fw_create(struct ks_fw *fw, struct ks_evloop *loop)
{
    fw->nft = ks_nft_new(loop);
    return fw->nft != NULL ? 0 : -1;
}

void ks_fw_destroy(struct ks_fw *fw)
{
    ks_nft_free(fw->nft);
    fw->nft = NULL;
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
    if (strcmp(fw_type, KS_FW_IPTABLES) == 0)
        ks_warning("iptables not available: not implemented in this port yet");

    ks_nft_stop(fw->nft);
    ks_nft_init(fw->nft, queue_num, config_path, monitor_interval ? monitor_interval : "",
                bypass_queue);
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
    if (fw->nft != NULL)
        ks_nft_stop(fw->nft);
}

bool ks_fw_is_running(const struct ks_fw *fw)
{
    return fw->nft != NULL && ks_nft_is_running(fw->nft);
}

const char *ks_fw_name(const struct ks_fw *fw)
{
    (void)fw;
    return KS_NFT_NAME;
}

int ks_fw_enable_interception(struct ks_fw *fw)
{
    if (fw->nft == NULL) {
        ks_error("firewall not initialized when trying to enable interception, report please");
        return -1;
    }
    ks_nft_enable_interception(fw->nft);
    return 0;
}

int ks_fw_disable_interception(struct ks_fw *fw)
{
    if (fw->nft == NULL) {
        ks_error("firewall not initialized when trying to disable interception, report please");
        return -1;
    }
    ks_nft_disable_interception(fw->nft, true);
    return 0;
}

void ks_fw_clean_rules(struct ks_fw *fw, bool log_errors)
{
    if (fw->nft != NULL)
        ks_nft_clean_rules(fw->nft, log_errors);
}
