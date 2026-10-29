/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * libFuzzer target for the task inputs: the first byte picks the "data"
 * object of a TASK_START (from the UI, untrusted) parsed as the handlers
 * do (sockets-monitor's initConfig, the pid's strconv.Atoi, the interval),
 * or an AF_PACKET sock_diag message as PacketDiagMsg.deserialize reads it.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common/log.h"
#include "common/vendor/cjson/cJSON.h"
#include "daemon/sockdiag.h"
#include "daemon/tasks/monitors.h"
#include "daemon/tasks/tasks.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ks_log_set_level(KS_LOG_FATAL + 1);
    if (size == 0)
        return 0;
    if (data[0] & 1) {
        struct ks_packet_sock s;
        ks_packet_diag_parse(data + 1, size - 1, &s);
        return 0;
    }
    char *txt = malloc(size);
    if (txt == NULL)
        return 0;
    memcpy(txt, data + 1, size - 1);
    txt[size - 1] = '\0';
    cJSON *j = cJSON_Parse(txt);
    char err[512];
    struct ks_sockmon_config cfg;
    if (ks_sockmon_config_parse(j, &cfg, err, sizeof(err)) == 0) {
        int64_t ns;
        ks_task_parse_interval(cfg.interval, &ns, err, sizeof(err));
    }
    const cJSON *pid = cJSON_GetObjectItem(j, "pid");
    long long v;
    if (ks_task_assert(pid, "string", err, sizeof(err)) == NULL)
        ks_task_atoi(pid->valuestring, &v, err, sizeof(err));
    cJSON_Delete(j);
    free(txt);
    return 0;
}
