/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * libFuzzer target for the auditd record parser (daemon/procmon/audit.c):
 * the records carry process names and paths chosen by any program. Each
 * line of the input is one record.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common/log.h"
#include "daemon/procmon/audit.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ks_log_set_level(KS_LOG_FATAL + 1);
    char *txt = malloc(size + 1);
    if (txt == NULL)
        return 0;
    memcpy(txt, data, size);
    txt[size] = '\0';
    char *save = NULL;
    for (char *l = strtok_r(txt, "\n", &save); l != NULL; l = strtok_r(NULL, "\n", &save))
        ks_audit_parse_line(l);
    for (size_t i = 0; i < ks_audit_count(); i++)
        (void)ks_audit_event_at(i)->pid;
    ks_audit_reset();
    free(txt);
    return 0;
}
