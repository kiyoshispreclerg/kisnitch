/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of StatsDialog._update_node_info() of upstream
 * ui/opensnitch/dialogs/stats.py.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/nodeinfo.h"

#include <glib.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#include "common/json_util.h"

/* "{0:.0f}": round half to even, which printf does on the exact value */
void ks_nodeinfo_bytes(double value, char *buf, size_t len)
{
    static const char *const units[] = {"B", "KB", "MB", "GB", "TB", "PB"};
    int idx = 0;
    /* upstream divides as floats: `while value / 1024 > 0` ends only at 0 or
     * at the break, so anything above 0 is at least "KB" */
    while (value / 1024 > 0) {
        value = value / 1024;
        idx++;
        if (value < 1024)
            break;
        if (idx >= 5)
            break;
    }
    snprintf(buf, len, "%.0f %s", value, units[idx]);
}

void ks_nodeinfo_uptime(double uptime, char *buf, size_t len)
{
    double hours = uptime / 3600;
    double minutes = fmod(uptime, 3600) / 60;
    double days = (uptime / 1440) / 60;
    if (days > 0) {
        hours = fmod(hours, 24);
        minutes = fmod(uptime, 3600) / 60;
        snprintf(buf, len, "<b>System uptime:</b> %.0f days %.0fh %.0fm", days, hours, minutes);
    } else {
        snprintf(buf, len, "<b>System uptime:</b> %.0fh %.0fm", hours, minutes);
    }
}

static bool num(const cJSON *o, const char *k, double *out)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    if (!cJSON_IsNumber(v))
        return false;
    *out = v->valuedouble;
    return true;
}

bool ks_nodeinfo_parse(const char *json, struct ks_nodeinfo *out)
{
    char err[96];
    cJSON *j = ks_json_parse(json, strlen(json), err, sizeof(err));
    if (!cJSON_IsObject(j)) {
        cJSON_Delete(j);
        return false;
    }
    double total_ram, free_ram, total_swap, free_swap, procs, uptime;
    const cJSON *loads = cJSON_GetObjectItemCaseSensitive(j, "Loads");
    bool ok = num(j, "Totalram", &total_ram) && num(j, "Freeram", &free_ram) &&
              num(j, "Totalswap", &total_swap) && num(j, "Freeswap", &free_swap) &&
              num(j, "Procs", &procs) && num(j, "Uptime", &uptime) && cJSON_IsArray(loads) &&
              cJSON_GetArraySize(loads) >= 3;
    double l[3] = {0, 0, 0};
    for (int i = 0; ok && i < 3; i++) {
        const cJSON *e = cJSON_GetArrayItem(loads, i);
        if (!cJSON_IsNumber(e))
            ok = false;
        else
            l[i] = e->valuedouble / 100000;
    }
    if (ok) {
        double used_ram = total_ram - free_ram, used_swap = total_swap - free_swap;
        out->ram_max = (int)(total_ram / 1000);
        out->ram_value = (int)(used_ram / 1000);
        out->swap_max = (int)(total_swap / 1000);
        out->swap_value = (int)(used_swap / 1000);
        if (out->ram_value == 0)
            out->ram_max = 1;
        if (out->swap_value == 0)
            out->swap_max = 1;
        char a[32], b[32];
        ks_nodeinfo_bytes(total_ram, a, sizeof(a));
        ks_nodeinfo_bytes(free_ram, b, sizeof(b));
        snprintf(out->ram, sizeof(out->ram), "<b>RAM:</b> %s <b>Free:</b> %s", a, b);
        ks_nodeinfo_bytes(total_swap, a, sizeof(a));
        ks_nodeinfo_bytes(free_swap, b, sizeof(b));
        snprintf(out->swap, sizeof(out->swap), "<b>Swap:</b> %s <b>Free:</b> %s", a, b);
        snprintf(out->procs, sizeof(out->procs), "<b>Processes:</b> %.0f", procs);
        /* "{0:.2f}" is not locale aware; printf is (GTK calls setlocale) */
        char l0[G_ASCII_DTOSTR_BUF_SIZE], l1[G_ASCII_DTOSTR_BUF_SIZE], l2[G_ASCII_DTOSTR_BUF_SIZE];
        g_ascii_formatd(l0, sizeof(l0), "%.2f", l[0]);
        g_ascii_formatd(l1, sizeof(l1), "%.2f", l[1]);
        g_ascii_formatd(l2, sizeof(l2), "%.2f", l[2]);
        snprintf(out->loadavg, sizeof(out->loadavg), "<b>Load avg:</b> %s, %s, %s", l0, l1, l2);
        ks_nodeinfo_uptime(uptime, out->uptime, sizeof(out->uptime));
    }
    cJSON_Delete(j);
    return ok;
}
