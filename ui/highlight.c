/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * See highlight.h.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/highlight.h"

#include <string.h>

/* QColor names are the SVG ones: "green" is #008000 */
#define GREEN "#008000"
#define RED "#ff0000"
#define PURPLE "#800080"
#define BLUE "#0000ff"

#define MAXTEXT 16
#define MAXCOLS 4

struct entry {
    const char *text[MAXTEXT]; /* NULL-terminated */
    int cols[MAXCOLS];         /* -1-terminated */
    const char *color;
};

static const struct entry common[] = {
    {{"allow", "\xe2\x9c\x93 online", NULL}, {1, 2, 3, -1}, GREEN},
    {{"deny", "\xe2\x98\x93 offline", NULL}, {1, 2, 3, -1}, RED},
    {{"reject", NULL}, {1, 2, 3, -1}, PURPLE},
    {{NULL}, {-1}, NULL},
};

static const struct entry rules[] = {
    {{"allow", "True", NULL}, {3, 4, -1}, GREEN},
    {{"deny", "False", NULL}, {3, 4, -1}, RED},
    {{"reject", NULL}, {3, 4, -1}, PURPLE},
    {{NULL}, {-1}, NULL},
};

static const struct entry fw[] = {
    {{"allow", "True", "accept", "jump", "masquerade", "snat", "dnat", "tproxy", "queue",
      "redirect", "True", "ACCEPT", NULL},
     {7, 10, -1},
     GREEN},
    {{"deny", "False", "drop", "DROP", "stop", NULL}, {7, 10, -1}, RED},
    {{"reject", "return", NULL}, {7, 10, -1}, PURPLE},
    {{NULL}, {-1}, NULL},
};

static const struct entry netstat[] = {
    {{"LISTEN", NULL}, {2, -1}, GREEN},
    {{"CLOSE", NULL}, {2, -1}, RED},
    {{"Established", NULL}, {2, -1}, BLUE},
    {{"TCP_SYN_SENT", "TCP_SYN_RECV", "TCP_FIN_WAIT1", "TCP_FIN_WAIT2", "TCP_TIME_WAIT",
      "TCP_CLOSE_WAIT", "TCP_LAST_ACK", "TCP_CLOSING", "TCP_NEW_SYNC_RECV", NULL},
     {2, -1},
     NULL},
    {{NULL}, {-1}, NULL},
};

enum ks_hl_config ks_highlight_for_tab(enum ks_tab tab)
{
    switch (tab) {
    case KS_TAB_RULES:
    case KS_TAB_ALERTS:
        return KS_HL_RULES;
    case KS_TAB_FIREWALL:
        return KS_HL_FW;
    case KS_TAB_NETSTAT:
        return KS_HL_NETSTAT;
    default:
        return KS_HL_COMMON;
    }
}

bool ks_highlight(enum ks_hl_config cfg, int col, const char *text, struct ks_hl_style *out)
{
    const struct entry *e;
    switch (cfg) {
    case KS_HL_COMMON: e = common; break;
    case KS_HL_RULES: e = rules; break;
    case KS_HL_FW: e = fw; break;
    case KS_HL_NETSTAT: e = netstat; break;
    default: return false;
    }
    bool hit = false;
    for (; e->text[0] != NULL; e++) {
        bool incol = false;
        for (int i = 0; e->cols[i] >= 0; i++) {
            if (e->cols[i] == col)
                incol = true;
        }
        if (!incol)
            continue;
        bool intext = false;
        for (int i = 0; e->text[i] != NULL; i++) {
            if (strcmp(e->text[i], text) == 0)
                intext = true;
        }
        if (!intext)
            continue;
        hit = true;
        out->color = e->color;
        out->center = true; /* every entry has "alignment": ["center"] */
    }
    return hit;
}
