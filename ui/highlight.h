/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The default highlighting of the statistics window's tables: the four
 * configurations of upstream ui/opensnitch/actions/default_configs.py
 * (commonDelegateConfig, defaultRulesDelegateConfig, defaultFWDelegateConfig,
 * netstatDelegateConfig) and the "cells" matching of
 * ui/opensnitch/plugins/highlight/highlight.py: a cell whose column is in
 * `cols` and whose text is one of `text` takes the configuration's color
 * and alignment; later entries override earlier ones.
 *
 * The user's own configurations (XDG_CONFIG_HOME/opensnitch/actions/) belong
 * to the plugin machinery of phase 10.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: static data; the returned strings are literals.
 */
#ifndef KS_UI_HIGHLIGHT_H
#define KS_UI_HIGHLIGHT_H

#include <stdbool.h>

#include "ui/statsq.h"

enum ks_hl_config { KS_HL_NONE, KS_HL_COMMON, KS_HL_RULES, KS_HL_FW, KS_HL_NETSTAT };

struct ks_hl_style {
    const char *color; /* "#rrggbb", or NULL: the widget's own */
    bool center;
};

/* TABLES[tab]['delegate'] */
enum ks_hl_config ks_highlight_for_tab(enum ks_tab tab);
/* True if some entry matches; `out` is the style of the last one. */
bool ks_highlight(enum ks_hl_config cfg, int col, const char *text, struct ks_hl_style *out);

#endif
