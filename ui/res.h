/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Resources embedded in the UI (ui/res/, copied from upstream by
 * tools/sync-ui-res.sh; the build turns them into C with tools/bin2c.c).
 * Each array ends with an extra NUL not counted in its length.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#ifndef KS_UI_RES_H
#define KS_UI_RES_H

#include <stddef.h>

#define KS_RES(name)                                                         \
    extern const unsigned char name[];                                       \
    extern const size_t name##_len

KS_RES(ks_res_network_aliases_json);
KS_RES(ks_res_icon_off_png);
KS_RES(ks_res_icon_white_png);
KS_RES(ks_res_icon_pause_png);
KS_RES(ks_res_icon_red_png);
KS_RES(ks_res_icon_alert_png);

#undef KS_RES

#endif
