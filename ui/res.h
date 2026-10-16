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
KS_RES(ks_res_kisnitch_png); /* data/icons/hicolor/128x128/apps/kisnitch.png */
KS_RES(ks_res_tray_off_png);
KS_RES(ks_res_tray_enabled_png);
KS_RES(ks_res_tray_pause_png);
KS_RES(ks_res_tray_alert_png);

#undef KS_RES

#endif
