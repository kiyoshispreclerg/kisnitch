/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * libFuzzer target for .desktop files (ui/desktop.c): the input is a
 * file, read with configparser's rules; its Exec goes through
 * _parse_exec(), and the app is then looked up.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ui/desktop.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct ks_desktop d;
    memset(&d, 0, sizeof(d));
    d.inotify_fd = -1;
    d.icons_dir = "/nonexistent";
    ks_strmap_init(&d.apps);
    snprintf(d.locale, sizeof(d.locale), "pt_BR");
    snprintf(d.locale_country, sizeof(d.locale_country), "pt");
    ks_desktop_parse_text(&d, "/x/fuzz.desktop", (const char *)data, size);
    struct ks_app_info *i = ks_desktop_info_by_path(&d, "/usr/bin/fuzz", "def");
    ks_app_info_free(i);
    i = ks_desktop_info_by_path(&d, "fuzz", "def");
    ks_app_info_free(i);

    /* _parse_exec() on the raw input, as a C string */
    char *s = malloc(size + 1);
    if (s != NULL) {
        memcpy(s, data, size);
        s[size] = '\0';
        free(ks_desktop_parse_exec(s));
        free(s);
    }
    ks_desktop_free(&d);
    return 0;
}
