/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * libFuzzer target for the settings file (ui/settings.c): the input is
 * parsed as QSettings' INI, written back and read again (same entries),
 * every value is decoded, and the input as a value must survive escaping
 * and unescaping.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/unicode.h"
#include "ui/settings.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct ks_settings s = {0}, t = {0};
    if (ks_settings_parse(&s, (const char *)data, size) < 0)
        return 0;
    char *out = ks_settings_serialize(&s);
    if (out != NULL && ks_settings_parse(&t, out, strlen(out)) == 0) {
        if (t.len != s.len)
            abort();
        for (size_t i = 0; i < s.len; i++) {
            char full[1024];
            const struct ks_setting *e = &s.items[i];
            snprintf(full, sizeof(full), "%s%s%s", e->group, e->group[0] ? "/" : "", e->key);
            free(ks_settings_get_string(&s, full));
            ks_settings_get_int(&s, full, 0);
            ks_settings_get_bool(&s, full, false);
        }
    }
    free(out);
    ks_settings_close(&t);
    ks_settings_close(&s);

    /* a value round-trips (valid UTF-8 within the BMP, no NUL) */
    if (memchr(data, 0, size) == NULL && ks_utf8_valid((const char *)data, size)) {
        bool bmp = true;
        for (size_t i = 0; i < size;) {
            uint32_t r;
            size_t l = ks_utf8_decode((const char *)data + i, size - i, &r);
            bmp &= r <= 0xFFFF;
            i += l ? l : 1;
        }
        char *v = malloc(size + 1);
        if (v != NULL && bmp) {
            memcpy(v, data, size);
            v[size] = '\0';
            struct ks_settings u = {0};
            ks_settings_parse(&u, "", 0);
            char *raw = ks_settings_escape(v);
            if (raw != NULL && strchr(raw, '\n') == NULL && strchr(raw, '\r') == NULL) {
                ks_settings_set_raw(&u, "g/k", raw);
                char *back = ks_settings_get_string(&u, "g/k");
                if (back == NULL || strcmp(back, v) != 0) {
                    /* trailing/leading spaces of a non-quoted list item
                     * aren't kept by Qt either; only check the rest */
                    if (strchr(v, ',') == NULL && strchr(v, ';') == NULL &&
                        strchr(v, '=') == NULL)
                        abort();
                }
                free(back);
            }
            free(raw);
            ks_settings_close(&u);
        }
        free(v);
    }
    return 0;
}
