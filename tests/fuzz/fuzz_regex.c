/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * libFuzzer target for the Go-to-PCRE2 regexp translation: the first line is
 * the pattern, the rest the subject. Every pattern we accept must compile in
 * PCRE2 (the translation must never produce invalid PCRE2 syntax).
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "daemon/rules/regex.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *buf = malloc(size + 1);
    if (buf == NULL)
        return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';
    char *nl = memchr(buf, '\n', size);
    const char *subject = "";
    if (nl != NULL) {
        *nl = '\0';
        subject = nl + 1;
    }

    char err[512];
    char *pcre = ks_regex_translate(buf, err, sizeof(err));
    if (pcre != NULL) {
        struct ks_regex *re = ks_regex_compile(buf, err, sizeof(err));
        /* The translator's output is always valid PCRE2, except for patterns
         * too big for it and Unicode 15 scripts an older PCRE2 lacks. */
        if (re == NULL && strstr(err, "too large") == NULL &&
            strstr(err, "too complicated") == NULL &&
            strstr(err, "unknown property") == NULL)
            abort();
        if (re != NULL) {
            (void)ks_regex_match(re, subject);
            ks_regex_free(re);
        }
        free(pcre);
    }
    free(buf);
    return 0;
}
