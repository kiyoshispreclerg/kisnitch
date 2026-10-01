/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * libFuzzer target for ks_parse_duration(), which parses rule durations that
 * arrive from the UI.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common/duration.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *s = malloc(size + 1);
    if (s == NULL)
        return 0;
    memcpy(s, data, size);
    s[size] = '\0';

    int64_t ns;
    char err[64];
    (void)ks_parse_duration(s, &ns, err, sizeof(err));
    (void)ks_rule_duration_kind(s);
    free(s);
    return 0;
}
