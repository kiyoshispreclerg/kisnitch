/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * libFuzzer target for ks_config_parse(): the daemon parses configs that the
 * UI sends over the network, so this input is untrusted. Every config that
 * parses must also survive a serialize/reparse round trip unchanged.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "daemon/config.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct ks_config a, b;
    char err[512];

    if (ks_config_parse((const char *)data, size, &a, err, sizeof(err)) < 0)
        return 0;

    char *json = ks_config_to_json(&a, false);
    if (json == NULL)
        abort();
    if (ks_config_parse(json, strlen(json), &b, err, sizeof(err)) < 0 ||
        !ks_config_equal(&a, &b))
        abort();

    free(json);
    ks_config_free(&a);
    ks_config_free(&b);
    return 0;
}
