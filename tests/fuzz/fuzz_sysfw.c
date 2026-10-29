/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * libFuzzer target for system-fw.json (daemon/fw/sysfw.c): the file is
 * also written from what the UI sends. Whatever parses must survive
 * Serialize() + Deserialize() and parse again to the same text.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common/arena.h"
#include "common/pb_util.h"
#include "daemon/fw/sysfw.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static char *round_trip(const struct ks_sysfw *cfg, bool defaults)
{
    struct ks_arena a = {0};
    Protocol__SysFirewall *pb = ks_sysfw_to_pb(&a, cfg);
    if (pb == NULL)
        abort();
    size_t len;
    uint8_t *buf = ks_pb_pack(&pb->base, &len);
    if (buf == NULL)
        abort();
    Protocol__SysFirewall *back = (Protocol__SysFirewall *)ks_pb_unpack(
        &protocol__sys_firewall__descriptor, buf, len);
    if (back == NULL)
        abort();
    char *json = ks_sysfw_pb_to_json(back, defaults);
    if (json == NULL)
        abort();
    protobuf_c_message_free_unpacked(&back->base, NULL);
    free(buf);
    ks_arena_free(&a);
    return json;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct ks_sysfw a, b;
    char err[512];
    if (ks_sysfw_parse((const char *)data, size, &a, err, sizeof(err)) < 0)
        return 0;
    for (int defaults = 0; defaults < 2; defaults++) {
        char *j1 = round_trip(&a, defaults);
        if (ks_sysfw_parse(j1, strlen(j1), &b, err, sizeof(err)) < 0)
            abort();
        char *j2 = round_trip(&b, defaults);
        if (strcmp(j1, j2) != 0)
            abort();
        free(j1);
        free(j2);
        ks_sysfw_free(&b);
    }
    ks_sysfw_free(&a);
    return 0;
}
