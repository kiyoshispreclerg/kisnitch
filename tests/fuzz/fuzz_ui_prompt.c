/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * libFuzzer target for what the UI does with a question from a daemon
 * (AskRule): the input is a Connection message (the first byte holds the
 * pop-up's choices), unpacked as the server does, then shown and turned
 * into a rule like ui/prompt.c does: combos, texts, details, the rule for
 * every entry of the "what" combo, and the checksum warning against the
 * rules table.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common/pb_util.h"
#include "ui/prompt_rule.h"
#include "ui/res.h"
#include "ui/rulesdb.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static struct ks_py_aliases aliases;
static int loaded;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return 0;
    if (!loaded) {
        ks_py_aliases_parse(&aliases, (const char *)ks_res_network_aliases_json,
                            ks_res_network_aliases_json_len);
        loaded = 1;
    }
    uint8_t bits = data[0];
    Protocol__Connection *con = (Protocol__Connection *)ks_pb_unpack(
        &protocol__connection__descriptor, data + 1, size - 1);
    if (con == NULL)
        return 0;

    struct ks_rulesdb db;
    ks_rulesdb_init(&db);
    const char *row[KS_RF_COUNT] = {
        [KS_RF_NODE] = "unix:/local", [KS_RF_NAME] = "r", [KS_RF_ENABLED] = "True",
        [KS_RF_ACTION] = "allow", [KS_RF_DURATION] = "always", [KS_RF_OP_TYPE] = "list",
        [KS_RF_OP_OPERAND] = "list",
        [KS_RF_OP_DATA] = "[{\"type\": \"simple\", \"operand\": \"process.hash.md5\", "
                          "\"data\": \"x\"}]",
    };
    ks_rulesdb_add_row(&db, row);
    row[KS_RF_NAME] = "r2";
    row[KS_RF_OP_DATA] = con->process_path ? con->process_path : "";
    ks_rulesdb_add_row(&db, row);

    char *uid = ks_prompt_uid_text(con, bits & 1);
    struct ks_combo what = {0}, ip = {0};
    ks_prompt_fill_combos(con, uid ? uid : "", &aliases, &what, &ip);
    free(uid);
    free(ks_prompt_message(bits & 1, "ipv4:1.2.3.4", "host", con->process_path, con));
    free(ks_prompt_details(con));
    free(ks_prompt_path_label("app", "app x", con));
    free(ks_prompt_args_label("app", "app x"));
    ks_prompt_default_target(&what, con, bits % 7, "app", "app x");

    for (size_t i = 0; i < what.len; i++) {
        struct ks_prompt_choice ch = {
            .action_idx = bits % 3,
            .duration_idx = bits % 10,
            .what = &what.items[i],
            .what_ip = ip.len ? &ip.items[(bits >> 2) % ip.len] : NULL,
            .dst_ip = (bits & 2) && ip.len,
            .dst_port = bits & 4,
            .user_id = bits & 8,
            .checksum = bits & 16,
            .checksum_text = ks_prompt_md5(con),
        };
        struct ks_arena a = {0};
        ks_prompt_build_rule(&a, con, &ch, &aliases, &db, "unix:/local", 0);
        ks_arena_free(&a);
    }
    char *names[8];
    size_t n = 0;
    char *expected = NULL;
    ks_prompt_checksum_mismatch(&db, "unix:/local", con, names, 8, &n, &expected);
    for (size_t i = 0; i < n; i++)
        free(names[i]);
    free(expected);
    struct ks_arena a = {0};
    ks_prompt_checksum_update(&a, &db, "unix:/local", "r", con);
    ks_arena_free(&a);

    ks_combo_free(&what);
    ks_combo_free(&ip);
    ks_rulesdb_free(&db);
    protobuf_c_message_free_unpacked(&con->base, NULL);
    return 0;
}
