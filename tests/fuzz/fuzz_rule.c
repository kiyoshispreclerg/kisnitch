/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * libFuzzer target for rule JSON (rules arrive from the UI over the network):
 * parse, compile, match against a fixed connection, and check that the
 * serialized rule parses back to the same thing.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common/log.h"
#include "daemon/rules/rule.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static const char *const args[] = {"/usr/bin/curl", "-s", "x"};
static const struct ks_env_var env[] = {{"HOME", "/root"}};
static const struct ks_process parent = {.pid = 1, .path = "/sbin/init"};
static const struct ks_process proc = {
    .pid = 42, .path = "/usr/bin/curl", .args = args, .nargs = 3, .env = env,
    .nenv = 1, .checksum_md5 = "d41d8cd98f00b204e9800998ecf8427e",
    .parent = &parent,
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char err[512];
    ks_log_set_level(KS_LOG_FATAL + 1);

    struct ks_rule *r = ks_rule_parse((const char *)data, size, err, sizeof(err));
    if (r == NULL)
        return 0;

    char *json = ks_rule_to_json(r);
    if (json == NULL)
        abort();
    struct ks_rule *again = ks_rule_parse(json, strlen(json), err, sizeof(err));
    if (again == NULL)
        abort();
    char *json2 = ks_rule_to_json(again);
    if (json2 == NULL || strcmp(json, json2) != 0)
        abort();
    free(json);
    free(json2);
    ks_rule_free(again);

    /* Lists read directories named in the rule: keep the fuzzer away from
     * the filesystem. */
    if (strcmp(r->operator.type, KS_TYPE_LISTS) == 0) {
        ks_rule_free(r);
        return 0;
    }
    struct ks_conn c;
    memset(&c, 0, sizeof(c));
    c.protocol = "tcp";
    c.dst_host = "example.org";
    ks_ip_parse("192.0.2.1", &c.dst_ip);
    ks_ip_parse("2001:db8::1", &c.src_ip);
    c.dst_port = 443;
    c.process = &proc;

    if (ks_operator_compile(&r->operator, NULL, err, sizeof(err)) == 0) {
        for (size_t i = 0; i < r->operator.list.len; i++) {
            struct ks_operator *o = KS_ARRAY_ITEM(r->operator.list, struct ks_operator, i);
            if (o->type != NULL && strcmp(o->type, KS_TYPE_LISTS) == 0)
                continue;
            ks_operator_compile(o, NULL, err, sizeof(err));
        }
        (void)ks_operator_match(&r->operator, &c, true);
        (void)ks_operator_match(&r->operator, &c, false);
    }
    ks_rule_free(r);
    return 0;
}
