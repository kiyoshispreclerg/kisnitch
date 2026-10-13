/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * libFuzzer target for the messages the UI sends the daemon: the input is
 * a protobuf message (the first byte picks Notification, Rule, ClientConfig
 * or PingReply), unpacked as the UI client does (UTF-8 checked), and then
 * converted like the handlers do: rules through rule.Deserialize() and
 * compilation, configurations (CHANGE_CONFIG data, Subscribe's reply)
 * through config.Parse(), tasks' JSON through cJSON.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common/log.h"
#include "common/vendor/cjson/cJSON.h"
#include "daemon/config.h"
#include "daemon/protocol.h"
#include "daemon/rules/rule.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void rule(const Protocol__Rule *pr)
{
    char err[512];
    struct ks_rule *r = ks_rule_from_pb(pr, err, sizeof(err));
    if (r == NULL)
        return;
    struct ks_rules_env env = {0};
    if (ks_operator_compile(&r->operator, &env, err, sizeof(err)) == 0) {
        static const struct ks_process proc = {.pid = 1, .path = "/usr/bin/curl"};
        struct ks_conn c = {.protocol = "tcp", .dst_host = "example.com", .uid = 0,
                            .process = &proc};
        ks_operator_match(&r->operator, &c, false);
    }
    /* and back, as Subscribe sends the rules */
    struct ks_arena a = {0};
    Protocol__Rule *back = ks_pb_rule(&a, r);
    size_t len;
    uint8_t *buf = back ? ks_pb_pack(&back->base, &len) : NULL;
    free(buf);
    ks_arena_free(&a);
    ks_rule_free(r);
}

static void config(const char *json)
{
    struct ks_config cfg;
    char err[512];
    if (ks_config_parse(json, strlen(json), &cfg, err, sizeof(err)) == 0)
        ks_config_free(&cfg);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ks_log_set_level(KS_LOG_FATAL + 1);
    if (size < 1)
        return 0;
    int kind = data[0] % 4;
    data++;
    size--;

    if (kind == 0) {
        Protocol__Notification *n = (Protocol__Notification *)ks_pb_unpack(
            &protocol__notification__descriptor, data, size);
        if (n == NULL)
            return 0;
        for (size_t i = 0; i < n->n_rules; i++)
            rule(n->rules[i]);
        config(n->data);
        cJSON *j = cJSON_Parse(n->data);
        cJSON_Delete(j);
        protobuf_c_message_free_unpacked(&n->base, NULL);
    } else if (kind == 1) {
        Protocol__Rule *r = (Protocol__Rule *)ks_pb_unpack(&protocol__rule__descriptor,
                                                           data, size);
        if (r == NULL)
            return 0;
        rule(r);
        protobuf_c_message_free_unpacked(&r->base, NULL);
    } else if (kind == 2) {
        Protocol__ClientConfig *cc = (Protocol__ClientConfig *)ks_pb_unpack(
            &protocol__client_config__descriptor, data, size);
        if (cc == NULL)
            return 0;
        config(cc->config);
        protobuf_c_message_free_unpacked(&cc->base, NULL);
    } else {
        ProtobufCMessage *m = ks_pb_unpack(&protocol__ping_reply__descriptor, data, size);
        if (m != NULL)
            protobuf_c_message_free_unpacked(m, NULL);
    }
    return 0;
}
