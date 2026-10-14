/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Our side of the pop-up differential test (tests/diff/prompt/run.sh):
 * reads the cases of gen_cases.py and writes, for each, the combo entries
 * and the rule ui/prompt_rule.c builds, in the format of
 * tests/diff/prompt/upstream_prompt.py (json.dumps with sorted keys).
 *
 * The defaults are taken the way ui/prompt.c takes them from the settings
 * when it renders a question.
 *
 *   ks_prompt_diff <cases> <out>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common/json_util.h"
#include "ui/prompt_rule.h"
#include "ui/pyjson.h"
#include "ui/res.h"
#include "ui/rulesdb.h"
#include "ui/settings.h"

#define NODE "unix:/local"

static struct ks_py_aliases aliases;

static const char *jstr(const cJSON *o, const char *k, const char *def)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    return cJSON_IsString(v) ? v->valuestring : def;
}

static double jnum(const cJSON *o, const char *k, double def)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    return cJSON_IsNumber(v) ? v->valuedouble : def;
}

/* null/missing: -1, false: 0, true: 1 */
static int jbool(const cJSON *o, const char *k)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    return cJSON_IsBool(v) ? cJSON_IsTrue(v) : -1;
}

struct conn {
    Protocol__Connection c;
    char **args;
    Protocol__Connection__ProcessChecksumsEntry md5, *sums[1];
};

static void make_conn(struct conn *k, const cJSON *j)
{
    memset(k, 0, sizeof(*k));
    protocol__connection__init(&k->c);
    k->c.protocol = (char *)(uintptr_t)jstr(j, "protocol", "tcp");
    k->c.src_ip = (char *)(uintptr_t)jstr(j, "src_ip", "10.0.0.2");
    k->c.src_port = (uint32_t)jnum(j, "src_port", 40000);
    k->c.dst_ip = (char *)(uintptr_t)jstr(j, "dst_ip", "");
    k->c.dst_host = (char *)(uintptr_t)jstr(j, "dst_host", "");
    k->c.dst_port = (uint32_t)jnum(j, "dst_port", 0);
    k->c.user_id = (uint32_t)jnum(j, "user_id", 1000);
    k->c.process_id = (uint32_t)jnum(j, "process_id", 4242);
    k->c.process_path = (char *)(uintptr_t)jstr(j, "process_path", "");
    k->c.process_cwd = (char *)(uintptr_t)jstr(j, "process_cwd", "/");
    const cJSON *args = cJSON_GetObjectItemCaseSensitive(j, "process_args");
    size_t n = (size_t)cJSON_GetArraySize(args);
    k->args = calloc(n ? n : 1, sizeof(*k->args));
    const cJSON *a;
    cJSON_ArrayForEach(a, args)
    {
        k->args[k->c.n_process_args++] = a->valuestring;
    }
    k->c.process_args = k->args;
    protocol__connection__process_checksums_entry__init(&k->md5);
    k->md5.key = (char *)(uintptr_t) "process.hash.md5";
    k->md5.value = (char *)(uintptr_t)jstr(j, "md5", "");
    k->sums[0] = &k->md5;
    k->c.process_checksums = k->sums;
    k->c.n_process_checksums = 1;
}

static cJSON *combo_json(const struct ks_combo *c)
{
    cJSON *a = cJSON_CreateArray();
    for (size_t i = 0; i < c->len; i++)
        cJSON_AddItemToArray(a, cJSON_CreateString(c->items[i].text));
    return a;
}

static cJSON *op_json(const Protocol__Operator *o)
{
    cJSON *j = cJSON_CreateObject(); /* sorted keys */
    cJSON_AddStringToObject(j, "data", o->data);
    cJSON_AddStringToObject(j, "operand", o->operand);
    cJSON_AddBoolToObject(j, "sensitive", o->sensitive);
    cJSON_AddStringToObject(j, "type", o->type);
    return j;
}

static cJSON *rule_json(const Protocol__Rule *r)
{
    if (r == NULL)
        return cJSON_CreateNull();
    cJSON *j = cJSON_CreateObject();
    const Protocol__Operator *o = r->operator_;
    cJSON_AddStringToObject(j, "action", r->action);
    cJSON_AddStringToObject(j, "data", o->data);
    cJSON_AddStringToObject(j, "duration", r->duration);
    cJSON_AddBoolToObject(j, "enabled", r->enabled);
    cJSON *list = cJSON_AddArrayToObject(j, "list");
    for (size_t i = 0; i < o->n_list; i++)
        cJSON_AddItemToArray(list, op_json(o->list[i]));
    cJSON_AddStringToObject(j, "name", r->name);
    cJSON_AddStringToObject(j, "operand", o->operand);
    cJSON_AddBoolToObject(j, "sensitive", o->sensitive);
    cJSON_AddStringToObject(j, "type", o->type);
    return j;
}

/* one run of a case; an override < -1 means "as the case says", and
 * `count` gets the number of entries of the "what" combo (`ip_combo`
 * false) or of the IP combo */
static char *run(const cJSON *c, const char *id, int override, bool ip_combo, size_t *count,
                 bool send)
{
    const cJSON *jcon = cJSON_GetObjectItemCaseSensitive(c, "con");
    const cJSON *jset = cJSON_GetObjectItemCaseSensitive(c, "settings");
    const cJSON *ch = cJSON_GetObjectItemCaseSensitive(c, "choice");
    const cJSON *rules = cJSON_GetObjectItemCaseSensitive(c, "rules");
    bool local = jbool(c, "local") != 0;
    const char *app_name = jstr(c, "app_name", "");

    /* the settings, plus what Config.__init__() adds */
    struct ks_settings s = {0};
    ks_settings_parse(&s, "", 0);
    const cJSON *kv;
    cJSON_ArrayForEach(kv, jset)
    {
        ks_settings_set_raw(&s, kv->string, kv->valuestring);
    }
    if (!ks_settings_has(&s, KS_CFG_DEFAULT_TIMEOUT_KEY))
        ks_settings_set_raw(&s, KS_CFG_DEFAULT_TIMEOUT_KEY, "30");
    if (!ks_settings_has(&s, KS_CFG_DEFAULT_ACTION_KEY))
        ks_settings_set_raw(&s, KS_CFG_DEFAULT_ACTION_KEY, "0");
    if (!ks_settings_has(&s, KS_CFG_DEFAULT_DURATION_KEY))
        ks_settings_set_raw(&s, KS_CFG_DEFAULT_DURATION_KEY, "6");
    if (!ks_settings_has(&s, KS_CFG_DEFAULT_TARGET_KEY))
        ks_settings_set_raw(&s, KS_CFG_DEFAULT_TARGET_KEY, "0");

    struct ks_rulesdb db;
    ks_rulesdb_init(&db);
    const cJSON *r;
    cJSON_ArrayForEach(r, rules)
    {
        const char *v[KS_RF_COUNT] = {
            [KS_RF_NODE] = NODE,
            [KS_RF_NAME] = jstr(r, "name", ""),
            [KS_RF_ENABLED] = jstr(r, "enabled", "True"),
            [KS_RF_PRECEDENCE] = "False",
            [KS_RF_ACTION] = jstr(r, "action", ""),
            [KS_RF_DURATION] = jstr(r, "duration", ""),
            [KS_RF_OP_TYPE] = jstr(r, "type", ""),
            [KS_RF_OP_SENSITIVE] = "False",
            [KS_RF_OP_OPERAND] = jstr(r, "operand", ""),
            [KS_RF_OP_DATA] = jstr(r, "data", ""),
            [KS_RF_NOLOG] = "False",
        };
        ks_rulesdb_add_row(&db, v);
    }

    struct conn k;
    make_conn(&k, jcon);
    char *uid = ks_prompt_uid_text(&k.c, local);
    struct ks_combo what = {0}, ip = {0};
    ks_prompt_fill_combos(&k.c, uid, &aliases, &what, &ip);
    free(uid);
    *count = ip_combo ? ip.len : what.len;

    /* render(): the defaults */
    struct ks_pybuf args = {0};
    ks_pybuf_add(&args, "", 0);
    for (size_t i = 0; i < k.c.n_process_args; i++) {
        if (i)
            ks_pybuf_adds(&args, " ");
        ks_pybuf_adds(&args, k.c.process_args[i]);
    }
    int action = ks_settings_get_int(&s, KS_CFG_DEFAULT_ACTION_KEY, 0);
    int duration = ks_settings_get_int(&s, KS_CFG_DEFAULT_DURATION_KEY, 0);
    if (duration < 0 || duration >= KS_DURATION_COUNT)
        duration = -1;
    int what_idx = ks_prompt_default_target(
        &what, &k.c, ks_settings_get_int(&s, KS_CFG_DEFAULT_TARGET_KEY, 0), app_name, args.s);
    int ip_idx = ip.len ? 0 : -1;
    bool dst_ip = ks_settings_get_bool(&s, KS_CFG_DEFAULT_POPUP_ADVANCED_DSTIP, false);
    bool dst_port = ks_settings_get_bool(&s, KS_CFG_DEFAULT_POPUP_ADVANCED_DSTPORT, false);
    bool uidc = ks_settings_get_bool(&s, KS_CFG_DEFAULT_POPUP_ADVANCED_UID, false);
    bool sum = ks_settings_get_bool(&s, KS_CFG_DEFAULT_POPUP_ADVANCED_CHECKSUM, false);
    free(args.s);

    /* the user */
    const cJSON *w = cJSON_GetObjectItemCaseSensitive(ch, "what");
    if (override >= -1 && !ip_combo)
        what_idx = override;
    else if (cJSON_IsNumber(w))
        what_idx = (w->valueint >= 0 && (size_t)w->valueint < what.len) ? w->valueint : -1;
    const cJSON *wi = cJSON_GetObjectItemCaseSensitive(ch, "what_ip");
    if (override >= -1 && ip_combo)
        ip_idx = override;
    else if (cJSON_IsNumber(wi))
        ip_idx = (wi->valueint >= 0 && (size_t)wi->valueint < ip.len) ? wi->valueint : -1;
    const cJSON *d = cJSON_GetObjectItemCaseSensitive(ch, "duration");
    if (cJSON_IsNumber(d))
        duration = (d->valueint >= 0 && d->valueint < KS_DURATION_COUNT) ? d->valueint : -1;
    if (jbool(ch, "dst_ip") >= 0)
        dst_ip = jbool(ch, "dst_ip");
    if (jbool(ch, "dst_port") >= 0)
        dst_port = jbool(ch, "dst_port");
    if (jbool(ch, "uid") >= 0)
        uidc = jbool(ch, "uid");
    if (jbool(ch, "sum") >= 0)
        sum = jbool(ch, "sum");
    const char *act = jstr(ch, "action", "timeout");
    if (strcmp(act, "allow") == 0)
        action = KS_CFG_ACTION_ALLOW_IDX;
    else if (strcmp(act, "deny") == 0)
        action = KS_CFG_ACTION_DENY_IDX;
    else if (strcmp(act, "reject") == 0)
        action = KS_CFG_ACTION_REJECT_IDX;
    else if (strcmp(act, "deny_button") == 0 && action == KS_CFG_ACTION_ALLOW_IDX)
        action = KS_CFG_ACTION_DENY_IDX;

    struct ks_prompt_choice choice = {
        .action_idx = action,
        .duration_idx = duration < 0 ? KS_DURATION_COUNT : duration,
        .what = what_idx >= 0 ? &what.items[what_idx] : NULL,
        .what_ip = ip_idx >= 0 ? &ip.items[ip_idx] : NULL,
        .dst_ip = dst_ip,
        .dst_port = dst_port,
        .user_id = uidc,
        .checksum = sum,
        .checksum_text = ks_prompt_md5(&k.c),
    };
    struct ks_arena a = {0};
    Protocol__Rule *rule = NULL;
    if (send && choice.what != NULL)
        rule = ks_prompt_build_rule(&a, &k.c, &choice, &aliases, &db, NODE,
                                    (int64_t)time(NULL));

    cJSON *out = cJSON_CreateObject();
    cJSON_AddStringToObject(out, "id", id);
    cJSON_AddItemToObject(out, "rule", rule_json(rule));
    cJSON_AddItemToObject(out, "what", combo_json(&what));
    cJSON_AddItemToObject(out, "what_ip", combo_json(&ip));
    char *line = ks_pyjson_dumps(out);
    cJSON_Delete(out);
    ks_arena_free(&a);
    ks_combo_free(&what);
    ks_combo_free(&ip);
    free(k.args);
    ks_rulesdb_free(&db);
    ks_settings_close(&s);
    return line;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: ks_prompt_diff <cases> <out>\n");
        return 2;
    }
    if (ks_py_aliases_parse(&aliases, (const char *)ks_res_network_aliases_json,
                            ks_res_network_aliases_json_len) < 0)
        return 1;
    FILE *in = fopen(argv[1], "r"), *out = fopen(argv[2], "w");
    if (in == NULL || out == NULL) {
        perror("open");
        return 1;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, in)) > 0) {
        char err[128];
        cJSON *c = ks_json_parse(line, (size_t)n, err, sizeof(err));
        if (c == NULL)
            continue;
        const char *id = jstr(c, "id", "");
        const cJSON *ch = cJSON_GetObjectItemCaseSensitive(c, "choice");
        size_t count = 0;
        bool each_what = strcmp(jstr(ch, "what", ""), "each") == 0;
        bool each_ip = strcmp(jstr(ch, "what_ip", ""), "each") == 0;
        if (!each_what && !each_ip) {
            char *o = run(c, id, -2, false, &count, true);
            fprintf(out, "%s\n", o);
            free(o);
        } else {
            free(run(c, id, -2, each_ip, &count, false));
            for (size_t i = 0; i < count; i++) {
                char sub[256];
                size_t ignored;
                snprintf(sub, sizeof(sub), "%s#%zu", id, i);
                char *o = run(c, sub, (int)i, each_ip, &ignored, true);
                fprintf(out, "%s\n", o);
                free(o);
            }
        }
        cJSON_Delete(c);
    }
    free(line);
    fclose(in);
    fclose(out);
    ks_py_aliases_free(&aliases);
    return 0;
}
