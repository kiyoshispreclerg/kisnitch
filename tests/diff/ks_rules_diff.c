/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Our side of the rules editor's differential test
 * (tests/diff/ruleseditor/run.sh): reads the cases of gen_cases.py and
 * writes, for each, what ui/rulegen.c gives, in the format of
 * tests/diff/ruleseditor/upstream_ruleseditor.py (json.dumps, sorted keys).
 *
 *   ks_rules_diff <cases> <out>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/json_util.h"
#include "ui/pyjson.h"
#include "ui/res.h"
#include "ui/rulegen.h"

static struct ks_py_aliases aliases;

static const char *jstr(const cJSON *o, const char *k, const char *def)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    return cJSON_IsString(v) ? v->valuestring : def;
}

static bool jbool(const cJSON *o, const char *k, bool def)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    return cJSON_IsBool(v) ? cJSON_IsTrue(v) : def;
}

static int jint(const cJSON *o, const char *k, int def)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    return cJSON_IsNumber(v) ? (int)v->valuedouble : def;
}

/* ---- the output, with its keys sorted (json.dumps(sort_keys=True)) ----------- */

static int by_key(const void *a, const void *b)
{
    return strcmp((*(const cJSON *const *)a)->string, (*(const cJSON *const *)b)->string);
}

static void sort_keys(cJSON *o)
{
    if (cJSON_IsArray(o)) {
        for (cJSON *c = o->child; c != NULL; c = c->next)
            sort_keys(c);
        return;
    }
    if (!cJSON_IsObject(o))
        return;
    int n = cJSON_GetArraySize(o);
    cJSON **v = calloc((size_t)(n ? n : 1), sizeof(*v));
    int i = 0;
    for (cJSON *c = o->child; c != NULL; c = c->next)
        v[i++] = c;
    for (i = 0; i < n; i++)
        cJSON_DetachItemViaPointer(o, v[i]);
    qsort(v, (size_t)n, sizeof(*v), by_key);
    for (i = 0; i < n; i++) {
        sort_keys(v[i]);
        cJSON_AddItemToObject(o, v[i]->string, v[i]);
    }
    free(v);
}

static cJSON *op_out(const Protocol__Operator *o)
{
    cJSON *j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "type", o->type);
    cJSON_AddStringToObject(j, "operand", o->operand);
    cJSON_AddStringToObject(j, "data", o->data);
    cJSON_AddBoolToObject(j, "sensitive", o->sensitive);
    return j;
}

static cJSON *rule_out(const Protocol__Rule *r)
{
    cJSON *j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "name", r->name);
    cJSON_AddStringToObject(j, "description", r->description);
    cJSON_AddBoolToObject(j, "enabled", r->enabled);
    cJSON_AddBoolToObject(j, "precedence", r->precedence);
    cJSON_AddBoolToObject(j, "nolog", r->nolog);
    cJSON_AddStringToObject(j, "action", r->action);
    cJSON_AddStringToObject(j, "duration", r->duration);
    cJSON_AddStringToObject(j, "type", r->operator_->type);
    cJSON_AddStringToObject(j, "operand", r->operator_->operand);
    cJSON_AddStringToObject(j, "data", r->operator_->data);
    cJSON_AddBoolToObject(j, "sensitive", r->operator_->sensitive);
    cJSON *l = cJSON_AddArrayToObject(j, "list");
    for (size_t i = 0; i < r->operator_->n_list; i++)
        cJSON_AddItemToArray(l, op_out(r->operator_->list[i]));
    return j;
}

/* ---- the form <-> JSON --------------------------------------------------------------- */

static const struct {
    const char *key;
    size_t off;
} keys[] = {
    {"proto", offsetof(struct ks_rform, proto)},     {"iface", offsetof(struct ks_rform, iface)},
    {"srcip", offsetof(struct ks_rform, srcip)},     {"dstip", offsetof(struct ks_rform, dstip)},
    {"uid", offsetof(struct ks_rform, uid)},         {"proc", offsetof(struct ks_rform, proc)},
    {"cmdline", offsetof(struct ks_rform, cmdline)}, {"pid", offsetof(struct ks_rform, pid)},
    {"srcport", offsetof(struct ks_rform, srcport)}, {"dstport", offsetof(struct ks_rform, dstport)},
    {"dsthost", offsetof(struct ks_rform, dsthost)}, {"lists", offsetof(struct ks_rform, lists)},
    {"lists_regexp", offsetof(struct ks_rform, lists_regexp)},
    {"lists_ips", offsetof(struct ks_rform, lists_ips)},
    {"lists_nets", offsetof(struct ks_rform, lists_nets)},
    {"md5", offsetof(struct ks_rform, md5)},
};
#define NKEYS (sizeof(keys) / sizeof(keys[0]))

static struct ks_rcheck *field(struct ks_rform *f, size_t i)
{
    return (struct ks_rcheck *)((char *)f + keys[i].off);
}

static void form_from_json(struct ks_rform *f, const cJSON *j)
{
    ks_rform_set_name(f, jstr(j, "name", ""));
    ks_rform_set_desc(f, jstr(j, "desc", ""));
    f->enabled = jbool(j, "enabled", false);
    f->precedence = jbool(j, "precedence", false);
    f->nolog = jbool(j, "nolog", false);
    f->sensitive = jbool(j, "sensitive", false);
    f->action = jint(j, "action", 0);
    f->duration = jint(j, "duration", 0);
    for (size_t i = 0; i < NKEYS; i++) {
        const cJSON *c = cJSON_GetObjectItemCaseSensitive(j, keys[i].key);
        if (c != NULL) {
            field(f, i)->on = jbool(c, "on", false);
            ks_rform_set(field(f, i), jstr(c, "text", ""));
        }
    }
    f->proc_regexp = jbool(j, "proc_regexp", false);
    f->cmdline_regexp = jbool(j, "cmdline_regexp", false);
    f->apply_all = jbool(j, "apply_all", false);
    f->node_is_local = jbool(j, "node_is_local", true);
}

static cJSON *form_to_json(struct ks_rform *f)
{
    cJSON *j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "name", f->name);
    cJSON_AddStringToObject(j, "desc", f->desc);
    cJSON_AddBoolToObject(j, "enabled", f->enabled);
    cJSON_AddBoolToObject(j, "precedence", f->precedence);
    cJSON_AddBoolToObject(j, "nolog", f->nolog);
    cJSON_AddBoolToObject(j, "sensitive", f->sensitive);
    cJSON_AddNumberToObject(j, "action", f->action);
    cJSON_AddNumberToObject(j, "duration", f->duration);
    cJSON_AddBoolToObject(j, "proc_regexp", f->proc_regexp);
    cJSON_AddBoolToObject(j, "cmdline_regexp", f->cmdline_regexp);
    for (size_t i = 0; i < NKEYS; i++) {
        cJSON *c = cJSON_AddObjectToObject(j, keys[i].key);
        cJSON_AddBoolToObject(c, "on", field(f, i)->on);
        cJSON_AddStringToObject(c, "text", field(f, i)->text);
    }
    return j;
}

/* the rule of a "load" case */
static Protocol__Rule *rule_from_json(struct ks_arena *a, const cJSON *d)
{
    Protocol__Rule *r = ks_arena_alloc(a, sizeof(*r));
    Protocol__Operator *op = ks_arena_alloc(a, sizeof(*op));
    protocol__rule__init(r);
    protocol__operator__init(op);
    r->operator_ = op;
    r->name = ks_arena_strdup(a, jstr(d, "name", ""));
    r->description = ks_arena_strdup(a, jstr(d, "description", ""));
    r->enabled = jbool(d, "enabled", false);
    r->precedence = jbool(d, "precedence", false);
    r->nolog = jbool(d, "nolog", false);
    r->action = ks_arena_strdup(a, jstr(d, "action", ""));
    r->duration = ks_arena_strdup(a, jstr(d, "duration", ""));
    op->type = ks_arena_strdup(a, jstr(d, "type", ""));
    op->operand = ks_arena_strdup(a, jstr(d, "operand", ""));
    op->data = ks_arena_strdup(a, jstr(d, "data", ""));
    op->sensitive = jbool(d, "sensitive", false);
    const cJSON *l = cJSON_GetObjectItemCaseSensitive(d, "list");
    size_t n = cJSON_IsArray(l) ? (size_t)cJSON_GetArraySize(l) : 0;
    if (n > 0) {
        op->list = ks_arena_calloc(a, n, sizeof(*op->list));
        const cJSON *it;
        cJSON_ArrayForEach(it, l)
        {
            Protocol__Operator *o = ks_arena_alloc(a, sizeof(*o));
            protocol__operator__init(o);
            o->type = ks_arena_strdup(a, jstr(it, "type", ""));
            o->operand = ks_arena_strdup(a, jstr(it, "operand", ""));
            o->data = ks_arena_strdup(a, jstr(it, "data", ""));
            o->sensitive = jbool(it, "sensitive", false);
            op->list[op->n_list++] = o;
        }
    }
    return r;
}

/* ---- the cases ---------------------------------------------------------------------------- */

static cJSON *pair(bool first_ok, const char *s)
{
    cJSON *a = cJSON_CreateArray();
    cJSON_AddItemToArray(a, first_ok ? cJSON_CreateString(s) : cJSON_CreateNull());
    return a;
}

static cJSON *run_case(const cJSON *c)
{
    const char *kind = jstr(c, "kind", "");
    cJSON *out = cJSON_CreateObject();
    cJSON_AddStringToObject(out, "id", jstr(c, "id", ""));
    struct ks_arena a = {0};
    char err[512] = "";
    if (strcmp(kind, "save") == 0) {
        struct ks_rform f;
        ks_rform_init(&f);
        form_from_json(&f, cJSON_GetObjectItemCaseSensitive(c, "form"));
        Protocol__Rule *r = NULL;
        bool ok = ks_rform_to_rule(&f, &aliases, &a, &r, err, sizeof(err));
        cJSON_AddBoolToObject(out, "ok", ok);
        if (ok)
            cJSON_AddItemToObject(out, "rule", rule_out(r));
        else
            cJSON_AddStringToObject(out, "error", err);
        ks_rform_free(&f);
    } else if (strcmp(kind, "load") == 0) {
        struct ks_rform f;
        ks_rform_init(&f);
        Protocol__Rule *r = rule_from_json(&a, cJSON_GetObjectItemCaseSensitive(c, "rule"));
        ks_rform_load_rule(&f, r, err, sizeof(err));
        cJSON_AddItemToObject(out, "form", form_to_json(&f));
        cJSON_AddStringToObject(out, "status", err);
        ks_rform_free(&f);
    } else {
        const cJSON *l, *it;
        char buf[512];
        l = cJSON_GetObjectItemCaseSensitive(c, "comma_to_regexp");
        cJSON_ArrayForEach(it, l)
        {
            const char *k = cJSON_GetArrayItem(it, 0)->valuestring;
            const char *t = cJSON_GetArrayItem(it, 1)->valuestring;
            bool ok = ks_rule_comma_to_regexp(t, strcmp(k, "int") == 0, buf, sizeof(buf));
            char key[600];
            snprintf(key, sizeof(key), "c2r:%s:%s", k, t);
            cJSON *p = cJSON_CreateArray();
            cJSON_AddItemToArray(p, ok ? cJSON_CreateTrue() : cJSON_CreateFalse());
            cJSON_AddItemToArray(p, cJSON_CreateString(buf));
            cJSON_AddItemToObject(out, key, p);
        }
        l = cJSON_GetObjectItemCaseSensitive(c, "regexp_to_comma");
        cJSON_ArrayForEach(it, l)
        {
            const char *k = cJSON_GetArrayItem(it, 0)->valuestring;
            const char *t = cJSON_GetArrayItem(it, 1)->valuestring;
            buf[0] = '\0';
            int rc = ks_rule_regexp_to_comma(t, strcmp(k, "int") == 0, buf, sizeof(buf));
            char key[600];
            snprintf(key, sizeof(key), "r2c:%s:%s", k, t);
            cJSON *p = pair(rc == 1, buf);
            cJSON_AddItemToArray(p, cJSON_CreateString(rc < 0 ? buf : ""));
            if (rc < 0) {
                cJSON_ReplaceItemInArray(p, 0, cJSON_CreateNull());
            }
            if (rc == 0)
                cJSON_ReplaceItemInArray(p, 1, cJSON_CreateString(""));
            cJSON_AddItemToObject(out, key, p);
        }
        l = cJSON_GetObjectItemCaseSensitive(c, "is_regex");
        cJSON_ArrayForEach(it, l)
        {
            char key[600];
            snprintf(key, sizeof(key), "isre:%s", it->valuestring);
            cJSON_AddBoolToObject(out, key, ks_rule_is_regex(it->valuestring));
        }
    }
    ks_arena_free(&a);
    return out;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: ks_rules_diff <cases> <out>\n");
        return 2;
    }
    if (ks_py_aliases_parse(&aliases, (const char *)ks_res_network_aliases_json,
                            ks_res_network_aliases_json_len) < 0) {
        fprintf(stderr, "bad aliases\n");
        return 1;
    }
    FILE *in = fopen(argv[1], "r");
    FILE *outf = fopen(argv[2], "w");
    if (in == NULL || outf == NULL)
        return 1;
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    while ((len = getline(&line, &cap, in)) > 0) {
        if (len == 1)
            continue;
        char err[128];
        cJSON *c = ks_json_parse(line, (size_t)len, err, sizeof(err));
        if (c == NULL) {
            fprintf(stderr, "bad case: %s\n", err);
            return 1;
        }
        cJSON *o = run_case(c);
        sort_keys(o);
        char *s = ks_pyjson_dumps(o);
        fprintf(outf, "%s\n", s);
        free(s);
        cJSON_Delete(o);
        cJSON_Delete(c);
    }
    free(line);
    fclose(in);
    fclose(outf);
    ks_py_aliases_free(&aliases);
    return 0;
}
