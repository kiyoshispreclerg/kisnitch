/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ui/settings.c: QSettings' INI format, as the upstream UI writes
 * ~/.config/opensnitch/settings.conf.
 */
#include "ui/settings.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/json_util.h"
#include "tests/harness.h"

/* What PyQt writes (shape of a real file: sections and keys sorted, a
 * blank line between sections, @ByteArray, quoted values, lists). */
static const char sample[] =
    "[General]\n"
    "statsDialog=0\n"
    "\n"
    "[database]\n"
    "file=file::memory:\n"
    "jrnl_wal=false\n"
    "type=0\n"
    "\n"
    "[global]\n"
    "default_action=2\n"
    "default_duration=3\n"
    "default_popup_advanced=true\n"
    "default_timeout=20\n"
    "server_address=unix:///tmp/osui.sock\n"
    "\n"
    "[promptDialog]\n"
    "geometry=@ByteArray(\\x1\\xd9\\xd0\\xcb\\0\\x3\\0\\0\\0\\0\\tG\\0\\0\\x1\\xb3)\n"
    "\n"
    "[statsDialog]\n"
    "general_filter_text=\n"
    "show_columns=0, 2, 3, 4, 5\n"
    "view_details_columns_state4=\"@ByteArray(\\0\\0\\0\\xff\\0\\x6=\\0)\"\n";

TEST(round_trip)
{
    struct ks_settings s = {0};
    CHECK(ks_settings_parse(&s, sample, sizeof(sample) - 1) == 0);
    char *out = ks_settings_serialize(&s);
    CHECK_STR_EQ(out, sample);
    free(out);
    ks_settings_close(&s);
}

TEST(typed_getters)
{
    struct ks_settings s = {0};
    CHECK(ks_settings_parse(&s, sample, sizeof(sample) - 1) == 0);
    CHECK_INT_EQ(ks_settings_get_int(&s, KS_CFG_DEFAULT_TIMEOUT_KEY, 7), 20);
    CHECK_INT_EQ(ks_settings_get_int(&s, KS_CFG_DEFAULT_ACTION_KEY, 7), 2);
    CHECK_INT_EQ(ks_settings_get_int(&s, "global/missing", 7), 7);
    CHECK_INT_EQ(ks_settings_get_int(&s, KS_CFG_DEFAULT_SERVER_ADDR, 7), 7); /* not a number */
    CHECK(ks_settings_get_bool(&s, KS_CFG_DEFAULT_POPUP_ADVANCED, false));
    CHECK(!ks_settings_get_bool(&s, KS_CFG_DEFAULT_DB_JRNL_WAL, true));
    CHECK(!ks_settings_get_bool(&s, "statsDialog/general_filter_text", true)); /* "" */
    CHECK(ks_settings_get_bool(&s, "global/nope", true));
    CHECK(ks_settings_has(&s, "statsDialog")); /* [General] */
    CHECK(!ks_settings_has(&s, "General/statsDialog"));
    char *v = ks_settings_get_string(&s, KS_CFG_DEFAULT_SERVER_ADDR);
    CHECK_STR_EQ(v, "unix:///tmp/osui.sock");
    free(v);
    v = ks_settings_get_string(&s, "statsDialog/show_columns");
    CHECK_STR_EQ(v, "0, 2, 3, 4, 5");
    free(v);
    CHECK_STR_EQ(ks_settings_raw(&s, "promptDialog/geometry"),
                 "@ByteArray(\\x1\\xd9\\xd0\\xcb\\0\\x3\\0\\0\\0\\0\\tG\\0\\0\\x1\\xb3)");
    ks_settings_close(&s);
}

TEST(escaping)
{
    static const struct {
        const char *value, *raw;
    } cases[] = {
        {"plain", "plain"},
        {"a,b", "\"a,b\""},
        {"x=y;z", "\"x=y;z\""},
        {" lead", "\" lead\""},
        {"trail ", "\"trail \""},
        {"@at", "@@at"},
        {"tab\there", "tab\\there"},
        {"quote\"back\\", "quote\\\"back\\\\"},
        {"\x01" "a", "\\x1\\x61"}, /* a hex digit after \x is escaped too */
        {"\x01z", "\\x1z"},
        {"jo\xc3\xa3o", "jo\xc3\xa3o"}, /* Qt 6: UTF-8 */
        {"", ""},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char *e = ks_settings_escape(cases[i].value);
        CHECK_STR_EQ(e, cases[i].raw);
        free(e);
    }
}

TEST(unescaping)
{
    static const struct {
        const char *raw, *value;
    } cases[] = {
        {"plain", "plain"},
        {"\"a,b\"", "a,b"},
        {"\" lead\"", " lead"},
        {"a, b ,c", "a, b, c"},       /* a list, trailing spaces chopped */
        {"tab\\there", "tab\there"},
        {"\\x41\\x42", "AB"},
        {"\\101", "A"},               /* octal */
        {"\\u00e9", "00e9"},          /* an unknown escape is skipped whole */
        {"x\\x00e9y", "x\xc3\xa9y"},  /* Qt 5 (PyQt5 UI): \x with the code point */
        {"  spaced  ", "spaced"},
        {"\"\"", ""},
        {"trailing\\", "trailing"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char *v = ks_settings_unescape(cases[i].raw);
        CHECK_MSG(v != NULL && strcmp(v, cases[i].value) == 0, "unescape(%s) = \"%s\"",
                  cases[i].raw, v ? v : "(null)");
        free(v);
    }
    /* "@@" stands for "@" */
    struct ks_settings s = {0};
    const char t[] = "[g]\nk=@@x\n";
    CHECK(ks_settings_parse(&s, t, sizeof(t) - 1) == 0);
    char *v = ks_settings_get_string(&s, "g/k");
    CHECK_STR_EQ(v, "@x");
    free(v);
    ks_settings_close(&s);
}

TEST(keys)
{
    struct ks_settings s = {0};
    /* %XX and %UXXXX escapes, "\" for "/", comments, key spacing */
    const char t[] = "; comment\n[gr%20p]\nsub\\key=1\na%E9 = 2\n%U00e9=3\n";
    CHECK(ks_settings_parse(&s, t, sizeof(t) - 1) == 0);
    CHECK_INT_EQ(ks_settings_get_int(&s, "gr p/sub/key", 0), 1);
    CHECK_INT_EQ(ks_settings_get_int(&s, "gr p/a\xc3\xa9", 0), 2);
    CHECK_INT_EQ(ks_settings_get_int(&s, "gr p/\xc3\xa9", 0), 3);
    CHECK(ks_settings_set_raw(&s, "General/k", "1") == 0); /* a group named General */
    char *out = ks_settings_serialize(&s);
    CHECK_STR_EQ(out, "[gr%20p]\nsub\\key=1\na%E9=2\n%E9=3\n");
    free(out);
    const char g[] = "[%General]\nk=1\n\n[General]\nk=2\n";
    CHECK(ks_settings_parse(&s, g, sizeof(g) - 1) == 0);
    CHECK_INT_EQ(ks_settings_get_int(&s, "General/k", 0), 1);
    CHECK_INT_EQ(ks_settings_get_int(&s, "k", 0), 2);
    out = ks_settings_serialize(&s);
    CHECK_STR_EQ(out, g);
    free(out);
    ks_settings_close(&s);
}

static char dir[64];

static void path_in(char *buf, size_t len, const char *name)
{
    snprintf(buf, len, "%s/%s", dir, name);
}

TEST(sync_keeps_other_entries)
{
    char path[128], err[128];
    path_in(path, sizeof(path), "opensnitch/settings.conf");
    char d[128];
    path_in(d, sizeof(d), "opensnitch");
    mkdir(d, 0700);
    CHECK(ks_write_file(path, sample, sizeof(sample) - 1, 0600, err, sizeof(err)) == 0);

    struct ks_settings s;
    CHECK(ks_settings_open(&s, path) == 0);
    /* someone else changes the file meanwhile: sync re-reads it */
    char *changed = malloc(sizeof(sample) + 32);
    CHECK(changed != NULL);
    snprintf(changed, sizeof(sample) + 32, "%s", sample);
    char *p = strstr(changed, "default_duration=3");
    p[17] = '5';
    CHECK(ks_write_file(path, changed, strlen(changed), 0600, err, sizeof(err)) == 0);
    free(changed);

    CHECK(ks_settings_set_int(&s, KS_CFG_DEFAULT_TIMEOUT_KEY, 15) == 0);
    CHECK(ks_settings_set_bool(&s, "global/hide_systray_warning", true) == 0);
    CHECK(ks_settings_set_string(&s, "newgroup/addr", "[::]:50051, x") == 0);
    ks_settings_close(&s);

    size_t len;
    char *text = ks_read_file(path, 1 << 20, &len, err, sizeof(err));
    CHECK(text != NULL);
    CHECK_STR_HAS(text, "default_timeout=15\n");
    CHECK_STR_HAS(text, "default_duration=5\n");
    CHECK_STR_HAS(text, "server_address=unix:///tmp/osui.sock\nhide_systray_warning=true\n");
    CHECK_STR_HAS(text, "geometry=@ByteArray(\\x1\\xd9\\xd0\\xcb\\0\\x3");
    CHECK_STR_HAS(text, "\n\n[newgroup]\naddr=\"[::]:50051, x\"\n");
    free(text);

    CHECK(ks_settings_open(&s, path) == 0);
    char *v = ks_settings_get_string(&s, "newgroup/addr");
    CHECK_STR_EQ(v, "[::]:50051, x");
    free(v);
    ks_settings_close(&s);
    unlink(path);
    rmdir(d);
}

TEST(defaults_on_first_start)
{
    char path[128], err[128];
    path_in(path, sizeof(path), "fresh/settings.conf");
    struct ks_settings s;
    CHECK(ks_settings_open(&s, path) == 0); /* no file yet */
    CHECK(!ks_settings_has(&s, KS_CFG_DEFAULT_TIMEOUT_KEY));
    CHECK(ks_settings_init_defaults(&s) == 0);
    ks_settings_close(&s);
    size_t len;
    char *text = ks_read_file(path, 1 << 20, &len, err, sizeof(err));
    CHECK_STR_EQ(text, "[global]\n"
                       "default_timeout=30\n"
                       "default_action=0\n"
                       "default_duration=6\n"
                       "default_target=0\n"
                       "\n"
                       "[database]\n"
                       "type=0\n"
                       "file=file::memory:\n"
                       "jrnl_wal=false\n");
    free(text);
    /* nothing missing: nothing written */
    CHECK(ks_settings_open(&s, path) == 0);
    struct stat st1, st2;
    stat(path, &st1);
    CHECK(ks_settings_init_defaults(&s) == 0);
    stat(path, &st2);
    CHECK(st1.st_ino == st2.st_ino);
    ks_settings_close(&s);
    unlink(path);
    path_in(path, sizeof(path), "fresh");
    rmdir(path);
}

TEST(default_path)
{
    char buf[256];
    setenv("XDG_CONFIG_HOME", "/x/cfg", 1);
    CHECK(ks_settings_default_path(buf, sizeof(buf)) == 0);
    CHECK_STR_EQ(buf, "/x/cfg/opensnitch/settings.conf");
    unsetenv("XDG_CONFIG_HOME");
    setenv("HOME", "/home/u", 1);
    CHECK(ks_settings_default_path(buf, sizeof(buf)) == 0);
    CHECK_STR_EQ(buf, "/home/u/.config/opensnitch/settings.conf");
    CHECK(ks_settings_default_path(buf, 10) < 0);
}

/* found by fuzz_ui_settings */
TEST(rewrite_is_stable)
{
    struct ks_settings s = {0}, t = {0};
    /* a final lone backslash (at the end of the file) means nothing; kept,
     * it would join the line written after it */
    const char a[] = "[g]\na=x\\";
    CHECK(ks_settings_parse(&s, a, sizeof(a) - 1) == 0);
    CHECK_STR_EQ(ks_settings_raw(&s, "g/a"), "x");
    CHECK(ks_settings_set_int(&s, "g/c", 2) == 0); /* in memory */
    char *out = ks_settings_serialize(&s);
    CHECK_STR_EQ(out, "[g]\na=x\nc=2\n");
    CHECK(ks_settings_parse(&t, out, strlen(out)) == 0);
    CHECK_INT_EQ(t.len, 2);
    free(out);
    /* keys above U+FFFF: a UTF-16 surrogate pair, as Qt writes them */
    const char b[] = "[g]\nk\xf0\x9f\x98\x80=1\n";
    CHECK(ks_settings_parse(&s, b, sizeof(b) - 1) == 0);
    out = ks_settings_serialize(&s);
    CHECK_STR_EQ(out, "[g]\nk%UD83D%UDE00=1\n");
    CHECK(ks_settings_parse(&t, out, strlen(out)) == 0);
    CHECK_INT_EQ(ks_settings_get_int(&t, "g/k\xf0\x9f\x98\x80", 0), 1);
    free(out);
    /* invalid UTF-8 reads as U+FFFD, as Qt 6 decodes the file */
    const char c[] = "[g]\nk\xff=v\xfe\n";
    CHECK(ks_settings_parse(&s, c, sizeof(c) - 1) == 0);
    char *v = ks_settings_get_string(&s, "g/k\xef\xbf\xbd");
    CHECK_STR_EQ(v, "v\xef\xbf\xbd");
    free(v);
    ks_settings_close(&s);
    ks_settings_close(&t);
}

TEST(garbage_does_not_crash)
{
    static const char *const inputs[] = {
        "[", "]", "=", "[a", "k=\\", "k=\"", "k=\\x", "k=\\7", "[%U00", "%", "a=b\\\nc",
        "\r\n\r\n", "k=\"a\"b\"c\", d\\", "[\xff]\n\xfe=\xfd",
    };
    for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
        struct ks_settings s = {0};
        CHECK(ks_settings_parse(&s, inputs[i], strlen(inputs[i])) == 0);
        char *out = ks_settings_serialize(&s);
        CHECK(out != NULL);
        free(out);
        for (size_t k = 0; k < s.len; k++) {
            char full[512];
            snprintf(full, sizeof(full), "%s/%s", s.items[k].group, s.items[k].key);
            free(ks_settings_get_string(&s, full));
        }
        ks_settings_close(&s);
    }
}

int main(void)
{
    snprintf(dir, sizeof(dir), "/tmp/ks-settings-XXXXXX");
    if (mkdtemp(dir) == NULL)
        return 1;
    RUN(round_trip);
    RUN(typed_getters);
    RUN(escaping);
    RUN(unescaping);
    RUN(keys);
    RUN(sync_keeps_other_entries);
    RUN(defaults_on_first_start);
    RUN(default_path);
    RUN(rewrite_is_stable);
    RUN(garbage_does_not_crash);
    rmdir(dir);
    return harness_report();
}
