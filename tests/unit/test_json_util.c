/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "common/json_util.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tests/harness.h"

static cJSON *P(const char *s)
{
    char err[128];
    return ks_json_parse(s, strlen(s), err, sizeof(err));
}

static int subset(const char *a, const char *b)
{
    cJSON *x = P(a), *y = P(b);
    int r = x != NULL && y != NULL && ks_json_is_subset(x, y);
    cJSON_Delete(x);
    cJSON_Delete(y);
    return r;
}

static int equal(const char *a, const char *b)
{
    cJSON *x = P(a), *y = P(b);
    int r = x != NULL && y != NULL && ks_json_equal(x, y);
    cJSON_Delete(x);
    cJSON_Delete(y);
    return r;
}

TEST(parse_accepts_trailing_whitespace_only)
{
    char err[128];
    cJSON *j = ks_json_parse("{\"a\":1} \n\t\r\n", 12, err, sizeof(err));
    CHECK_MSG(j != NULL, "%s", err);
    cJSON_Delete(j);

    CHECK(ks_json_parse("{} x", 4, err, sizeof(err)) == NULL);
    CHECK_STR_HAS(err, "line 1, column 4");
    CHECK(ks_json_parse("1 2", 3, err, sizeof(err)) == NULL);
}

TEST(parse_respects_length)
{
    char err[128];
    /* Not NUL-terminated within len; the trailing garbage is outside it. */
    const char buf[] = "{\"a\":true}GARBAGE";
    cJSON *j = ks_json_parse(buf, 10, err, sizeof(err));
    CHECK_MSG(j != NULL, "%s", err);
    cJSON_Delete(j);
    CHECK(ks_json_parse(buf, 9, err, sizeof(err)) == NULL);
}

TEST(parse_error_positions)
{
    char err[128];
    CHECK(ks_json_parse("", 0, err, sizeof(err)) == NULL);
    CHECK_STR_HAS(err, "line 1, column 1: unexpected end of JSON input");

    const char *s = "{\n  \"a\": 1,\n  \"b\": x\n}";
    CHECK(ks_json_parse(s, strlen(s), err, sizeof(err)) == NULL);
    CHECK_STR_HAS(err, "line 3, column 8: invalid JSON near 'x'");

    const char bin[] = "{\"a\":\x01}";
    CHECK(ks_json_parse(bin, sizeof(bin) - 1, err, sizeof(err)) == NULL);
    /* cJSON's position can be one token past the culprit; only the line is
     * reliable in every case. */
    CHECK_STR_HAS(err, "line 1, column ");
}

TEST(equality_is_semantic)
{
    CHECK(equal("{\"a\":1,\"b\":[1,2]}", "{\"b\":[1,2],\"a\":1.0}"));
    CHECK(!equal("{\"a\":1}", "{\"A\":1}"));
    CHECK(!equal("[1,2]", "[2,1]"));
    CHECK(!equal("{\"a\":1}", "{\"a\":1,\"b\":2}"));
    CHECK(!equal("null", "false"));
}

TEST(subset_semantics)
{
    CHECK(subset("{}", "{\"a\":1}"));
    CHECK(subset("{\"a\":{\"b\":1}}", "{\"a\":{\"b\":1,\"c\":2},\"d\":3}"));
    CHECK(subset("[{\"a\":1}]", "[{\"a\":1,\"b\":2}]"));
    CHECK(!subset("{\"a\":1}", "{}"));
    CHECK(!subset("{\"a\":1}", "{\"a\":2}"));
    CHECK(!subset("{\"a\":{\"b\":1}}", "{\"a\":{\"b\":true}}"));
    CHECK(!subset("[1]", "[1,2]"));
    CHECK(!subset("{\"a\":[]}", "{\"a\":{}}"));
    CHECK(!subset("{\"a\":1}", "[1]"));
}

TEST(read_and_write_file)
{
    char path[64], err[256];
    size_t len;
    snprintf(path, sizeof(path), "/tmp/kisnitch-ju-XXXXXX");
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    close(fd);

    CHECK(ks_write_file(path, "hello", 5, 0600, err, sizeof(err)) == 0);
    char *s = ks_read_file(path, 5, &len, err, sizeof(err));
    CHECK(s != NULL);
    CHECK_INT_EQ(len, 5);
    CHECK_STR_EQ(s, "hello");
    free(s);

    CHECK(ks_read_file(path, 4, &len, err, sizeof(err)) == NULL);
    CHECK_STR_HAS(err, "larger than 4 bytes");

    /* Bigger than the initial buffer, so it has to grow. */
    size_t big = 100000;
    char *data = malloc(big);
    CHECK(data != NULL);
    memset(data, 'q', big);
    CHECK(ks_write_file(path, data, big, 0600, err, sizeof(err)) == 0);
    s = ks_read_file(path, big, &len, err, sizeof(err));
    CHECK_MSG(s != NULL, "%s", err);
    CHECK_INT_EQ(len, big);
    CHECK(memcmp(s, data, big) == 0 && s[big] == '\0');
    free(s);
    CHECK(ks_read_file(path, big - 1, &len, err, sizeof(err)) == NULL);
    free(data);

    unlink(path);
    CHECK(ks_read_file(path, 10, &len, err, sizeof(err)) == NULL);
    CHECK_STR_HAS(err, "No such file or directory");
    CHECK(ks_write_file("/nonexistent/x", "a", 1, 0600, err, sizeof(err)) == -1);
}

static char *slurp(const char *path)
{
    char err[128];
    size_t len;
    return ks_read_file(path, 1 << 20, &len, err, sizeof(err));
}

static bool has_content(const char *path, const char *want)
{
    char *s = slurp(path);
    bool r = s != NULL && strcmp(s, want) == 0;
    free(s);
    return r;
}

static bool mode_is(const char *path, mode_t want)
{
    struct stat st;
    return stat(path, &st) == 0 && (st.st_mode & 07777) == want;
}

static bool only_two(const char *text, size_t len)
{
    return ks_check_usable(text, len) && len == 2;
}

TEST(safe_write_backs_up_the_previous_file)
{
    char dir[] = "/tmp/kisnitch-safe-XXXXXX", path[128], bak[140], tmp[140], err[256];
    CHECK(mkdtemp(dir) != NULL);
    snprintf(path, sizeof(path), "%s/f.json", dir);
    snprintf(bak, sizeof(bak), "%s.backup", path);
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);

    /* first write: nothing to copy */
    CHECK_MSG(ks_write_file_safe(path, "one", 3, 0640, ks_check_usable, err, sizeof(err)) == 0,
              "%s", err);
    CHECK(has_content(path, "one"));
    CHECK(access(bak, F_OK) != 0);
    CHECK(mode_is(path, 0640));

    /* second: the backup holds the previous content, with its mode; an
     * existing file keeps its mode whatever `mode` says */
    CHECK(chmod(path, 0600) == 0);
    CHECK(ks_write_file_safe(path, "two", 3, 0644, ks_check_usable, err, sizeof(err)) == 0);
    CHECK(has_content(path, "two"));
    CHECK(has_content(bak, "one"));
    CHECK(mode_is(bak, 0600));
    CHECK(mode_is(path, 0600));
    CHECK(access(tmp, F_OK) != 0);

    /* an empty main file (what a power cut leaves) does not replace a good
     * backup */
    CHECK(ks_write_file(path, "", 0, 0600, err, sizeof(err)) == 0);
    CHECK(ks_write_file_safe(path, "three", 5, 0600, ks_check_usable, err, sizeof(err)) == 0);
    CHECK(has_content(path, "three"));
    CHECK(has_content(bak, "one"));

    /* same for NUL bytes, and for a file the validator rejects */
    CHECK(ks_write_file(path, "a\0b", 3, 0600, err, sizeof(err)) == 0);
    CHECK(ks_write_file_safe(path, "four", 4, 0600, ks_check_usable, err, sizeof(err)) == 0);
    CHECK(has_content(bak, "one"));
    CHECK(ks_write_file_safe(path, "ab", 2, 0600, only_two, err, sizeof(err)) == 0);
    CHECK(has_content(bak, "one")); /* "four" is not two bytes long */
    CHECK(ks_write_file_safe(path, "cd", 2, 0600, only_two, err, sizeof(err)) == 0);
    CHECK(has_content(bak, "ab"));

    /* a failed backup does not stop the write */
    CHECK(unlink(bak) == 0);
    CHECK(mkdir(bak, 0700) == 0);
    CHECK(ks_write_file_safe(path, "ef", 2, 0600, only_two, err, sizeof(err)) == 0);
    CHECK(has_content(path, "ef"));
    rmdir(bak);

    unlink(bak);
    unlink(path);
    rmdir(dir);
}

TEST(read_or_backup_falls_back_only_when_the_main_is_unusable)
{
    char dir[] = "/tmp/kisnitch-safe-XXXXXX", path[128], bak[140], err[256];
    size_t len;
    CHECK(mkdtemp(dir) != NULL);
    snprintf(path, sizeof(path), "%s/f.conf", dir);
    snprintf(bak, sizeof(bak), "%s.backup", path);

    /* neither: the same failure as ks_read_file */
    errno = 0;
    CHECK(ks_read_file_or_backup(path, 100, ks_check_usable, &len, err, sizeof(err)) == NULL);
    CHECK_INT_EQ(errno, ENOENT);
    CHECK_STR_HAS(err, "No such file or directory");

    CHECK(ks_write_file(bak, "old", 3, 0600, err, sizeof(err)) == 0);
    char *s = ks_read_file_or_backup(path, 100, ks_check_usable, &len, err, sizeof(err));
    CHECK(s != NULL && strcmp(s, "old") == 0 && len == 3); /* missing */
    free(s);

    CHECK(ks_write_file(path, "", 0, 0600, err, sizeof(err)) == 0);
    s = ks_read_file_or_backup(path, 100, ks_check_usable, &len, err, sizeof(err));
    CHECK(s != NULL && strcmp(s, "old") == 0); /* empty */
    free(s);

    CHECK(ks_write_file(path, "x\0y", 3, 0600, err, sizeof(err)) == 0);
    s = ks_read_file_or_backup(path, 100, ks_check_usable, &len, err, sizeof(err));
    CHECK(s != NULL && strcmp(s, "old") == 0); /* zeroed */
    free(s);

    CHECK(ks_write_file(path, "new", 3, 0600, err, sizeof(err)) == 0);
    s = ks_read_file_or_backup(path, 100, ks_check_usable, &len, err, sizeof(err));
    CHECK(s != NULL && strcmp(s, "new") == 0); /* the main wins */
    free(s);

    /* no good backup: what the plain read returns */
    CHECK(ks_write_file(path, "", 0, 0600, err, sizeof(err)) == 0);
    CHECK(ks_write_file(bak, "", 0, 0600, err, sizeof(err)) == 0);
    s = ks_read_file_or_backup(path, 100, ks_check_usable, &len, err, sizeof(err));
    CHECK(s != NULL && len == 0);
    free(s);
    unlink(bak);
    CHECK(ks_write_file(path, "q", 1, 0600, err, sizeof(err)) == 0);
    s = ks_read_file_or_backup(path, 100, ks_check_json_object, &len, err, sizeof(err));
    CHECK(s != NULL && strcmp(s, "q") == 0);
    free(s);

    unlink(bak);
    unlink(path);
    rmdir(dir);
}

TEST(json_object_check)
{
    CHECK(ks_check_json_object("{\"a\":1}", 7));
    CHECK(!ks_check_json_object("[1]", 3));
    CHECK(!ks_check_json_object("", 0));
    CHECK(!ks_check_json_object("{\"a\":", 5));
    CHECK(!ks_check_json_object("{\0}", 3));
}

int main(void)
{
    RUN(parse_accepts_trailing_whitespace_only);
    RUN(parse_respects_length);
    RUN(parse_error_positions);
    RUN(equality_is_semantic);
    RUN(subset_semantics);
    RUN(read_and_write_file);
    RUN(safe_write_backs_up_the_previous_file);
    RUN(read_or_backup_falls_back_only_when_the_main_is_unusable);
    RUN(json_object_check);
    return harness_report();
}
