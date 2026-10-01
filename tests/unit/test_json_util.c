/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "common/json_util.h"

#include <stdlib.h>
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

int main(void)
{
    RUN(parse_accepts_trailing_whitespace_only);
    RUN(parse_respects_length);
    RUN(parse_error_positions);
    RUN(equality_is_semantic);
    RUN(subset_semantics);
    RUN(read_and_write_file);
    return harness_report();
}
