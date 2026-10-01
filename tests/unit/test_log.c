/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "common/log.h"

#include <stdlib.h>
#include <unistd.h>

#include "common/json_util.h"
#include "tests/harness.h"

static char *buf;
static size_t buflen;
static FILE *mem;

static void capture(void)
{
    free(buf);
    buf = NULL;
    buflen = 0;
    mem = open_memstream(&buf, &buflen);
    ks_log_set_output(mem);
}

/* Stops capturing; `buf` holds the output. */
static void release(void)
{
    ks_log_set_output(NULL);
    fclose(mem);
    mem = NULL;
}

static int is_digit(char c)
{
    return c >= '0' && c <= '9';
}

/* Checks "YYYY-MM-DD HH:MM:SS" at s. */
static int is_timestamp(const char *s)
{
    static const char shape[] = "dddd-dd-dd dd:dd:dd";
    for (size_t i = 0; i < sizeof(shape) - 1; i++)
        if (shape[i] == 'd' ? !is_digit(s[i]) : s[i] != shape[i])
            return 0;
    return 1;
}

TEST(plain_format_matches_upstream)
{
    ks_log_set_colors(false);
    ks_log_set_level(KS_LOG_INFO);
    capture();
    ks_info("hello %d", 42);
    release();

    /* "[2006-01-02 15:04:05]  INF  hello 42\n" */
    CHECK(buf[0] == '[');
    CHECK(is_timestamp(buf + 1));
    CHECK_STR_EQ(buf + 20, "]  INF  hello 42\n");
}

TEST(colored_format_matches_upstream)
{
    ks_log_set_colors(true);
    ks_log_set_level(KS_LOG_INFO);
    capture();
    ks_warning("careful");
    release();

    CHECK(strncmp(buf, "\033[2m[", 5) == 0);
    CHECK(is_timestamp(buf + 5));
    CHECK_STR_EQ(buf + 24, "]\033[0m \033[97m\033[43m WAR \033[0m careful\n");
}

TEST(labels_for_every_level)
{
    static const struct {
        int level;
        const char *label;
    } levels[] = {
        {KS_LOG_TRACE, " TRC "}, {KS_LOG_DEBUG, " DBG "},
        {KS_LOG_INFO, " INF "}, {KS_LOG_IMPORTANT, " IMP "},
        {KS_LOG_WARNING, " WAR "}, {KS_LOG_ERROR, " ERR "},
    };
    ks_log_set_colors(false);
    ks_log_set_level(KS_LOG_TRACE);
    for (size_t i = 0; i < sizeof(levels) / sizeof(levels[0]); i++) {
        capture();
        ks_log(levels[i].level, "x");
        release();
        CHECK_STR_HAS(buf, levels[i].label);
    }
}

TEST(level_filtering)
{
    ks_log_set_colors(false);
    ks_log_set_level(KS_LOG_WARNING);
    CHECK_INT_EQ(ks_log_get_level(), KS_LOG_WARNING);
    capture();
    ks_debug("no");
    ks_info("no");
    ks_important("no");
    ks_warning("yes1");
    ks_error("yes2");
    release();
    CHECK(strstr(buf, "no") == NULL);
    CHECK_STR_HAS(buf, "yes1");
    CHECK_STR_HAS(buf, "yes2");
}

TEST(newline_is_added_once)
{
    ks_log_set_colors(false);
    ks_log_set_level(KS_LOG_INFO);
    capture();
    ks_info("a\n");
    ks_info("b");
    ks_info("%s", "");
    release();
    CHECK_STR_HAS(buf, "  a\n[");
    CHECK_STR_HAS(buf, "  b\n[");
    size_t len = strlen(buf);
    CHECK(len >= 2 && buf[len - 1] == '\n' && buf[len - 2] == ' ');
}

TEST(microseconds)
{
    ks_log_set_colors(false);
    ks_log_set_level(KS_LOG_INFO);
    ks_log_set_micro(true);
    capture();
    ks_info("m");
    release();
    ks_log_set_micro(false);
    /* "[2006-01-02 15:04:05.000000]" */
    CHECK(buf[20] == '.');
    for (int i = 21; i < 27; i++)
        CHECK(is_digit(buf[i]));
    CHECK(buf[27] == ']');
}

TEST(long_messages_are_not_truncated)
{
    size_t n = 5000;
    char *big = malloc(n + 1);
    CHECK(big != NULL);
    memset(big, 'z', n);
    big[n] = '\0';

    ks_log_set_colors(false);
    ks_log_set_level(KS_LOG_INFO);
    capture();
    ks_info("<%s>", big);
    release();
    CHECK_STR_HAS(buf, big);
    CHECK_STR_HAS(buf, "z>\n");
    free(big);
}

TEST(open_file_appends)
{
    char path[64], err[128];
    size_t len;
    snprintf(path, sizeof(path), "/tmp/kisnitch-log-XXXXXX");
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    CHECK(write(fd, "previous\n", 9) == 9);
    close(fd);

    ks_log_set_colors(false);
    ks_log_set_level(KS_LOG_INFO);
    CHECK(ks_log_open_file(path) == 0);
    ks_info("to file");
    ks_log_close();

    char *content = ks_read_file(path, 4096, &len, err, sizeof(err));
    unlink(path);
    CHECK(content != NULL);
    CHECK(strncmp(content, "previous\n", 9) == 0);
    CHECK_STR_HAS(content, "  IMP  Start writing logs to /tmp/kisnitch-log-");
    CHECK_STR_HAS(content, "  INF  to file\n");
    free(content);
}

TEST(open_file_failure_falls_back)
{
    ks_log_set_colors(false);
    ks_log_set_level(KS_LOG_INFO);
    /* Output goes to stdout after the failure; keep it out of the way. */
    ks_log_set_level(KS_LOG_FATAL + 1);
    CHECK(ks_log_open_file("/nonexistent/dir/log") == -1);
    CHECK(ks_log_open_file(KS_LOG_STDOUT_FILE) == 0);
}

int main(void)
{
    RUN(plain_format_matches_upstream);
    RUN(colored_format_matches_upstream);
    RUN(labels_for_every_level);
    RUN(level_filtering);
    RUN(newline_is_added_once);
    RUN(microseconds);
    RUN(long_messages_are_not_truncated);
    RUN(open_file_appends);
    RUN(open_file_failure_falls_back);
    free(buf);
    return harness_report();
}
