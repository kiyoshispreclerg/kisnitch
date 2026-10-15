/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ui/procinfo.c: the JSON of daemon/procmon.Process as the process dialog
 * shows it (expected strings produced with upstream's Python formatting).
 */
#include "ui/procinfo.h"

#include <glib.h>
#include <string.h>

#include "tests/harness.h"

static const char *sample =
    "{\"Path\": \"/usr/bin/curl\", \"Args\": [\"curl\", \"-s\", \"https://a.example/?x=1&y=2\"], "
    "\"CWD\": \"/home/u\", \"Comm\": \"curl\", "
    "\"Statm\": {\"Size\": 123456789, \"Resident\": 1048575, \"Lib\": 0, \"Data\": 52428800, \"Text\": 2097152}, "
    "\"Status\": \"Name:\\tcurl\\nState:\\tS (sleeping)\\n\", \"Maps\": \"7f00-7f01 r-xp\", \"Stack\": \"[<0>] x\", "
    "\"Env\": {\"HOME\": \"/root\", \"LANG\": \"C\"}, "
    "\"IOStats\": {\"RChar\": 104857600, \"WChar\": 2097152, \"SyscallRead\": 10, \"SyscallWrite\": 20, "
    "\"ReadBytes\": 0, \"WriteBytes\": 3145728}, "
    "\"Tree\": [{\"key\": \"/usr/bin/curl\", \"value\": 4242}, {\"key\": \"/bin/bash\", \"value\": 100}, "
    "{\"key\": \"/sbin/init\", \"value\": 1}], "
    "\"Checksums\": {\"process.hash.md5\": \"d41d8cd98f00b204e9800998ecf8427e\"}, "
    "\"Descriptors\": [{\"Size\": 0, \"ModTime\": \"2026-01-01T10:00:00Z\", \"Name\": \"0\", \"SymLink\": \"/dev/null\"}, "
    "{\"Size\": 4096, \"ModTime\": \"2026-01-01T10:00:00Z\", \"Name\": \"3\", \"SymLink\": \"socket:[123] state:x\"}, "
    "{\"Size\": 12, \"ModTime\": \"2026-01-02T10:00:00Z\", \"Name\": \"4\", \"SymLink\": \"/tmp/x\"}]}";

TEST(header)
{
    struct ks_procinfo p;
    CHECK(ks_procinfo_parse(&p, sample));
    char *s = ks_procinfo_path(&p);
    CHECK_STR_EQ(s, "(/usr/bin/curl)"); /* the path is not in Args */
    g_free(s);
    s = ks_procinfo_args(&p);
    CHECK_STR_EQ(s, "curl -s https://a.example/?x=1&y=2");
    g_free(s);
    s = ks_procinfo_cwd(&p);
    CHECK_STR_EQ(s, "<b>CWD: </b>/home/u");
    g_free(s);
    s = ks_procinfo_parents(&p);
    CHECK_STR_EQ(s, "<b>Parent(s): </b>/sbin/init \xe2\x9e\xa1 /bin/bash \xe2\x9e\xa1 /usr/bin/curl");
    g_free(s);
    s = ks_procinfo_checksums(&p);
    CHECK_STR_EQ(s, "<b>md5:</b> d41d8cd98f00b204e9800998ecf8427e");
    g_free(s);
    s = ks_procinfo_mem(&p);
    CHECK_STR_EQ(s, "<b>VIRT:</b> 117MB, <b>RSS:</b> 0MB, <b>Libs:</b> 0MB, <b>Data:</b> 50MB, <b>Text:</b> 2MB");
    g_free(s);
    ks_procinfo_free(&p);
}

TEST(tabs)
{
    struct ks_procinfo p;
    CHECK(ks_procinfo_parse(&p, sample));
    char *s = ks_procinfo_env(&p);
    CHECK_STR_EQ(s, "Name           \tValue\n\nHOME           :\t/root\nLANG           :\tC\n");
    g_free(s);
    s = ks_procinfo_iostats(&p);
    CHECK_STR_HAS(s, "<b>Chars read:</b> 100MB\n<b>Chars written:</b> 2MB\n");
    CHECK_STR_HAS(s, "<b>KB written: </b>3MB");
    g_free(s);
    s = ks_procinfo_status(&p);
    CHECK_STR_HAS(s, "State:\tS (sleeping)");
    g_free(s);
    s = ks_procinfo_descriptors(&p, true, false);
    CHECK_STR_EQ(s, "Size        Time                                    Name     -> Symlink\n\n"
                    "4096        2026-01-01T10:00:00Z                    3        -> socket:[123] state:x\n"
                    "12          2026-01-02T10:00:00Z                    4        -> /tmp/x\n");
    g_free(s);
    s = ks_procinfo_descriptors(&p, false, false);
    CHECK_STR_HAS(s, "0           2026-01-01T10:00:00Z                    0        -> /dev/null\n");
    g_free(s);
    /* the sockets filter: only the lines the regex "(socket.*:.*state.*)" matches */
    s = ks_procinfo_descriptors(&p, false, true);
    CHECK_STR_EQ(s, "\nsocket:[123] state:x");
    g_free(s);
    s = ks_procinfo_descriptors(&p, true, true);
    CHECK_STR_HAS(s, "/tmp/x\n\nsocket:[123] state:x");
    g_free(s);
    ks_procinfo_free(&p);
}

TEST(edge_cases)
{
    struct ks_procinfo p;
    CHECK(ks_procinfo_parse(&p, "{\"Path\": \"/bin/x\", \"Args\": [\"/bin/x\"], \"CWD\": \"/\", \"Env\": {}}"));
    CHECK(ks_procinfo_path(&p) == NULL); /* the path is in Args: no label */
    char *s = ks_procinfo_env(&p);
    CHECK_STR_EQ(s, "<no environment variables>");
    g_free(s);
    s = ks_procinfo_parents(&p);
    CHECK_STR_EQ(s, "&lt;could not obtain hash&gt;");
    g_free(s);
    CHECK(ks_procinfo_mem(&p) == NULL);
    CHECK(ks_procinfo_status(&p) == NULL);
    ks_procinfo_free(&p);
    CHECK(!ks_procinfo_parse(&p, "{\"Args\": []}"));
    CHECK(!ks_procinfo_parse(&p, "nope"));
}

int main(void)
{
    RUN(header);
    RUN(tabs);
    RUN(edge_cases);
    return harness_report();
}
