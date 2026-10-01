#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Generates tests/diff/corpus.json: operators and rule sets evaluated
against simulated connections, by upstream's Go code and by ours.

The corpus is committed; this script is only needed to change it.
Paths are relative to the repository root, where both harnesses run.
"""
import itertools
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
LISTS = "tests/fixtures/upstream/rules/lists"

# ---------------------------------------------------------------- conns

def proc(pid, path, args=None, env=None, checksums=None, parent=None):
    return {"pid": pid, "path": path, "args": args or [], "env": env or {},
            "checksums": checksums or {}, "parent": parent}

INIT = proc(1, "/sbin/init")
BASH = proc(900, "/usr/bin/bash", ["bash"], parent=INIT)

conns = {
    # upstream's operator_test.go connection
    "upstream": {
        "protocol": "TCP", "dst_host": "opensnitch.io", "src_ip": "192.168.1.111",
        "dst_ip": "185.53.178.14", "src_port": 66666, "dst_port": 443,
        "iface_in": 0, "iface_out": 0, "uid": 666,
        "process": proc(12345, "/usr/bin/opensnitchd",
                        ["-rules-path", "/etc/opensnitchd/rules/"]),
    },
    "rich": {
        "protocol": "udp", "dst_host": "WWW.Test.ORG", "src_ip": "2001:db8::10",
        "dst_ip": "1.1.1.1", "src_port": 5353, "dst_port": 53,
        "iface_in": 1, "iface_out": 1, "uid": 0,
        "process": proc(4242, "/usr/bin/curl",
                        ["/usr/bin/curl", "-s", "https://www.test.org/a b"],
                        {"HOME": "/root", "LANG": "C.UTF-8", "EMPTY": ""},
                        {"process.hash.md5": "d41d8cd98f00b204e9800998ecf8427e",
                         "process.hash.sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
                        BASH),
    },
    "v6": {
        "protocol": "tcp6", "dst_host": "", "src_ip": "fe80::1",
        "dst_ip": "2606:4700:4700::1111", "src_port": 40000, "dst_port": 853,
        "iface_in": 0, "iface_out": 9999, "uid": 1000,
        "process": proc(7, "/opt/Ünïcode/ÄPP", ["ÄPP", "--Ω"], {"X": "ü"},
                        {"process.hash.md5": ""}),
    },
    "lan": {
        "protocol": "TCP", "dst_host": "printer.local", "src_ip": "10.0.0.2",
        "dst_ip": "192.168.0.10", "src_port": 1, "dst_port": 631,
        "iface_in": 0, "iface_out": 0, "uid": 65534,
        "process": proc(0, "", None, None, None, None),
    },
    "noproc": {
        "protocol": "icmp", "dst_host": "multicast", "src_ip": "0.0.0.0",
        "dst_ip": "224.0.0.251", "src_port": 0, "dst_port": 0,
        "iface_in": 0, "iface_out": 0, "uid": -1, "process": None,
    },
}

# Subjects for the regexp battery: process.path takes each value.
SUBJECTS = [
    "", "TCP", "TCP\n", "tcp", "a", "aa", "aaa", "a{01}", "a{,3}", "ab", "a.b",
    "axb", "a b", "a\tb", "a\vb", "a\nb", "\n", "a\n", "x\nTCP\n", "/usr/bin/curl",
    "/usr/sbin/curl", "/USR/BIN/Curl", "foo bar", "afoob", "é", "É", "日本",
    "αβγ", "k", "K", "K", "straße", "STRASSE", "1", "٣", "#", "]", "-",
    "\\", "{", "}", "a{2}", "aa{2}", "�", "x" * 40,
]

PATTERNS = [
    # accepted by Go
    "", "|", "()", "a|", "^TCP$", "^/usr/bin/.*", "a{2,5}", "a{1000}", "^a{2}$",
    "a{2,}", "(a|b)+", "(?i)abc", "(?i:TCP)", "(?i-s:a.)", "(?P<name>a)",
    "(?<name>a)", "(?P<1a>a)b", "[[:alpha:]]+", "[[:^space:]]", "[^a-z]", "\\pL",
    "\\p{Greek}", "\\PL", "\\p{^Greek}", "\\p{Any}", "\\P{Any}", "\\p{Han}",
    "[\\p{Lu}\\d]", "\\x41", "\\x{263a}", "\\Qa.b\\E", "\\Qa.b", "\\Q", "\\0",
    "\\012", "\\12", "\\17", "a*?", "a+?", "a??", "a{2}?", "(?s).", ".", "^.$",
    "(?m)^TCP$", "(?m)^$", "^$", "$", "^", "[]a]", "[a-]", "[-a]", "\\.", "\\-",
    "\\ ", "a{", "a{,3}", "a{01}", "a{1,2", "x{2}{", "^*a", "$+", "\\b*", "(?i)",
    "(?)", "\\bfoo\\b", "\\B", "\\Aa", "a\\z", "\\d", "\\D", "\\s", "\\S",
    "[\\s]", "[\\S]", "[^\\S]", "\\w", "\\W", "[\\d\\s]", "\\v", "\\t", "\\n",
    "(?U)a+", "(a{10}){100}", "é", "(?i)é", "(?i)É", "[à-ÿ]", "\\a\\f",
    "((((a))))", "[[]", "[a[]", "a]", "a}", "#", "\\#", "[\\[\\]]", "(?i)k",
    "(?i)K", "(?i)straße", "\\x{fffd}", "[[:space:]]", "[[:word:]]+$",
    "(?i)^/usr/bin/curl$", "^/usr/(s)?bin/", ".*curl$", "(a+)+$", "x*",
    "[\\x00-\\x1f]", "\\x00", "[^\\x00-\\x7f]",
    # rejected by Go
    "^TC(P$", "a)", ")", "a**", "a*+", "a++", "a?*", "a{2}*", "a*{2}", "a*??",
    "a{1001}", "a{2,1}", "(a{500}){3}", "(?=a)", "(?!a)", "(?<=a)", "(?<!a)",
    "(?>a)", "(?#c)", "(?|a)", "(?P=n)", "(?x)a", "\\1", "\\7", "(a)\\1", "\\8",
    "\\Z", "\\G", "\\K", "\\h", "\\e", "\\C", "\\c", "\\u0041", "\\N", "\\E",
    "[\\b]", "[a", "[]", "[z-a]", "[[:foo:]]", "\\p", "\\p{}", "\\p{Foo}",
    "*a", "a|*", "(*)", "(?i)*", "+", "\\xZZ", "\\x{}", "\\x{110000}",
    "(?P<n>a)(?P<n>b)", "(?P<>a)", "(?P<a-b>x)", "\\", "(?i-)", "(?-)", "(?",
    "\\é", "(*UTF)a", "a{2}{3}",
]

# ---------------------------------------------------------------- operators

OPERANDS_STR = {
    "process.id": ["12345", "4242", "0", "7"],
    "process.path": ["/usr/bin/opensnitchd", "/USR/BIN/CURL", "/usr/bin/curl", "",
                     "/opt/ünïcode/äpp"],
    "process.parent.path": ["/sbin/init", "/usr/bin/bash", "/usr/bin/curl", ""],
    "process.command": ["-rules-path /etc/opensnitchd/rules/",
                        "/usr/bin/curl -s https://www.test.org/a b", "ÄPP --Ω", ""],
    "process.env.HOME": ["/root", "/ROOT", ""],
    "process.env. LANG ": ["c.utf-8"],
    "process.env.EMPTY": ["", "x"],
    "process.env.X": ["Ü", "ü"],
    "process.hash.md5": ["d41d8cd98f00b204e9800998ecf8427e", "ffff", ""],
    "process.hash.sha1": ["da39a3ee5e6b4b0d3255bfef95601890afd80709", "d41d8cd98f00b204e9800998ecf8427e"],
    "user.id": ["666", "0", "1000", "-1", "65534"],
    "user.name": ["root", "nobody", "no-such-user-kisnitch"],
    "source.ip": ["192.168.1.111", "2001:db8::10", "fe80::1", "0.0.0.0"],
    "source.port": ["66666", "5353", "0"],
    "dest.ip": ["185.53.178.14", "1.1.1.1", "2606:4700:4700::1111", "192.168.0.10"],
    "dest.host": ["opensnitch.io", "www.test.org", "WWW.TEST.ORG", "", "printer.local"],
    "dest.port": ["443", "53", "0443", "853"],
    "protocol": ["TCP", "tcp", "udp", "tcp6", "icmp"],
    "iface.in": ["lo", ""],
    "iface.out": ["lo", "LO", ""],
    "unknown.operand": ["x", ""],
    "true": ["", "x"],
}

NETWORK_DATA = ["185.53.178.14/24", "8.8.8.8/24", "1.1.1.0/24", "2001:db8::/32",
                "2606:4700::/32", "fe80::/10", "0.0.0.0/0", "::/0",
                "::ffff:185.53.178.0/120", "::ffff:1.1.1.0/64", "192.168.0.0/16",
                "LAN", "MULTICAST", "185.53.178.14", "1.2.3.4/33", "", "bogus",
                "010.0.0.0/8"]
NETWORK_OPERANDS = ["dest.network", "source.network", "dest.ip", "true"]

LISTS_CASES = [
    ("lists.domains", LISTS + "/domains/"),
    ("lists.domains_regexp", LISTS + "/regexp/"),
    ("lists.ips", LISTS + "/ips/"),
    ("lists.nets", LISTS + "/nets/"),
    ("lists.hash.md5", LISTS + "/ips/"),
    ("lists.domains", LISTS + "/nonexistent/"),
    ("lists.domains", ""),
    ("dest.host", LISTS + "/domains/"),
]

cases = []

def add(conn, op, has_checksums=False, path=None):
    case = {"id": "op-%05d" % len(cases), "conn": conn,
            "has_checksums": has_checksums, "operator": op}
    if path is not None:
        case["path"] = path  # overrides the connection's process.path
    cases.append(case)

def op(type_, operand, data, sensitive=False, lst=None):
    o = {"type": type_, "operand": operand, "data": data, "sensitive": sensitive}
    if lst is not None:
        o["list"] = lst
    return o

# every string operand with simple and regexp types
for conn in conns:
    for operand, datas in OPERANDS_STR.items():
        for data, sens in itertools.product(datas, [False, True]):
            for chk in [False, True] if "hash" in operand else [False]:
                add(conn, op("simple", operand, data, sens), chk)
            add(conn, op("regexp", operand, "^" + data, sens))

# networks (with every type, including the ones upstream panics on)
for conn in conns:
    for operand, data in itertools.product(NETWORK_OPERANDS, NETWORK_DATA):
        add(conn, op("network", operand, data))
    for operand in ["dest.network", "source.network", "lists.nets"]:
        add(conn, op("simple", operand, "185.53.178.14"))
        add(conn, op("regexp", operand, ".*"))

# lists
for conn in ["upstream", "rich", "v6"]:
    for operand, data in LISTS_CASES:
        for sens in [False, True]:
            add(conn, op("lists", operand, data, sens))

# unknown types
for t in ["complex", "bogus", ""]:
    add("upstream", op(t, "process.path", "/usr/bin/opensnitchd"))

# lists of operators
L = lambda *items: list(items)
add("upstream", op("list", "list", "", lst=L()))
add("upstream", op("list", "list", "", lst=None))
add("upstream", op("list", "list", "", lst=L(op("simple", "dest.port", "443"),
                                              op("simple", "dest.ip", "185.53.178.14"))))
add("upstream", op("list", "list", "", lst=L(op("simple", "dest.port", "443"),
                                              op("simple", "dest.port", "80"))))
add("upstream", op("list", "protocol", "", lst=L(op("regexp", "process.path", "^/usr/BiN/.*"))))
add("upstream", op("list", "list", "", lst=L(op("regexp", "process.path", "^(bad"))))
add("upstream", op("list", "list", "", lst=L(op("list", "list", "", lst=L(op("simple", "dest.port", "443"))))))
add("upstream", op("simple", "list", "", lst=L(op("simple", "dest.port", "80"))))
add("rich", op("list", "list", "", lst=L(op("simple", "user.id", "0"),
                                          op("lists", "lists.ips", LISTS + "/ips/"))))

# The regexp battery (every pattern against every subject, as process.path
# of the "upstream" connection, sensitive and not) is expanded by the
# harnesses to keep this file small: ids are re-<pattern>-<subject>-<s|i>.

# ---------------------------------------------------------------- rule sets

def rule(name, action="allow", duration="always", enabled=True, precedence=False,
         operator=None):
    return {"name": name, "action": action, "duration": duration, "enabled": enabled,
            "precedence": precedence,
            "operator": operator or op("simple", "true", "")}

CHROME = op("simple", "process.path", "/usr/bin/curl")
rulesets = []

def ruleset(conn, rules):
    rulesets.append({"id": "rs-%04d" % len(rulesets), "conn": conn, "rules": rules})

for conn in ["upstream", "rich"]:
    ruleset(conn, [])
    ruleset(conn, [rule("a"), rule("b")])
    ruleset(conn, [rule("a"), rule("b", "deny"), rule("c")])
    ruleset(conn, [rule("b", "deny"), rule("a", precedence=True)])
    ruleset(conn, [rule("a", "reject"), rule("b", "deny")])
    ruleset(conn, [rule("z", "deny", enabled=False), rule("y")])
    ruleset(conn, [rule("x", operator=CHROME), rule("y", "deny", operator=CHROME)])
    ruleset(conn, [rule("A"), rule("a"), rule("_"), rule("0")])
    ruleset(conn, [rule("dup"), rule("dup", "deny")])
    ruleset(conn, [rule("bad", operator=op("regexp", "process.path", "(")), rule("ok")])
    ruleset(conn, [rule("t", duration="1h"), rule("u", "deny", duration="until restart")])
    ruleset(conn, [rule("l", operator=op("list", "list",
                                        json.dumps([op("simple", "dest.port", "443")])))])
    ruleset(conn, [rule("l", enabled=False, operator=op("list", "list",
                                        json.dumps([op("simple", "dest.port", "443")]))),
                   rule("m")])
# upstream's own test rules
upstream_rules = []
for fname in sorted(os.listdir(os.path.join(HERE, "../fixtures/upstream/rules"))):
    if fname.endswith(".json"):
        with open(os.path.join(HERE, "../fixtures/upstream/rules", fname)) as f:
            upstream_rules.append(json.load(f))
for conn in conns:
    ruleset(conn, upstream_rules)

corpus = {
    "aliases": "tests/fixtures/upstream/network_aliases.json",
    "conns": conns,
    "cases": cases,
    "rulesets": rulesets,
    "regex_battery": {"conn": "upstream", "patterns": PATTERNS, "subjects": SUBJECTS},
}
with open(os.path.join(HERE, "corpus.json"), "w") as f:
    json.dump(corpus, f, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    f.write("\n")
print("%d operator cases, %d regexp cases, %d rule sets, %d connections" %
      (len(cases), 2 * len(PATTERNS) * len(SUBJECTS), len(rulesets), len(conns)))
