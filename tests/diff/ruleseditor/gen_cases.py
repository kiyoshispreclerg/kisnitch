#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# The cases of the rules editor's differential test (one JSON per line):
# forms to save, rules to load, and the small helpers.
import itertools
import json
import sys

n = 0


def out(case):
    global n
    n += 1
    case["id"] = "%04d" % n
    print(json.dumps(case, sort_keys=True))


def chk(text, on=True):
    return {"on": on, "text": text}


def base(**kw):
    f = {"name": "r", "desc": "", "action": 0, "duration": 0}
    f.update(kw)
    return f


ALIASES = ["private", "lan", "cloudflare", "ALIAS-NOT-THERE"]

# ---- forms: one field at a time, with the texts that make the interesting branches --------

TEXT = {
    "proto": ["", "TCP", "udp", "tcp,udp", "TCP, UDP ,sctp", "tcp,", ",tcp", "tcp|udp", "t(cp",
              "TCP6", "tcp,,udp"],
    "proc": ["", "/usr/bin/curl", "/usr/bin/.*curl", "/usr/bin/(curl", "/home/u/my prog"],
    "cmdline": ["", "curl -L https://x.org", "curl .*", "curl [", "a b  c"],
    "iface": ["", "eth0", "eth0,wlan0", "eth.*", "eth0,", "wl[0-9", "lo , eth1"],
    "srcport": ["", "80", "80,443", "80, 443", "8080,abc", "80,", "[0-9]+", "(80", "+80", "-1,2"],
    "dstport": ["", "443", "80,443,8080", "x", "53,", "1 2", "^(80|443)$", "*443"],
    "dsthost": ["", "www.a.org", "a.org,b.org", ".*\\.a\\.org", "a.org,", "a b", "x[", "a.org|b.org"],
    "srcip": ["", "10.0.0.1", "::1", "192.168.0.0/16", "LAN", "MULTICAST", "10.0.0.1,10.0.0.2",
              "10.0.*", "1.2.3", "fe80::1%eth0", "300.1.1.1", "127.0.0.0/8", "(10", "10.0.0.1/33",
              "10.0.0.1,", "192.168.0.0/24,10.0.0.0/8"],
    "dstip": ["", "10.0.0.1", "LAN", "MULTICAST", "private", "lan", "cloudflare", "8.8.8.8,8.8.4.4",
              "1.2.3.0/24", "2001:db8::/32", "1\\.1\\.1\\..*", "bad", "foo,bar", "ALIAS-NOT-THERE"],
    "uid": ["", "0", "1000", "root (0)", "root", "nosuchuser (5)", "abc", "10.*", "^(0|1000)$",
            "12 34", "(", "+5", "-5", "5_0"],
    "pid": ["", "1234", "12.*", "(", "abc"],
    "md5": ["", "D41D8CD98F00B204E9800998ECF8427E", "abc.*", "(", "AA"],
}
# regular expressions where Python's `re` and PCRE2 are known to differ (not the possessive
# quantifiers, "a*+": Python takes them from 3.11 on)
TRICKY = ["\\p{L}", "(?P<n>a)(?P<n>b)", "\\d{2,1}", "[z-a]", "a{,3}", "(?<n>a)", "\\k<n>",
          "\\1", "(a)\\2", "a**", "(?<=a+)b", "[[:alpha:]]", "\\Z", "\\z", "\\A.*", "(?#c)a",
          "(?x) a b", "\\h", "\\R", "\\X", "(?|a|b)", "a{1,2}{3}", "\\_", "\\-", "\\e", "\\a",
          "[\\d-z]", "(?P=n)", "(?(1)a|b)", "\\N{DIGIT ONE}", "x{65536}", "(?s).", "\\G", "\\Q.\\E",
          "[]a]", "[^]a]", "a|*", "(*)", "?a", "+", "(", ")", "\\"]
# mid-pattern global flags: a warning up to Python 3.10, an error from 3.11 (ours follows 3.11;
# tests/unit/test_ui_rulegen.c covers it)
if sys.version_info >= (3, 11):
    TRICKY.append("a(?i)b")
for t in TRICKY:
    for key in ("dsthost", "proc"):
        f = base()
        f[key] = chk(t)
        if key == "proc":
            f["proc_regexp"] = True
        out({"kind": "save", "form": f})

LISTS = ["", "/nonexistent-dir", "/tmp", "/etc/lists", "relative/dir"]

for key, texts in TEXT.items():
    for t in texts:
        for sens in (False, True):
            f = base(sensitive=sens)
            f[key] = chk(t)
            # md5 needs the process path checked, as the dialog says (the check is the save
            # handler's, not _save_rule's), so the md5 alone is a case too
            out({"kind": "save", "form": f})
for t in TEXT["proc"]:
    f = base(proc_regexp=True)
    f["proc"] = chk(t)
    out({"kind": "save", "form": f})
for t in TEXT["cmdline"]:
    f = base(cmdline_regexp=True)
    f["cmdline"] = chk(t)
    out({"kind": "save", "form": f})
# a regexp flag with nothing checked, or on the other field
f = base(proc_regexp=True)
f["pid"] = chk("1234")
out({"kind": "save", "form": f})
f = base(cmdline_regexp=True)
f["proc"] = chk("/bin/x")
out({"kind": "save", "form": f})

for key in ("lists", "lists_regexp", "lists_ips", "lists_nets"):
    for t in LISTS:
        for local, apply_all in ((True, False), (False, False), (True, True)):
            f = base(node_is_local=local, apply_all=apply_all)
            f[key] = chk(t)
            out({"kind": "save", "form": f})

# nothing checked, and names
out({"kind": "save", "form": base()})
out({"kind": "save", "form": base(name="", proto=chk("tcp"))})
out({"kind": "save", "form": dict(base(name=""), dstport=chk("443,80"), action=1)})
for name in ("my rule", "ça va", "a/b"):
    f = base(name=name)
    f["dstport"] = chk("443")
    out({"kind": "save", "form": f})

# actions, durations, flags
for action in (0, 1, 2):
    for duration in range(9):
        f = base(action=action, duration=duration, desc="d é", enabled=bool(duration % 2),
                 precedence=bool(action == 1), nolog=bool(duration == 3))
        f["dstip"] = chk("1.1.1.1")
        out({"kind": "save", "form": f})

# lists of operators: pairs of fields
PAIR = {"proto": "tcp", "proc": "/usr/bin/curl", "cmdline": "curl x", "iface": "eth0,lo",
        "srcport": "1,2", "dstport": "443", "dsthost": ".*a\\.org", "srcip": "LAN",
        "dstip": "192.168.0.0/16", "uid": "root (0)", "pid": "1", "md5": "AB12"}
keys = list(PAIR)
for a, b in itertools.combinations(keys, 2):
    f = base(sensitive=True)
    f[a] = chk(PAIR[a])
    f[b] = chk(PAIR[b])
    out({"kind": "save", "form": f})
# many at once
f = base(sensitive=True, proc_regexp=True)
for k in keys:
    f[k] = chk(PAIR[k])
out({"kind": "save", "form": f})
f = base()
for k in keys:
    f[k] = chk(PAIR[k])
f["lists"] = chk("/tmp")
f["lists_nets"] = chk("/tmp")
f["lists_ips"] = chk("/tmp")
f["lists_regexp"] = chk("/tmp")
out({"kind": "save", "form": f})
# an unchecked field with text does nothing
f = base()
f["dstport"] = chk("443", on=False)
f["proc"] = chk("/bin/x")
out({"kind": "save", "form": f})

# ---- rules to load ---------------------------------------------------------------------------


def rule(op, **kw):
    r = {"name": "x", "description": "desc", "enabled": True, "precedence": False,
         "nolog": False, "action": "allow", "duration": "always"}
    r.update(kw)
    r["type"] = op.get("type", "simple")
    r["operand"] = op.get("operand", "")
    r["data"] = op.get("data", "")
    r["sensitive"] = op.get("sensitive", False)
    r["list"] = op.get("list", [])
    return r


LAN = "^(127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|169\\.254\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3}|172\\.1[6-9]\\.\\d+\\.\\d+|172\\.2[0-9]\\.\\d+\\.\\d+|172\\.3[0-1]+\\.\\d{1,3}\\.\\d{1,3}|10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|::1|f[cde].*::.*)$"
MC = "^(2[32][23459]\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})$"
OPS = [
    ("protocol", ["tcp", "UDP", "^(tcp|udp)$", "^(tcp|udp|sctp6)$", "x", "^(a|)$", "^(ß|ü)$"]),
    ("process.path", ["/usr/bin/curl", ".*curl"]),
    ("process.command", ["curl x", "curl.*"]),
    ("process.id", ["12"]),
    ("process.hash.md5", ["abc"]),
    ("user.id", ["1000", "0"]),
    ("iface.out", ["eth0", "^(eth0|lo)$", "^(eth0|)$"]),
    ("source.port", ["80", "^(80|443)$", "^(80|x)$", "^(80||443)$", "^()$"]),
    ("dest.port", ["443", "^(1|2|3)$", "^(53|)$", "^(5|a)$"]),
    ("source.ip", ["1.2.3.4", LAN, MC, "^(1\\.1\\.1\\.1|8\\.8\\.8\\.8)$", "^(1.1.1.1|8.8.8.8)$"]),
    ("source.network", ["192.168.0.0/16", "private"]),
    ("dest.ip", ["1.2.3.4", LAN, MC, "^(1\\.1\\.1\\.1|8\\.8\\.8\\.8)$"]),
    ("dest.network", ["192.168.0.0/16", "private", LAN, MC]),
    ("dest.host", ["a.org", "^(a.org|b.org)$", "^(www.a-b.org|c.uk)$", ".*\\.a\\.org"]),
    ("lists.domains", ["/etc/lists"]),
    ("lists.domains_regexp", ["/etc/rlists"]),
    ("lists.ips", ["/etc/ips"]),
    ("lists.nets", ["/etc/nets"]),
    ("process.env.HOME", ["/root"]),
    ("nope", ["x"]),
]
for operand, datas in OPS:
    for data in datas:
        for typ in ("simple", "regexp", "network"):
            for sens in (False, True):
                out({"kind": "load", "rule": rule({"type": typ, "operand": operand, "data": data,
                                                   "sensitive": sens})})
for action in ("deny", "allow", "reject", "drop", ""):
    for duration in ("once", "30s", "5m", "15m", "30m", "1h", "12h", "until restart", "always",
                     "weird", ""):
        out({"kind": "load", "rule": rule({"operand": "dest.port", "data": "443"},
                                          action=action, duration=duration,
                                          precedence=action == "allow", nolog=duration == "once")})
# lists of operators
out({"kind": "load", "rule": rule({"type": "list", "operand": "list", "list": [
    {"type": "simple", "operand": "process.path", "data": "/bin/x", "sensitive": True},
    {"type": "regexp", "operand": "dest.port", "data": "^(80|443)$", "sensitive": False},
    {"type": "network", "operand": "dest.network", "data": "private", "sensitive": True},
    {"type": "lists", "operand": "lists.domains", "data": "/etc/l", "sensitive": False},
    {"type": "simple", "operand": "protocol", "data": "tcp", "sensitive": False}]})})
out({"kind": "load", "rule": rule({"type": "list", "operand": "list", "list": []})})
out({"kind": "load", "rule": rule({"type": "list", "operand": "list", "list": [
    {"type": "regexp", "operand": "source.ip", "data": LAN},
    {"type": "regexp", "operand": "dest.ip", "data": MC}]})})
out({"kind": "load", "rule": rule({"type": "list", "operand": "list", "list": [
    {"type": "regexp", "operand": "source.port", "data": "^(1|x)$"},
    {"type": "regexp", "operand": "dest.port", "data": "^(2|y)$"}]})})

# ---- helpers ------------------------------------------------------------------------------------
out({"kind": "helpers",
     "comma_to_regexp": [[k, t] for k in ("int", "str") for t in
                         ["1,2,3", "1, 2", "a,b", "1,,2", "", ",", "1,a", "x.y,z", "(1,2", "a|b,c",
                          "+1,-2", "1_0,2", " 1 , 2 ", "1,2,"]],
     "regexp_to_comma": [[k, t] for k in ("int", "str") for t in
                         ["^(1|2|3)$", "^(a-b.c|d)$", "^(1||2)$", "^()$", "x^(1|2)$y", "(1|2)",
                          "^(1|2)", "^(1|a)$", "^(ß|ü_w)$", "^(a b)$", "^(a|b)$|c"]],
     "is_regex": ["", "a", "a.b", "a\\b", "a*", "a{1}", "a[b", "a|b", "^a", "a$", "a?", "a+", "a(b)",
                  "a-b", "ß"]})
