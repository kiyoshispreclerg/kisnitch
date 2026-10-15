#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# The cases of the preferences' differential test (one JSON per line):
# node configurations to load into the form, and forms to turn back into
# configurations.
import copy
import json
import os
import sys

here = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(here, "..", "..", "fixtures", "upstream")
base = json.load(open(os.path.join(FIX, "default-config.json")))
n = 0


def out(case):
    global n
    n += 1
    case["id"] = "%04d" % n
    print(json.dumps(case, sort_keys=True))


def dumps(c, indent=None):
    return json.dumps(c, indent=indent)


# ---- node configurations ------------------------------------------------------------------

variants = [("default", base)]


def variant(name, fn):
    c = copy.deepcopy(base)
    fn(c)
    variants.append((name, c))


def drop(*path):
    def f(c):
        o = c
        for p in path[:-1]:
            o = o[p]
        del o[path[-1]]
    return f


def setv(path, value):
    def f(c):
        o = c
        for p in path[:-1]:
            o = o[p]
        o[path[-1]] = value
    return f


for key in ("DefaultAction", "ProcMonitorMethod", "InterceptUnknown", "LogLevel", "LogUTC",
            "LogMicro", "Server", "Rules", "Internal", "FwOptions", "Stats"):
    variant("drop-" + key, drop(key))
    variant("null-" + key, setv([key], None))
for path in (["Server", "Address"], ["Server", "LogFile"], ["Server", "Authentication"],
             ["Rules", "Path"], ["Rules", "EnableChecksums"], ["Internal", "GCPercent"],
             ["Internal", "FlushConnsOnStart"], ["FwOptions", "MonitorInterval"],
             ["FwOptions", "QueueBypass"], ["Stats", "MaxEvents"], ["Stats", "MaxStats"]):
    variant("drop-" + "/".join(path), drop(*path))
    variant("null-" + "/".join(path), setv(path, None))
variant("action-reject", setv(["DefaultAction"], "reject"))
variant("action-weird", setv(["DefaultAction"], "weird"))
variant("monitor-proc", setv(["ProcMonitorMethod"], "proc"))
variant("monitor-audit", setv(["ProcMonitorMethod"], "audit"))
variant("monitor-weird", setv(["ProcMonitorMethod"], "x"))
variant("intercept-true", setv(["InterceptUnknown"], True))
# (2.0 would come back as 2: cJSON does not keep the literal, divergence 49)
for ll in (0, 1, 5, 6, 9, -1, "3", "x", None, [1]):
    variant("loglevel-%s" % ll, setv(["LogLevel"], ll))
variant("utc-false", setv(["LogUTC"], False))
variant("micro-true", setv(["LogMicro"], True))
variant("rules-empty-path", setv(["Rules", "Path"], ""))
variant("rules-path", setv(["Rules", "Path"], "/home/u/rules"))
variant("checksums-true", setv(["Rules", "EnableChecksums"], True))
variant("gc-50", setv(["Internal", "GCPercent"], 50))
variant("flush-true", setv(["Internal", "FlushConnsOnStart"], True))
variant("interval-empty", setv(["FwOptions", "MonitorInterval"], ""))
variant("interval-60s", setv(["FwOptions", "MonitorInterval"], "60s"))
variant("interval-1m", setv(["FwOptions", "MonitorInterval"], "1m"))
variant("bypass-false", setv(["FwOptions", "QueueBypass"], False))
variant("stats-values", lambda c: c.update({"Stats": {"MaxEvents": 1000, "MaxStats": 10}}))
variant("stats-extra", lambda c: c["Stats"].update({"Workers": 6}))
variant("server-empty", setv(["Server"], {}))
variant("server-noaddr", drop("Server", "Address"))
variant("server-nolog", drop("Server", "LogFile"))
variant("auth-empty", setv(["Server", "Authentication"], {}))
for t in ("simple", "tls-simple", "tls-mutual", "nope"):
    variant("auth-" + t, setv(["Server", "Authentication"],
                              {"Type": t, "TLSOptions": {"CACert": "/ca", "ServerCert": "/srv",
                                                         "ClientCert": "/cli", "ClientKey": "/key",
                                                         "SkipVerify": True,
                                                         "ClientAuthType": "verify-cert"}}))
variant("auth-notype", setv(["Server", "Authentication"], {"TLSOptions": {"CACert": "/ca"}}))
variant("auth-notls", setv(["Server", "Authentication"], {"Type": "tls-simple"}))
variant("auth-nulltls", setv(["Server", "Authentication"], {"Type": "tls-mutual", "TLSOptions": None}))
variant("auth-weird-verify", setv(["Server", "Authentication"],
                                  {"Type": "tls-simple", "TLSOptions": {"ClientAuthType": "x"}}))
variant("addr-other", setv(["Server", "Address"], "ipv4:10.0.0.1:50051"))
variant("extra-keys", lambda c: c.update({"Audit": {"AudispSocket": "/x"}, "Ebpf": {"ModulesPath": "/y"}}))

for name, cfg in variants:
    for ll in (0, 3, 7):
        out({"kind": "load", "version": "1.8.0", "name": "host-é", "loglevel": ll,
             "config": dumps(cfg)})

# ---- forms to build ---------------------------------------------------------------------

DEFAULT_FORM = {"comboNodeAction": 1, "comboNodeMonitorMethod": 2, "comboNodeLogLevel": 3,
                "comboNodeAddress": "unix:///tmp/osui.sock", "comboNodeLogFile": "/dev/stdout",
                "comboNodeAuthType": 0, "comboNodeAuthVerifyType": 0,
                "lineNodeRulesPath": "/etc/opensnitchd/rules", "lineNodeFwMonInterval": "15",
                "lineNodeMaxEvents": "250", "lineNodeMaxStats": "50", "spinNodeGC": 100}
FORMS = [("default", {})]


def form(name, **kw):
    FORMS.append((name, kw))


form("allow", comboNodeAction=1)
form("reject", comboNodeAction=2)
form("monitor-ebpf", comboNodeMonitorMethod=1)
form("loglevel-last", comboNodeLogLevel=5)
form("loglevel-none", comboNodeLogLevel=-1)
form("checks", checkInterceptUnknown=True, checkNodeLogUTC=True, checkNodeLogMicro=True,
     enableChecksums=True, checkNodeFlushConns=True, checkNodeBypassQueue=True)
form("empty-addr", comboNodeAddress="")
form("addr", comboNodeAddress="ipv4:1.2.3.4:50051", comboNodeLogFile="/var/log/x.log")
form("auth-simple", comboNodeAuthType=0)
form("auth-tls", comboNodeAuthType=1, lineNodeServerCertFile="/s", lineNodeCertFile="/c",
     lineNodeCertKeyFile="/k", checkNodeAuthSkipVerify=True, comboNodeAuthVerifyType=3)
form("auth-mutual", comboNodeAuthType=2, lineNodeCACertFile="/ca", comboNodeAuthVerifyType=4)
form("auth-none", comboNodeAuthType=-1)
form("verify-none", comboNodeAuthType=1, comboNodeAuthVerifyType=-1)
form("rules-empty", lineNodeRulesPath="")
form("rules-path", lineNodeRulesPath="/srv/rules")
form("gc", spinNodeGC=25)
form("interval", lineNodeFwMonInterval="30")
form("interval-empty", lineNodeFwMonInterval="")
for me in ("1000", " 12 ", "abc", "", "1_0", "-5", "+7", "1.5"):
    form("events-" + me, lineNodeMaxEvents=me)
    form("stats-" + me, lineNodeMaxStats=me)

CONFIGS = [("default", dumps(base)), ("indented", dumps(base, 4)),
           ("minimal", dumps({"DefaultAction": "deny"})),
           ("server", dumps({"Server": {"Address": "x", "LogFile": "y"}})),
           ("null-server", dumps({"Server": None})),
           ("server-auth", dumps({"Server": {"Authentication": {"Type": "tls-mutual", "TLSOptions": {"CACert": "z", "SkipVerify": False}}}})),
           ("rules-null", dumps({"Rules": None, "Internal": None, "FwOptions": None, "Stats": None})),
           ("stats-null", dumps({"Stats": {"MaxEvents": None, "MaxStats": None}})),
           ("extra", dumps(dict(base, Zzz=[1, 2, {"a": None}], Audit={"x": 1.5}))),
           ("unicode", dumps(dict(base, Name="éü"))),
           ("invalid", "not json"), ("array", "[1, 2]"), ("none", None)]
for cname, cfg in CONFIGS:
    for fname, kw in FORMS:
        f = dict(DEFAULT_FORM)
        f.update(kw)
        out({"kind": "build", "config": cfg, "form": f})
