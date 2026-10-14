#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Writes the cases of the pop-up differential test (one JSON object per
# line) to stdout. A case: a connection, the UI settings, the rules already
# in the UI's table, and what the user does. "what": "each" (or "what_ip":
# "each") runs the case once per entry of that combo (both sides expand it
# the same way).
import itertools
import json

CONNS = {
    "curl": dict(dst_ip="93.184.216.34", dst_host="www.example.com", dst_port=443,
                 process_path="/usr/bin/curl",
                 process_args=["curl", "-s", "https://www.example.com/"]),
    "relative": dict(dst_ip="192.168.1.20", dst_port=8080, process_path="/usr/bin/python3.10",
                     process_args=["python3", "-m", "http.server"]),
    "procfd": dict(dst_ip="10.1.2.3", dst_host="intra.lan", dst_port=22,
                   process_path="/usr/bin/x", process_args=["/proc/self/fd/3", "--x"]),
    "absolute": dict(dst_ip="151.101.1.1", dst_host="a.b.c.d.example.org", dst_port=80,
                     process_path="/usr/bin/wget",
                     process_args=["/usr/bin/wget", "-q", "http://a.b.c.d.example.org/"]),
    "appimage": dict(dst_ip="1.2.3.4", dst_port=443,
                     process_path="/tmp/.mount_Foo1a2b/usr/bin/app.bin",
                     process_args=["/tmp/.mount_Foo1a2b/usr/bin/app.bin"]),
    "snap": dict(dst_ip="34.117.65.55", dst_host="push.services.mozilla.com", dst_port=443,
                 process_path="/snap/firefox/4793/usr/lib/firefox/firefox",
                 process_args=["/snap/firefox/4793/usr/lib/firefox/firefox"]),
    "ipv6": dict(dst_ip="2001:db8:0:1::5", dst_host="ipv6.example.com", dst_port=443,
                 process_path="/usr/bin/curl", process_args=["curl", "-6", "x"]),
    "dns": dict(protocol="udp", dst_ip="8.8.8.8", dst_host="www.google.com", dst_port=53,
                process_path="/usr/lib/systemd/systemd-resolved",
                process_args=["/usr/lib/systemd/systemd-resolved"]),
    "icmp": dict(protocol="icmp", dst_ip="1.1.1.1", dst_port=0, process_path="/usr/bin/ping",
                 process_args=["ping", "1.1.1.1"]),
    "md5": dict(dst_ip="140.82.112.3", dst_host="github.com", dst_port=443,
                process_path="/usr/bin/git", process_args=["git", "fetch"],
                md5="d41d8cd98f00b204e9800998ecf8427e"),
    "nopid": dict(dst_ip="9.9.9.9", dst_port=853, process_id=0, process_path="",
                  process_args=[]),
    "unicode": dict(dst_ip="200.1.2.3", dst_host="exemplo.com.br", dst_port=443,
                    process_path="/home/joão/Área de Trabalho/app",
                    process_args=["./app", "--maçã"]),
    "loopback6": dict(dst_ip="::1", dst_port=631, process_path="/usr/bin/lpstat",
                      process_args=["lpstat", "-a"]),
    "multicast": dict(protocol="udp", dst_ip="239.255.255.250", dst_port=1900,
                      process_path="/usr/bin/minissdpd", process_args=["minissdpd"]),
    "emptyargs": dict(dst_ip="5.6.7.8", dst_port=80, process_path="/usr/bin/daemon",
                      process_args=[""]),
}

APP = {"nopid": "", "unicode": "app", "appimage": "App"}


def case(cid, con, settings=None, choice=None, rules=None, local=True):
    c = {"id": cid, "con": CONNS[con], "app_name": APP.get(con, con), "local": local,
         "settings": settings or {}, "choice": choice or {}, "rules": rules or []}
    print(json.dumps(c, ensure_ascii=False))


def main():
    n = 0
    # every entry of the combo, with each action
    for con in CONNS:
        for action in ("allow", "deny_button", "reject", "timeout"):
            case("%s-each-%s" % (con, action), con,
                 {"global/default_action": "2" if action == "timeout" else "0"},
                 {"what": "each", "duration": 8, "action": action})
            n += 1
    # the defaults: target, duration, action from the settings
    for con, target, dur, act in itertools.product(("curl", "nopid", "appimage", "snap"),
                                                   ("0", "1", "3", "5", "9"), ("0", "6", "7"),
                                                   ("0", "1", "2")):
        case("%s-defaults-t%s-d%s-a%s" % (con, target, dur, act), con,
             {"global/default_target": target, "global/default_duration": dur,
              "global/default_action": act}, {"action": "timeout"})
    # the advanced checks, alone and together, on each target
    for con in ("curl", "relative", "ipv6", "md5", "dns", "icmp", "multicast", "loopback6"):
        for checks in itertools.product((False, True), repeat=4):
            ip, port, uid, sm = checks
            tag = "".join("1" if c else "0" for c in checks)
            case("%s-checks-%s" % (con, tag), con, {"global/default_action": "1"},
                 {"what": "each", "duration": 0, "dst_ip": ip, "dst_port": port, "uid": uid,
                  "sum": sm, "action": "allow"})
    # the IP combo's entries
    for con in ("curl", "absolute", "ipv6", "relative"):
        case("%s-whatip" % con, con, {},
             {"what": 0, "what_ip": "each", "dst_ip": True, "duration": 8, "action": "deny"})
    # checks from the settings (applied whatever is visible)
    case("settings-checks", "curl",
         {"global/default_popup_advanced": "true", "global/default_popup_advanced_dstip": "true",
          "global/default_popup_advanced_uid": "true", "global/default_action": "1",
          "global/default_duration": "8"}, {"action": "timeout"})
    # names already taken, and the same rule again
    taken = [{"name": "allow-always-simple-usr-bin-curl", "action": "deny",
              "duration": "always", "type": "simple", "operand": "process.path",
              "data": "/usr/bin/curl"}]
    for i in range(3):
        taken.append(dict(taken[0], name="allow-always-simple-usr-bin-curl-%d" % i))
    case("taken", "curl", {"global/default_action": "1", "global/default_duration": "8"},
         {"action": "timeout"}, rules=taken)
    same = [{"name": "allow-always-simple-usr-bin-curl", "action": "allow",
             "duration": "always", "type": "simple", "operand": "process.path",
             "data": "/usr/bin/curl"}]
    case("exists", "curl", {"global/default_action": "1", "global/default_duration": "8"},
         {"action": "timeout"}, rules=same)
    lst = [{"name": "allow-always-list-usr-bin-curl", "action": "allow", "duration": "always",
            "type": "list", "operand": "list",
            "data": '[{"type": "simple", "operand": "dest.host", "data": "www.example.com"}, '
                    '{"type": "simple", "operand": "process.path", "data": "/usr/bin/curl"}]'}]
    case("exists-list", "curl", {"global/default_action": "1"},
         {"what": 0, "dst_ip": True, "duration": 8, "action": "allow"}, rules=lst)
    # a remote node: the uid entry has no user name
    case("remote", "curl", {}, {"what": "each", "duration": 8, "action": "allow"}, local=False)


main()
