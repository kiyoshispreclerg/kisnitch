#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# A notification daemon (org.freedesktop.Notifications) for the tests: it
# records every Notify call as a JSON line in the file given as argument,
# and "clicks" the first action of each notification that has one
# (ActionInvoked, then NotificationClosed).
import json
import sys

import gi

gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib  # noqa: E402

XML = """
<node>
  <interface name="org.freedesktop.Notifications">
    <method name="GetCapabilities"><arg type="as" direction="out"/></method>
    <method name="Notify">
      <arg type="s" direction="in"/><arg type="u" direction="in"/>
      <arg type="s" direction="in"/><arg type="s" direction="in"/>
      <arg type="s" direction="in"/><arg type="as" direction="in"/>
      <arg type="a{sv}" direction="in"/><arg type="i" direction="in"/>
      <arg type="u" direction="out"/>
    </method>
    <method name="CloseNotification"><arg type="u" direction="in"/></method>
    <method name="GetServerInformation">
      <arg type="s" direction="out"/><arg type="s" direction="out"/>
      <arg type="s" direction="out"/><arg type="s" direction="out"/>
    </method>
    <signal name="NotificationClosed"><arg type="u"/><arg type="u"/></signal>
    <signal name="ActionInvoked"><arg type="u"/><arg type="s"/></signal>
  </interface>
</node>
"""

log = open(sys.argv[1], "a")
next_id = [0]
conn = [None]


def emit(name, args):
    conn[0].emit_signal(None, "/org/freedesktop/Notifications",
                        "org.freedesktop.Notifications", name, args)


def call(c, sender, path, iface, method, params, inv):
    if method == "GetCapabilities":
        inv.return_value(GLib.Variant("(as)", (["actions", "body"],)))
    elif method == "GetServerInformation":
        inv.return_value(GLib.Variant("(ssss)", ("fake", "kisnitch", "1", "1.2")))
    elif method == "CloseNotification":
        inv.return_value(None)
    elif method == "Notify":
        app, _, icon, summary, body, actions, hints, timeout = params.unpack()
        next_id[0] += 1
        nid = next_id[0]
        rec = {"app": app, "icon": icon, "summary": summary, "body": body,
               "actions": actions, "timeout": timeout,
               "urgency": hints.get("urgency"), "category": hints.get("category")}
        log.write(json.dumps(rec) + "\n")
        log.flush()
        inv.return_value(GLib.Variant("(u)", (nid,)))
        if actions:
            def click():
                emit("ActionInvoked", GLib.Variant("(us)", (nid, actions[0])))
                emit("NotificationClosed", GLib.Variant("(uu)", (nid, 2)))
                return False
            GLib.timeout_add(100, click)


def on_bus(c, name):
    conn[0] = c
    node = Gio.DBusNodeInfo.new_for_xml(XML)
    c.register_object("/org/freedesktop/Notifications", node.interfaces[0], call, None, None)


def on_name(c, name):
    print("ready", flush=True)


Gio.bus_own_name(Gio.BusType.SESSION, "org.freedesktop.Notifications",
                 Gio.BusNameOwnerFlags.NONE, on_bus, on_name, None)
GLib.MainLoop().run()
