#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# A stand-in for the OpenSnitch UI, for the integration tests: a gRPC
# server (python grpcio, like the real UI) implementing service protocol.UI
# from proto/ui.proto. Everything it receives goes to a log, one JSON object
# per line, which tests/integration/run.sh greps.
#
#   fake_ui.py <pb dir> <socket path> <log> <control dir>
#
# <socket path> may be a TCP address ("127.0.0.1:50051"). With
# FAKE_UI_TLS="<cert>:<key>:<ca>" it listens with TLS as the real UI does
# (grpc.ssl_server_credentials: with a CA, clients must present a
# certificate it signed; ":"-separated, the CA may be empty).
#
# <pb dir> holds ui_pb2.py and ui_pb2_grpc.py (grpc_tools.protoc output).
# Files in <control dir>, read on each request:
#   ask            how AskRule answers: "allow" / "deny" (a rule on the
#                  process path and the destination port), "none" (returns
#                  None, as the real UI does on errors), "hang:<seconds>"
#                  (answers "allow" after a while)
#   duration       duration of the rules it answers (default "always")
#   ui_config      JSON returned by Subscribe as the UI's config
#   notify.json    a notification to send ({"type": N, "data": "..."}; with
#                  "sysfw": <path>, that system-fw.json goes in sysFirewall);
#                  the file is removed once sent
import json
import os
import sys
import threading
import time
import warnings
from concurrent import futures

warnings.filterwarnings("ignore")
sys.path.insert(0, sys.argv[1])

import grpc  # noqa: E402
import ui_pb2  # noqa: E402
from google.protobuf import json_format  # noqa: E402
import ui_pb2_grpc  # noqa: E402

SOCKET, LOG, CTL = sys.argv[2], sys.argv[3], sys.argv[4]
log_lock = threading.Lock()


def log(**kw):
    with log_lock, open(LOG, "a") as f:
        f.write(json.dumps(kw) + "\n")


def ctl(name, default=""):
    try:
        with open(os.path.join(CTL, name)) as f:
            return f.read().strip()
    except OSError:
        return default


class UI(ui_pb2_grpc.UIServicer):
    def Ping(self, request, context):
        s = request.stats
        log(rpc="Ping", id=request.id, version=s.daemon_version,
            connections=s.connections, events=len(s.events), rules=s.rules,
            by_executable=dict(s.by_executable))
        return ui_pb2.PingReply(id=request.id)

    def AskRule(self, request, context):
        mode = ctl("ask", "allow")
        log(rpc="AskRule", path=request.process_path, dst_port=request.dst_port,
            protocol=request.protocol, pid=request.process_id, mode=mode)
        if mode.startswith("hang:"):
            time.sleep(float(mode[5:]))
            mode = "allow"
        if mode == "none":
            return None
        op = ui_pb2.Operator(type="list", operand="list", list=[
            ui_pb2.Operator(type="simple", operand="process.path",
                            data=request.process_path),
            ui_pb2.Operator(type="simple", operand="dest.port",
                            data=str(request.dst_port)),
        ])
        return ui_pb2.Rule(
            name="%s-%d" % (mode, request.dst_port), enabled=True, action=mode,
            duration=ctl("duration", "always"), operator=op)

    def Subscribe(self, request, context):
        log(rpc="Subscribe", name=request.name, version=request.version,
            config=request.config, rules=[r.name for r in request.rules],
            fw_running=request.isFirewallRunning, log_level=request.logLevel,
            sysfw=json_format.MessageToDict(request.systemFirewall,
                                            preserving_proto_field_name=True)
            if request.HasField("systemFirewall") else None)
        return ui_pb2.ClientConfig(
            name=request.name, version=request.version,
            config=ctl("ui_config", request.config), rules=request.rules)

    def Notifications(self, request_iterator, context):
        log(rpc="Notifications", event="open")
        done = threading.Event()

        def reader():
            try:
                for reply in request_iterator:
                    log(rpc="NotificationReply", id=reply.id, code=reply.code,
                        data=reply.data)
            except Exception as e:  # the daemon went away
                log(rpc="Notifications", event="error", error=str(e))
            done.set()

        threading.Thread(target=reader, daemon=True).start()
        nid = 100
        while not done.is_set() and context.is_active():
            path = os.path.join(CTL, "notify.json")
            if os.path.exists(path):
                with open(path) as f:
                    n = json.load(f)
                os.unlink(path)
                nid += 1
                log(rpc="Notification", id=nid, type=n["type"])
                ntf = ui_pb2.Notification(id=nid, type=n["type"],
                                          data=n.get("data", ""))
                if "sysfw" in n:
                    with open(n["sysfw"]) as f:
                        json_format.Parse(f.read(), ntf.sysFirewall,
                                          ignore_unknown_fields=True)
                yield ntf
            time.sleep(0.1)
        log(rpc="Notifications", event="closed")

    def PostAlert(self, request, context):
        log(rpc="PostAlert", type=request.type, text=request.text)
        return ui_pb2.MsgResponse(id=0)


def main():
    # Same server options as the real UI (ui/bin/opensnitch-ui).
    opts = [
        ("grpc.keepalive_time_ms", 5000),
        ("grpc.keepalive_timeout_ms", 20000),
        ("grpc.keepalive_permit_without_calls", True),
    ]
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8), options=opts)
    ui_pb2_grpc.add_UIServicer_to_server(UI(), server)
    addr = SOCKET if ":" in SOCKET else "unix:" + SOCKET
    tls = os.environ.get("FAKE_UI_TLS")
    if tls:
        cert, key, ca = tls.split(":")
        rd = lambda p: open(p, "rb").read() if p else None  # noqa: E731
        creds = grpc.ssl_server_credentials(((rd(key), rd(cert)),), rd(ca), bool(ca))
        server.add_secure_port(addr, creds)
    else:
        server.add_insecure_port(addr)
    server.start()
    log(rpc="started")
    server.wait_for_termination()


if __name__ == "__main__":
    main()
