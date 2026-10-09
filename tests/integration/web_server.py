#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Static file server for the integration tests, over HTTPS when given a
# certificate and key.
#
# Usage: web_server.py <listen ip> <port> <directory> [<cert.pem> <key.pem>]

import functools
import http.server
import ssl
import sys


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def main():
    listen, port, directory = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    handler = functools.partial(Quiet, directory=directory)
    srv = http.server.HTTPServer((listen, port), handler)
    if len(sys.argv) == 6:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(sys.argv[4], sys.argv[5])
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
