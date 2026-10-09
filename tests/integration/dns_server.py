#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# A tiny authoritative DNS server for the integration tests (UDP only):
#
#   exemplo.test        A      <ip>
#   alias.exemplo.test  CNAME  exemplo.test, then A <ip>
#   anything else       NXDOMAIN; AAAA and other types: no answers
#
# Usage: dns_server.py <listen ip> <port> <answer ip>

import socket
import struct
import sys

ZONE = "exemplo.test"
ALIAS = "alias." + ZONE


def read_name(msg, off):
    labels = []
    while True:
        n = msg[off]
        off += 1
        if n == 0:
            return ".".join(labels), off
        labels.append(msg[off:off + n].decode("ascii", "replace"))
        off += n


def encode_name(name):
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\0"


def rr(name, rtype, rdata):
    return encode_name(name) + struct.pack(">HHIH", rtype, 1, 60, len(rdata)) + rdata


def answer(query, ip):
    qid, _flags, qd = struct.unpack(">HHH", query[:6])
    if qd != 1:
        return None
    qname, off = read_name(query, 12)
    qtype, _qclass = struct.unpack(">HH", query[off:off + 4])
    question = query[12:off + 4]
    name = qname.lower()
    answers = []
    rcode = 0
    if name in (ZONE, ALIAS):
        target = ZONE
        if name == ALIAS:
            answers.append(rr(ALIAS, 5, encode_name(ZONE)))
        if qtype == 1:
            answers.append(rr(target, 1, socket.inet_aton(ip)))
    else:
        rcode = 3
    flags = 0x8400 | rcode  # response, authoritative
    head = struct.pack(">HHHHHH", qid, flags, 1, len(answers), 0, 0)
    return head + question + b"".join(answers)


def main():
    listen, port, ip = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((listen, port))
    while True:
        query, peer = s.recvfrom(4096)
        try:
            resp = answer(query, ip)
        except (IndexError, struct.error):
            continue
        if resp is not None:
            s.sendto(resp, peer)


if __name__ == "__main__":
    main()
