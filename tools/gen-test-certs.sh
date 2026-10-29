#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Regenerates the certificates of tests/fixtures/tls/ (for the TLS tests of
# daemon <-> UI): a CA, a server certificate for localhost, 127.0.0.1 and
# ::1, a client certificate, and a CA that signed nothing of the others.
# Valid for 100 years; EC P-256 keys.
set -eu
out=$(cd "$(dirname "$0")/.." && pwd)/tests/fixtures/tls
mkdir -p "$out"
cd "$out"
days=36500
key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }

for ca in ca other-ca; do
    key "$ca.key"
    openssl req -x509 -new -key "$ca.key" -days $days -subj "/CN=kisnitch test $ca" \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -out "$ca.pem"
done

sign() { # name cn extfile
    key "$1.key"
    openssl req -new -key "$1.key" -subj "/CN=$2" -out "$1.csr"
    openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days $days \
        -extfile "$3" -out "$1.pem" 2>/dev/null
    rm -f "$1.csr"
}
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\nextendedKeyUsage=serverAuth\n' > ext.cnf
sign server "kisnitch test server" ext.cnf
printf 'extendedKeyUsage=clientAuth\n' > ext.cnf
sign client "kisnitch test node" ext.cnf
rm -f ext.cnf ca.srl
echo "certificates in $out"
