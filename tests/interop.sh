#!/bin/bash
# Interop tests against OpenSSL's s_server / s_client.
# usage: tests/interop.sh [filter]   (run from the repo root after make)
# Each test prints PASS/FAIL; the exit status is the number of failures.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$WORK"' EXIT
FILTER=${1:-}
FAILS=0
PORT=$(( 20000 + RANDOM % 20000 ))

cd "$WORK"
openssl req -x509 -newkey rsa:2048 -sha1 -nodes -keyout key.pem -out cert.pem \
  -subj /CN=localhost -days 30 2>/dev/null
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs8 -topk8 -v1 PBE-MD5-DES -in key.pem -outform DER -out key.pkcs8 \
  -passout pass:password -provider legacy -provider default 2>/dev/null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout ec-key.pem -out ec-cert.pem -sha256 -subj /CN=localhost -days 30 2>/dev/null
# client certificate signed by a private root
openssl req -x509 -newkey rsa:2048 -sha1 -nodes -keyout root-key.pem -out root-cert.pem \
  -subj /CN=Root -days 30 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout client-key.pem -out client.csr \
  -subj /CN=Client 2>/dev/null
openssl x509 -req -in client.csr -CA root-cert.pem -CAkey root-key.pem -sha1 \
  -set_serial 2 -days 30 -out client-cert.pem 2>/dev/null
mkdir client && openssl x509 -in client-cert.pem -outform DER -out client/cert.der \
  && openssl rsa -in client-key.pem -traditional -outform DER -out client/key.der 2>/dev/null

next_port() { PORT=$(( PORT + 1 )); }
wanted() { [[ -z "$FILTER" || "$1" == *"$FILTER"* ]]; }
report() { # name ok log...
  if [ "$2" = 1 ]; then echo "PASS $1"; else echo "FAIL $1"; FAILS=$(( FAILS + 1 ));
    shift 2; for f in "$@"; do echo "  --- $f"; tail -5 "$f" | sed 's/^/  /'; done; fi
}

# client <name> <client binary + args...> -- <s_server args...>
client() {
  local name=$1; shift
  local cargs=() sargs=()
  while [ "$1" != "--" ]; do cargs+=("$1"); shift; done; shift
  sargs=("$@")
  wanted "$name" || return 0
  next_port
  openssl s_server -accept $PORT -www "${sargs[@]}" > s.log 2>&1 &
  local sp=$!
  sleep 0.5
  (cd "${CLIENT_DIR:-.}" && timeout 60 "${cargs[0]}" "${cargs[@]:1}" https://localhost:$PORT/) > c.log 2>&1
  kill $sp 2>/dev/null; wait $sp 2>/dev/null
  if [[ "$name" == reject-* ]]; then
    grep -q "Rejected server certificate" c.log && report "$name" 1 || report "$name" 0 c.log s.log
  else
    grep -q "HTTP/1.0 200 ok" c.log && report "$name" 1 || report "$name" 0 c.log s.log
  fi
}

# server <name> <server binary> -- <s_client args...>
server() {
  local name=$1; shift
  local sargs=()
  while [ "$1" != "--" ]; do sargs+=("$1"); shift; done; shift
  wanted "$name" || return 0
  next_port
  "${sargs[0]}" $PORT "${sargs[@]:1}" > w.log 2>&1 &
  local wp=$!
  sleep 0.5
  printf 'GET / HTTP/1.0\r\n\r\n' | timeout 60 openssl s_client -connect localhost:$PORT \
    -ign_eof "$@" > sc.log 2>&1
  kill $wp 2>/dev/null; wait $wp 2>/dev/null
  grep -q "HTTP/1.[01] 200" sc.log && report "$name" 1 || report "$name" 0 sc.log w.log
}

S0='@SECLEVEL=0'
B=$ROOT
client tls10-rsa-aes128        $B/https -C $WORK/cert.pem -V 1.0 -c 2f   -- -tls1   -cert cert.pem -key key.pem -cipher "AES128-SHA:$S0"
client tls10-dhe-rsa           $B/https -C $WORK/cert.pem -V 1.0 -c 33   -- -tls1   -cert cert.pem -key key.pem -cipher "DHE-RSA-AES128-SHA:$S0"
client tls10-ecdhe-rsa         $B/https -C $WORK/cert.pem -V 1.0 -c c013 -- -tls1   -cert cert.pem -key key.pem -cipher "ECDHE-RSA-AES128-SHA:$S0"
client tls10-ecdhe-ecdsa       $B/https -C $WORK/ec-cert.pem -V 1.0 -c c009 -- -tls1   -cert ec-cert.pem -key ec-key.pem -cipher "ECDHE-ECDSA-AES128-SHA:$S0"
client tls12-rsa-aes128        $B/https -C $WORK/cert.pem -V 1.2 -c 2f   -- -tls1_2 -cert cert.pem -key key.pem -cipher "AES128-SHA:$S0"
client tls12-rsa-aes256        $B/https -C $WORK/cert.pem -V 1.2 -c 35   -- -tls1_2 -cert cert.pem -key key.pem -cipher "AES256-SHA:$S0"
client tls12-rsa-gcm           $B/https -C $WORK/cert.pem -V 1.2 -c 9c   -- -tls1_2 -cert cert.pem -key key.pem -cipher "AES128-GCM-SHA256:$S0"
client tls12-dhe-rsa           $B/https -C $WORK/cert.pem -V 1.2 -c 33   -- -tls1_2 -cert cert.pem -key key.pem -cipher "DHE-RSA-AES128-SHA:$S0"
client tls12-ecdhe-rsa         $B/https -C $WORK/cert.pem -V 1.2 -c c013 -- -tls1_2 -cert cert.pem -key key.pem -cipher "ECDHE-RSA-AES128-SHA:$S0"
client tls12-ecdhe-ecdsa       $B/https -C $WORK/ec-cert.pem -V 1.2 -c c009 -- -tls1_2 -cert ec-cert.pem -key ec-key.pem -cipher "ECDHE-ECDSA-AES128-SHA:$S0"
client tls12-ecdhe-rsa-gcm     $B/https -C $WORK/cert.pem -V 1.2 -c c02f -- -tls1_2 -cert cert.pem -key key.pem -cipher "ECDHE-RSA-AES128-GCM-SHA256:$S0"
client tls12-ecdhe-ecdsa-gcm   $B/https -C $WORK/ec-cert.pem -V 1.2 -c c02b -- -tls1_2 -cert ec-cert.pem -key ec-key.pem -cipher "ECDHE-ECDSA-AES128-GCM-SHA256:$S0"
client tls12-ecdhe-p384        $B/https -C $WORK/cert.pem -V 1.2 -c c02f -- -tls1_2 -cert cert.pem -key key.pem -cipher "ECDHE-RSA-AES128-GCM-SHA256:$S0" -groups P-384
CLIENT_DIR=client client tls12-client-auth $B/https -C $WORK/cert.pem -V 1.2 -c 2f -- -tls1_2 -cert cert.pem -key key.pem \
  -cipher "AES128-SHA:$S0" -Verify 1 -CAfile root-cert.pem
client reject-untrusted        $B/https -C $WORK/root-cert.pem -- -cert cert.pem -key key.pem -cipher "ALL:$S0"
server tls10-server            $B/ssl_webserver   -- -tls1   -cipher "AES128-SHA:$S0"
server tls12-server-cbc        $B/ssl_webserver -- -tls1_2 -cipher "AES128-SHA:$S0"
client tls11-rsa-aes128        $B/https -C $WORK/cert.pem -V 1.1 -c 2f -- -tls1_1 -cert cert.pem -key key.pem -cipher "AES128-SHA:$S0"
client negotiate-default       $B/https -C $WORK/cert.pem -- -cert cert.pem -key key.pem -cipher "ALL:$S0"
server tls11-server            $B/ssl_webserver -- -tls1_1 -cipher "AES128-SHA:$S0"
server tls12-server-ecdhe      $B/ssl_webserver -- -tls1_2 -cipher "ECDHE-RSA-AES128-GCM-SHA256:$S0"
server tls10-server-ecdhe      $B/ssl_webserver -- -tls1 -cipher "ECDHE-RSA-AES128-SHA:$S0"
server server-pem-default      $B/ssl_webserver -cert $WORK/cert.pem -key $WORK/key.pem -- -cipher "ALL:$S0"
server tls12-server-gcm        $B/ssl_webserver -- -tls1_2 -cipher "AES128-GCM-SHA256:$S0"

echo "$FAILS failure(s)"
exit $FAILS
