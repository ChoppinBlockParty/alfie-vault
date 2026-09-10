#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <ip-address> <output-dir> [days]" >&2
  exit 2
}

IP_ADDRESS="${1:-}"
OUT_DIR="${2:-}"
DAYS="${3:-825}"

[[ -n "$IP_ADDRESS" && -n "$OUT_DIR" ]] || usage
[[ "$DAYS" =~ ^[0-9]+$ ]] || usage

if ! python3 - "$IP_ADDRESS" <<'PY'
import ipaddress
import sys
ipaddress.ip_address(sys.argv[1])
PY
then
  echo "invalid IP address: $IP_ADDRESS" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"

CONFIG="$OUT_DIR/openssl-ip-san.cnf"
CERT="$OUT_DIR/alfie-ip-cert.pem"
KEY="$OUT_DIR/alfie-ip-key.pem"

cat > "$CONFIG" <<EOF
[req]
default_bits = 3072
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_req

[dn]
CN = $IP_ADDRESS

[v3_req]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = IP:$IP_ADDRESS
EOF

umask 077
openssl req -x509 \
  -newkey rsa:3072 \
  -keyout "$KEY" \
  -out "$CERT" \
  -days "$DAYS" \
  -nodes \
  -config "$CONFIG" \
  -sha256 >/dev/null 2>&1
chmod 600 "$KEY"
chmod 644 "$CERT"

openssl x509 -in "$CERT" -noout -subject -dates -ext subjectAltName
printf 'certificate: %s\nprivate_key: %s\n' "$CERT" "$KEY"
