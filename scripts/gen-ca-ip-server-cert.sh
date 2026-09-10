#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <ip-address> <output-dir> <ca-cert.pem> <ca-key.pem> [days]" >&2
  exit 2
}

IP_ADDRESS="${1:-}"
OUT_DIR="${2:-}"
CA_CERT="${3:-}"
CA_KEY="${4:-}"
DAYS="${5:-825}"

[[ -n "$IP_ADDRESS" && -n "$OUT_DIR" && -n "$CA_CERT" && -n "$CA_KEY" ]] || usage
[[ "$DAYS" =~ ^[0-9]+$ ]] || usage
[[ -f "$CA_CERT" ]] || { echo "missing CA certificate: $CA_CERT" >&2; exit 2; }
[[ -f "$CA_KEY" ]] || { echo "missing CA private key: $CA_KEY" >&2; exit 2; }

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

CONFIG="$OUT_DIR/openssl-ip-server.cnf"
CSR="$OUT_DIR/alfie-ip.csr"
CERT="$OUT_DIR/alfie-ip-cert.pem"
KEY="$OUT_DIR/alfie-ip-key.pem"
SERIAL="$OUT_DIR/alfie-local-ca.srl"

cat > "$CONFIG" <<EOF
[req]
default_bits = 3072
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
CN = $IP_ADDRESS
O = Alfie Local Server

[v3_req]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = IP:$IP_ADDRESS
EOF

umask 077
openssl req \
  -newkey rsa:3072 \
  -keyout "$KEY" \
  -out "$CSR" \
  -nodes \
  -config "$CONFIG" \
  -sha256 >/dev/null 2>&1

openssl x509 -req \
  -in "$CSR" \
  -CA "$CA_CERT" \
  -CAkey "$CA_KEY" \
  -CAcreateserial \
  -CAserial "$SERIAL" \
  -out "$CERT" \
  -days "$DAYS" \
  -sha256 \
  -extfile "$CONFIG" \
  -extensions v3_req >/dev/null 2>&1

rm -f "$CSR"
chmod 600 "$KEY"
chmod 644 "$CERT"

openssl verify -CAfile "$CA_CERT" "$CERT"
openssl x509 -in "$CERT" -noout -subject -dates -ext subjectAltName
printf 'certificate: %s\nprivate_key: %s\n' "$CERT" "$KEY"
