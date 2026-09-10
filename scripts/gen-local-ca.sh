#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <output-dir> [common-name] [days]" >&2
  exit 2
}

OUT_DIR="${1:-}"
COMMON_NAME="${2:-Alfie Local CA}"
DAYS="${3:-3650}"

[[ -n "$OUT_DIR" ]] || usage
[[ "$DAYS" =~ ^[0-9]+$ ]] || usage

mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"

CONFIG="$OUT_DIR/openssl-ca.cnf"
CA_CERT="$OUT_DIR/alfie-local-ca-cert.pem"
CA_KEY="$OUT_DIR/alfie-local-ca-key.pem"

cat > "$CONFIG" <<EOF
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_ca

[dn]
CN = $COMMON_NAME
O = Alfie Local Trust

[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

umask 077
openssl req -x509 \
  -newkey rsa:4096 \
  -keyout "$CA_KEY" \
  -out "$CA_CERT" \
  -days "$DAYS" \
  -nodes \
  -config "$CONFIG" \
  -sha256 >/dev/null 2>&1

chmod 600 "$CA_KEY"
chmod 644 "$CA_CERT"

openssl x509 -in "$CA_CERT" -noout -subject -dates -ext basicConstraints -ext keyUsage
printf 'ca_certificate: %s\nca_private_key: %s\n' "$CA_CERT" "$CA_KEY"
printf 'Install/trust only the CA certificate on iPhone/Mac. Keep the CA private key offline/private.\n'
