#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <server-ip> <vault-dir> <login> <bind-host> <port> <work-dir>" >&2
  exit 2
}

SERVER_IP="${1:-}"
VAULT_DIR="${2:-}"
LOGIN="${3:-}"
BIND_HOST="${4:-}"
PORT="${5:-}"
WORK_DIR="${6:-}"

[[ -n "$SERVER_IP" && -n "$VAULT_DIR" && -n "$LOGIN" && -n "$BIND_HOST" && -n "$PORT" && -n "$WORK_DIR" ]] || usage

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CA_DIR="$WORK_DIR/ca"
SERVER_DIR="$WORK_DIR/server"

"$ROOT_DIR/scripts/gen-local-ca.sh" "$CA_DIR" "Alfie Local CA"
"$ROOT_DIR/scripts/gen-ca-ip-server-cert.sh" "$SERVER_IP" "$SERVER_DIR" \
  "$CA_DIR/alfie-local-ca-cert.pem" "$CA_DIR/alfie-local-ca-key.pem"

printf '\nTrust this CA certificate on iPhone/Mac:\n%s\n\n' "$CA_DIR/alfie-local-ca-cert.pem"
printf 'Starting one-time vault unlock link to store CA private key, then wipe/remove source key.\n'

exec "$ROOT_DIR/build/alfie-vault" serve-store-file-tls "$VAULT_DIR" "$LOGIN" "$BIND_HOST" "$PORT" \
  "$SERVER_DIR/alfie-ip-cert.pem" "$SERVER_DIR/alfie-ip-key.pem" \
  secret-file alfie.local.ca alfie-local-ca-key.pem store_ca_key \
  "$CA_DIR/alfie-local-ca-key.pem"
