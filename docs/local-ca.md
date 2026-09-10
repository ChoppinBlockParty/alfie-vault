# Local CA for IP HTTPS

Use this when Alfie is accessed by IP address instead of a DNS name.

## Create CA

```bash
./scripts/gen-local-ca.sh ./certs/ca "Alfie Local CA"
```

Outputs:

- `./certs/ca/alfie-local-ca-cert.pem` — install/trust this on iPhone/Mac
- `./certs/ca/alfie-local-ca-key.pem` — keep private; do not install on devices

## Create IP server certificate signed by CA

```bash
./scripts/gen-ca-ip-server-cert.sh <server-ip> ./certs/server \
  ./certs/ca/alfie-local-ca-cert.pem \
  ./certs/ca/alfie-local-ca-key.pem
```

Outputs:

- `./certs/server/alfie-ip-cert.pem`
- `./certs/server/alfie-ip-key.pem`

Run Alfie TLS with those files:

```bash
./build/alfie-vault serve-unlock-tls ./vault slava 0.0.0.0 18443 \
  ./certs/server/alfie-ip-cert.pem ./certs/server/alfie-ip-key.pem \
  account example.com slava@example.com fill_password
```

Then open:

```text
https://<server-ip>:18443/unlock/<token>
```

## Trust behavior

This encrypts the HTTPS connection. iPhone/Mac will trust it only after the CA certificate is installed and enabled as trusted.

Trust the CA certificate, not the server private key. Keep both private keys off chat and out of backups unless encrypted.

## Store CA private key into vault, then remove it from disk

Preferred flow:

```bash
./scripts/start-ca-key-store-link.sh <server-ip> ./vault slava 0.0.0.0 18443 ./private/ca-setup
```

It will:

1. generate the local CA
2. generate the IP HTTPS server certificate
3. print the CA certificate path to install/trust on iPhone/Mac
4. print a one-time HTTPS `/store-file/<token>` link
5. after Slava enters vault login + master password, encrypt the CA private key into the vault
6. wipe and remove the plaintext CA private key file from disk

The CA certificate is public and can be shared. The CA private key must never be sent in chat.
