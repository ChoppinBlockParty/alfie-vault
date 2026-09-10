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
