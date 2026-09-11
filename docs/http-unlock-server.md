# HTTP unlock server

This is the first simple web unlock layer.

## What it does

1. Alfie creates a one-time token for one requested credential.
2. The server prints a link like:

```text
http://127.0.0.1:18080/unlock/<token>
```

3. Yuki opens the link and enters:
   - vault login
   - vault master password
4. The server checks the login.
5. The server unlocks exactly one vault chunk.
6. The HTTP response says only that unlock succeeded.
7. The final website password/card value is not shown in the page.
8. The token is consumed and cannot be reused.

## Store a new secret via web link

For secrets that should not go through Telegram, Alfie creates a one-time store link:

```bash
./alfie-vault serve-store ./vault yuki 127.0.0.1 18080 account example.com yuki@example.com store_secret
```

The page asks for:

- vault login
- vault master password
- secret JSON value

After submit, the server encrypts the value into the vault chunk and returns only `Stored`; it does not echo the secret.

## Current command

```bash
./alfie-vault serve-unlock ./vault yuki 127.0.0.1 18080 account example.com yuki@example.com fill_password
```

TLS variants:

```bash
./build/alfie-vault serve-unlock-tls ./vault yuki 127.0.0.1 18443 cert.pem key.pem account example.com yuki@example.com fill_password
./build/alfie-vault serve-store-tls ./vault yuki 127.0.0.1 18443 cert.pem key.pem account example.com yuki@example.com store_secret
```

## Current limitation

Plain HTTP mode is local-development only. Do not expose it outside localhost.

TLS server mode is implemented with OpenSSL and requires a PEM certificate and private key. Production should use a real certificate, e.g. via Caddy/nginx reverse proxy or Let's Encrypt.

If there is no DNS name, generate a local CA and an IP-address server certificate signed by that CA:

```bash
./scripts/gen-local-ca.sh ./certs/ca "Alfie Local CA"
./scripts/gen-ca-ip-server-cert.sh 127.0.0.1 ./certs/server \
  ./certs/ca/alfie-local-ca-cert.pem ./certs/ca/alfie-local-ca-key.pem
./build/alfie-vault serve-unlock-tls ./vault yuki 127.0.0.1 18443 \
  ./certs/server/alfie-ip-cert.pem ./certs/server/alfie-ip-key.pem \
  account example.com yuki@example.com fill_password
```

The server certificate includes an IP Subject Alternative Name. Browsers will trust it only after Yuki installs and trusts `alfie-local-ca-cert.pem` on the device. The connection is encrypted, but identity trust is private/manual instead of public-CA trusted.

The CLI still exists only for smoke testing. Real production secrets must not be passed through argv.

## Next integration

Replace the temporary metadata-only delivery in `UnlockService::handle_submit` with the encrypted Unix-socket IPC browser-worker delivery from `ipc_crypto.hpp` and `ipc_transport.hpp`.
