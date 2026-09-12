# HTTPS unlock server

The web unlock layer. It is HTTPS-only by design: every page carries the vault master password,
so there is no plaintext-HTTP server in this build.

## Pages

| Page | Minted by | Asks for | Result |
|---|---|---|---|
| `/init/<token>` | `serve-init-tls` | login, password, confirm | Creates the vault and the CA. Red page, shown once. See [first-time-init.md](first-time-init.md). |
| `/unlock/<token>` | `serve-unlock-tls` | login, password | Decrypts one record for one task |
| `/store/<token>` | `serve-store-tls` | login, password, secret JSON | Encrypts one new record |

A token is minted for exactly one mode and is rejected on any other path. Anything else is 404.

## Page rendering

The pages are [Mustache](https://mustache.github.io/) templates under `templates/`, rendered with
the single-header renderer in `third_party/mustache/`:

| Template | Page |
|---|---|
| `unlock_page.mustache` | the form, in all three modes |
| `page_style.mustache` | the shared `<style>` block, pulled in as `{{>page_style}}` |
| `init_complete.mustache` | the 201 page after first-time setup |
| `outcome.mustache` | the page that closes a successful unlock or store |

`scripts/embed_templates.cmake` compiles them into the binary at build time as
`build/generated/templates.h`; nothing is read from disk while serving. That is deliberate. These
pages ask for the master password, and the setup page is what the operator compares a certificate
fingerprint against, so the markup should be no easier to alter than the executable. Editing a
template and rebuilding is the supported way to change a page.

Mustache escapes `{{value}}`, so every value interpolated into a page is HTML-escaped by
construction. The unescaped forms `{{{value}}}` and `{{&value}}` fail `make style-check`.

## What it does

1. Alfie creates a one-time token for one requested credential.
2. The server prints a link like:

```text
https://127.0.0.1:18443/unlock/<token>
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
./alfie-vault serve-store-tls ./vault yuki 127.0.0.1 18443 cert.pem key.pem account example.com yuki@example.com store_secret
```

The page asks for:

- vault login
- vault master password
- secret JSON value

After submit, the server encrypts the value into the vault chunk and returns only `Stored`; it does not echo the secret.

## Current command

```bash
./build/alfie-vault serve-unlock-tls ./vault yuki 127.0.0.1 18443 cert.pem key.pem account example.com yuki@example.com fill_password
```

## Current limitation

TLS is implemented with OpenSSL at TLS 1.3 minimum and needs a PEM certificate and private key.
[First-time setup](first-time-init.md) produces both, signed by the CA it stores in the vault:

```bash
./build/alfie-vault serve-unlock-tls ./vault yuki 127.0.0.1 18443 \
  ./certs/alfie-ip-cert.pem ./certs/alfie-ip-key.pem \
  account example.com yuki@example.com fill_password
```

The server certificate carries an IP subjectAltName. Browsers trust it only after the CA
certificate from setup is installed and trusted on the device; the connection is encrypted
either way, but identity trust is private rather than public-CA trusted. A public DNS name plus
a real certificate (Caddy, nginx, Let's Encrypt) is the alternative.

The setup server is the one exception: it serves under a one-off in-memory certificate, verified
by comparing its fingerprint with the value printed on the box's terminal.

## Next integration

Replace the temporary metadata-only delivery in `UnlockService::handleSubmit` with the encrypted Unix-socket IPC browser-worker delivery from `ipc_crypto.h` and `ipc_transport.h`.
