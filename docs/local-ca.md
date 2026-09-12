# Local CA for IP HTTPS

Use this when Alfie is reached by IP address instead of a DNS name.

The CA is created by [first-time vault setup](first-time-init.md), not by a script. It is
generated in memory and its private key goes straight into the vault; it never touches disk.

```bash
./build/alfie-vault serve-init-tls ./vault <server-ip> <bind-host> <port> ./certs
```

Setup produces:

- `./certs/alfie-local-ca-cert.pem` -- install and trust this on iPhone/Mac. Public.
- `./certs/alfie-ip-cert.pem` -- server certificate carrying an IP subjectAltName.
- `./certs/alfie-ip-key.pem` -- server private key, 0600.

The CA **private** key is not in that list. It lives encrypted inside the vault, and reading it
back needs the master password, which means a human at an unlock page.

## Trust behavior

Installing the CA certificate is what makes the browser stop warning. Until then the connection
is still encrypted, but its identity is unverified -- which is why first-time setup prints a
fingerprint to compare out of band.

Trust the CA *certificate*. There is no CA private key to protect on disk any more, and the
server private key should never leave the box.

## Serving with the generated pair

```bash
./build/alfie-vault serve-unlock-tls ./vault yuki 0.0.0.0 18443 \
  ./certs/alfie-ip-cert.pem ./certs/alfie-ip-key.pem \
  account example.com yuki@example.com fill_password
```

Then open `https://<server-ip>:18443/unlock/<token>`.

## Standalone self-signed certificate

`scripts/gen-ip-cert.sh` still generates a plain self-signed IP certificate with no CA involved.
It is useful for throwaway testing only; it writes a private key to disk and browsers will warn
on every connection.
