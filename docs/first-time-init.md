# First-time vault setup

Creating the vault is a separate, one-time act. It fixes the login and the master password, and
it produces the local CA that every later HTTPS unlock depends on. Nothing exists before it.

```bash
./build/alfie-vault serve-init-tls ./vault <server-ip> <bind-host> <port> ./certs
```

## What it does

1. Refuses to start if `vault.meta` already exists. The setup page is unreachable whenever a
   vault exists -- not merely rejected after someone has typed a password into it.
2. Generates a **one-off TLS certificate in memory**. It is never written to disk and dies with
   the process.
3. Prints that certificate's SHA-256 fingerprint and a one-time `https://<host>:<port>/init/<token>`
   link.
4. Serves a red setup page that echoes the same fingerprint.
5. On submit: creates the vault, generates the CA **in memory**, stores the CA private key in
   the vault it just created, writes the CA certificate and a CA-signed server certificate/key.
6. Exits. The one-off certificate and the link are both dead.

## Verify the fingerprint before typing anything

No CA is trusted yet, so the browser will warn. That warning is expected exactly once, and it is
also the moment the setup page is most useful to an attacker: it is the only page that asks for
the password protecting everything, and the only one users reach by clicking through a warning.

The defense is out-of-band comparison. The fingerprint is printed on the box's own terminal --
your SSH session, a channel an attacker does not control -- and the red page shows the same
value. An attacker can serve a convincing red page; they cannot make its fingerprint match the
one printed in your terminal.

```text
==========================================================
  FIRST-TIME VAULT SETUP - this runs exactly once
==========================================================

  SHA-256: 27:57:5F:80:C4:00:BE:8D:...

setup link: https://127.0.0.1:18470/init/a1a534b3...
```

If the browser's certificate details and the page's fingerprint do not both match that line,
close the page.

## What it writes

| Path | Contents | Mode |
|---|---|---|
| `<vault>/vault.meta` | format marker, vault salt, Argon2id costs, login + password verifiers | 0600 |
| `<vault>/records/...` | the CA private key, encrypted | 0600 |
| `<out>/alfie-local-ca-cert.pem` | CA certificate -- public, install and trust this on your devices | 0644 |
| `<out>/alfie-ip-cert.pem` | server certificate for the given IP | 0644 |
| `<out>/alfie-ip-key.pem` | server private key | 0600 |

**The CA private key is never written to disk.** It is generated as an `EVP_PKEY` in memory,
PEM-encoded into a `SecureBuffer`, and encrypted straight into a vault record. The only private
key on disk is the server key, which is the boot anchor: the HTTPS server needs it to start
before any human can unlock anything.

That is a deliberate trade. A stolen server key lets someone impersonate one IP until the
certificate expires; a stolen CA key would let them mint certificates for anything your devices
trust. Only the second one lives in the vault.

## Rules the setup enforces

- **Master password minimum 12 characters.** It can never be changed, so the moment it is chosen
  is the only chance to refuse a hopeless one.
- **Typed twice.** A typo would otherwise become an unrecoverable vault.
- **Login must not be empty.**
- **One-time token**, like every other link.
- **Never re-runnable.** `init_vault` throws if the vault exists, so an init link can never
  re-key a live vault or overwrite existing records.

## After setup

Trust `alfie-local-ca-cert.pem` on the phone or laptop that will open unlock links, then serve
normal unlock sessions with the certificate pair that setup produced:

```bash
./build/alfie-vault serve-unlock-tls ./vault yuki 0.0.0.0 18443 \
  ./certs/alfie-ip-cert.pem ./certs/alfie-ip-key.pem \
  account example.com yuki@example.com fill_password
```

The CA private key stays in the vault. Reading it back requires the master password, which means
a human at an unlock page -- the same rule as every other secret.
