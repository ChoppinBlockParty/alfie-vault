# Encrypted IPC design

Alfie uses two layers between the vault process and the browser worker.

## Layer 1: local transport

- Unix domain socket, not TCP.
- Runtime directory is forced to `0700`.
- Socket file is forced to `0600`.
- Server checks peer UID with `SO_PEERCRED` before serving a secret.
- One request should carry one short-lived capability token.

## Layer 2: cryptographic envelope

Even inside the Unix socket, the secret is encrypted:

1. Vault process and browser worker each generate an ephemeral X25519 keypair.
2. Both derive the same session key from X25519 shared secret + HKDF-SHA256.
3. HKDF info/AAD binds the session to:
   - one-time token
   - domain
   - action, e.g. `fill_password` or `fill_card`
4. Payload is encrypted with AES-256-GCM.
5. Receiver rejects reused `(token, nonce)` pairs.
6. Decrypted payload is returned as `SecureBuffer` and wiped by RAII.

## Secret path

```text
encrypted vault chunk
  -> C++ SecureBuffer
  -> encrypted IPC frame over Unix socket
  -> browser-worker SecureBuffer
  -> Chromium field via CDP/Playwright
  -> wipe buffers
```

No Telegram, logs, normal files, or shell argv should carry production secrets.

## Payment rule

Payment data can use the same IPC path, but with stronger policy:

- whitelist must allow the domain
- card fill needs approval
- final pay/checkout click needs a second approval
