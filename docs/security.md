# Security notes

## Why chunks

The vault does not decrypt all data at once. A lookup decrypts only one encrypted record. This reduces damage from accidental memory exposure.

## Record format

Records are `ALFIECHUNK2`: `magic + 16-byte salt + 12-byte nonce + AES-256-GCM ciphertext/tag`,
with **magic + record id + salt** bound in as GCM AAD. Binding the id is what stops a record file
being moved to another record's path -- an attacker with write access to the vault directory, but
no master password, could otherwise make an unlock hand a task the wrong credential.

`ALFIECHUNK1` records predate that binding and authenticated only the magic. They are still
readable, and a rewrite upgrades them in place (the stale V1 file is removed). Until they are
rewritten they remain swappable, so re-store anything written before this change.

Record ids also changed: the field separator in `HMAC(index_key, purpose \0 domain \0 account)`
was being dropped, because `a + "\0" + b` decays to a C string and `strlen` stops at the NUL.
Ids are now genuinely NUL-separated, and lookups fall back to the old id so existing vaults keep
resolving.

## Memory protections

`init_process_memory_protections()` runs before any secret is read. It initializes the OpenSSL
secure heap -- one arena, locked as a unit, that serves every secret allocation -- and sets
`RLIMIT_CORE` to 0. `ALFIE_VAULT_STRICT_MEMORY=1` makes both mandatory: the process refuses to
start rather than hold a master password it cannot protect. The default is best-effort.

## What is still not solved

- If the host is fully compromised while Alfie is using a credential, that credential can be read at the moment of use.
- Secrets are read from stdin, never argv. `get-account` still prints a decrypted record to
  stdout and requires `ALFIE_VAULT_ALLOW_PLAINTEXT_STDOUT=1`; it is a test fixture, not a
  delivery path.
- Password derivation uses Argon2id, not scrypt/PBKDF2.
- Each vault has a random 32-byte salt in `vault.meta`; this salt is not secret, but it makes key derivation unique per vault.
- Decrypted records should be consumed through `ChunkVault::use(...)`; this keeps plaintext inside a callback-owned `SecureBuffer` and avoids returning a long-lived plaintext `std::string`.
- `SecureBuffer`, `VaultKeys`, and passphrase buffers are move-only. Their storage is wiped by
  the allocator on free, so a container that grows does not leave a readable copy behind.
- Failed unlock attempts are neither rate-limited nor audit-logged within a token's TTL window.
- The production path must use a short-lived HTTPS unlock server and stdin/socket memory buffers.

## First-time setup

Creating the vault is a separate one-time act: it fixes the login and master password, generates
the local CA in memory, and stores the CA private key inside the vault. The setup page is served
under a one-off certificate whose fingerprint is printed on the box's terminal for out-of-band
comparison, and it is styled red so it cannot be mistaken for a routine unlock.

The setup server refuses to start once a vault exists, and `init_vault` throws if `vault.meta` is
present, so an init link can never re-key a live vault. See `docs/first-time-init.md`.

The residual risk is phishing, not forgery: an attacker who stands up their own empty vault and
persuades you to type your master password into its setup page has harvested that password. The
fingerprint comparison is the defense; the red styling only makes the page hard to confuse.

## Export

Export only encrypted files:

```bash
tar -czf alfie-vault-backup.tgz vault/
```

Include `vault.meta`; records cannot be found or decrypted without the vault salt. No plaintext export command should exist.

## Socket hardening

- Unix IPC requires a trusted absolute path without symlinks, a UID-owned `0700` directory,
  and a `0600` socket. Existing entries are never replaced; stale sockets require explicit cleanup.
- `accept_secure_unix_socket` verifies the peer UID. IPC descriptors are nonblocking and
  close-on-exec; callers manage readiness and lifetime. Browser-worker delivery remains unwired.
- HTTPS network I/O has a 10-second deadline, 16 KiB header limit, and 1 MiB request limit.
  Malformed or disconnected clients are isolated; request buffers are wiped on exit.
  TLS session resumption and early data are disabled.
- Use physical paths on macOS. Avoid concurrent fork/exec with the non-atomic CLOEXEC fallback.
  Same-UID processes remain trusted; repeated connections can still deny service. Linux-specific
  branches need deployment testing.

References: [Unix socket permissions and credentials](https://www.man7.org/linux/man-pages/man7/unix.7.html),
[OpenSSL nonblocking TLS](https://docs.openssl.org/3.5/man7/ossl-guide-tls-client-non-block/).
