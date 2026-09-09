# Alfie Vault C++

C++ encrypted chunk vault for Alfie credentials and card details.

## Design

- Runtime vault is a directory of small encrypted records, not one big decrypted JSON.
- Record path is derived from `HMAC(index_key, purpose/domain/account)`.
- Each record is decrypted alone, used through `ChunkVault::use(...)`, then wiped.
- Export/backup can be a tarball of the encrypted vault directory.

## Crypto

- OpenSSL libcrypto.
- Key derivation: Argon2id.
- Record encryption: AES-256-GCM.
- Record IDs: HMAC-SHA256.
- Random 32-byte vault salt in `vault.meta` for Argon2id.
- Random nonce per record.

## Memory

- Secrets use `SecureBuffer`.
- `SecureBuffer` and `VaultKeys` are move-only, so secret buffers are not accidentally copied.
- Best effort `mlock` to avoid swap.
- Best effort `MADV_DONTDUMP` to avoid core dumps.
- Wipe uses `OPENSSL_cleanse`.
- Argon2id passphrase buffers are wiped immediately after key derivation.
- Prefer `ChunkVault::use(...)`; it keeps decrypted data inside a callback-owned `SecureBuffer` instead of returning a long-lived plaintext `std::string`.

## Build

```bash
make
make test
```

This repo vendors only Debian OpenSSL/Argon2 headers extracted from distro packages; it links to system `libcrypto.so.3` and local `libargon2`.

## Vault metadata

The first write creates `vault.meta` with:

- format marker: `ALFIEVAULT1`
- random vault salt
- Argon2id cost parameters

The salt is not secret. It makes two vaults with the same master password derive different keys and record IDs.

## Encrypted IPC

Vault-to-browser-worker handoff uses two layers:

- private Unix domain socket: `0700` runtime dir, `0600` socket, peer UID checked with `SO_PEERCRED`
- encrypted payload: ephemeral X25519, HKDF-SHA256, AES-256-GCM, token/domain/action bound as AAD, nonce replay rejection

See `docs/encrypted-ipc.md`.

## HTTP unlock server

Simple local HTTP unlock server is implemented:

```bash
./alfie-vault serve-unlock ./vault slava 127.0.0.1 18080 account example.com slava@example.com fill_password
```

It creates a one-time `/unlock/<token>` page. The page accepts login + vault password, unlocks one chunk, never displays the final secret, then consumes the token.

It can also create a one-time `/store/<token>` page for adding new secrets without Telegram:

```bash
./alfie-vault serve-store ./vault slava 127.0.0.1 18080 account example.com slava@example.com store_secret
```

The store page accepts login + vault password + secret JSON, encrypts the new chunk, and never echoes the secret.

See `docs/http-unlock-server.md`.

## C++ style

Use Make as the main build system. C++ formatting/tidying is configured with `.clang-format` and `.clang-tidy`; see `docs/cpp-style.md`.

## Current CLI

```bash
./alfie-vault put-account ./vault example.com slava@example.com passphrase '{"login":"slava@example.com","secret":"..."}'
./alfie-vault get-account ./vault example.com slava@example.com passphrase
```

Next step: put TLS/reverse proxy in front of the HTTP unlock server and wire successful unlocks into encrypted Unix-socket browser-worker delivery. The CLI is smoke-test only because argv is visible to the OS.
