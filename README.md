# Alfie Vault C++

C++ encrypted chunk vault for Alfie credentials and card details.

## Primary use case

A secure secret vault that lives on a **remote box** (server, VPS, always-on machine), holding
credentials that automation on that box needs but must not hold permanently.

The vault stays encrypted at rest and there is no unattended unlock path. When a task needs a
credential:

1. The vault process mints a **one-time, TTL-bound HTTPS link** for exactly one record
   (purpose/domain/account/action).
2. A **human opens that link** from a phone or laptop and enters the vault login and master
   password. That human step is the authorization; nothing on the remote box can perform it.
3. Exactly one chunk is decrypted, used for that one task, and wiped. The link is consumed and
   cannot be replayed.
4. The secret value is **never shown on the page**, never logged, and never passed through argv,
   chat, or files.

So the master password is present on the remote box only for the brief window of a single
authorized task, and the blast radius of any one unlock is one record — not the whole vault.

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
cmake -S . -B build -G Ninja -DCMAKE_MAKE_PROGRAM=$PWD/third_party/ninja/usr/bin/ninja
cmake --build build
ctest --test-dir build --output-on-failure
```

This repo uses CMake with Ninja. Local tool packages are extracted under `third_party/` because this box has no root package-install permission. See `docs/build.md`.

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
./alfie-vault serve-unlock ./vault yuki 127.0.0.1 18080 account example.com yuki@example.com fill_password
```

It creates a one-time `/unlock/<token>` page. The page accepts login + vault password, unlocks one chunk, never displays the final secret, then consumes the token.

It can also create a one-time `/store/<token>` page for adding new secrets without Telegram:

```bash
./alfie-vault serve-store ./vault yuki 127.0.0.1 18080 account example.com yuki@example.com store_secret
```

The store page accepts login + vault password + secret JSON, encrypts the new chunk, and never echoes the secret.

TLS variants are also implemented:

```bash
./build/alfie-vault serve-unlock-tls ./vault yuki 127.0.0.1 18443 cert.pem key.pem account example.com yuki@example.com fill_password
./build/alfie-vault serve-store-tls ./vault yuki 127.0.0.1 18443 cert.pem key.pem account example.com yuki@example.com store_secret
```

Without DNS, generate an IP-address certificate:

```bash
./scripts/gen-local-ca.sh ./certs/ca "Alfie Local CA"
./scripts/gen-ca-ip-server-cert.sh 127.0.0.1 ./certs/server \
  ./certs/ca/alfie-local-ca-cert.pem ./certs/ca/alfie-local-ca-key.pem
```

It encrypts HTTPS traffic, but browsers trust it only after the CA certificate is installed and trusted.

See `docs/http-unlock-server.md` and `docs/local-ca.md`.

## C++ style

Use CMake with Ninja as the main build system. C++ formatting/tidying is configured with `.clang-format` and `.clang-tidy`; see `docs/cpp-style.md`.

## Current CLI

```bash
./alfie-vault put-account ./vault example.com yuki@example.com passphrase '{"login":"yuki@example.com","secret":"..."}'
./alfie-vault get-account ./vault example.com yuki@example.com passphrase
```

Next step: wire successful unlocks into encrypted Unix-socket browser-worker delivery. The CLI is smoke-test only because argv is visible to the OS.
