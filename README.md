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

Before any of that, the vault has to exist. Creating it is a separate one-time act that sets the
login and master password and generates the local CA: see
[first-time setup](docs/first-time-init.md).

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

First-time setup creates `vault.meta` with:

- format marker: `ALFIEVAULT2`
- random vault salt
- Argon2id cost parameters
- login verifier and master-password verifier

The salt is not secret. It makes two vaults with the same master password derive different keys
and record IDs.

The verifiers are HMACs under the master key, so neither the login nor the password can be
recovered from them. They let an unlock tell "wrong master password" apart from "no such
record" — without them, a typo at store time silently writes a record that can never be found
again. Legacy `ALFIEVAULT1` vaults have no verifiers and fall back to the login given at server
start.

Nothing creates a vault implicitly. Reads and writes against an uninitialized directory fail
rather than bringing an empty vault into existence.

## First-time setup

The vault does not exist until it is created, and creating it is deliberately its own step:

```bash
./build/alfie-vault serve-init-tls ./vault <server-ip> <bind-host> <port> ./certs
```

It refuses to start if a vault already exists, serves a red one-time `/init/<token>` page under a
**one-off in-memory certificate**, and prints that certificate's SHA-256 fingerprint for you to
compare against what the browser shows — the setup page is the only page that asks for the
password protecting everything, and the only one reached by clicking through a warning, so it is
verified out of band rather than by looks alone.

On submit it creates the vault, generates the CA in memory, stores the CA private key inside the
vault, writes the CA certificate plus a CA-signed server certificate/key, and exits. The CA
private key never touches disk. Details in [docs/first-time-init.md](docs/first-time-init.md).

## Encrypted IPC

Vault-to-browser-worker handoff uses two layers:

- private Unix domain socket: `0700` runtime dir, `0600` socket, peer UID checked with `SO_PEERCRED`
- encrypted payload: ephemeral X25519, HKDF-SHA256, AES-256-GCM, token/domain/action bound as AAD, nonce replay rejection

See `docs/encrypted-ipc.md`.

## HTTPS unlock server

The unlock server is HTTPS-only; there is no plaintext-HTTP server in this build, because the
page carries the vault master password.

```bash
./alfie-vault serve-unlock-tls ./vault yuki 127.0.0.1 18443 cert.pem key.pem account example.com yuki@example.com fill_password
```

It creates a one-time `/unlock/<token>` page. The page accepts login + vault password, unlocks one chunk, never displays the final secret, then consumes the token.

It can also create a one-time `/store/<token>` page for adding new secrets without Telegram:

```bash
./alfie-vault serve-store-tls ./vault yuki 127.0.0.1 18443 cert.pem key.pem account example.com yuki@example.com store_secret
```

The store page accepts login + vault password + secret JSON, encrypts the new chunk, and never echoes the secret.

Both certificates come from first-time setup, which signs them with the CA it stores in the
vault. Browsers trust them only after `alfie-local-ca-cert.pem` is installed and trusted on the
device.

See `docs/first-time-init.md`, `docs/http-unlock-server.md` and `docs/local-ca.md`.

## C++ style

Use CMake with Ninja as the main build system. C++ formatting/tidying is configured with `.clang-format` and `.clang-tidy`; see `docs/cpp-style.md`.

## Current CLI

```bash
# Secrets go in on stdin -- argv is visible process-wide. First line is the master password;
# for put-account the rest of stdin is the record payload.
printf 'master-pass\n{"login":"yuki@example.com","secret":"..."}\n' \
  | ./alfie-vault put-account ./vault example.com yuki@example.com

# get-account prints a decrypted record, so it is gated behind an explicit opt-in and exists
# for test fixtures only. The real read path is serve-unlock-tls.
printf 'master-pass\n' \
  | ALFIE_VAULT_ALLOW_PLAINTEXT_STDOUT=1 ./alfie-vault get-account ./vault example.com yuki@example.com
```

Next step: wire successful unlocks into encrypted Unix-socket browser-worker delivery. The CLI is smoke-test only because argv is visible to the OS.
