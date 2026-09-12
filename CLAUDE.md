# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`alfie-vault` is a C++20 encrypted chunk vault for Alfie's credentials and card details, plus the
local web/IPC delivery paths that hand a secret to a browser worker without ever printing it.

**Primary use case — human-unlocked secrets on a remote box.** The vault runs on a remote box
(server/VPS) whose automation needs credentials but must not hold them. There is deliberately **no
unattended unlock path**: when a task needs a credential, the vault mints a one-time, TTL-bound
HTTPS link scoped to exactly one record, a human opens it from a phone or laptop and enters the
vault login + master password, one chunk is decrypted for that one task and wiped, and the link is
consumed. The secret value is never rendered on the page.

Two properties follow, and every change should preserve them:

- **The human step is the authorization.** Anything that lets the box unlock a record without a
  person at the HTTPS page (a stored master password, a daemon that holds derived keys, a reusable
  token, a longer default TTL) removes the security model, not just a step. Don't add one.
- **Brief window, one record.** A master password should exist in memory only for the span of a
  single authorized unlock, and one unlock should expose one record — never the whole vault.

## Build and test

CMake + Ninja. The `Makefile` is a thin wrapper and is the shortest path:

```bash
make all          # configure + build into build/
make test         # build, then ctest --output-on-failure
make format       # clang-format -i over src/ and tests/
make format-check # fails on unformatted code
make tidy         # clang-tidy against build/compile_commands.json
make clean
```

Raw equivalent (see `docs/build.md`):

```bash
cmake -S . -B build -G Ninja -DCMAKE_MAKE_PROGRAM=$PWD/third_party/ninja/usr/bin/ninja
cmake --build build
ctest --test-dir build --output-on-failure
```

Run a single test: `ctest --test-dir build -R vault --output-on-failure`, or invoke the binary
directly (`./build/test_vault`). CTest names: `vault`, `ipc_crypto`, `ipc_transport`,
`http_unlock`, `https_smoke`, `gen_ip_cert`, `gen_local_ca`, `gen_ca_ip_server_cert`.

### Toolchain caveat

This repo was developed on a Linux x86_64 box without root package-install permission, so
dependencies are vendored under `third_party/` and hardcoded in `CMakeLists.txt` for that platform:

- `third_party/argon2/usr/lib/x86_64-linux-gnu` (checked in), `third_party/libssl-dev/usr/include`
- `third_party/ninja/` and `third_party/clang-tools/` are **gitignored** — the build, `format`, and
  `tidy` targets all fail until those local tool packages are extracted there.

On a different platform (e.g. macOS/arm64) the vendored paths do not apply; expect to adjust
`CMakeLists.txt`'s `find_library`/include paths rather than assuming the build is broken.

## Architecture

`src/` builds one static lib (`alfie_vault_core`) plus a thin CLI (`src/main.cpp`). Four layers:

**1. `vault.{hpp,cpp}` — the chunk vault.** A vault is a *directory of independently encrypted
records*, never one decrypted blob. `vault.meta` (`ALFIEVAULT1` + random 32-byte salt + Argon2id
cost params) is created on first write; Argon2id (m=64 MiB, t=3, p=1) over that salt derives a
64-byte secret split into an **index key** and a **record key**. The record path is
`records/<id[0:2]>/<id[2:4]>/<id>.enc` where `id = HMAC-SHA256(index_key, purpose \0
normalize_domain(domain) \0 account)` — so domains and usernames never appear in filenames. Record
file layout is `ALFIECHUNK1\n` magic (also used as GCM AAD) + 16-byte salt (reserved, unused today)
+ 12-byte nonce + AES-256-GCM ciphertext/tag.

`SecureBuffer` is the memory discipline: move-only, best-effort `mlock` + `MADV_DONTDUMP`, wiped
with `OPENSSL_cleanse` in the destructor. `VaultKeys` is move-only for the same reason, and
`derive_keys` wipes the passphrase buffer as soon as Argon2id returns.

**2. `ipc_crypto.{hpp,cpp}` — the encrypted envelope.** Ephemeral X25519 → HKDF-SHA256 session key;
`IpcRequestContext{token, domain, action}` is bound as HKDF info and GCM AAD, so a frame is only
valid for the one token/domain/action it was minted for. `ReplayGuard` rejects reused
`(token, nonce)` pairs. Decrypted payloads come back as `SecureBuffer`.

**3. `ipc_transport.{hpp,cpp}` — the socket guard.** Unix domain socket only: `0700` runtime dir,
`0600` socket, peer UID verified via `SO_PEERCRED`. Deliberately separate from the crypto layer.

**4. `http_unlock.{hpp,cpp}` — the one-time web unlock/store server.** This is the layer that
implements the primary use case above. Hand-rolled HTTP parsing and a small OpenSSL TLS server (no
framework). `UnlockService` mints single-use, TTL-bound tokens in
three modes — unlock (`/unlock/<token>`), store a pasted secret (`/store/<token>`), and store a file
(`/store-file/<token>`, used to move a CA private key into the vault and wipe it from disk). A token
is checked for `used`, mode match, and expiry on both GET and POST, and marked used after submit.
The pages are mobile-friendly inline HTML. `UnlockService::handle_submit` currently records only
metadata in `last_delivery_` (token/domain/account/action/secret size) — wiring it to the encrypted
IPC layer above is the intended next step.

## Conventions and constraints

- **Never widen the plaintext window.** Prefer `ChunkVault::use(...)` (callback receives a
  `SecureBuffer`, wiped on return) over `get()`, which returns a long-lived `std::string`. Nothing
  should log, echo, or return a secret value; the unlock pages report success only.
- **Keep the unlock human-gated.** Plain-HTTP mode (`serve-unlock`/`serve-store`) is
  localhost-development only; a remote box must use the TLS variants, which on an IP-only host means
  the local-CA flow in `docs/local-ca.md`. Tokens are single-use and TTL-bound (`UnlockRequestSpec`
  defaults to 300s) — treat both as load-bearing.
- **No production secrets through argv.** The `put-account`/`get-account` CLI subcommands take a
  passphrase as an argument and exist for smoke tests only — argv is visible OS-wide. New
  functionality belongs on the HTTPS/stdin/socket path.
- `docs/best-practices.md` holds the standards-backed rationale plus a live "must improve next"
  list (SecureBuffer-first APIs, OpenSSL secure heap, fail-closed mlock, `RLIMIT_CORE`, corruption
  fuzz tests); consult it before changing crypto or memory handling.
- Style is Google C++ via `.clang-format` (100 cols, left pointers) with project naming:
  `lower_case` functions/variables, `CamelCase` types, trailing `_` on private members. All code is
  in `namespace alfie`. Crypto/auth failures throw `alfie::CryptoError`.
- Tests are plain `assert`-based `main()` binaries (no framework) for C++, and standalone Python
  scripts driving the shell scripts and a real TLS server for the integration tests. `openssl` and
  `python3` must be on PATH for those.
- `scripts/*.sh` are `set -euo pipefail` bash helpers for the local-CA/IP-certificate flow; they
  enforce `0700` dirs and `0600` private keys, which the Python tests assert.
