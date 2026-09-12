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
make naming-check # enforce LLVM/Clang identifier naming
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
directly (`./build/test_vault`). CTest names: `ca`, `vault`, `ipc_crypto`, `ipc_transport`,
`corruption`, `secure_memory`, `http_unlock`, `init_smoke`, `https_smoke`, `gen_ip_cert`.

The C++ binaries are Catch2, so each one also runs a subset on its own:
`./build/test_vault --list-tests`, `./build/test_vault "[record]"` for one tag,
`./build/test_corruption "Every tag bit flip is rejected"` for one case.

### Toolchain caveat

This repo was developed on a Linux x86_64 box without root package-install permission, so
dependencies are vendored under `third_party/` and hardcoded in `CMakeLists.txt` for that platform:

- `third_party/argon2/usr/lib/x86_64-linux-gnu` (checked in), `third_party/libssl-dev/usr/include`
- `third_party/catch2/` holds the Catch2 amalgamated release and `third_party/mustache/` the
  single-header Mustache renderer (both checked in, both platform-independent).
- `third_party/ninja/` and `third_party/clang-tools/` are **gitignored**. Build helpers prefer
  those tools when available and otherwise look on PATH.

On other platforms (e.g. macOS/arm64), CMake discovers system OpenSSL and Argon2.

## Architecture

`src/` builds one static lib (`alfie_vault_core`) plus a thin CLI (`src/main.cpp`). Five layers:

**0. `secure_memory.{h,cpp}` — process memory protections.** The OpenSSL secure heap,
`RLIMIT_CORE`, the strict/best-effort policy, and `SecureAllocator`. Call
`initProcessMemoryProtections()` before reading any secret.

**1. `vault.{h,cpp}` — the chunk vault.** A vault is a *directory of independently encrypted
records*, never one decrypted blob. `vault.meta` (`ALFIEVAULT2` + random 32-byte salt + Argon2id
cost params + two HMAC credential verifiers) is created on first write; Argon2id (m=64 MiB, t=3, p=1) over that salt derives a
64-byte secret split into an **index key** and a **record key**. The record path is
`records/<id[0:2]>/<id[2:4]>/<id>.enc` where `id = HMAC-SHA256(IndexKey, purpose \0
normalizeDomain(domain) \0 account)` with real NUL separators — so domains and usernames never
appear in filenames. Record file layout is `ALFIECHUNK2\n` magic + 16-byte salt (reserved) +
12-byte nonce + AES-256-GCM ciphertext/tag, with **magic + record id + salt** as GCM AAD. Binding
the id is what stops record files being swapped between accounts by anyone with write access to
the vault directory. `ALFIECHUNK1` records (magic-only AAD, separator-less ids) stay readable and
upgrade on the next write.

The Argon2id cost is read back from `vault.meta` on every unlock rather than hardcoded, so it can
be raised for new vaults without orphaning existing ones.

`SecureBuffer` is the memory discipline: move-only, and backed by `SecureBytes` — a vector over
`SecureAllocator`, which serves from the OpenSSL secure heap (one arena, locked as a unit) and
wipes on free. The wipe belongs to the allocator, not a destructor, so a container that grows
cannot leave a readable copy in the abandoned block. `secure_memory.h` also owns the
process-level protections: secure-heap init, `RLIMIT_CORE` 0, and `MemoryPolicy::Strict`
(`ALFIE_VAULT_STRICT_MEMORY=1`), which fails closed instead of degrading. `VaultKeys` is move-only
for the same reason, and `deriveKeys` wipes the passphrase buffer as soon as Argon2id returns.

`VaultSession` is the production entry point: it runs Argon2id **once**, wipes the passphrase,
verifies login + master password against the stored verifiers, and holds the derived keys only
for that one request. Prefer it over `ChunkVault`, which cannot check a login.

**2. `ipc_crypto.{h,cpp}` — the encrypted envelope.** Ephemeral X25519 → HKDF-SHA256 session key;
`IpcRequestContext{token, domain, action}` is bound as HKDF info and GCM AAD, so a frame is only
valid for the one token/domain/action it was minted for. `ReplayGuard` rejects reused
`(token, nonce)` pairs. Decrypted payloads come back as `SecureBuffer`.

**3. `ipc_transport.{h,cpp}` — the socket guard.** Unix domain socket only: `0700` runtime dir,
`0600` socket, peer UID verified via `SO_PEERCRED`. Deliberately separate from the crypto layer.

**4. `http_unlock.{h,cpp}` — the one-time web server.** This is the layer that implements the
primary use case above. Hand-rolled HTTP parsing and a small OpenSSL TLS server (no framework).
`UnlockService` mints single-use, TTL-bound tokens in three modes (`UnlockMode`) — `/init/<token>`
(first-time setup), `/unlock/<token>` (decrypt one record), `/store/<token>` (encrypt a pasted
secret). A token is minted for exactly one mode and rejected on any other path; `findLiveToken()` is
the single place that checks existence, `used`, mode match and expiry, on both GET and POST.
Pages are mobile-friendly HTML rendered from the Mustache templates in `templates/` (see
**Templates** below). `handleSubmit` records only metadata in `LastDelivery`
(token/domain/account/action/secret size) for the unlock path — wiring that to the encrypted IPC
layer above is the intended next step.

**5. `ca.{h,cpp}` — in-memory X.509.** Generates the CA, CA-signed IP server certificates, and
the one-off setup certificate. Private keys are never serialized to disk by this module: they
exist as an `EVP_PKEY` inside the call and leave only as PEM bytes in a `SecureBuffer`, so callers
can put them straight into the vault. `writePrivateFile()` creates 0600 files with `open(2)`
rather than widening permissions after the fact.

### First-time setup

`serve-init-tls` is the bootstrap and has rules the other paths do not. It **refuses to start**
if `vault.meta` exists (the red page must be unreachable whenever a vault exists, not merely
rejected after a password is typed). It serves under a one-off certificate generated in memory by
`generateEphemeralCertificate()` and never written to disk, prints that certificate's SHA-256
fingerprint to the terminal, and the page echoes the same value — out-of-band comparison is the
real anti-phishing defense, since no CA is trusted yet and the user is clicking through a
warning. On submit it creates the vault, generates the CA in memory, stores the CA private key in
the vault, writes the CA cert plus a CA-signed server cert/key, sets `Finished`, and the serve
loop exits. See `docs/first-time-init.md`.

The threat here is phishing, not forgery: re-keying a live vault is already impossible, but an
attacker running their own empty vault can harvest a master password from a convincing setup
page. Keep the fingerprint echo, the red palette, and the refuse-to-start check intact — they are
load-bearing, and the tests assert all three.

### Templates

The HTML pages live in `templates/*.mustache` and are **compiled into the binary** by
`scripts/embed_templates.cmake`, which emits `build/generated/templates.h` as
`alfie::tmpl::kUnlockPage` and friends. `http_unlock.cpp` is the only file that includes that
header or `mustache.hpp`.

They are embedded rather than read from disk at runtime on purpose. These are the pages that ask
for the vault login and master password, and the setup page is what the operator checks a
certificate fingerprint against; a `templates/` directory read at runtime would let anyone who can
write to it rewrite that page -- drop the fingerprint, add a field, post the password elsewhere --
without touching the binary. Adding a runtime template path would remove that property.

Mustache escapes `{{value}}`, which is why there is no `htmlEscape` helper any more: every value
substituted into a page is escaped by construction instead of by remembering to call a function.
`{{{value}}}` and `{{&value}}` bypass that, so `make style-check` fails if either appears in a
template. Keep it that way: an unescaped interpolation here is an injection point into the one
page that must not have one.

`unlock_page.mustache` serves all three modes; `{{#initMode}}`, `{{#storeMode}}` and
`{{#hasFingerprint}}` select the parts that differ, and the palette arrives as data so that the
red setup page and the slate unlock page cannot drift into looking alike.

## Conventions and constraints

- **Never widen the plaintext window.** Prefer `VaultSession::use(...)` / `ChunkVault::use(...)`
  (callback receives a `SecureBuffer`, wiped on return) over `get()`, which returns a long-lived
  `std::string`. The `std::string` passphrase/plaintext overloads in `vault.h` are marked
  test-fixture-only; production paths take `SecureBuffer`. Nothing should log, echo, or return a
  secret value; the unlock pages report success only.
- **Keep the unlock human-gated.** There is no plaintext-HTTP server in this build: the unlock
  page carries a master password, so every `serve-*` subcommand is TLS-only. On an IP-only host
  the certificates come from first-time setup (`docs/first-time-init.md`). Tokens are single-use and TTL-bound (`UnlockRequestSpec`
  defaults to 300s) — treat both as load-bearing.
- **The vault never springs into existence.** `initVault()` is the only thing that creates
  `vault.meta`, and it throws if one exists. Reads and writes call a strict meta read that throws
  when the vault is absent — a typo'd vault path must fail, not become a new empty vault. The
  minimum master password length (`MinimumMasterPasswordLength`) is enforced at init because the
  password can never be changed afterwards.
- **No production secrets through argv.** All CLI subcommands read secrets from stdin (first line
  = master password, echo off on a TTY); argv is visible OS-wide. `get-account` prints a
  decrypted record and is gated behind `ALFIE_VAULT_ALLOW_PLAINTEXT_STDOUT=1` — a test fixture,
  not a delivery path. New functionality belongs on the HTTPS/stdin/socket path.
- `docs/best-practices.md` holds the standards-backed rationale, what each rule bought, and a live
  "must improve next" list (IPC delivery wiring, re-storing V1 records, probing that the secure
  arena is really resident, `ReplayGuard` growth, unlock rate-limiting); consult it before changing
  crypto or memory handling.
- Formatting follows LLVM/Clang via `.clang-format` (LLVM preset: 80 columns, right-aligned
  pointers). Naming is LLVM for types and functions but deliberately **not** LLVM for values:
  functions, methods, variables, parameters and members use `lowerCamelCase`; private and
  protected members carry a trailing underscore (`root_`); compile-time constants take a `k`
  prefix (`kNonceLen`); types, enums and enum constants use `UpperCamelCase`. LLVM itself would
  spell every variable `UpperCamelCase` with no member suffix -- the departure is intentional, so
  a member is distinguishable from a local at the point of use. Standard-library protocol names
  such as `value_type` retain their required spelling. `.clang-tidy` is the authority and
  `make naming-check` enforces it. All code is in `namespace alfie`. Crypto/auth failures throw
  `alfie::CryptoError`.
- C++ tests are Catch2 v3 (`TEST_CASE`/`SECTION`, `REQUIRE`/`CHECK`, `REQUIRE_THROWS_AS`,
  `CHECK_THAT` with matchers), vendored as the amalgamated release under `third_party/catch2/`
  so the test build needs no network or package manager. `add_catch_test()` in `CMakeLists.txt`
  registers one CTest entry per binary. Prefer a fixture struct with `TEST_CASE_METHOD` over
  shared state between cases, and give each fixture its own `mkdtemp` root so a failed run
  cannot change the next run's result. Integration tests are standalone Python scripts driving
  the shell scripts and a real TLS server; `openssl` and `python3` must be on PATH for those.
- `scripts/*.sh` are `set -euo pipefail` bash helpers for the local-CA/IP-certificate flow; they
  enforce `0700` dirs and `0600` private keys, which the Python tests assert.
