# Vault security best practices research

## Standards-backed rules for Alfie Vault

1. Minimize the time that secrets exist in plaintext memory; OWASP explicitly frames memory protection as reducing the time window where a secret is present, not as a perfect defense once an attacker can read process memory.[1]
2. Zero sensitive memory after use with a function the compiler cannot optimize away; OWASP recommends zeroing memory after secret use, libsodium documents `sodium_memzero`, and OpenSSL documents secure-memory/clean-free APIs.[1][3][4]
3. Lock secret memory where possible and keep it out of dumps; libsodium documents `mlock`/`VirtualLock` wrappers and dump exclusion behavior, while also warning that OS locked-memory limits can cause failure.[3]
4. Prefer guarded/secure heaps for long-running services; OpenSSL secure heap is designed for keys and other sensitive values, but must be initialized or it degrades to normal allocation.[4]
5. Use Argon2id for password-derived keys; OWASP recommends Argon2id, with a minimum of 19 MiB memory, 2 iterations, and parallelism 1.[2]
6. Tune Argon2id cost as high as practical; NIST says verifier cost factors should be as high as practical without hurting performance and should increase over time.[5]
7. Store KDF parameters and salt/version metadata with the encrypted vault so the format can migrate later; NIST recommends storing the password hashing scheme and cost factor for migration.[5]
8. Avoid encrypted passwords where possible, but this vault is the valid exception: OWASP says encryption is only appropriate when the original plaintext must be recovered to authenticate to another system.[2]
9. Do not pass real secrets through argv, logs, files, or chat. The production path should use HTTPS/stdin/socket buffers and wipe them immediately.
10. Treat memory hygiene as defense-in-depth only. If root or the process is compromised while a credential is in use, that live credential can still be stolen.[1]

## Current implementation status

Already good:

- Argon2id with stronger-than-OWASP-minimum settings: 64 MiB, 3 iterations, p=1 -- and the cost
  is read back from `vault.meta` on every unlock, so it can be raised for new vaults without
  making existing ones underivable (rules 6, 7).
- AES-256-GCM protects each record independently.
- HMAC-SHA256 record IDs avoid plaintext domains/usernames in filenames.
- Secret containers allocate from the OpenSSL secure heap, are locked out of swap, excluded from
  core dumps, and wiped on free -- including the buffer abandoned when a container grows
  (rules 1-4).
- Core dumps are disabled process-wide with `setrlimit(RLIMIT_CORE, 0)`.
- `ChunkVault::use(...)` / `VaultSession::use(...)` keep decrypted records in a callback-scoped
  `SecureBuffer`.
- Secrets reach the CLI on stdin, never argv (rule 9).
- Record corruption, truncation, tag tampering and record-swapping are covered by tests.

Resolved from the previous "must improve next" list:

1. **SecureBuffer-first APIs.** `SecureBuffer` is now the parameter and return type for every
   passphrase and plaintext on a production path. `SecureBuffer` holds `SecureBytes` -- a vector
   over `SecureAllocator`, so its storage is locked and wiped by the allocator itself rather than
   by a destructor that a reallocation can outrun. The `std::string` overloads survive only as
   test fixtures and are marked as such in `vault.h`.
2. **OpenSSL secure heap.** `initProcessMemoryProtections()` calls
   `CRYPTO_secure_malloc_init()` at process start and every secret allocation is served from
   that arena. This also removes a hazard in the old per-buffer `mlock`: locks are page-granular,
   so two secrets sharing a page shared a lock and freeing one would unlock the other. The arena
   is locked once, as a unit. The per-buffer path remains only as a fallback.
3. **Fail closed.** `MemoryPolicy::Strict` (`ALFIE_VAULT_STRICT_MEMORY=1`) throws rather than
   continuing when the secure heap is unavailable, core dumps cannot be disabled, or a fallback
   allocation cannot be locked. The default stays best-effort so a developer box still runs.
4. **`RLIMIT_CORE`.** Set to 0 during the same init, and asserted by `tests/test_secure_memory.cpp`.
5. **No secrets in argv.** `init-vault` and `put-account` read the master password from the first
   line of stdin (echo off on a TTY) and the payload from the rest. `get-account` decrypts to
   stdout and now refuses to run without `ALFIE_VAULT_ALLOW_PLAINTEXT_STDOUT=1`.
6. **Corruption/fuzz tests.** `tests/test_corruption.cpp` flips every byte of a record, every bit
   of the GCM tag, truncates at every length, appends, feeds garbage, swaps record files between
   accounts, and runs a seeded random-mutation sweep. The invariant is absolute: an altered
   record must never decrypt, and must never yield another record's contents.

Found while validating the rules above, and fixed:

- **Record IDs were not domain-separated.** `purpose + "\0" + domain + "\0" + account` looks like
  it inserts NUL separators but does not: the literal decays to a C string and `strlen` stops at
  the NUL, so the fields were concatenated bare. `("acc", "ountX")` and `("account", "X")` hashed
  to the same record, silently overwriting each other. The same bug was in the IPC AAD, where it
  weakened the binding between a frame and its `(token, domain, action)`.
- **Records were not bound to their own identity.** V1 authenticated only the 12-byte magic, so
  the reserved salt field was malleable and, worse, record files could be swapped between
  accounts: anyone able to write to the vault directory -- without knowing the master password --
  could make an unlock hand a task the wrong credential. The `ALFIECHUNK2` format binds
  magic + record id + salt into the GCM AAD. V1 records stay readable and upgrade to V2 on the
  next write; see `docs/security.md` for the migration note.
- **A wrong master password reported "record not found".** The stored verifiers exist precisely
  to tell those two cases apart, but only the HTTPS path consulted them. `VaultSession` now
  checks the password verifier on every open.

## Must improve next

1. Wire `UnlockService::handleSubmit` to the encrypted IPC layer. It still records only
   delivery metadata, so the browser-worker handoff is unimplemented.
2. Re-store records written before the `ALFIECHUNK2` change. They remain readable, but until
   they are rewritten they carry the V1 AAD and are still swappable.
3. Verify that the secure arena is actually resident: `CRYPTO_secure_malloc_init` reports
   success even where its internal `mlock` was refused, so `SecureHeap == true` is weaker than
   "locked". Strict mode should probe this rather than trust the flag.
4. The IPC `ReplayGuard` keeps every `(token, nonce)` pair it has ever seen in memory, with no
   eviction -- an unbounded growth path in a long-running server.
5. Rate-limit and audit-log failed unlock attempts. A token is single-use and TTL-bound, but
   within its window a wrong password can be retried without limit or trace.

## Sources

[1] OWASP Secrets Management Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
[2] OWASP Password Storage Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
[3] Libsodium Secure Memory — https://libsodium.gitbook.io/doc/memory_management
[4] OpenSSL secure heap docs — https://docs.openssl.org/3.4/man3/OPENSSL_secure_malloc/
[5] NIST SP 800-63B authenticators/password verifier guidance — https://pages.nist.gov/800-63-4/sp800-63b/authenticators/
