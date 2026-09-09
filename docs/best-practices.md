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

- Argon2id is used with stronger-than-OWASP-minimum settings: 64 MiB, 3 iterations, p=1.
- AES-256-GCM protects each record independently.
- HMAC-SHA256 record IDs avoid plaintext domains/usernames in filenames.
- `SecureBuffer` is move-only and wipes with `OPENSSL_cleanse`.
- `mlock` and `MADV_DONTDUMP` are attempted for secret buffers.
- `ChunkVault::use(...)` keeps decrypted records in callback-scoped `SecureBuffer`.

Must improve next:

1. Replace `std::string` passphrase and plaintext APIs with `SecureBuffer`-first APIs.
2. Initialize OpenSSL secure heap at process start and use secure allocations where practical.
3. Add runtime checks that fail closed if memory locking/secure heap fails in strict mode.
4. Disable core dumps for the process with `setrlimit(RLIMIT_CORE, 0)`.
5. Remove production CLI secret arguments; keep CLI only for test fixtures.
6. Add a fuzz/corruption test for encrypted chunks and authentication tag failures.

## Sources

[1] OWASP Secrets Management Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
[2] OWASP Password Storage Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
[3] Libsodium Secure Memory — https://libsodium.gitbook.io/doc/memory_management
[4] OpenSSL secure heap docs — https://docs.openssl.org/3.4/man3/OPENSSL_secure_malloc/
[5] NIST SP 800-63B authenticators/password verifier guidance — https://pages.nist.gov/800-63-4/sp800-63b/authenticators/
