# Security notes

## Why chunks

The vault does not decrypt all data at once. A lookup decrypts only one encrypted record. This reduces damage from accidental memory exposure.

## What is still not solved

- If the host is fully compromised while Alfie is using a credential, that credential can be read at the moment of use.
- Passphrases must not be passed as CLI arguments in production. The current CLI is for tests/smoke only.
- Password derivation uses Argon2id, not scrypt/PBKDF2.
- Decrypted records should be consumed through `ChunkVault::use(...)`; this keeps plaintext inside a callback-owned `SecureBuffer` and avoids returning a long-lived plaintext `std::string`.
- `SecureBuffer`, `VaultKeys`, and passphrase buffers are move-only and wiped with `OPENSSL_cleanse` before release.
- The production path must use a short-lived HTTPS unlock server and stdin/socket memory buffers.

## Export

Export only encrypted files:

```bash
tar -czf alfie-vault-backup.tgz vault/
```

No plaintext export command should exist.
