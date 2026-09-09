# Alfie Vault C++

C++ encrypted chunk vault for Alfie credentials and card details.

## Design

- Runtime vault is a directory of small encrypted records, not one big decrypted JSON.
- Record path is derived from `HMAC(index_key, purpose/domain/account)`.
- Each record is decrypted alone, used, then wiped.
- Export/backup can be a tarball of the encrypted vault directory.

## Crypto

- OpenSSL libcrypto.
- Key derivation: Argon2id.
- Record encryption: AES-256-GCM.
- Record IDs: HMAC-SHA256.
- Random salt and nonce per record.

## Memory

- Secrets use `SecureBuffer`.
- Best effort `mlock` to avoid swap.
- Best effort `MADV_DONTDUMP` to avoid core dumps.
- Wipe uses `OPENSSL_cleanse`.

## Build

```bash
make
make test
```

This repo vendors only Debian OpenSSL/Argon2 headers extracted from distro packages; it links to system `libcrypto.so.3` and local `libargon2`.

## Current CLI

```bash
./alfie-vault put-account ./vault example.com slava@example.com passphrase '{"login":"slava@example.com","secret":"..."}'
./alfie-vault get-account ./vault example.com slava@example.com passphrase
```

Next step: replace passphrase CLI args with HTTPS short-lived unlock server before real use.
