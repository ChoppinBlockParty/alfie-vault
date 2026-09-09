# HTTP unlock server

This is the first simple web unlock layer.

## What it does

1. Alfie creates a one-time token for one requested credential.
2. The server prints a link like:

```text
http://127.0.0.1:18080/unlock/<token>
```

3. Slava opens the link and enters:
   - vault login
   - vault master password
4. The server checks the login.
5. The server unlocks exactly one vault chunk.
6. The HTTP response says only that unlock succeeded.
7. The final website password/card value is not shown in the page.
8. The token is consumed and cannot be reused.

## Store a new secret via web link

For secrets that should not go through Telegram, Alfie creates a one-time store link:

```bash
./alfie-vault serve-store ./vault slava 127.0.0.1 18080 account example.com slava@example.com store_secret
```

The page asks for:

- vault login
- vault master password
- secret JSON value

After submit, the server encrypts the value into the vault chunk and returns only `Stored`; it does not echo the secret.

## Current command

```bash
./alfie-vault serve-unlock ./vault slava 127.0.0.1 18080 account example.com slava@example.com fill_password
```

## Current limitation

This is HTTP-only and local-development only. Production needs TLS/domain or a trusted reverse proxy before exposing it outside localhost.

The CLI still exists only for smoke testing. Real production secrets must not be passed through argv.

## Next integration

Replace the temporary metadata-only delivery in `UnlockService::handle_submit` with the encrypted Unix-socket IPC browser-worker delivery from `ipc_crypto.hpp` and `ipc_transport.hpp`.
