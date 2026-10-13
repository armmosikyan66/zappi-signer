# Platform behavior

`createOsKeyStore()` chooses one credential backend from `process.platform`. Secrets stay in that backend. The vault file holds ciphertext only.

| Platform | Backend |
| --- | --- |
| `darwin` | Local helper `~/.zappi-signer/bin/macos-keychain` |
| `linux` | `@napi-rs/keyring` pinned to Secret Service |
| `win32` | `@napi-rs/keyring` (Windows Credential Manager) |
| anything else | Throws `keychain unavailable` |

A backend failure throws `keychain unavailable`. The signer has no plaintext file fallback on any platform.

## Vault file

`defaultVaultPath()` uses `os.homedir()`, not the `HOME` environment variable by itself.

- macOS and Linux: `~/.zappi-signer/seed-vault.json`
- Windows: `%APPDATA%\zappi-signer\seed-vault.json`. A missing or blank `APPDATA` uses `%USERPROFILE%\AppData\Roaming\zappi-signer\seed-vault.json`

The writer asks for directory mode `0700` and file mode `0600` on every platform (`mkdir` mode `0700`, `open` mode `0600`). Off Windows it also `chmod`s the vault directory to `0700` and the vault file to `0600` before and after the atomic rename. On Windows those `chmod` calls are skipped; the modes passed to `mkdir` and `open` are unchanged.

Off Windows, a read refuses the vault file when any group or other mode bit is set (`mode & 077`), or when the file uid is not `process.getuid()`. The error is `vault locked`. Windows skips both checks.

The lock file `<vault>.lock` is created mode `0600`. Off Windows its directory is `chmod`ed to `0700`.

### Symlinks

`VaultStore` `lstat`s the vault path and the vault directory on every platform, including Windows. A symlink is `vault locked`. The atomic replace does the same check and will not rename a new file onto a symlink. `readNoFollow` adds `O_NOFOLLOW` off Windows, so opening a symlink there fails (`ELOOP`, or any other open error except `ENOENT`) as `vault locked`. Windows does not set `O_NOFOLLOW`. The vault loader still refuses a symlink because the `lstat` check runs first.

A missing vault file is absence (`ENOENT`), not a locked vault. `readNoFollow` rethrows `ENOENT`. The loader treats that as no vault.

## Device-bound seal

Version 4 field keys are HKDF-SHA256 over the scrypt key, using the 32-byte device factor as salt and the info string `zappi-pot-device-v4`. `keystore.deviceFactor()` must return exactly 32 bytes; any other length throws `keychain unavailable`.

Opening a version 4 file whose AES-256-GCM tag does not verify throws `vault is sealed to another device`. A vault copied to a machine with a different device factor fails that way. The same error is used for every version-4 authentication failure, including a different unlock secret.

Version 3 files open without the device factor. The next write stores version 4 and seals the fields to this device.

## Keychain names

Service name: `zappi-signer`. The macOS helper also labels items `zappi-signer`.

| Account | Role |
| --- | --- |
| `seed-vault-unlock` | Vault unlock secret |
| `device-factor` | Device factor |
| `vault-high-water` | Monotonic vault version used as a rollback guard |
| `user-presence` | macOS user-presence item |
| `device-token` | Device token for the `local` host |
| `oauth-client-id` | OAuth client id for the `local` host |
| `device-token-<host>` | Device token for another host |
| `oauth-client-<host>` | OAuth client id for another host |

`local` uses the unsuffixed token and client accounts. Any other host must match `^[a-z][a-z0-9-]{0,19}$`. An account name must match `^[a-z0-9-]{1,64}$`. Anything else throws `keychain account refused` before the backend is called.

A secret must be non-empty and at most 8192 bytes. Otherwise the store throws `keychain unavailable` and does not call the helper or `@napi-rs/keyring`.

## macOS

The TypeScript store talks only to the helper. A missing helper, a failed compile, a spawn error, a timeout, or a bad device factor throws `keychain unavailable`. There is no login-keychain fallback and no `security` CLI fallback.

The helper is resolved in this order:

1. `ZAPPI_SIGNER_KEYCHAIN_HELPER` (absolute path), when set.
2. The prebuilt helper the one-line installer puts at `~/.zappi-signer/macos-keychain` (verified there against the pinned release signature). It wins over everything else because it matches the pinned binary release.
3. `~/.zappi-signer/bin/macos-keychain`, compiled from the package source when the source is newer than the binary.

On first use, and again whenever `native/macos-keychain.c` is newer than the compiled binary, the signer compiles:

```text
clang -O2 -o ~/.zappi-signer/bin/macos-keychain native/macos-keychain.c -framework Security -framework CoreFoundation
```

The source path is the package file `native/macos-keychain.c`. The binary directory is `dirname(defaultVaultPath())/bin`, normally `~/.zappi-signer/bin`, even if a `VaultStore` is pointed at a different vault path. That directory is created and `chmod`ed to `0700`. A successful compile `chmod`s the binary to `0700`. `clang` is allowed 120 seconds. A non-zero compile throws `keychain unavailable`. A standalone binary (`npm run build:bin`) ships no helper source, so only the override and the installer's prebuilt helper can supply it; with neither, every keychain operation throws `keychain unavailable`.

The helper is spawned with only `PATH`, `HOME`, `USER`, and `LOGNAME`. `set` sends the secret on stdin. `get` and `factor` return bytes on stdout. The secret is not placed in argv. The parent wipes its stdin buffer after the write. `get`, `set`, `delete`, and `factor` time out after 60 seconds. `presence` times out after 120 seconds.

| Op | Arguments | Result |
| --- | --- | --- |
| `get` | account | Exit 0 and a non-empty stdout: the secret. Exit 0 and empty stdout: null. Exit 2: item absent, null. Any other status: `keychain unavailable` |
| `set` | account, secret on stdin | Exit 0: stored. The helper rejects an empty stdin or more than 8192 bytes. Any other status: `keychain unavailable` |
| `delete` | account | Exit 0, including when the item was already absent. Any other status: `keychain unavailable` |
| `presence` | `user-presence` | Exit 0: true. Any other completed status: false. Spawn or timeout: `keychain unavailable` |
| `factor` | `device-factor` | Exit 0 and stdout base64 of exactly 32 bytes: the factor. Otherwise: `keychain unavailable` |

When `HOME` is set, the helper opens `~/Library/Keychains/login.keychain-db` and passes it as `kSecUseKeychain`. Items are generic passwords with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and `kSecAttrSynchronizable` false. That login keychain is the helper's only store. If the helper fails, the signer does not try another keychain API.

### Device factor

`deviceFactor()` runs `factor device-factor`.

The helper first tries a Secure Enclave P-256 key. The key tag is `zappi-device.device-factor`. It lives in the data-protection keychain, with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and private-key usage. The 32 factor bytes are ECIES-sealed to that key (`kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM`). The ciphertext is the `device-factor` keychain item. An ECDSA signature is not used, because it is not a stable value.

An unsigned helper is often denied the enclave (`errSecMissingEntitlement`). The helper then stores the raw 32 bytes as a this-device-only, non-synchronizable generic password and prints those bytes as base64 on stdout. If that store fails too, the helper exits non-zero and the signer throws `keychain unavailable`. The factor is not written to the vault file.

Linux and Windows store the factor as base64 text in the account password. The macOS software item is the raw 32 bytes. Both paths hand the vault the same kind of 32-byte buffer.

### User presence

Only the macOS store implements `confirmUserPresence`. An empty reason, or a reason longer than 80 characters, returns false and does not start the helper. Any other reason runs `presence user-presence`. The reason text is not sent to the helper. The helper's prompt is the fixed string `Authorize Zappi`, on an item protected by `kSecAccessControlUserPresence` (Touch ID or the account password).

`VaultStore.confirmPresence()` calls `confirmUserPresence('Authorize Zappi')`. A missing method or a false result throws `keychain unavailable`. Presence-gated operations fail closed when the check cannot succeed.

## Linux

`createOsKeyStore()` returns the `@napi-rs/keyring` store. Every call builds:

```text
new Entry("zappi-signer", account, { linux: { store: "secret-service" } })
```

The `secret-service` pin is applied when `process.platform` is `linux` at the call. The library's default keyutils fallback is not used. If Secret Service is unavailable — a headless machine with no Secret Service daemon — the `Entry` constructor throws, and the signer maps that throw to `keychain unavailable`. A locked or unreadable store does the same. There is no plaintext fallback.

A missing item is not a failure. `getSecret` returns null when the password is null, when the error code is `NoEntry` or `NotFound`, when the message starts with `NoEntry`, or when the message contains `No matching entry` or `The specified item could not be found`. `deleteSecret` of a missing item resolves. Every other keyring error throws `keychain unavailable`.

There is no Secure Enclave on this path. `stableDeviceFactor` reads `device-factor`. If it is absent, the signer draws 32 random bytes, stores them as base64 in Secret Service, and reuses them. A stored value that does not decode to 32 bytes throws `keychain unavailable`.

This store does not implement `confirmUserPresence`. `VaultStore.confirmPresence()` throws `keychain unavailable`, so presence-gated operations fail closed.

## Windows

`createOsKeyStore()` uses the same `@napi-rs/keyring` store and passes no Linux `store` option. On Windows that library uses Credential Manager. This package does not call DPAPI and has no second store when Credential Manager throws. Those errors follow the Linux missing-item and `keychain unavailable` rules. There is no plaintext fallback.

The device factor is the same software factor as Linux: 32 random bytes, base64, account `device-factor`, kept in Credential Manager.

`confirmUserPresence` is absent, so `VaultStore.confirmPresence()` throws `keychain unavailable`. Presence-gated operations fail closed.

The vault file is `%APPDATA%\zappi-signer\seed-vault.json`. Unix mode and uid checks do not run on Windows. Symlink refusal through `lstat` still does.
