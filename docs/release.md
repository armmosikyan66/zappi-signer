# Release

The signed binary release is the GitHub release for a `zappi-signer-v*` tag.
The public shell installer is gone. This repo does not download one, and
`scripts/release.mjs` does not write an installer in another repo. A release
pins:

- The tag — the GitHub release to fetch.
- The provenance `version` — refuses a binary whose version does not match the tag.
- The Ed25519 publisher key — the secret stays in `ZAPPI_SIGNER_RELEASE_KEY`.

## What a release contains

Per target (`darwin-arm64`, `darwin-x64`, `linux-x64`, `linux-arm64`,
`win-x64`):

| File | Meaning |
| --- | --- |
| `zappi-signer-<target>[.exe]` | Standalone binary (Bun `--compile`, Node SEA fallback) |
| `zappi-signer-<target>[.exe].sig` | Base64 raw Ed25519 signature (64 bytes) |
| `zappi-signer-<target>.provenance.json` | `version`, `target`, `commitSha`, `binarySha256`, `signedAt` |
| `zappi-signer-<target>[.exe].sha256` | Hex digest sidecar |

Darwin targets also carry `macos-keychain` and `macos-keychain.sig`: the
prebuilt keychain helper published at
`~/.zappi-signer/macos-keychain`.

Each artifact is an Ed25519 signature over the binary, a provenance file, and
a SHA-256 sidecar. `scripts/sign-release.mjs` refuses to emit them without
the publisher key. A failed sign does not publish the binary.

## Build and sign locally

```sh
npm run build:bin                 # tsc + scripts/build-bin.mjs -> dist/bin/
ZAPPI_SIGNER_RELEASE_KEY=... npm run sign:release -- --provenance
ZAPPI_SIGNER_RELEASE_KEY=... npm run sign:release -- dist/bin/macos-keychain
```

`scripts/build-bin.mjs` embeds the `@napi-rs/keyring` native bindings into the
bundle (base64, dlopened from a private temp dir at runtime), so the binary
needs no node_modules on the user machine. On darwin it strips Bun's malformed
code-signature block and re-signs ad hoc; an unusable Bun result falls back to
Node SEA automatically.

## Publish

Bump `package.json` first — the workflow refuses a tag
that does not match the package version, so a stale binary can never be
published under an old version number again.

Push a tag `zappi-signer-v<semver>`. `.github/workflows/zappi-signer-release.yml`
builds every target in a matrix, runs tests, signs with the repo secret
`ZAPPI_SIGNER_RELEASE_KEY`, and publishes the GitHub release. Without the
secret, `scripts/sign-release.mjs` fails the build: no unsigned release is
produced.

## The release key

- `ZAPPI_SIGNER_RELEASE_KEY` is base64 of a 64-byte Ed25519 secret:
  `seed(32) || public-key(32)`. Generate it offline, store it as a GitHub repo
  secret, never commit or log it.
- Rotating the key means a new secret and a new signed release. Older
  binaries fail verification under the new key.

Rotation:

1. Generate a new keypair offline.
2. Update the repo secret.
3. Cut a new `zappi-signer-v*` release.

Old binaries fail verification under the new key — by design. The remote MCP
(`https://api.zappi.money/mcp`) keeps working; only autonomous free-pot
spending pauses until the user reinstalls.