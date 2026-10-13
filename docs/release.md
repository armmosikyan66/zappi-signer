# Release

The signed binary release is what the one-line installer
(`web/install/signer.sh`, served at `https://zappi.money/signer/install`)
downloads and verifies. It pins:

- `RELEASE_REPO` / `RELEASE_TAG` — the GitHub release to fetch.
- `MIN_VERSION` — refuses a provenance version below it.
- `PUBLISHER_PUBKEY_PEM` — the Ed25519 public key, written in the installer
  itself, never fetched next to the binary.

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
prebuilt keychain helper that the installer places at
`~/.zappi-signer/macos-keychain`.

The installer verifies the Ed25519 signature with `openssl pkeyutl -verify
-rawin` (or cosign), checks the SHA-256 in the provenance, refuses a version
below `MIN_VERSION`, and installs mode `0500`. Any failure exits without
running the file.

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

Bump `packages/zappi-signer/package.json` first — the workflow refuses a tag
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
- Its public half must equal `PUBLISHER_PUBKEY_PEM` in
  `web/install/signer.sh`. Changing either is a coordinated change: new
  installer bytes plus a new release, published together.

Rotation:

1. Generate a new keypair offline.
2. Update the repo secret and `PUBLISHER_PUBKEY_PEM` together.
3. Cut a new installer (the served `web/install/signer.sh` bytes) and a new
   `zappi-signer-v*` release.

Old binaries fail verification under the new key — by design. The remote MCP
(`https://api.zappi.money/mcp`) keeps working; only autonomous free-pot
spending pauses until the user reinstalls.