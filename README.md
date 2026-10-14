# @zappimoney/zappi-signer

Local signer for a Zappi pot. The mnemonic stays in the vault on this machine. The process is a command-line tool: remote MCP calls do not sign.

Node `>= 20`. Package binary name: `zappi-signer` (`package.json` `bin` → `dist/index.js`).

Platform keystores, the Windows vault path, and user-presence behavior are in [docs/platforms.md](docs/platforms.md).

## Install

From this directory:

```bash
npm install
npm run build
node dist/index.js --help
```

`node dist/index.js` and the `zappi-signer` bin take the same arguments. `--help` prints the command list and exits 0.

## Development

```bash
npm run sync:local   # build + refresh the installed zappi-signer command (wrapper over the release bundle)
npm run smoke:bin -- dist/bin/zappi-signer-<target>   # CI-only smoke test; refuses on machines with a real vault
npm run release      # patch bump + tag; CI builds, smoke-tests, signs, and publishes
npm run release -- minor   # or: major | <explicit version>
```

`sync:local` never touches the vault, keychain, or trust pin. The release tag
triggers `.github/workflows/zappi-signer-release.yml`; the smoke test gates
the release (see [docs/agent.md](docs/agent.md)).

## Setup

The client accepts `https`, and `http` only for `127.0.0.1`, `localhost`, or `[::1]`. Any other `http` host is refused, as are userinfo, a query string, and a fragment. Request paths already start with `/api`, so `ZAPPI_SIGNER_API_URL` is the origin (a path prefix is optional and is not `/api` by itself). Local Nest on this machine is `http://127.0.0.1:3011`.

```bash
export ZAPPI_SIGNER_API_URL='https://api.example.com'
export ZAPPI_SIGNER_SERVER_PUBKEY='<compressed-secp256k1-hex>'
export ZAPPI_POT_ID='<nest-pot-uuid>'
```

`ZAPPI_SIGNER_SERVER_PUBKEY` is the install pin. When both the environment variable and `~/.zappi-signer/trust.json` set `serverPubkey`, the environment variable wins. A missing trust file is an empty key map. The file shape is `{ "keys": { "<keyId>": "<hex pubkey>" }, "serverPubkey": "<hex>" }`.

`sign` and `status` do not take `--pot`. They read `ZAPPI_POT_ID`. That value must be a UUID. It selects the keychain account `pot-client-token-<potId>` (the pot id is lowercased). The header on those requests is `x-zappi-pot-client`. The CLI has no flag for the token.

The vault file is version 4. The `kind` string is `zappi-pots-mcp`. On macOS and Linux the path is `~/.zappi-signer/seed-vault.json`. The keychain service is `zappi-signer`. The first `provision` stores a machine-generated unlock secret in the account `seed-vault-unlock`. Opening the vault uses that item. The recovery passphrase is only for `backup` and `restore`.

`ZAPPI_SIGNER_RECOVERY`, when set to a non-empty string, is that recovery passphrase. Otherwise a TTY prompts `Recovery passphrase: `. There is no passphrase flag. A non-TTY `backup` or `restore` without the environment variable fails with `vault locked`.

`ZAPPI_SIGNER_DEBUG=1` makes swallowed Spark causes print one redacted line on stderr before the failure: the error name, a code if set, and standalone gRPC/OS status tokens (for example `SPARK_UNREACHABLE` with `DEADLINE_EXCEEDED`). Never the raw message.

## Commands

```text
zappi-signer sign <requestId> [--yes] [--json]
zappi-signer status <requestId> [--json]
zappi-signer policy view --pot <id> [--json]
zappi-signer policy tighten --pot <id> [--json]
zappi-signer trust-server --pubkey <hex> [--json]
zappi-signer provision [<potId>] [--label <text>] [--json]
zappi-signer prove-address <provisionId> [--challenge <json>] [--json]
zappi-signer prove-address --pot <id> [--json]
zappi-signer finalize --pot <id> [--json]
zappi-signer backup --pot <id> [--json]
zappi-signer restore --pot <id> [--json]
```

An unknown command prints `unknown command` on stderr and exits 1. Failures print a redacted message on stderr (control characters stripped, at most 200 characters) and exit 1.

`sign <requestId>` requires `ZAPPI_POT_ID` and a UUID `requestId`. Without `--yes`, a TTY asks `Send <amountCents> cents to <receiverSparkAddress> on <network>? [y/N] `. `y` and `yes` continue. Any other answer refuses. A non-TTY `sign` without `--yes` refuses and does not spend. The lookup must be `authorization_required` and `MAINNET`. Any other status refuses with `refused to spend` and does not broadcast. Text output is `<status>` or `<status> <txid>`. `--json` prints `{ requestId, potId, status, intentId?, txid? }`.

`status <requestId>` is a read of `GET /api/wallet/pots/client-spend-requests/:requestId`. It does not open the mnemonic. Text output is the public `status`. `--json` prints the public fields (`requestId`, `approvalId`, `potId`, `amountCents`, `receiverSparkAddress`, `network`, `status`).

`policy view --pot <id>` prints `<potId> <role> <freeze>`. `--json` adds the sealed policy. `policy tighten --pot <id>` reads the next policy JSON on stdin (at most 1 MiB). Caps, destination rules, and guards may only narrow. Spend counters stay on the stored record. User presence is required (`Authorize Zappi`). Where the keystore cannot confirm presence, tighten fails with `keychain unavailable`. See [docs/platforms.md](docs/platforms.md).

`provision` creates a local pot, derives a MAINNET address at account index 1, and posts `POST /api/wallet/pots/address-proof-challenge` with `{ sparkAddress }`. It signs the returned `message`. It does not mark the pot bound (`bound` stays false). Text output is `<potId> <address>`. `--json` also includes `provisionId` (`prov_` plus 16 hex bytes), `pubkey`, `signature`, and `nonce`. The local id is `pot_` plus 32 hex characters. `--label` is display text, at most 64 characters. The command does not print a mnemonic.

`prove-address --pot <id>` reads a binding receipt on stdin. It checks the receipt with `verifyBindingReceipt` against `ZAPPI_SIGNER_SERVER_PUBKEY`, including `potId` and the vault record's `sparkAddress`. `markBound` runs only after that check. A failed check leaves the pot unbound. Text output is `<potId> bound`. `--json` prints `{ potId, address, bound: true }`.

### Server-pot-first flow (MCP free pots)

For a pot the backend already created (`create_pot`), the wallet is created locally and bound to that pot id. Every step is idempotent and resumes after an interruption. The mnemonic never leaves this machine.

1. `trust-server --pubkey <hex>` pins the server's address-challenge public key (returned by the MCP `start_pot_address_proof` tool) into `~/.zappi-signer/trust.json`. The pin is never taken from a challenge body.
2. `provision <backendPotId> --json` generates the mnemonic, derives the MAINNET address, and stores the record under the backend pot id (a UUID). Output: `{ potId, provisionId, address, pubkey }`. Re-running returns the same wallet.
3. `prove-address <provisionId> --challenge <json> --json` verifies the server-signed `attach` challenge (nonce, message, expiresAt, sparkAddress, action, signature) against the pin, then signs the message with the address identity key. Output includes `signature` and `nonce` for the MCP `bind_pot_address` tool. With no `--challenge`, the challenge JSON is read from stdin.
4. `bind_pot_address` (MCP) submits `{ potId, sparkAddress, nonce, signature, provisionId }` and returns a `bindingReceipt`.
5. `finalize --pot <backendPotId> --json` reads the binding receipt on stdin, verifies it against the pin, and marks the record bound. Text output is `<potId> bound`.

`backup --pot <id>` prints a JSON envelope (`kdf`, `t`, `m`, `p`, `salt`, `nonce`, `tag`, `ciphertext`). The mnemonic is inside the ciphertext. `--json` does not add another wrapper. `restore --pot <id>` reads that envelope on stdin, creates a new vault record, and prints the new pot id. `--json` prints `{ potId, createdAt }`. `--pot` must be present and non-empty; `restore` does not use that value as the new id.

## Examples

Pin and API origin, then a spend the remote MCP already marked `authorization_required`:

```bash
export ZAPPI_SIGNER_API_URL='https://api.example.com'
export ZAPPI_SIGNER_SERVER_PUBKEY='<compressed-secp256k1-hex>'
export ZAPPI_POT_ID='22222222-2222-4222-8222-222222222222'

zappi-signer status 11111111-1111-4111-8111-111111111111 --json
zappi-signer sign 11111111-1111-4111-8111-111111111111
zappi-signer sign 11111111-1111-4111-8111-111111111111 --yes --json
```

Provision, then bind only after Nest returns a receipt. The receipt object is [SIGNER_PROTOCOL.md](../../zappi-plugin/SIGNER_PROTOCOL.md) §12. `--pot` is the local vault id that must equal the receipt's `potId`.

```bash
zappi-signer provision --label 'agent pot' --json
zappi-signer prove-address --pot pot_0123456789abcdef0123456789abcdef --json < receipt.json
```

View a policy, then tighten it. Build the stdin object from `policy view --json` and lower a cap. A higher cap is refused.

```bash
zappi-signer policy view --pot pot_0123456789abcdef0123456789abcdef --json
zappi-signer policy tighten --pot pot_0123456789abcdef0123456789abcdef --json <<'EOF'
{"perTxSats":50000,"dailySats":500000,"spentDay":"2026-10-13","spentTodaySats":0,"monthlySats":3000000,"destinations":{"mode":"allowlist","allow":[],"block":[]},"guard":{"maxTxPerHour":10,"maxFailuresPerHour":5,"onTrip":"freeze"}}
EOF
```

Backup and restore. The passphrase is the environment variable or the TTY prompt.

```bash
export ZAPPI_SIGNER_RECOVERY='<recovery-passphrase>'
zappi-signer backup --pot pot_0123456789abcdef0123456789abcdef > pot.backup.json
zappi-signer restore --pot pot_0123456789abcdef0123456789abcdef --json < pot.backup.json
```

## More detail

- [docs/agent.md](docs/agent.md) — agent playbook: wallet-first ceremony, spend flow, troubleshooting
- [docs/architecture.md](docs/architecture.md) — trust invariants, module map, spend sequence
- [docs/protocol.md](docs/protocol.md) — endpoints and divergences
- [docs/threat-model.md](docs/threat-model.md) — Tier A, B, and C
- [docs/platforms.md](docs/platforms.md) — macOS, Linux, and Windows keystores
