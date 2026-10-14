# Agent guide — operating zappi-signer

For AI agents that install and drive the signer (MCP free-pot flow, spends).
Command semantics live in [../README.md](../README.md); this file is the
operational playbook: the ceremony order, the environment, and what to do when
a command fails.

## Hard rules

- Never print, log, quote, or transmit the mnemonic, seed, recovery passphrase,
  or unlock secret. Never pass them as CLI arguments.
- Never ask the human to paste a secret in chat. The vault unlock may pop the
  OS keychain/passphrase dialog — that is expected; do not ask for it in chat.
- Always pass `--json` when driving the CLI as an agent and read stdout as JSON.
- Failures print one redacted message on stderr (≤200 characters) and exit 1.
  The redaction is intentional; do not try to capture more from the process.

## Environment

| Variable | Purpose |
| --- | --- |
| `ZAPPI_SIGNER_API_URL` | Signer API origin (paths already include `/api`). Local Nest: `http://127.0.0.1:3011`. |
| `ZAPPI_SIGNER_SERVER_PUBKEY` | Trust pin; wins over `~/.zappi-signer/trust.json`. |
| `ZAPPI_POT_ID` | Required by `sign` and `status` (UUID, lowercased). |
| `ZAPPI_SIGNER_RECOVERY` | Recovery passphrase for `backup`/`restore` only. |

Files: vault `~/.zappi-signer/seed-vault.json` (version 4, `kind: zappi-pots-mcp`),
trust pin `~/.zappi-signer/trust.json`, unlock secret in keychain service
`zappi-signer`, account `seed-vault-unlock`.

## Wallet-first free-pot ceremony (MCP-driven, idempotent)

Used when the MCP `create_pot` tool returns `need_wallet`. The backend pot row
does not exist until step 5; every step resumes safely after an interruption.

1. `trust-server --pubkey <serverPubkey> --json` — pin the server's
   address-challenge key (from the MCP `create_pot`/`start_pot_address_proof`
   result). Never take the pin from a challenge body.
2. `provision <backendPotId> --json` → `{ potId, provisionId, address, pubkey }`.
   Generates the mnemonic locally; re-running returns the same wallet.
3. MCP `start_pot_address_proof { sparkAddress }` → one-time challenge
   `{ nonce, message, expiresAt, sparkAddress, action, signature }`.
4. `prove-address <provisionId> --challenge '<challenge json>' --json` →
   `{ signature, nonce, ... }`. Do **not** include `serverPubkey` inside the
   challenge object — the CLI refuses it.
5. MCP `create_pot` with
   `walletProof { potId, sparkAddress, nonce, signature, provisionId }` →
   creates the pot active and attached, returns a `bindingReceipt`.
6. `finalize --pot <backendPotId> --json` with the receipt JSON on stdin →
   `{ bound: true }`.

## Spend flow (free pot)

The MCP `consume` tool returns a `signCommand`. Run
`zappi-signer sign <requestId> --yes --json` — the host command-approval dialog
is the only user gate — then poll the MCP `payment_status` tool until
`submitted` or `confirmed`. On `uncertain`, stop and tell the human; never send
the payment again.

## Troubleshooting: `could not create pot`

This message is a redacted catch-all thrown from multiple sites
(`commands/provision.ts`, `commands/agent.ts`, `vault/vault.ts`). In
`derivePot` the underlying cause (Spark SDK error, gRPC deadline, network) is
discarded on purpose, so the CLI cannot say more.

Known issue (v0.1.3 darwin standalone): the Bun-compiled release binary fails
`provision` reproducibly at ~10s while the identical command through the repo
CLI succeeds in ~5s. Verified in isolation (same bundle, three runtimes):

- esbuild bundle → Node: OK (~4s). Same bundle → `bun` source: OK (~4.4s).
- Same bundle via `bun build --compile`: fails at 10.0s with
  `SparkAuthnService/get_challenge DEADLINE_EXCEEDED` (the SDK's 10s
  `DEFAULT_AUTH_TIMEOUT_MS`; `serverTraceId` present, so the request reached
  Spark and the response missed the deadline).
- With the deadline raised to 60s: `get_challenge UNAVAILABLE — connection
  attempt timed out after 20000ms`. The compiled binary stalls on gRPC
  connection setup to the coordinator; node http2 transport, both.

So the defect is `bun --compile` + the SDK's node gRPC transport, not the
network and not the SDK at source. ESM vs CJS bundling makes no difference.

Workaround: re-run the same command through the repo build. The vault format
and paths are identical and `provision` is idempotent, so switching runtimes
mid-ceremony resumes the same wallet:

```bash
npm install && npm run build
node dist/index.js provision <potId> --json
```

Fixes applied (2026-10-14):

1. `build-bin.mjs` builds Node SEA by default; `ZAPPI_SIGNER_BUN_COMPILE=1`
   opts back into Bun compile for experiments. Node runs the identical bundle
   fine, SEA keeps the shipped runtime off the broken Bun path.
2. `scripts/smoke-bin.mjs` runs `provision <potId>` on the actual built
   artifact with a scratch `HOME` (no backend calls, full Spark gRPC init).
   Wired into the release workflow for darwin and win-x64 before signing;
   skips on linux CI (no secret service). It refuses to run on a machine with
   a real vault: the keychain is user-scoped and a scratch run would bump the
   shared high-water mark ("vault rollback refused").
3. Swallowed causes now carry safe codes (`SPARK_UNREACHABLE`,
   `SPARK_DERIVE_INVALID`, `SPARK_SIGN_FAILED`, `SPARK_SIGN_MISMATCH`,
   `POT_ID_MALFORMED`, `PROVISION_ID_MALFORMED`, `POSITIONS_INVALID`,
   `LABEL_INVALID`) instead of one opaque message, and
   `ZAPPI_SIGNER_DEBUG=1` prints a redacted cause line (error name + gRPC/OS
   status tokens only).
4. Local builds of the SEA binary can segfault at startup on a dev machine
   (observed with Node 22 and 24 + postject under the Cursor shell; the same
   bundle runs cleanly under plain node). The release smoke test on CI
   runners is the authority for shipped artifacts; on a dev machine run the
   bundle directly (`node dist/bin/.build/app.cjs …`) or a thin `exec node`
   wrapper.
5. Untested alternative for a future release: bundle the SDK's browser
   condition (grpc-web over fetch) for the standalone binary.
