# Protocol

Canonical bodies, signatures, expiry, and the binding receipt are specified in [SIGNER_PROTOCOL.md](../../../zappi-plugin/SIGNER_PROTOCOL.md). This page lists the routes this package calls and the divergences recorded in §11 of that file.

The client sends `accept: application/json`. Spend routes also send `x-zappi-pot-client`. `GET /api/signer/trust` and the address-challenge POST do not. Any non-2xx response, a TLS failure, or a timeout refuses the call. The default timeout is 10 seconds.

## Endpoints

| Method | Path | Auth | Body |
| --- | --- | --- | --- |
| `GET` | `/api/signer/trust` | none | — |
| `GET` | `/api/wallet/pots/client-spend-requests/:requestId` | `x-zappi-pot-client` | — |
| `POST` | `/api/wallet/pots/:id/spend-authorizations` | `x-zappi-pot-client` | `{ approvalId, idempotencyKey }` |
| `POST` | `/api/wallet/pots/:id/spend-receipts` | `x-zappi-pot-client` | `{ intentId, status, txid? }` |
| `POST` | `/api/wallet/pots/address-proof-challenge` | none from this CLI | `{ sparkAddress }` |

`idempotencyKey` on spend-authorizations is the spend `requestId`. Receipt `status` is `submitted`, `confirmed`, or `uncertain`. `txid` is required for `submitted` and `confirmed`. `uncertain` may omit it.

The address-challenge response the provision command accepts is `{ nonce, expiresAt, message }`. `message` must start with `zappi-pot-address-bind:v1:` and end with `:create:<sparkAddress>:<nonce>` or `:attach:<sparkAddress>:<nonce>`. The identity key signs that message. A `serverPubkey` on the body, when present, must equal the install pin. A `signature` on the body, when present, is checked and is not stored as a new pin.

The binding receipt is still the §12 object (`v`, `provisionId`, `potId`, `sparkAddress`, `nonce`, `backendSig`). `prove-address` verifies it with `verifyBindingReceipt` and the install pin, then `markBound`.

Public spend status values are `authorization_required`, `submitted`, `confirmed`, `uncertain`, `expired`, and `consumed`. `sign` continues only when the status is `authorization_required`. `status` prints the other values and does not broadcast.

## Divergences

These match §11 in the contract. Where this package and an older plan disagree, the code in `packages/zappi-signer` is what runs.

**Storage.** The vault is the absorbed zappi-pots-mcp file: version 4, `kind` string `zappi-pots-mcp`, path `~/.zappi-signer/seed-vault.json`, keychain service `zappi-signer`. It is not a separate seed-vault envelope.

**Modernization plan.** [MCP_SIGNER_MODERNIZATION_PLAN.md](../../../zappi-plugin/MCP_SIGNER_MODERNIZATION_PLAN.md) assumed an in-place edit of a pre-existing `packages/zappi-signer`. This package was created by absorbing zappi-pots-mcp. The plan items that name `src/policy.ts`, `src/journal.ts`, `src/spark.ts`, `src/seed-vault.ts`, `src/keychain.ts`, `src/platform.ts` (`refuseWindows`), `src/custody.ts`, `src/daemon.ts`, and the shim/helper split are superseded. Windows key storage is `@napi-rs/keyring`. Restart recovery is `FileSpendJournal` in `src/spend-journal.ts`. The live signer is this pull CLI, not an Intent-WS daemon role added to that older tree.

**Address challenge.** Provision calls `POST /api/wallet/pots/address-proof-challenge` with `{ sparkAddress }`. Binding receipt verification remains §12. `provision` does not mark the pot bound.
