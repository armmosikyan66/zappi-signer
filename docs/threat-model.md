# Threat model

Adapted from [MCP_SIGNER_ISOLATION_DESIGN.md](../../../zappi-plugin/MCP_SIGNER_ISOLATION_DESIGN.md). That document describes an older local stdio signer. The store in this package is the absorbed zappi-pots-mcp vault (`src/vault/vault.ts`, version 4, `kind` `zappi-pots-mcp`). The agent path is remote MCP plus this CLI. Section 2.3 of the older document refuses Windows. That refusal is superseded: this package supports Windows through `@napi-rs/keyring` (Windows Credential Manager). See [platforms.md](platforms.md).

The tiers below are the same privilege split. The mechanisms are the ones this package implements.

## Tier A — same user, local shell

This is the realistic agent host. The agent can run commands as the user who owns the vault.

The vault file mode is `0600` under a `0700` directory on macOS and Linux. Those modes stop a different uid. They do not stop this user. A same-user process can read `~/.zappi-signer/seed-vault.json` (ciphertext) and `spend-journal.json`.

The unlock secret and the device factor are keychain items on service `zappi-signer`, not fields in the vault file. On macOS the helper stores them in the login keychain as this-device-only, non-synchronizable items, and it does not fall back to the `security` CLI. On Linux the items are in Secret Service (`@napi-rs/keyring`, store pinned to `secret-service`). On Windows they are in Credential Manager through the same library. A same-user process in an unlocked session can still be able to read those items. Secret Service and Credential Manager are not an app-identity boundary.

`sign --yes` spends without the TTY prompt. A same-user agent that can execute the binary can pass `--yes`. Policy still applies: a sealed policy, no `WILDCARD`, MAINNET USDB, and a backend-signed intent. The agent does not need those checks once it holds the mnemonic.

`policy tighten` asks for user presence. Only the macOS keystore implements that check. On Linux and Windows the method is absent, so tighten fails closed. Presence does not gate `sign --yes`.

Replacing the binary, or pointing `PATH` at another program named `zappi-signer`, makes that program the signer. This package does not add a separate helper uid or an XPC peer check.

## Tier B — root or kernel

Root can read the vault, ptrace the process, and read keychain material the kernel will yield. A software vault cannot survive that. Full OS compromise is out of scope. The device seal stops a copied vault file on a machine that lacks the device factor. It does not stop an attacker who can read this machine's keychain and memory.

## Tier C — MCP only, no shell

If the host gives the agent remote MCP tools and no local execution, the agent cannot read the vault, the keychain, or this binary. Remote `pay`, `send`, and `consume` on a ready free pot return `authorization_required` and `signCommand`. They do not return a seed, a backend signature, the pot client token, or the signer identity-key signature. `payment_status` returns the public status and a txid after one has been posted.

The older document's Tier C tool list (`provision_free_pot`, `sign_free_spend`, and the other local stdio tools) is the absorbed package's former MCP surface. Those tools are not this CLI. The controls that remain meaningful without a shell are the remote approval row, the install pin, and the sealed policy, and they apply when some other principal runs `zappi-signer`.

An agent that cannot run the signer cannot broadcast. An agent that can run the signer is Tier A.

## What this package still enforces

- The mnemonic is wiped after derive, sign, and backup. Command stdout is checked so a result object does not contain it.
- Backend signatures are verified against the install pin. The trust response cannot add a new key on its own.
- `provision` leaves `bound` false. `markBound` follows a verified §12 receipt.
- A journaled txid is not broadcast a second time.
- User-backup ciphertext uses a separate Argon2id passphrase. That passphrase is not the vault unlock secret and is not accepted as an argv flag.
