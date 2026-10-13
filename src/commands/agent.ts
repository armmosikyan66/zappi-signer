/**
 * Server-pot-first commands (the MCP free-pot flow).
 *
 * The backend pot already exists (`create_pot`); the wallet is created on
 * this machine and bound to it:
 *  1. `provision <potId>` — generate the mnemonic locally, store the record
 *     under the backend pot id, and return the Spark address. Idempotent:
 *     re-running returns the same wallet instead of a second one.
 *  2. `prove-address <provisionId> --challenge <json>` — verify the
 *     server-signed `attach` challenge against the pinned server pubkey,
 *     then sign its message with the address identity key. The signature is
 *     what `bind_pot_address` submits.
 *  3. `finalize --pot <id>` — verify the backend-signed binding receipt and
 *     mark the record bound.
 *
 * The mnemonic never leaves this machine and is never returned.
 */
import { randomBytes } from 'node:crypto'
import { generateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
import { PotError } from '../errors.js'
import {
  assertWithinExpiryWindow,
  normalizeSecp256k1Pubkey,
  parseExpiresAt,
  verifyBindingReceipt,
} from '../intent.js'
import { utcDay } from '../policy/policy.js'
import { assertSparkAddress } from '../spark/address.js'
import { type SparkSigner } from '../spark/signer.js'
import type { PinnedTrust } from '../trust.js'
import { assertResultHasNoMnemonic } from '../zeroize.js'
import {
  pickConfirmPositions,
  type MnemonicContext,
  type PotSnapshot,
  SERVER_POT_ID_RE,
} from '../vault/vault.js'
import {
  NONCE_RE,
  derivePot,
  typedChallengeMessage,
  usableLabel,
  verifyMessage,
} from './provision.js'

const PROVISION_ID_RE = /^prov_[0-9a-f]{16}$/

/** Vault surface the agent commands need (VaultStore satisfies this). */
export interface AgentVault {
  list(): Promise<PotSnapshot[]>
  snapshot(potId?: string): Promise<PotSnapshot | null>
  create(input: {
    potId: string
    provisionId: string
    mnemonic: string
    address: string
    pubkey: string
    accountIndex: 1
    network: 'MAINNET'
    positions: [number, number, number]
    today: string
    role: 'free'
    label?: string
  }): Promise<{ potId: string; createdAt: string }>
  markBound(potId: string): Promise<void>
  withMnemonic<T>(potId: string, fn: (ctx: MnemonicContext) => Promise<T>): Promise<T>
}

export interface AgentProvisionResult {
  potId: string
  provisionId: string
  address: string
  pubkey: string
}

export interface ProveChallengeResult {
  potId: string
  provisionId: string
  sparkAddress: string
  pubkey: string
  /** Identity-key signature over the challenge message, for bind_pot_address. */
  signature: string
  nonce: string
}

export interface FinalizeResult {
  potId: string
  address: string
  bound: true
}

export async function runAgentProvision(input: {
  vault: AgentVault
  spark: SparkSigner
  potId: string
  label?: string
}): Promise<AgentProvisionResult> {
  const potId = input.potId.trim().toLowerCase()
  if (!SERVER_POT_ID_RE.test(potId)) {
    throw new PotError('pot id is not a server pot id')
  }
  if (input.label !== undefined && !usableLabel(input.label)) {
    throw new PotError('could not create pot')
  }
  // Idempotent resume: the wallet for this pot already exists locally.
  const existing = (await input.vault.list()).find((pot) => pot.potId === potId)
  if (existing) {
    return {
      potId,
      provisionId: existing.provisionId ?? '',
      address: existing.address,
      pubkey: existing.pubkey,
    }
  }
  const provisionId = `prov_${randomBytes(8).toString('hex')}`
  const mnemonic = generateMnemonic(wordlist, 128)
  const phrase = Buffer.from(mnemonic, 'utf8')
  try {
    const derived = await derivePot(input.spark, phrase)
    const created = await input.vault.create({
      potId,
      provisionId,
      mnemonic,
      address: derived.address,
      pubkey: derived.pubkey,
      accountIndex: 1,
      network: 'MAINNET',
      positions: pickConfirmPositions(),
      today: utcDay(new Date()),
      role: 'free',
      ...(input.label !== undefined ? { label: input.label } : {}),
    })
    const result: AgentProvisionResult = {
      potId: created.potId,
      provisionId,
      address: derived.address,
      pubkey: derived.pubkey,
    }
    assertResultHasNoMnemonic(result, mnemonic)
    return result
  } finally {
    phrase.fill(0)
  }
}

export async function runProveChallenge(input: {
  vault: AgentVault
  spark: SparkSigner
  trust: PinnedTrust
  provisionId: string
  challenge: unknown
}): Promise<ProveChallengeResult> {
  const serverPubkey = input.trust.serverPubkey
  if (!serverPubkey) throw new PotError('signer trust is not pinned', 'TRUST_UNPINNED')
  const pin = normalizeSecp256k1Pubkey(serverPubkey)
  const provisionId = input.provisionId.trim()
  if (!PROVISION_ID_RE.test(provisionId)) {
    throw new PotError('provision id is malformed', 'BINDING_MALFORMED')
  }
  const challenge = parseAttachChallenge(input.challenge, pin)
  const matches = (await input.vault.list()).filter((pot) => pot.provisionId === provisionId)
  if (matches.length === 0) throw new PotError('no pot')
  if (matches.length > 1) throw new PotError('provision is ambiguous', 'BINDING_MISMATCH')
  const pot = matches[0] as PotSnapshot
  const signature = await input.vault.withMnemonic(pot.potId, async (ctx) => {
    if (ctx.address !== challenge.sparkAddress || ctx.pubkey !== pot.pubkey) {
      throw new PotError('challenge does not match the provision', 'BINDING_MISMATCH')
    }
    return signIdentity(input.spark, ctx.mnemonic, ctx.network, challenge.message, ctx.pubkey)
  })
  return {
    potId: pot.potId,
    provisionId,
    sparkAddress: challenge.sparkAddress,
    pubkey: pot.pubkey,
    signature,
    nonce: challenge.nonce,
  }
}

export async function runFinalize(input: {
  vault: Pick<AgentVault, 'snapshot' | 'markBound'>
  trust: PinnedTrust
  potId: string
  bindingReceipt: unknown
}): Promise<FinalizeResult> {
  const serverPubkey = input.trust.serverPubkey
  if (!serverPubkey) throw new PotError('signer trust is not pinned', 'TRUST_UNPINNED')
  const potId = input.potId.trim().toLowerCase()
  if (!SERVER_POT_ID_RE.test(potId)) throw new PotError('no pot')
  const snapshot = await input.vault.snapshot(potId)
  if (!snapshot) throw new PotError('no pot')
  if (snapshot.provisionId === undefined) {
    throw new PotError('binding receipt does not match the provision', 'BINDING_MISMATCH')
  }
  const verified = verifyBindingReceipt(input.bindingReceipt, serverPubkey, {
    provisionId: snapshot.provisionId,
    potId,
    sparkAddress: snapshot.address,
  })
  await input.vault.markBound(potId)
  return { potId, address: verified.sparkAddress, bound: true }
}

interface AttachChallenge {
  nonce: string
  expiresAt: string
  message: string
  sparkAddress: string
}

/** Sign the challenge message with the address identity key. */
async function signIdentity(
  spark: SparkSigner,
  phrase: Uint8Array,
  network: 'MAINNET' | 'REGTEST' | 'TESTNET',
  message: string,
  pubkey: string,
): Promise<string> {
  let signed: { signature: string; pubkey: string }
  try {
    signed = await spark.signRelay(phrase, network, message)
  } catch (error) {
    if (error instanceof PotError) throw error
    throw new PotError('could not sign the address challenge')
  }
  if (signed.pubkey.toLowerCase() !== pubkey.toLowerCase()) {
    throw new PotError('challenge does not match the provision', 'BINDING_MISMATCH')
  }
  const signature = signed.signature.trim().toLowerCase()
  if (!isIdentitySignature(signature)) {
    throw new PotError('address challenge signature is invalid', 'CHALLENGE_BAD_SIGNATURE')
  }
  return signature
}

function isIdentitySignature(value: string): boolean {
  return value.length >= 64 && value.length <= 200 && value.length % 2 === 0 && /^[0-9a-f]+$/.test(value)
}

/**
 * MCP `start_pot_address_proof` body: `{ nonce, message, expiresAt,
 * sparkAddress, action: 'attach', signature }`. The pin comes from
 * trust-server — a `serverPubkey` field inside the challenge is refused so
 * the pin can never be learned from the challenge itself.
 */
function parseAttachChallenge(value: unknown, pin: string): AttachChallenge {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new PotError('address challenge is malformed', 'CHALLENGE_MALFORMED')
  }
  const body = value as Record<string, unknown>
  if (body.serverPubkey !== undefined) {
    throw new PotError('address challenge is malformed', 'CHALLENGE_MALFORMED')
  }
  const nonce = typeof body.nonce === 'string' ? body.nonce.trim() : ''
  const expiresAt = typeof body.expiresAt === 'string' ? body.expiresAt.trim() : ''
  const message = typeof body.message === 'string' ? body.message : ''
  const sparkAddress = typeof body.sparkAddress === 'string' ? body.sparkAddress.trim() : ''
  const action = typeof body.action === 'string' ? body.action : ''
  const signature = typeof body.signature === 'string' ? body.signature : ''
  if (action !== 'attach' || !NONCE_RE.test(nonce)) {
    throw new PotError('address challenge is malformed', 'CHALLENGE_MALFORMED')
  }
  try {
    assertSparkAddress(sparkAddress)
  } catch (error) {
    if (error instanceof PotError) {
      throw new PotError('address challenge is malformed', 'CHALLENGE_MALFORMED')
    }
    throw error
  }
  if (
    !typedChallengeMessage(message, sparkAddress, nonce) ||
    !message.endsWith(`:attach:${sparkAddress}:${nonce}`)
  ) {
    throw new PotError('address challenge is malformed', 'CHALLENGE_MALFORMED')
  }
  let expiresAtMs: number
  try {
    expiresAtMs = parseExpiresAt(expiresAt, 'intent')
    assertWithinExpiryWindow(expiresAtMs, Date.now(), 'intent')
  } catch (error) {
    if (error instanceof PotError && (error.code === 'INTENT_EXPIRED' || error.code === 'INTENT_TTL')) {
      throw new PotError('address challenge expired', 'CHALLENGE_EXPIRED')
    }
    throw new PotError('address challenge is malformed', 'CHALLENGE_MALFORMED')
  }
  if (!verifyMessage(message, signature, pin)) {
    throw new PotError('address challenge signature is invalid', 'CHALLENGE_BAD_SIGNATURE')
  }
  return { nonce, expiresAt, message, sparkAddress }
}