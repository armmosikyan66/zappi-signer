/**
 * Provision a pending free pot, and mark it bound only after a §12 receipt.
 *
 * Address challenge: POST /api/wallet/pots/address-proof-challenge
 * with `{ sparkAddress }`. The identity key signs that route's `message`.
 * prove-address uses verifyBindingReceipt and then VaultStore.markBound.
 */
import { randomBytes } from 'node:crypto'
import { secp256k1 } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha2'
import { generateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
import { PotError } from '../errors.js'
import {
  assertWithinExpiryWindow,
  normalizeSecp256k1Pubkey,
  parseExpiresAt,
  verifyBindingReceipt,
  type NonceStore,
} from '../intent.js'
import { debugCause } from '../log.js'
import { utcDay } from '../policy/policy.js'
import { assertSparkAddress } from '../spark/address.js'
import { type SparkSigner } from '../spark/signer.js'
import { verifyPinnedTrust, type PinnedTrust } from '../trust.js'
import { pickConfirmPositions, type VaultStore } from '../vault/vault.js'
import { assertResultHasNoMnemonic } from '../zeroize.js'

export const SIGNER_TRUST_PATH = '/api/signer/trust'

/** Nest pots.controller `POST wallet/pots/address-proof-challenge` (global prefix `api`). */
export const ADDRESS_PROOF_CHALLENGE_PATH = '/api/wallet/pots/address-proof-challenge'

const BIND_PREFIX = 'zappi-pot-address-bind:v1:'
export const NONCE_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
export const PUBKEY_RE = /^(02|03)[0-9a-fA-F]{64}$|^04[0-9a-fA-F]{128}$/

export interface ProvisionClient {
  request(method: 'GET' | 'POST', path: string, body?: unknown): Promise<unknown>
}

export interface ProvisionResult {
  potId: string
  /** Sent on bind_pot_address so Nest can return a §12 binding receipt. */
  provisionId: string
  address: string
  pubkey: string
  /** Identity-key signature over the server challenge message. */
  signature: string
  /** Address-proof challenge id (`nonce`) for bind_pot_address. */
  nonce: string
}

export interface ProveAddressResult {
  potId: string
  address: string
  bound: true
}

export async function runProvision(input: {
  vault: VaultStore
  spark: SparkSigner
  client: ProvisionClient
  trust: PinnedTrust
  ledger: NonceStore
  potLabel?: string
}): Promise<ProvisionResult> {
  if (input.potLabel !== undefined && !usableLabel(input.potLabel)) {
    throw new PotError('label is unusable', 'LABEL_INVALID')
  }
  const serverPubkey = input.trust.serverPubkey
  if (!serverPubkey) throw new PotError('signer trust is not pinned', 'TRUST_UNPINNED')
  const pin = normalizeSecp256k1Pubkey(serverPubkey)
  const trustDocument = await call(input.client, 'GET', SIGNER_TRUST_PATH)
  verifyPinnedTrust(input.trust, trustDocument)

  const mnemonic = generateMnemonic(wordlist, 128)
  const phrase = Buffer.from(mnemonic, 'utf8')
  try {
    const derived = await derivePot(input.spark, phrase)
    // Divergence: SIGNER_PROTOCOL §12 signs canonicalBindingBody; this route takes { sparkAddress } and the identity key signs the returned `message`.
    // Nest stores action `create` here. bind_pot_address consumes `attach` from MCP start_pot_address_proof; the signer signs the action in the server message.
    const challenge = parseChallenge(
      await call(input.client, 'POST', ADDRESS_PROOF_CHALLENGE_PATH, {
        sparkAddress: derived.address,
      }),
      derived.address,
      pin,
    )
    if (challenge.message.includes(mnemonic)) {
      throw new PotError('address challenge is malformed', 'CHALLENGE_MALFORMED')
    }
    const consumed = input.ledger.consume(
      challenge.nonce,
      `challenge:${challenge.nonce}`,
      challenge.expiresAt,
      new Date(),
    )
    if (consumed.replay) throw new PotError('address challenge was already used', 'CHALLENGE_REPLAY')
    const created = await input.vault.create({
      mnemonic,
      address: derived.address,
      pubkey: derived.pubkey,
      accountIndex: 1,
      network: 'MAINNET',
      positions: pickConfirmPositions(),
      today: utcDay(new Date()),
      role: 'free',
      ...(input.potLabel !== undefined ? { label: input.potLabel } : {}),
    })
    const signature = await signChallenge(input.spark, phrase, challenge.message, derived.pubkey)
    const result: ProvisionResult = {
      potId: created.potId,
      provisionId: `prov_${randomBytes(8).toString('hex')}`,
      address: derived.address,
      pubkey: derived.pubkey,
      signature,
      nonce: challenge.nonce,
    }
    assertResultHasNoMnemonic(result, mnemonic)
    return result
  } finally {
    phrase.fill(0)
  }
}

/**
 * Verify a §12 binding receipt, then mark the local pot bound.
 * A failed check leaves the pot unbound.
 */
export async function runProveAddress(input: {
  vault: VaultStore
  trust: PinnedTrust
  bindingReceipt: unknown
  potId: string
}): Promise<ProveAddressResult> {
  const serverPubkey = input.trust.serverPubkey
  if (!serverPubkey) throw new PotError('signer trust is not pinned', 'TRUST_UNPINNED')
  if (input.potId.trim() === '') throw new PotError('no pot')
  const snapshot = await input.vault.snapshot(input.potId)
  if (!snapshot) throw new PotError('no pot')
  const verified = verifyBindingReceipt(input.bindingReceipt, serverPubkey, {
    potId: input.potId,
    sparkAddress: snapshot.address,
  })
  await input.vault.markBound(input.potId)
  return { potId: input.potId, address: verified.sparkAddress, bound: true }
}

async function call(
  client: ProvisionClient,
  method: 'GET' | 'POST',
  path: string,
  body?: unknown,
): Promise<unknown> {
  try {
    return await client.request(method, path, body)
  } catch (error) {
    if (error instanceof PotError) throw error
    throw new PotError('request failed')
  }
}

export async function derivePot(spark: SparkSigner, phrase: Uint8Array): Promise<{ address: string; pubkey: string }> {
  try {
    const derived = await spark.derive(phrase, 'MAINNET')
    assertSparkAddress(derived.address)
    if (!PUBKEY_RE.test(derived.pubkey)) throw new PotError('spark derive returned an invalid pubkey', 'SPARK_DERIVE_INVALID')
    return { address: derived.address, pubkey: derived.pubkey }
  } catch (error) {
    if (error instanceof PotError) {
      // Coded errors (and the legacy explicit collapse) pass through intact.
      if (error.code !== undefined || error.message === 'could not create pot') throw error
      if (error.message === 'could not reach Spark') throw sparkUnreachable(error)
      throw new PotError('could not create pot', 'SPARK_DERIVE_INVALID')
    }
    throw sparkUnreachable(error)
  }
}

/** Swallowed Spark/network causes become one safe code; debugCause explains why under ZAPPI_SIGNER_DEBUG=1. */
function sparkUnreachable(error: unknown): PotError {
  debugCause(error)
  return new PotError('spark unreachable', 'SPARK_UNREACHABLE')
}

export async function signChallenge(
  spark: SparkSigner,
  phrase: Uint8Array,
  message: string,
  pubkey: string,
): Promise<string> {
  let signed: { signature: string; pubkey: string }
  try {
    signed = await spark.signRelay(phrase, 'MAINNET', message)
  } catch (error) {
    if (error instanceof PotError && error.code !== undefined) throw error
    debugCause(error)
    throw new PotError('could not sign the challenge', 'SPARK_SIGN_FAILED')
  }
  if (signed.pubkey.toLowerCase() !== pubkey.toLowerCase()) {
    throw new PotError('signature pubkey does not match the derived pubkey', 'SPARK_SIGN_MISMATCH')
  }
  const signature = signed.signature.trim().toLowerCase()
  if (!isIdentitySignature(signature)) throw new PotError('signature is malformed', 'SPARK_SIGN_FAILED')
  return signature
}

interface ParsedChallenge {
  nonce: string
  expiresAt: string
  message: string
}

function parseChallenge(value: unknown, sparkAddress: string, pin: string): ParsedChallenge {
  const body = record(value)
  const nonce = typeof body.nonce === 'string' ? body.nonce.trim() : ''
  const expiresAt = typeof body.expiresAt === 'string' ? body.expiresAt.trim() : ''
  const message = typeof body.message === 'string' ? body.message : ''
  if (!NONCE_RE.test(nonce) || !typedChallengeMessage(message, sparkAddress, nonce)) {
    throw new PotError('address challenge is malformed', 'CHALLENGE_MALFORMED')
  }
  try {
    const expiresAtMs = parseExpiresAt(expiresAt, 'intent')
    assertWithinExpiryWindow(expiresAtMs, Date.now(), 'intent')
  } catch (error) {
    if (error instanceof PotError && (error.code === 'INTENT_EXPIRED' || error.code === 'INTENT_TTL')) {
      throw new PotError('address challenge expired', 'CHALLENGE_EXPIRED')
    }
    throw new PotError('address challenge is malformed', 'CHALLENGE_MALFORMED')
  }
  if (body.serverPubkey !== undefined) {
    let advertised: string
    try {
      advertised = normalizeSecp256k1Pubkey(typeof body.serverPubkey === 'string' ? body.serverPubkey : '')
    } catch (error) {
      if (error instanceof PotError) throw new PotError('signer trust pin mismatch', 'TRUST_MISMATCH')
      throw new PotError('address challenge is malformed', 'CHALLENGE_MALFORMED')
    }
    if (advertised !== pin) throw new PotError('signer trust pin mismatch', 'TRUST_MISMATCH')
  }
  // Nest's HTTP JSON omits `signature`. MCP start_pot_address_proof includes it; never learn a key from it.
  if (body.signature !== undefined) {
    const signature = typeof body.signature === 'string' ? body.signature.trim() : ''
    if (!verifyMessage(message, signature, pin)) {
      throw new PotError('address challenge signature is invalid', 'CHALLENGE_BAD_SIGNATURE')
    }
  }
  return { nonce, expiresAt, message }
}

/** Server message `zappi-pot-address-bind:v1:<project>:<subject>:<action>:<address>:<nonce>`. Subject may contain colons. */
export function typedChallengeMessage(message: string, sparkAddress: string, nonce: string): boolean {
  if (message.length < BIND_PREFIX.length + 8 || message.length > 512) return false
  if (message !== message.trim() || hasControl(message) || !message.startsWith(BIND_PREFIX)) return false
  const suffix = message.endsWith(`:attach:${sparkAddress}:${nonce}`)
    ? `:attach:${sparkAddress}:${nonce}`
    : message.endsWith(`:create:${sparkAddress}:${nonce}`)
      ? `:create:${sparkAddress}:${nonce}`
      : ''
  if (!suffix) return false
  const middle = message.slice(BIND_PREFIX.length, message.length - suffix.length)
  const split = middle.indexOf(':')
  return split > 0 && split < middle.length - 1
}

export function verifyMessage(message: string, signatureHex: string, pubkeyHex: string): boolean {
  try {
    const clean = signatureHex.trim().toLowerCase()
    if (!/^[0-9a-f]+$/.test(clean) || clean.length % 2 !== 0) return false
    const signature = Buffer.from(clean, 'hex')
    const pubkey = Buffer.from(pubkeyHex.trim().toLowerCase(), 'hex')
    const digest = sha256(Buffer.from(message, 'utf8'))
    const format = signature.length === 64 ? 'compact' : 'der'
    return secp256k1.verify(signature, digest, pubkey, { prehash: false, format })
  } catch {
    return false
  }
}

function isIdentitySignature(value: string): boolean {
  return value.length >= 64 && value.length <= 200 && value.length % 2 === 0 && /^[0-9a-f]+$/.test(value)
}

export function usableLabel(value: string): boolean {
  return value.length <= 64 && !hasControl(value)
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new PotError('address challenge is malformed', 'CHALLENGE_MALFORMED')
  }
  return value as Record<string, unknown>
}

function hasControl(value: string): boolean {
  for (const char of value) {
    if (char.charCodeAt(0) <= 0x1f || char.charCodeAt(0) === 0x7f) return true
  }
  return false
}
