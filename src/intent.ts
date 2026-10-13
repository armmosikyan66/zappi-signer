/**
 * Spend-intent, lock-attestation, and binding-receipt checks.
 * Canonical bytes follow zappi-plugin/SIGNER_PROTOCOL.md §2, §4, and §12.
 */
import { secp256k1 } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha2'
import { z } from 'zod'
import { PotError } from './errors.js'

export const INTENT_VERSION = 1 as const
export const MAX_INTENT_TTL_MS = 5 * 60 * 1000
export const MAX_CLOCK_SKEW_MS = 30 * 1000
export const MAX_ID_LEN = 128
export const MAX_ADDRESS_LEN = 256
export const MAX_INVOICE_LEN = 2048
export const MAX_BACKEND_SIG_LEN = 512

export const INTENT_KINDS = ['spark_transfer', 'lightning_pay', 'l1_withdraw', 'sweep_to_main'] as const
export type IntentKind = (typeof INTENT_KINDS)[number]

/** keyId → hex secp256k1 public key. Populated only from install pins. */
export type IntentTrustStore = ReadonlyMap<string, string>

export interface SparkTransferPayload {
  to: string
  amountSats: number
  maxFeeSats: number
  amountCents?: number
}

export interface LightningPayPayload {
  invoice: string
  maxFeeSats: number
  amountCents?: number
}

export interface L1WithdrawPayload {
  address: string
  amountSats: number
  amountCents?: number
}

export interface SweepToMainPayload {
  mainAddress: string
  amountCents?: number
}

export type IntentPayload =
  | SparkTransferPayload
  | LightningPayPayload
  | L1WithdrawPayload
  | SweepToMainPayload

export interface SpendIntent {
  v: 1
  intentId: string
  potId: string
  kind: IntentKind
  payload: IntentPayload
  nonce: string
  expiresAt: string
  keyId: string
  backendSig: string
}

export interface LockAttestation {
  decision: 'open' | 'locked'
  nonce: string
  expiresAt: string
  keyId: string
  backendSig: string
}

export interface BindingReceipt {
  v: 1
  provisionId: string
  potId: string
  sparkAddress: string
  nonce: string
  backendSig: string
}

/**
 * Local spending policy supplied by the sign flow.
 * Throw to refuse. A return allows nonce consumption.
 */
export interface NonceRecord {
  intentId: string
  expiresAt: string
}

export interface NonceConsumeResult {
  replay: boolean
  record: NonceRecord
}

/** Ledger port. `NonceLedger` in intent-store.ts is the 0600 file implementation. */
export interface NonceStore {
  consume(nonce: string, intentId: string, expiresAt: string, now?: Date): NonceConsumeResult
}

export type IntentPolicyCheck = (intent: SpendIntent) => void

export interface VerifiedIntent {
  intent: SpendIntent
  /** False when the policy hook was omitted and the nonce was left unused. */
  consumed: boolean
  /** True when the ledger already held this nonce for this intentId. */
  replay: boolean
}

export interface VerifiedLock {
  lock: LockAttestation
  consumed: boolean
  replay: boolean
}

const ISO_UTC = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/
const HEX_RE = /^(?:[0-9a-fA-F]{2})+$/
const PROVISION_ID_RE = /^prov_[0-9a-f]{16}$/

const idSchema = z.string().min(1).max(MAX_ID_LEN).refine((value) => !hasControlChar(value))
const sigSchema = z.string().min(2).max(MAX_BACKEND_SIG_LEN).regex(HEX_RE)
const positiveInt = z.number().int().positive().refine((value) => Number.isSafeInteger(value))
const nonNegativeInt = z.number().int().nonnegative().refine((value) => Number.isSafeInteger(value))
const amountCents = positiveInt.optional()

const sparkPayload = z
  .object({
    to: z.string().min(1).max(MAX_ADDRESS_LEN),
    amountSats: positiveInt,
    maxFeeSats: nonNegativeInt,
    amountCents,
  })
  .strict()

const lightningPayload = z
  .object({
    invoice: z.string().min(1).max(MAX_INVOICE_LEN),
    maxFeeSats: nonNegativeInt,
    amountCents,
  })
  .strict()

const l1Payload = z
  .object({
    address: z.string().min(1).max(MAX_ADDRESS_LEN),
    amountSats: positiveInt,
    amountCents,
  })
  .strict()

const sweepPayload = z
  .object({
    mainAddress: z.string().min(1).max(MAX_ADDRESS_LEN),
    amountCents,
  })
  .strict()

const spendIntentSchema = z.discriminatedUnion('kind', [
  z
    .object({
      v: z.literal(INTENT_VERSION),
      intentId: idSchema,
      potId: idSchema,
      kind: z.literal('spark_transfer'),
      payload: sparkPayload,
      nonce: idSchema,
      expiresAt: z.string().min(1).max(40),
      keyId: idSchema,
      backendSig: sigSchema,
    })
    .strict(),
  z
    .object({
      v: z.literal(INTENT_VERSION),
      intentId: idSchema,
      potId: idSchema,
      kind: z.literal('lightning_pay'),
      payload: lightningPayload,
      nonce: idSchema,
      expiresAt: z.string().min(1).max(40),
      keyId: idSchema,
      backendSig: sigSchema,
    })
    .strict(),
  z
    .object({
      v: z.literal(INTENT_VERSION),
      intentId: idSchema,
      potId: idSchema,
      kind: z.literal('l1_withdraw'),
      payload: l1Payload,
      nonce: idSchema,
      expiresAt: z.string().min(1).max(40),
      keyId: idSchema,
      backendSig: sigSchema,
    })
    .strict(),
  z
    .object({
      v: z.literal(INTENT_VERSION),
      intentId: idSchema,
      potId: idSchema,
      kind: z.literal('sweep_to_main'),
      payload: sweepPayload,
      nonce: idSchema,
      expiresAt: z.string().min(1).max(40),
      keyId: idSchema,
      backendSig: sigSchema,
    })
    .strict(),
])

const lockSchema = z
  .object({
    decision: z.enum(['open', 'locked']),
    nonce: idSchema,
    expiresAt: z.string().min(1).max(40),
    keyId: idSchema,
    backendSig: sigSchema,
    /** Daemon frames carry this. It is not part of the signed body. */
    type: z.string().min(1).max(32).optional(),
  })
  .strict()

const bindingSchema = z
  .object({
    v: z.literal(INTENT_VERSION),
    provisionId: z.string().regex(PROVISION_ID_RE),
    potId: idSchema,
    sparkAddress: z.string().min(1).max(MAX_ADDRESS_LEN),
    nonce: idSchema,
    backendSig: sigSchema,
  })
  .strict()

/** Recursively sorts object keys so canonical bytes are construction-order independent. */
function sortedKeysReplacer(_key: string, value: unknown): unknown {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const sorted: Record<string, unknown> = {}
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = (value as Record<string, unknown>)[key]
    }
    return sorted
  }
  return value
}

export function canonicalIntentBody(intent: Omit<SpendIntent, 'backendSig'>): string {
  const body = {
    expiresAt: intent.expiresAt,
    intentId: intent.intentId,
    keyId: intent.keyId,
    kind: intent.kind,
    nonce: intent.nonce,
    payload: intent.payload,
    potId: intent.potId,
    v: intent.v,
  }
  return JSON.stringify(body, sortedKeysReplacer)
}

export function canonicalLockBody(lock: Omit<LockAttestation, 'backendSig'>): string {
  return JSON.stringify(
    {
      decision: lock.decision,
      expiresAt: lock.expiresAt,
      keyId: lock.keyId,
      nonce: lock.nonce,
      v: 1,
    },
    sortedKeysReplacer,
  )
}

export function canonicalBindingBody(receipt: Omit<BindingReceipt, 'backendSig'>): string {
  return JSON.stringify(
    {
      nonce: receipt.nonce,
      potId: receipt.potId,
      provisionId: receipt.provisionId,
      sparkAddress: receipt.sparkAddress,
      v: receipt.v,
    },
    sortedKeysReplacer,
  )
}

/** Synthetic ledger id for a lock attestation (SIGNER_PROTOCOL §3.4). */
export function lockIntentId(nonce: string): string {
  return `lock:${nonce}`
}

export function parseExpiresAt(value: string, kind: 'intent' | 'lock' = 'intent'): number {
  const match = ISO_UTC.exec(value)
  const yearText = match?.[1]
  const monthText = match?.[2]
  const dayText = match?.[3]
  const hourText = match?.[4]
  const minuteText = match?.[5]
  const secondText = match?.[6]
  if (!yearText || !monthText || !dayText || !hourText || !minuteText || !secondText) {
    throw malformed(kind)
  }
  const year = Number(yearText)
  const month = Number(monthText)
  const day = Number(dayText)
  const hour = Number(hourText)
  const minute = Number(minuteText)
  const second = Number(secondText)
  const fraction = (match?.[7] ?? '').padEnd(3, '0')
  const millis = Number(fraction || '0')
  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    !Number.isInteger(millis)
  ) {
    throw malformed(kind)
  }
  const parsed = new Date(Date.UTC(year, month - 1, day, hour, minute, second, millis))
  if (
    parsed.getUTCFullYear() !== year ||
    parsed.getUTCMonth() !== month - 1 ||
    parsed.getUTCDate() !== day ||
    parsed.getUTCHours() !== hour ||
    parsed.getUTCMinutes() !== minute ||
    parsed.getUTCSeconds() !== second
  ) {
    throw malformed(kind)
  }
  return parsed.getTime()
}

/** True when the acceptance window has closed (`now − 30s >= expiresAt`). */
export function isPastExpiry(expiresAtMs: number, nowMs: number): boolean {
  return nowMs - MAX_CLOCK_SKEW_MS >= expiresAtMs
}

export function assertWithinExpiryWindow(
  expiresAtMs: number,
  nowMs: number,
  kind: 'intent' | 'lock' = 'intent',
): void {
  if (!Number.isFinite(nowMs)) throw malformed(kind)
  if (isPastExpiry(expiresAtMs, nowMs)) {
    throw new PotError(
      kind === 'lock' ? 'lock attestation expired' : 'intent expired',
      kind === 'lock' ? 'LOCK_EXPIRED' : 'INTENT_EXPIRED',
    )
  }
  if (expiresAtMs - nowMs > MAX_INTENT_TTL_MS + MAX_CLOCK_SKEW_MS) {
    throw new PotError(
      kind === 'lock' ? 'lock attestation expiry is too far ahead' : 'intent expiry is too far ahead',
      kind === 'lock' ? 'LOCK_TTL' : 'INTENT_TTL',
    )
  }
}

/**
 * Lower-case hex secp256k1 public key, compressed (33 bytes) or uncompressed (65).
 * Invalid material throws and the message does not include the input.
 */
export function normalizeSecp256k1Pubkey(value: string): string {
  const hex = value.trim().toLowerCase()
  if (!HEX_RE.test(hex)) throw new PotError('signer trust pin is invalid', 'TRUST_PIN_INVALID')
  const bytes = hexToBytes(hex)
  if (bytes.length !== 33 && bytes.length !== 65) {
    throw new PotError('signer trust pin is invalid', 'TRUST_PIN_INVALID')
  }
  if (!secp256k1.utils.isValidPublicKey(bytes)) {
    throw new PotError('signer trust pin is invalid', 'TRUST_PIN_INVALID')
  }
  return hex
}

/**
 * Fail-closed checks, in order: schema, pinned keyId, expiry window,
 * backendSig, optional policy hook, nonce consumption.
 *
 * The policy hook is optional so signature checks stay testable without a
 * vault. When it is omitted, this returns `{ consumed: false }` and does
 * not touch the ledger. Nonce consumption runs only after the hook returns.
 * A hook that throws does not consume. A hook without a ledger fails closed.
 */
export function verifyIntent(input: {
  intent: unknown
  trust: IntentTrustStore
  now?: Date
  policy?: IntentPolicyCheck
  ledger?: NonceStore
}): VerifiedIntent {
  const parsed = parseSpendIntent(input.intent)
  const pubkey = input.trust.get(parsed.keyId)
  if (!pubkey) throw new PotError('intent key is not pinned', 'INTENT_UNTRUSTED_KEY')
  const nowMs = (input.now ?? new Date()).getTime()
  const expiresAtMs = parseExpiresAt(parsed.expiresAt, 'intent')
  assertWithinExpiryWindow(expiresAtMs, nowMs, 'intent')
  if (!verifySha256Secp256k1(canonicalIntentBody(parsed), parsed.backendSig, pubkey)) {
    throw new PotError('intent signature is invalid', 'INTENT_BAD_SIGNATURE')
  }
  if (!input.policy) return { intent: parsed, consumed: false, replay: false }
  input.policy(parsed)
  if (!input.ledger) throw new PotError('intent nonce ledger is required', 'INTENT_LEDGER_REQUIRED')
  const consumed = input.ledger.consume(parsed.nonce, parsed.intentId, parsed.expiresAt, input.now ?? new Date(nowMs))
  return { intent: parsed, consumed: true, replay: consumed.replay }
}

/**
 * Same key, expiry, and signature rules as an intent. `decision: "locked"`
 * refuses after a valid signature and before nonce consumption, so a kill
 * switch is not recorded. When `ledger` is omitted, an open attestation
 * returns `{ consumed: false }`. With a ledger, the nonce is stored as
 * `lock:<nonce>`.
 */
export function verifyLockAttestation(input: {
  lock: unknown
  trust: IntentTrustStore
  now?: Date
  ledger?: NonceStore
}): VerifiedLock {
  const parsed = parseLock(input.lock)
  const pubkey = input.trust.get(parsed.keyId)
  if (!pubkey) throw new PotError('lock key is not pinned', 'LOCK_UNTRUSTED_KEY')
  const nowMs = (input.now ?? new Date()).getTime()
  const expiresAtMs = parseExpiresAt(parsed.expiresAt, 'lock')
  assertWithinExpiryWindow(expiresAtMs, nowMs, 'lock')
  if (!verifySha256Secp256k1(canonicalLockBody(parsed), parsed.backendSig, pubkey)) {
    throw new PotError('lock signature is invalid', 'LOCK_BAD_SIGNATURE')
  }
  if (parsed.decision === 'locked') throw new PotError('Spend is locked. Refusing the spend.', 'LOCK_LOCKED')
  if (!input.ledger) return { lock: parsed, consumed: false, replay: false }
  const consumed = input.ledger.consume(
    parsed.nonce,
    lockIntentId(parsed.nonce),
    parsed.expiresAt,
    input.now ?? new Date(nowMs),
  )
  return { lock: parsed, consumed: true, replay: consumed.replay }
}

/** Schema and signature against the install pin. Does not learn a key from the receipt. */
export function verifyBindingReceipt(
  receipt: unknown,
  serverPubkey: string,
  expected?: { provisionId?: string; potId?: string; sparkAddress?: string },
): BindingReceipt {
  const parsed = parseBinding(receipt)
  if (serverPubkey.trim() === '') throw new PotError('signer trust is not pinned', 'TRUST_UNPINNED')
  const pin = normalizeSecp256k1Pubkey(serverPubkey)
  if (!verifySha256Secp256k1(canonicalBindingBody(parsed), parsed.backendSig, pin)) {
    throw new PotError('binding receipt signature is invalid', 'BINDING_BAD_SIGNATURE')
  }
  if (expected?.provisionId !== undefined && expected.provisionId !== parsed.provisionId) {
    throw new PotError('binding receipt does not match the provision', 'BINDING_MISMATCH')
  }
  if (expected?.potId !== undefined && expected.potId !== parsed.potId) {
    throw new PotError('binding receipt does not match the pot', 'BINDING_MISMATCH')
  }
  if (expected?.sparkAddress !== undefined && expected.sparkAddress !== parsed.sparkAddress) {
    throw new PotError('binding receipt does not match the address', 'BINDING_MISMATCH')
  }
  return parsed
}

function parseSpendIntent(value: unknown): SpendIntent {
  const parsed = spendIntentSchema.safeParse(value)
  if (!parsed.success) throw new PotError('intent is malformed', 'INTENT_MALFORMED')
  return {
    v: 1,
    intentId: parsed.data.intentId,
    potId: parsed.data.potId,
    kind: parsed.data.kind,
    payload: parsed.data.payload,
    nonce: parsed.data.nonce,
    expiresAt: parsed.data.expiresAt,
    keyId: parsed.data.keyId,
    backendSig: parsed.data.backendSig,
  }
}

function parseLock(value: unknown): LockAttestation {
  const parsed = lockSchema.safeParse(value)
  if (!parsed.success) throw new PotError('lock attestation is malformed', 'LOCK_MALFORMED')
  return {
    decision: parsed.data.decision,
    nonce: parsed.data.nonce,
    expiresAt: parsed.data.expiresAt,
    keyId: parsed.data.keyId,
    backendSig: parsed.data.backendSig,
  }
}

function parseBinding(value: unknown): BindingReceipt {
  const parsed = bindingSchema.safeParse(value)
  if (!parsed.success) throw new PotError('binding receipt is malformed', 'BINDING_MALFORMED')
  return parsed.data
}

function malformed(kind: 'intent' | 'lock'): PotError {
  if (kind === 'lock') return new PotError('lock attestation is malformed', 'LOCK_MALFORMED')
  return new PotError('intent is malformed', 'INTENT_MALFORMED')
}

/** sha256(utf8(message)), then secp256k1. Compact 64-byte signatures are preferred; DER is accepted. */
function verifySha256Secp256k1(message: string, signatureHex: string, pubkeyHex: string): boolean {
  try {
    const digest = sha256(Buffer.from(message, 'utf8'))
    const signature = hexToBytes(signatureHex.trim())
    const pubkey = hexToBytes(pubkeyHex.trim())
    const format = signature.length === 64 ? 'compact' : 'der'
    return secp256k1.verify(signature, digest, pubkey, { prehash: false, format })
  } catch {
    return false
  }
}

function hasControlChar(value: string): boolean {
  for (const char of value) {
    if (char.charCodeAt(0) <= 0x1f) return true
  }
  return false
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim().toLowerCase()
  if (!HEX_RE.test(clean)) throw new Error('invalid hex')
  const out = new Uint8Array(clean.length / 2)
  for (let index = 0; index < out.length; index += 1) {
    out[index] = Number.parseInt(clean.slice(index * 2, index * 2 + 2), 16)
  }
  return out
}
