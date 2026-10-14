import { PotError } from './errors.js'
import {
  assertSignerBaseUrl,
  DEFAULT_SIGNER_API_URL,
  loadPinnedApiBaseUrl,
  signerApiBaseUrl,
  SIGNER_API_URL_ENV,
} from './config.js'
import { potClientTokenAccount, type KeyStore } from './keystore/types.js'

/**
 * Pull-model client for the live Nest routes (global prefix `api`).
 *
 * Field names match spend-intent.dto.ts. No divergence:
 * - GET  /api/wallet/pots/client-spend-requests/:requestId
 * - POST /api/wallet/pots/:id/spend-authorizations
 *   JSON { approvalId, idempotencyKey } — pass the spend requestId as idempotencyKey
 * - POST /api/wallet/pots/:id/spend-receipts
 *   JSON { intentId, txid, status } — status is submitted | confirmed | uncertain.
 *   txid is optional on the server and may be omitted only for uncertain.
 * - GET  /api/signer/trust — no pot client token; the route is not spend auth.
 *
 * The pot id is not a path parameter on the spend-request GET. It selects
 * the keychain account `pot-client-token-<potId>`.
 */

export const POT_CLIENT_HEADER = 'x-zappi-pot-client'

/**
 * Signer-auth fallback headers. MCP wallet-first free pots never go through
 * an attach ceremony, so no pot client token exists for them. The signer
 * instead signs each request with the pot's Spark identity key; Nest derives
 * the expected public key from the pot's stored sparkAddress. The message
 * format is duplicated on the server (pot-signer-auth.ts) and pinned by tests.
 */
export const POT_SIGNER_POT_HEADER = 'x-zappi-pot-id'
export const POT_SIGNER_STAMP_HEADER = 'x-zappi-pot-signer-stamp'
export const POT_SIGNER_SIGNATURE_HEADER = 'x-zappi-pot-signer-signature'

export function potSignerAuthMessage(input: {
  scope: string
  potId: string
  subject: string
  stamp: string
}): string {
  return `zappi-pot-signer:v1:${input.scope}:${input.potId}:${input.subject}:${input.stamp}`
}

/** Signed material for one API call. The signature binds scope+potId+subject+stamp. */
export interface SignerAuthMaterial {
  stamp: string
  signature: string
}

/**
 * Produces an identity-key signature for one signer API call. Called only
 * when the keychain has no pot client token for the pot.
 */
export type SignerAuthProvider = (input: {
  scope: 'get' | 'authorize' | 'receipt'
  subject: string
  potId: string
}) => Promise<SignerAuthMaterial>

const REFUSE = 'refused to spend'
const DEFAULT_TIMEOUT_MS = 10_000
const MAX_TIMEOUT_MS = 60_000
const MAX_TOKEN_LENGTH = 2048

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

const CLIENT_SPEND_STATUSES = [
  'authorization_required',
  'submitted',
  'confirmed',
  'uncertain',
  'expired',
  'consumed',
] as const

export type ClientSpendPublicStatus = (typeof CLIENT_SPEND_STATUSES)[number]

export type SpendReceiptStatus = 'submitted' | 'confirmed' | 'uncertain'

/** GET /api/wallet/pots/client-spend-requests/:requestId */
export interface ClientSpendRequestResponse {
  requestId: string
  approvalId: string
  potId: string
  amountCents: number
  receiverSparkAddress: string
  network: 'MAINNET'
  status: ClientSpendPublicStatus
}

/** POST /api/wallet/pots/:id/spend-authorizations */
export interface SpendAuthorizationBody {
  approvalId: string
  idempotencyKey: string
}

export interface SpendIntentWire {
  v: 1
  intentId: string
  potId: string
  kind: string
  payload: Record<string, unknown>
  nonce: string
  expiresAt: string
  keyId: string
  backendSig: string
}

export interface LockAttestationWire {
  decision: 'open' | 'locked'
  nonce: string
  expiresAt: string
  keyId: string
  backendSig: string
}

export interface SpendAuthorizationResponse {
  intent: SpendIntentWire
  lock: LockAttestationWire
}

/** POST /api/wallet/pots/:id/spend-receipts */
export interface SpendReceiptBody {
  intentId: string
  txid?: string
  status: SpendReceiptStatus
}

export interface SpendReceiptResponse {
  intentId: string
  status: string
  txid: string | null
  receiptStatus: SpendReceiptStatus | null
}

/** GET /api/signer/trust */
export interface SignerTrustResponse {
  keys: Record<string, string>
  activeKeyId: string
  addressChallengePubkey?: string
}

export interface SignerBackendClientOptions {
  keystore: KeyStore
  /** Test double. Production uses global fetch. */
  fetch?: typeof fetch
  /** Overrides ZAPPI_SIGNER_API_URL. */
  baseUrl?: string
  /** Read when baseUrl is omitted. Defaults to process.env. */
  env?: Readonly<Record<string, string | undefined>>
  /** Install-time origin pin location. Defaults to ~/.zappi-signer/api.json. */
  apiConfigPath?: string
  /** Finite deadline in milliseconds. Failure refuses the spend. */
  timeoutMs?: number
  /**
   * Identity-key signing fallback for pots with no keychain client token
   * (MCP wallet-first free pots). When the token is absent, each request is
   * signed with the pot's Spark identity key instead.
   */
  signerAuth?: SignerAuthProvider
}

type FetchResult =
  | { kind: 'response'; response: Response }
  | { kind: 'fail' }
  | { kind: 'timeout' }

export class SignerBackendClient {
  private readonly baseUrl: string
  private readonly fetchImpl: typeof fetch
  private readonly keystore: KeyStore
  private readonly timeoutMs: number
  private readonly signerAuth?: SignerAuthProvider

  constructor(options: SignerBackendClientOptions) {
    this.keystore = options.keystore
    this.fetchImpl =
      options.fetch ??
      ((input: string | URL | Request, init?: RequestInit) => globalThis.fetch(input, init))
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TIMEOUT_MS) refuse()
    this.timeoutMs = timeoutMs
    const env = options.env ?? process.env
    const fromEnv = env[SIGNER_API_URL_ENV]?.trim() || undefined
    // Resolution order: explicit baseUrl (test seam) > ZAPPI_SIGNER_API_URL >
    // install-time pin (~/.zappi-signer/api.json) > the production default.
    const raw =
      options.baseUrl ??
      fromEnv ??
      loadPinnedApiBaseUrl({ env, ...(options.apiConfigPath !== undefined ? { configPath: options.apiConfigPath } : {}) }) ??
      DEFAULT_SIGNER_API_URL
    this.baseUrl = signerApiBaseUrl(raw)
    this.signerAuth = options.signerAuth
  }

  /** Public spend-request lookup. potId selects the keychain token, not the path. */
  async getClientSpendRequest(potId: string, requestId: string): Promise<ClientSpendRequestResponse> {
    const request = uuid(requestId)
    const body = await this.request(
      'GET',
      `/api/wallet/pots/client-spend-requests/${encodeURIComponent(request)}`,
      potId,
      undefined,
      { scope: 'get', subject: request },
    )
    return parseClientSpendRequest(body)
  }

  /** Mints a backend-signed spend intent. idempotencyKey is the spend requestId. */
  async createSpendAuthorization(
    potId: string,
    body: SpendAuthorizationBody,
  ): Promise<SpendAuthorizationResponse> {
    const payload = {
      approvalId: uuid(body.approvalId),
      idempotencyKey: uuid(body.idempotencyKey),
    }
    const response = await this.request(
      'POST',
      `/api/wallet/pots/${encodeURIComponent(uuid(potId))}/spend-authorizations`,
      potId,
      payload,
      { scope: 'authorize', subject: payload.idempotencyKey },
    )
    return parseSpendAuthorization(response)
  }

  /** Reports broadcast state. uncertain may omit txid; submitted and confirmed may not. */
  async postSpendReceipt(potId: string, body: SpendReceiptBody): Promise<SpendReceiptResponse> {
    const status = receiptStatus(body.status)
    const payload: SpendReceiptBody = {
      intentId: uuid(body.intentId),
      status,
    }
    const txid = normalizeTxid(body.txid, status)
    if (txid !== null) payload.txid = txid
    const response = await this.request(
      'POST',
      `/api/wallet/pots/${encodeURIComponent(uuid(potId))}/spend-receipts`,
      potId,
      payload,
      { scope: 'receipt', subject: payload.intentId },
    )
    return parseSpendReceipt(response)
  }

  /** Pin advertisement. Unauthenticated; the pot client token is not sent. */
  async getSignerTrust(): Promise<SignerTrustResponse> {
    const body = await this.request('GET', '/api/signer/trust', null)
    return parseSignerTrust(body)
  }

  private async request(
    method: 'GET' | 'POST',
    path: string,
    potId: string | null,
    jsonBody?: unknown,
    signerAuthScope?: { scope: 'get' | 'authorize' | 'receipt'; subject: string },
  ): Promise<unknown> {
    const url = endpoint(this.baseUrl, path)
    const headers: Record<string, string> = { accept: 'application/json' }
    if (potId !== null) {
      const token = await this.tokenOrNull(potId)
      if (token !== null) {
        if (new URL(url).pathname.split('/').includes(token)) refuse()
        headers[POT_CLIENT_HEADER] = token
      } else if (this.signerAuth && signerAuthScope) {
        const id = uuid(potId)
        const material = await this.signerAuth({
          scope: signerAuthScope.scope,
          subject: signerAuthScope.subject,
          potId: id,
        })
        headers[POT_SIGNER_POT_HEADER] = id
        headers[POT_SIGNER_STAMP_HEADER] = material.stamp
        headers[POT_SIGNER_SIGNATURE_HEADER] = material.signature
      } else {
        refuse()
      }
    }
    let body: string | undefined
    if (jsonBody !== undefined) {
      headers['content-type'] = 'application/json'
      try {
        body = JSON.stringify(jsonBody)
      } catch {
        refuse()
      }
    }
    const response = await fetchOnce(this.fetchImpl, url, {
      method,
      headers,
      body,
      credentials: 'omit',
    }, this.timeoutMs)
    if (!response.ok) {
      await discard(response)
      refuse()
    }
    try {
      return await response.json()
    } catch {
      refuse()
    }
  }

  /** Keychain token for the pot, or null when the keychain has none. */
  private async tokenOrNull(potId: string): Promise<string | null> {
    const id = uuid(potId)
    try {
      const stored = await getPotClientToken(this.keystore, id)
      return stored === null ? null : usableToken(stored)
    } catch (error) {
      if (error instanceof PotError) throw error
      refuse()
    }
  }

  private async tokenFor(potId: string): Promise<string> {
    const stored = await this.tokenOrNull(potId)
    if (stored === null) refuse()
    return stored
  }
}

export async function getPotClientToken(keystore: KeyStore, potId: string): Promise<string | null> {
  return keystore.getSecret(potClientTokenAccount(uuid(potId)))
}

export async function setPotClientToken(keystore: KeyStore, potId: string, token: string): Promise<void> {
  const value = usableToken(token)
  await keystore.setSecret(potClientTokenAccount(uuid(potId)), value)
}

function refuse(): never {
  throw new PotError(REFUSE)
}

function endpoint(base: string, path: string): string {
  const root = base.endsWith('/') ? base.slice(0, -1) : base
  const suffix = path.startsWith('/') ? path : `/${path}`
  let url: URL
  try {
    url = new URL(`${root}${suffix}`)
    assertSignerBaseUrl(url)
  } catch (error) {
    if (error instanceof PotError) throw error
    refuse()
  }
  return url.href
}

async function fetchOnce(
  fetchImpl: typeof fetch,
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<Response> {
  const controller = new AbortController()
  let timer: ReturnType<typeof setTimeout> | undefined
  const deadline = new Promise<FetchResult>((resolve) => {
    timer = setTimeout(() => {
      controller.abort()
      resolve({ kind: 'timeout' })
    }, timeoutMs)
  })
  const pending = fetchImpl(url, { ...init, redirect: 'error', signal: controller.signal }).then(
    (response) => ({ kind: 'response' as const, response }),
    () => ({ kind: 'fail' as const }),
  )
  try {
    const outcome = await Promise.race([pending, deadline])
    if (outcome.kind !== 'response') refuse()
    return outcome.response
  } finally {
    if (timer !== undefined) clearTimeout(timer)
  }
}

async function discard(response: Response): Promise<void> {
  const body = response.body
  if (!body) return
  try {
    await body.cancel()
  } catch {
    return
  }
}

function uuid(value: string): string {
  if (typeof value !== 'string') refuse()
  const id = value.trim().toLowerCase()
  if (!UUID_RE.test(id)) refuse()
  return id
}

function receiptStatus(value: string): SpendReceiptStatus {
  if (value !== 'submitted' && value !== 'confirmed' && value !== 'uncertain') refuse()
  return value
}

/** Server trims, lowercases, and strips a leading 0x. Empty is allowed only for uncertain. */
function normalizeTxid(value: string | undefined, status: SpendReceiptStatus): string | null {
  const trimmed = typeof value === 'string' ? value.trim() : ''
  if (trimmed === '') {
    if (status === 'uncertain') return null
    refuse()
  }
  const txid = trimmed.toLowerCase().replace(/^0x/, '')
  if (!/^[0-9a-f]{64}$/.test(txid)) refuse()
  return txid
}

function usableToken(token: string): string {
  if (typeof token !== 'string') refuse()
  const value = token.trim()
  if (value.length === 0 || value.length > MAX_TOKEN_LENGTH || hasControlChar(value)) refuse()
  return value
}

function hasControlChar(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i)
    if (code <= 0x1f || code === 0x7f) return true
  }
  return false
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function expectRecord(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) refuse()
  return value
}

function expectString(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) refuse()
  return value
}

function isClientSpendStatus(value: string): value is ClientSpendPublicStatus {
  return (CLIENT_SPEND_STATUSES as readonly string[]).includes(value)
}

function parseClientSpendRequest(value: unknown): ClientSpendRequestResponse {
  const body = expectRecord(value)
  const status = expectString(body.status)
  if (!isClientSpendStatus(status)) refuse()
  if (body.network !== 'MAINNET') refuse()
  const amountCents = body.amountCents
  if (typeof amountCents !== 'number' || !Number.isSafeInteger(amountCents) || amountCents < 0) refuse()
  return {
    requestId: expectString(body.requestId),
    approvalId: expectString(body.approvalId),
    potId: expectString(body.potId),
    amountCents,
    receiverSparkAddress: expectString(body.receiverSparkAddress),
    network: 'MAINNET',
    status,
  }
}

function parseSpendAuthorization(value: unknown): SpendAuthorizationResponse {
  const body = expectRecord(value)
  const intent = expectRecord(body.intent)
  const lock = expectRecord(body.lock)
  if (intent.v !== 1) refuse()
  expectString(intent.intentId)
  expectString(intent.potId)
  expectString(intent.kind)
  if (!isRecord(intent.payload)) refuse()
  expectString(intent.nonce)
  expectString(intent.expiresAt)
  expectString(intent.keyId)
  expectString(intent.backendSig)
  if (lock.decision !== 'open' && lock.decision !== 'locked') refuse()
  expectString(lock.nonce)
  expectString(lock.expiresAt)
  expectString(lock.keyId)
  expectString(lock.backendSig)
  return {
    intent: intent as unknown as SpendIntentWire,
    lock: lock as unknown as LockAttestationWire,
  }
}

function parseSpendReceipt(value: unknown): SpendReceiptResponse {
  const body = expectRecord(value)
  if (body.txid !== null && body.txid !== undefined && typeof body.txid !== 'string') refuse()
  return {
    intentId: expectString(body.intentId),
    status: expectString(body.status),
    txid: typeof body.txid === 'string' ? body.txid : null,
    receiptStatus: parseReceiptStatusField(body.receiptStatus),
  }
}

function parseReceiptStatusField(value: unknown): SpendReceiptStatus | null {
  if (value === null || value === undefined) return null
  if (value === 'submitted' || value === 'confirmed' || value === 'uncertain') return value
  refuse()
}

function parseSignerTrust(value: unknown): SignerTrustResponse {
  const body = expectRecord(value)
  const keysRaw = body.keys
  if (!isRecord(keysRaw)) refuse()
  const keys: Record<string, string> = {}
  for (const [key, pub] of Object.entries(keysRaw)) {
    if (key.length === 0) refuse()
    keys[key] = expectString(pub)
  }
  const result: SignerTrustResponse = {
    keys,
    activeKeyId: expectString(body.activeKeyId),
  }
  if (body.addressChallengePubkey !== undefined && body.addressChallengePubkey !== null) {
    result.addressChallengePubkey = expectString(body.addressChallengePubkey)
  }
  return result
}
