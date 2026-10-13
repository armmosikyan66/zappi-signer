/**
 * Read-only lookup of a client spend request.
 * GET /api/wallet/pots/client-spend-requests/:requestId (§5.4).
 * Does not call spend-authorizations, sign, or open a mnemonic.
 */
import { type ClientSpendPublicStatus, type ClientSpendRequestResponse } from '../client.js'
import { PotError } from '../errors.js'

export const CLIENT_SPEND_REQUEST_PATH = '/api/wallet/pots/client-spend-requests'

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

const STATUSES: readonly ClientSpendPublicStatus[] = [
  'authorization_required',
  'submitted',
  'confirmed',
  'uncertain',
  'expired',
  'consumed',
]

export interface StatusClient {
  request(method: 'GET' | 'POST', path: string, body?: unknown): Promise<unknown>
}

export async function runStatus(input: {
  client: StatusClient
  requestId: string
}): Promise<ClientSpendRequestResponse> {
  const requestId = normalizeRequestId(input.requestId)
  let body: unknown
  try {
    body = await input.client.request('GET', `${CLIENT_SPEND_REQUEST_PATH}/${requestId}`)
  } catch (error) {
    if (error instanceof PotError) throw error
    throw new PotError('spend status is unavailable')
  }
  return publicSpendStatus(body, requestId)
}

function normalizeRequestId(value: string): string {
  const requestId = value.trim().toLowerCase()
  if (!UUID_RE.test(requestId)) throw new PotError('spend status is unavailable')
  return requestId
}

function publicSpendStatus(value: unknown, requestId: string): ClientSpendRequestResponse {
  const body = record(value)
  const status = typeof body.status === 'string' ? body.status : ''
  if (!isStatus(status)) throw new PotError('spend status is unavailable')
  if (body.network !== 'MAINNET') throw new PotError('spend status is unavailable')
  const amountCents = body.amountCents
  if (typeof amountCents !== 'number' || !Number.isSafeInteger(amountCents) || amountCents < 0) {
    throw new PotError('spend status is unavailable')
  }
  const returnedId = text(body.requestId)
  if (returnedId.toLowerCase() !== requestId) throw new PotError('spend status is unavailable')
  return {
    requestId,
    approvalId: text(body.approvalId),
    potId: text(body.potId),
    amountCents,
    receiverSparkAddress: text(body.receiverSparkAddress),
    network: 'MAINNET',
    status,
  }
}

function isStatus(value: string): value is ClientSpendPublicStatus {
  return (STATUSES as readonly string[]).includes(value)
}

function text(value: unknown): string {
  if (typeof value !== 'string') throw new PotError('spend status is unavailable')
  const trimmed = value.trim()
  if (trimmed.length < 1 || trimmed.length > 256 || hasControl(trimmed)) {
    throw new PotError('spend status is unavailable')
  }
  return trimmed
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new PotError('spend status is unavailable')
  }
  return value as Record<string, unknown>
}

function hasControl(value: string): boolean {
  for (const char of value) {
    if (char.charCodeAt(0) <= 0x1f || char.charCodeAt(0) === 0x7f) return true
  }
  return false
}
