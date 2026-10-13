import { bech32m } from '@scure/base'
import { secp256k1 } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha2'
import { expect, test } from 'vitest'
import {
  type ClientSpendRequestResponse,
  type SpendAuthorizationBody,
  type SpendReceiptBody,
  type SignerTrustResponse,
} from '../src/client.js'
import { PotError } from '../src/errors.js'
import {
  MAX_CLOCK_SKEW_MS,
  MAX_INTENT_TTL_MS,
  canonicalIntentBody,
  canonicalLockBody,
  type LockAttestation,
  type NonceConsumeResult,
  type NonceStore,
  type SpendIntent,
} from '../src/intent.js'
import { main } from '../src/index.js'
import { freshPolicy, type SpendingPolicy } from '../src/policy/policy.js'
import { encodeSparkAddress } from '../src/spark/address.js'
import type { SpendJournal, SpendJournalRecord, UnreceiptedSpend } from '../src/spend-journal.js'
import { signCommand, type SignCommandOptions, type SignOutcome, type SignPot, type SignVault } from '../src/sign-flow.js'
import type { SendUsdbFromPotInput } from '../src/spark/usdb.js'

/**
 * Same public test scalar as test/intent.test.ts (§7). Not a production secret.
 * Cases already asserted elsewhere (byte vectors, vault round-trip, trust-pin
 * mismatch, locked decisions, forged or expired intents, non-TTY without
 * --yes, offline and non-2xx) are not repeated here.
 */
const TEST_KEY = '0000000000000000000000000000000000000000000000000000000000000001'
const TEST_PUBKEY = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const KEY_ID = 'backend-secp256k1-v1'
const PHRASE =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

const POT_ID = '7f3d9c2a-1b4e-4f8a-b6c5-9d0e1f2a3b4c'
const OTHER_POT = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
const OTHER_REQUEST = '99999999-8888-4777-8666-555555555555'
const OTHER_INTENT = '12121212-3434-4545-8656-787878787878'
const REQUEST_ID = '11111111-2222-4333-8444-555555555555'
const APPROVAL_ID = '22222222-3333-4444-8555-666666666666'
const INTENT_ID = '0e2f3a4b-5c6d-4e7f-8a9b-0c1d2e3f4a5b'
const INTENT_NONCE = '5ee4d3c2b1a0-4f5e-4d3c-2b1a-0987654321fe'
const LOCK_NONCE = 'lock-nonce-0f1e2d3c4b5a69788796a5b4c3d2e1f0'
const EXPIRES_AT = '2026-10-09T12:05:00.000Z'
const NOW_MS = Date.parse('2026-10-09T12:04:30.000Z')
const DEST = encodeSparkAddress(new Uint8Array(33).fill(4))
const OTHER_DEST = encodeSparkAddress(new Uint8Array(33).fill(5))
const REGTEST_DEST = bech32m.encode('sparkrt', bech32m.toWords(new Uint8Array(33).fill(4)))
const TXID = 'ab'.repeat(32)

class MemoryLedger implements NonceStore {
  readonly rows = new Map<string, string>()

  consume(nonce: string, intentId: string, expiresAt: string): NonceConsumeResult {
    const existing = this.rows.get(nonce)
    if (existing) {
      if (existing !== intentId) {
        throw new PotError('Intent nonce was already used. Refusing the replay.', 'INTENT_NONCE_REUSED')
      }
      return { replay: true, record: { intentId, expiresAt } }
    }
    this.rows.set(nonce, intentId)
    return { replay: false, record: { intentId, expiresAt } }
  }
}

class MemoryJournal implements SpendJournal {
  readonly rows = new Map<string, SpendJournalRecord>()

  put(intentId: string, txid: string): void {
    const existing = this.rows.get(intentId)
    if (existing) {
      if (existing.txid === txid) return
      throw new PotError('refused to spend', 'SPEND_JOURNAL')
    }
    this.rows.set(intentId, { txid, receipted: false })
  }

  markReceipted(intentId: string): void {
    const existing = this.rows.get(intentId)
    if (!existing) throw new PotError('refused to spend', 'SPEND_JOURNAL')
    existing.receipted = true
  }

  get(intentId: string): SpendJournalRecord | null {
    const existing = this.rows.get(intentId)
    return existing ? { txid: existing.txid, receipted: existing.receipted } : null
  }

  listUnreceipted(): readonly UnreceiptedSpend[] {
    return [...this.rows.entries()]
      .filter((entry): entry is [string, SpendJournalRecord] => entry[1]?.receipted === false)
      .map(([intentId, row]) => ({ intentId, txid: row.txid, receipted: false as const }))
  }
}

interface Flow {
  sign: (extra?: Partial<SignCommandOptions>) => Promise<SignOutcome>
  injected: Partial<Omit<SignCommandOptions, 'requestId' | 'yes'>>
  broadcasts: SendUsdbFromPotInput[]
  receipts: SpendReceiptBody[]
  authorizations: SpendAuthorizationBody[]
  ledger: MemoryLedger
  journal: MemoryJournal
  requests: number
  opens: number
}

function compactSign(body: string): string {
  return secp256k1.sign(sha256(Buffer.from(body, 'utf8')), TEST_KEY).toHex('compact')
}

function signedIntent(overrides: {
  kind: SpendIntent['kind']
  payload: SpendIntent['payload']
  nonce?: string
  intentId?: string
  potId?: string
  expiresAt?: string
}): SpendIntent {
  const unsigned: Omit<SpendIntent, 'backendSig'> = {
    v: 1,
    intentId: overrides.intentId ?? INTENT_ID,
    potId: overrides.potId ?? POT_ID,
    kind: overrides.kind,
    payload: overrides.payload,
    nonce: overrides.nonce ?? INTENT_NONCE,
    expiresAt: overrides.expiresAt ?? EXPIRES_AT,
    keyId: KEY_ID,
  }
  return { ...unsigned, backendSig: compactSign(canonicalIntentBody(unsigned)) }
}

function sparkIntent(amountCents = 12, to = DEST, potId = POT_ID): SpendIntent {
  return signedIntent({
    kind: 'spark_transfer',
    potId,
    payload: { to, amountSats: amountCents, maxFeeSats: 0, amountCents },
  })
}

function signedLock(decision: 'open' | 'locked', expiresAt = EXPIRES_AT): LockAttestation {
  const unsigned = { decision, nonce: LOCK_NONCE, expiresAt, keyId: KEY_ID }
  return { ...unsigned, backendSig: compactSign(canonicalLockBody(unsigned)) }
}

function potFor(receiver: string, policy?: SpendingPolicy): SignPot {
  const base = policy ?? freshPolicy('2026-10-09')
  return {
    potId: POT_ID,
    policy: {
      ...base,
      destinations: { ...base.destinations, allow: [receiver] },
    },
    role: 'free',
    freeze: 'active',
    network: 'MAINNET',
    accountIndex: 1,
  }
}

function setup(partial?: {
  intent?: unknown
  lock?: LockAttestation
  view?: Partial<ClientSpendRequestResponse>
  trust?: SignerTrustResponse
  pot?: SignPot | null
  clock?: () => Date
}): Flow {
  const ledger = new MemoryLedger()
  const journal = new MemoryJournal()
  const broadcasts: SendUsdbFromPotInput[] = []
  const receipts: SpendReceiptBody[] = []
  const authorizations: SpendAuthorizationBody[] = []
  const flow: Flow = {
    sign: () => Promise.reject(new Error('sign is not ready')),
    injected: {},
    broadcasts,
    receipts,
    authorizations,
    ledger,
    journal,
    requests: 0,
    opens: 0,
  }
  const pot = partial && 'pot' in partial ? partial.pot ?? null : potFor(DEST)
  const vault: SignVault = {
    async read() {
      return pot
    },
    async withMnemonic(_potId, fn) {
      flow.opens += 1
      const mnemonic = Buffer.from(PHRASE, 'utf8')
      try {
        return await fn({
          mnemonic,
          potId: POT_ID,
          address: DEST,
          pubkey: TEST_PUBKEY,
          accountIndex: 1,
          network: 'MAINNET',
          bound: true,
        })
      } finally {
        mnemonic.fill(0)
      }
    },
  }
  const view: ClientSpendRequestResponse = {
    requestId: REQUEST_ID,
    approvalId: APPROVAL_ID,
    potId: POT_ID,
    amountCents: 12,
    receiverSparkAddress: DEST,
    network: 'MAINNET',
    status: 'authorization_required',
    ...partial?.view,
  }
  const trust = partial?.trust ?? { keys: { [KEY_ID]: TEST_PUBKEY }, activeKeyId: KEY_ID }
  const intent = partial?.intent ?? sparkIntent(view.amountCents, view.receiverSparkAddress)
  const lock = partial?.lock ?? signedLock('open')
  const client = {
    async getSignerTrust() {
      return trust
    },
    async getClientSpendRequest() {
      flow.requests += 1
      return view
    },
    async createSpendAuthorization(_potId: string, body: SpendAuthorizationBody) {
      authorizations.push(body)
      return { intent, lock }
    },
    async postSpendReceipt(_potId: string, body: SpendReceiptBody) {
      receipts.push(body)
      return {
        intentId: body.intentId,
        status: body.status,
        txid: body.txid ?? null,
        receiptStatus: body.status,
      }
    },
  }
  const injected: Flow['injected'] = {
    potId: POT_ID,
    stdinIsTty: false,
    env: {},
    pinnedTrust: { keys: new Map([[KEY_ID, TEST_PUBKEY]]) },
    clock: partial?.clock ?? (() => new Date(NOW_MS)),
    client,
    vault,
    ledger,
    journal,
    broadcaster: async (input) => {
      broadcasts.push(input)
      return { txid: TXID }
    },
  }
  flow.injected = injected
  flow.sign = (extra) =>
    signCommand({
      requestId: REQUEST_ID,
      yes: true,
      ...injected,
      ...extra,
    })
  return flow
}

function expectNoSpend(flow: Flow): void {
  expect(flow.broadcasts).toHaveLength(0)
  expect(flow.receipts).toHaveLength(0)
  expect(flow.opens).toBe(0)
}

async function captureIo(run: () => Promise<void>): Promise<{ out: string; err: string }> {
  let out = ''
  let err = ''
  const writeOut = process.stdout.write.bind(process.stdout)
  const writeErr = process.stderr.write.bind(process.stderr)
  process.stdout.write = ((chunk: string | Uint8Array) => {
    out += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8')
    return true
  }) as typeof process.stdout.write
  process.stderr.write = ((chunk: string | Uint8Array) => {
    err += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8')
    return true
  }) as typeof process.stderr.write
  try {
    await run()
  } finally {
    process.stdout.write = writeOut
    process.stderr.write = writeErr
  }
  return { out, err }
}

test('a validly signed stale or over-long lock refuses before broadcast', async () => {
  const staleAt = new Date(NOW_MS - MAX_CLOCK_SKEW_MS).toISOString()
  const stale = setup({ lock: signedLock('open', staleAt) })
  await expect(stale.sign()).rejects.toMatchObject({ code: 'LOCK_EXPIRED' })
  expectNoSpend(stale)
  expect(stale.ledger.rows.size).toBe(0)
  expect(stale.authorizations).toHaveLength(1)

  const tooFar = new Date(NOW_MS + MAX_INTENT_TTL_MS + MAX_CLOCK_SKEW_MS + 1).toISOString()
  const distant = setup({ lock: signedLock('open', tooFar) })
  await expect(distant.sign()).rejects.toMatchObject({ code: 'LOCK_TTL' })
  expectNoSpend(distant)
  expect(distant.ledger.rows.size).toBe(0)
  expect(distant.authorizations).toHaveLength(1)
})

test('a replayed nonce with no journal posts uncertain and does not broadcast', async () => {
  const flow = setup()
  flow.ledger.rows.set(INTENT_NONCE, INTENT_ID)
  const first = await flow.sign()
  expect(first).toEqual({
    requestId: REQUEST_ID,
    potId: POT_ID,
    intentId: INTENT_ID,
    status: 'uncertain',
  })
  expect(first.txid).toBeUndefined()
  expect(flow.broadcasts).toHaveLength(0)
  expect(flow.opens).toBe(0)
  expect(flow.journal.get(INTENT_ID)).toBeNull()
  expect(flow.receipts).toEqual([{ intentId: INTENT_ID, status: 'uncertain' }])

  const second = await flow.sign()
  expect(second).toEqual(first)
  expect(flow.broadcasts).toHaveLength(0)
  expect(flow.opens).toBe(0)
  expect(flow.receipts).toEqual([
    { intentId: INTENT_ID, status: 'uncertain' },
    { intentId: INTENT_ID, status: 'uncertain' },
  ])
})

test('a nonce reused for a different intent refuses before broadcast', async () => {
  const flow = setup()
  flow.ledger.rows.set(INTENT_NONCE, OTHER_INTENT)
  await expect(flow.sign()).rejects.toMatchObject({
    code: 'INTENT_NONCE_REUSED',
    message: 'Intent nonce was already used. Refusing the replay.',
  })
  expectNoSpend(flow)
  expect(flow.ledger.rows.get(INTENT_NONCE)).toBe(OTHER_INTENT)
})

test('daily cap, an unlisted destination, a vault role, and a non-mainnet target refuse before broadcast', async () => {
  const dailyPot = potFor(DEST)
  const dailyPolicy = dailyPot.policy
  if (!dailyPolicy) throw new Error('expected a sealed policy')
  const daily = setup({
    pot: {
      ...dailyPot,
      policy: { ...dailyPolicy, spentTodaySats: dailyPolicy.dailySats - 11 },
    },
  })
  await expect(daily.sign()).rejects.toMatchObject({ code: 'LIMIT_DAILY' })
  expectNoSpend(daily)
  expect(daily.ledger.rows.has(INTENT_NONCE)).toBe(false)

  const closed = freshPolicy('2026-10-09')
  const unlisted = setup({
    pot: {
      ...potFor(DEST),
      policy: {
        ...closed,
        destinations: { mode: 'allowlist', allow: [], block: [] },
      },
    },
  })
  await expect(unlisted.sign()).rejects.toMatchObject({ code: 'DESTINATION_NOT_ALLOWED' })
  expectNoSpend(unlisted)
  expect(unlisted.ledger.rows.has(INTENT_NONCE)).toBe(false)

  const vault = setup({ pot: { ...potFor(DEST), role: 'vault' } })
  await expect(vault.sign()).rejects.toMatchObject({ code: 'POT_NOT_SPENDABLE' })
  expectNoSpend(vault)
  expect(vault.ledger.rows.has(INTENT_NONCE)).toBe(false)

  const regtestPot = setup({ pot: { ...potFor(DEST), network: 'REGTEST' } })
  await expect(regtestPot.sign()).rejects.toMatchObject({ message: 'refused to spend' })
  expectNoSpend(regtestPot)
  expect(regtestPot.ledger.rows.has(INTENT_NONCE)).toBe(false)

  const regtestAddress = setup({
    intent: sparkIntent(12, REGTEST_DEST),
    view: { receiverSparkAddress: REGTEST_DEST },
    pot: potFor(REGTEST_DEST),
  })
  await expect(regtestAddress.sign()).rejects.toMatchObject({ message: 'refused to spend' })
  expectNoSpend(regtestAddress)
  expect(regtestAddress.ledger.rows.has(INTENT_NONCE)).toBe(false)
})

test('--yes on a TTY spends without prompting', async () => {
  const flow = setup()
  let prompted = false
  const io = await captureIo(async () => {
    expect(
      await main(['sign', REQUEST_ID, '--yes', '--json'], {
        ...flow.injected,
        stdinIsTty: true,
        confirm: () => {
          prompted = true
          return false
        },
      }),
    ).toBe(0)
  })
  expect(prompted).toBe(false)
  expect(JSON.parse(io.out)).toMatchObject({
    requestId: REQUEST_ID,
    potId: POT_ID,
    intentId: INTENT_ID,
    txid: TXID,
    status: 'submitted',
  })
  expect(io.err).toBe('')
  expect(io.out).not.toContain('abandon')
  expect(io.out).not.toContain(TEST_KEY)
  expect(flow.broadcasts).toHaveLength(1)
  expect(flow.opens).toBe(1)
  expect(flow.requests).toBe(1)
})

test('a spend request or intent that does not match refuses before broadcast', async () => {
  const wrongRequest = setup({ view: { requestId: OTHER_REQUEST } })
  await expect(wrongRequest.sign()).rejects.toMatchObject({ message: 'refused to spend' })
  expectNoSpend(wrongRequest)
  expect(wrongRequest.requests).toBe(1)
  expect(wrongRequest.authorizations).toHaveLength(0)
  expect(wrongRequest.ledger.rows.size).toBe(0)

  const wrongPot = setup({ view: { potId: OTHER_POT } })
  await expect(wrongPot.sign()).rejects.toMatchObject({ message: 'refused to spend' })
  expectNoSpend(wrongPot)
  expect(wrongPot.authorizations).toHaveLength(0)
  expect(wrongPot.ledger.rows.size).toBe(0)

  const wrongAmount = setup({ intent: sparkIntent(11) })
  await expect(wrongAmount.sign()).rejects.toMatchObject({ message: 'refused to spend' })
  expectNoSpend(wrongAmount)
  expect(wrongAmount.authorizations).toHaveLength(1)
  expect(wrongAmount.ledger.rows.has(INTENT_NONCE)).toBe(false)

  const wrongDestination = setup({ intent: sparkIntent(12, OTHER_DEST) })
  await expect(wrongDestination.sign()).rejects.toMatchObject({ message: 'refused to spend' })
  expectNoSpend(wrongDestination)
  expect(wrongDestination.ledger.rows.has(INTENT_NONCE)).toBe(false)

  const wrongIntentPot = setup({ intent: sparkIntent(12, DEST, OTHER_POT) })
  await expect(wrongIntentPot.sign()).rejects.toMatchObject({ message: 'refused to spend' })
  expectNoSpend(wrongIntentPot)
  expect(wrongIntentPot.ledger.rows.has(INTENT_NONCE)).toBe(false)
})
