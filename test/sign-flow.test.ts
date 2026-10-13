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
  canonicalIntentBody,
  canonicalLockBody,
  type LockAttestation,
  type NonceConsumeResult,
  type NonceStore,
  type SpendIntent,
} from '../src/intent.js'
import { main } from '../src/index.js'
import { MemoryKeyStore } from '../src/keystore/memory.js'
import { freshPolicy } from '../src/policy/policy.js'
import { encodeSparkAddress } from '../src/spark/address.js'
import type { SpendJournal, SpendJournalRecord, UnreceiptedSpend } from '../src/spend-journal.js'
import {
  signCommand,
  type SignCommandOptions,
  type SignOutcome,
  type SignPot,
  type SignVault,
  type UsdbBroadcaster,
} from '../src/sign-flow.js'
import type { SendUsdbFromPotInput } from '../src/spark/usdb.js'

/**
 * Same public test scalar as test/intent.test.ts (§7). Not a production secret.
 */
const TEST_KEY = '0000000000000000000000000000000000000000000000000000000000000001'
const TEST_PUBKEY = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const KEY_ID = 'backend-secp256k1-v1'
const PHRASE =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
const TOKEN = 'zpc_testtokenvalue_do_not_leak'

const POT_ID = '7f3d9c2a-1b4e-4f8a-b6c5-9d0e1f2a3b4c'
const REQUEST_ID = '11111111-2222-4333-8444-555555555555'
const APPROVAL_ID = '22222222-3333-4444-8555-666666666666'
const INTENT_ID = '0e2f3a4b-5c6d-4e7f-8a9b-0c1d2e3f4a5b'
const INTENT_NONCE = '5ee4d3c2b1a0-4f5e-4d3c-2b1a-0987654321fe'
const LOCK_NONCE = 'lock-nonce-0f1e2d3c4b5a69788796a5b4c3d2e1f0'
const EXPIRES_AT = '2026-10-09T12:05:00.000Z'
const NOW = '2026-10-09T12:04:30.000Z'
const DEST = encodeSparkAddress(new Uint8Array(33).fill(4))
const TXID = 'ab'.repeat(32)
const SEEDED_TXID = 'cd'.repeat(32)

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
  failReceipt: boolean
  setBroadcast: (fn: UsdbBroadcaster) => void
}

function compactSign(body: string): string {
  return secp256k1.sign(sha256(Buffer.from(body, 'utf8')), TEST_KEY).toHex('compact')
}

function signedIntent(overrides: {
  kind: SpendIntent['kind']
  payload: SpendIntent['payload']
  nonce?: string
}): SpendIntent {
  const unsigned: Omit<SpendIntent, 'backendSig'> = {
    v: 1,
    intentId: INTENT_ID,
    potId: POT_ID,
    kind: overrides.kind,
    payload: overrides.payload,
    nonce: overrides.nonce ?? INTENT_NONCE,
    expiresAt: EXPIRES_AT,
    keyId: KEY_ID,
  }
  return { ...unsigned, backendSig: compactSign(canonicalIntentBody(unsigned)) }
}

function sparkIntent(amountCents = 12, to = DEST): SpendIntent {
  return signedIntent({
    kind: 'spark_transfer',
    payload: { to, amountSats: amountCents, maxFeeSats: 0, amountCents },
  })
}

function signedLock(decision: 'open' | 'locked', expiresAt = EXPIRES_AT): LockAttestation {
  const unsigned = { decision, nonce: LOCK_NONCE, expiresAt, keyId: KEY_ID }
  return { ...unsigned, backendSig: compactSign(canonicalLockBody(unsigned)) }
}

function potFor(receiver: string): SignPot {
  const policy = freshPolicy('2026-10-09')
  return {
    potId: POT_ID,
    policy: {
      ...policy,
      destinations: { ...policy.destinations, allow: [receiver] },
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
    failReceipt: false,
    setBroadcast: () => undefined,
  }
  let broadcastImpl: UsdbBroadcaster = async () => ({ txid: TXID })
  const broadcaster: UsdbBroadcaster = async (input) => {
    broadcasts.push(input)
    return broadcastImpl(input)
  }
  flow.setBroadcast = (fn) => {
    broadcastImpl = fn
  }
  const pot = partial && 'pot' in partial ? partial.pot ?? null : potFor(DEST)
  const vault: SignVault = {
    async read() {
      return pot
    },
    async withMnemonic(_potId, fn) {
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
      if (flow.failReceipt) throw new PotError('refused to spend')
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
    clock: partial?.clock ?? (() => new Date(NOW)),
    client,
    vault,
    ledger,
    journal,
    broadcaster,
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

function expectNoPhrase(text: string): void {
  expect(text).not.toContain('abandon')
  expect(text).not.toContain(TEST_KEY)
  expect(text).not.toContain(TOKEN)
}

test('happy path posts a submitted receipt and a second run does not rebroadcast', async () => {
  const flow = setup()
  const first = await flow.sign()
  expect(first).toEqual({
    requestId: REQUEST_ID,
    potId: POT_ID,
    intentId: INTENT_ID,
    txid: TXID,
    status: 'submitted',
  })
  expect(flow.authorizations).toEqual([{ approvalId: APPROVAL_ID, idempotencyKey: REQUEST_ID }])
  expect(flow.broadcasts).toHaveLength(1)
  expect(flow.broadcasts[0]).toMatchObject({
    destination: DEST,
    amountCents: 12,
    network: 'MAINNET',
    accountNumber: 1,
  })
  expect(flow.broadcasts[0]?.mnemonic).toBe(PHRASE)
  expect(flow.receipts).toEqual([{ intentId: INTENT_ID, txid: TXID, status: 'submitted' }])
  expect(flow.journal.get(INTENT_ID)).toEqual({ txid: TXID, receipted: true })
  expect(flow.ledger.rows.get(INTENT_NONCE)).toBe(INTENT_ID)

  const second = await flow.sign()
  expect(second).toEqual(first)
  expect(flow.broadcasts).toHaveLength(1)
  expect(flow.receipts).toEqual([
    { intentId: INTENT_ID, txid: TXID, status: 'submitted' },
    { intentId: INTENT_ID, txid: TXID, status: 'submitted' },
  ])
})

test('--json writes the outcome to stdout and a later run still does not rebroadcast', async () => {
  const flow = setup()
  const json = await captureIo(async () => {
    expect(await main(['sign', REQUEST_ID, '--yes', '--json'], flow.injected)).toBe(0)
  })
  expect(JSON.parse(json.out)).toEqual({
    requestId: REQUEST_ID,
    potId: POT_ID,
    intentId: INTENT_ID,
    txid: TXID,
    status: 'submitted',
  })
  expectNoPhrase(json.out)
  expectNoPhrase(json.err)
  expect(flow.broadcasts).toHaveLength(1)

  const plain = await captureIo(async () => {
    expect(await main(['sign', REQUEST_ID, '--yes'], flow.injected)).toBe(0)
  })
  expect(plain.out).toBe(`submitted ${TXID}\n`)
  expectNoPhrase(plain.out)
  expectNoPhrase(plain.err)
  expect(flow.broadcasts).toHaveLength(1)
})

test('confirmed is posted only when this broadcast observed it', async () => {
  const flow = setup()
  flow.setBroadcast(async () => ({ txid: TXID, confirmed: true }))
  const first = await flow.sign()
  expect(first.status).toBe('confirmed')
  expect(flow.receipts[0]).toEqual({ intentId: INTENT_ID, txid: TXID, status: 'confirmed' })
  const second = await flow.sign()
  expect(second).toMatchObject({ status: 'submitted', txid: TXID })
  expect(flow.broadcasts).toHaveLength(1)
  expect(flow.receipts[1]).toEqual({ intentId: INTENT_ID, txid: TXID, status: 'submitted' })
})

test('a failed receipt is posted again from the journal without a second broadcast', async () => {
  const flow = setup()
  flow.failReceipt = true
  await expect(flow.sign()).rejects.toMatchObject({ message: 'refused to spend' })
  expect(flow.broadcasts).toHaveLength(1)
  expect(flow.journal.get(INTENT_ID)).toEqual({ txid: TXID, receipted: false })
  flow.failReceipt = false
  const second = await flow.sign()
  expect(second).toMatchObject({ status: 'submitted', txid: TXID })
  expect(flow.broadcasts).toHaveLength(1)
  expect(flow.journal.get(INTENT_ID)?.receipted).toBe(true)
})

test('a journaled txid is not broadcast again', async () => {
  const flow = setup({ pot: { ...potFor(DEST), policy: null } })
  flow.journal.put(INTENT_ID, SEEDED_TXID)
  const outcome = await flow.sign()
  expect(outcome).toMatchObject({ status: 'submitted', txid: SEEDED_TXID, intentId: INTENT_ID })
  expect(flow.broadcasts).toHaveLength(0)
  expect(flow.receipts).toEqual([{ intentId: INTENT_ID, txid: SEEDED_TXID, status: 'submitted' }])
  expect(flow.journal.get(INTENT_ID)?.receipted).toBe(true)
})

test('a broadcast that throws after the txid is journaled is not repeated', async () => {
  const flow = setup()
  flow.setBroadcast(async () => {
    flow.journal.put(INTENT_ID, TXID)
    throw new PotError('refused to spend', 'BROADCAST_UNCERTAIN')
  })
  const first = await flow.sign()
  expect(first).toMatchObject({ status: 'submitted', txid: TXID })
  expect(flow.receipts[0]).toEqual({ intentId: INTENT_ID, txid: TXID, status: 'submitted' })
  const second = await flow.sign()
  expect(second.status).toBe('submitted')
  expect(flow.broadcasts).toHaveLength(1)
})

test('an unknown broadcast with no txid posts uncertain and is not retried', async () => {
  const flow = setup()
  flow.setBroadcast(async () => {
    throw new PotError('refused to spend', 'BROADCAST_UNCERTAIN')
  })
  const first = await flow.sign()
  expect(first).toEqual({
    requestId: REQUEST_ID,
    potId: POT_ID,
    intentId: INTENT_ID,
    status: 'uncertain',
  })
  expect(first.txid).toBeUndefined()
  expect(flow.journal.get(INTENT_ID)).toBeNull()
  expect(flow.receipts).toEqual([{ intentId: INTENT_ID, status: 'uncertain' }])
  const second = await flow.sign()
  expect(second.status).toBe('uncertain')
  expect(second.txid).toBeUndefined()
  expect(flow.broadcasts).toHaveLength(1)
  expect(flow.receipts[1]).toEqual({ intentId: INTENT_ID, status: 'uncertain' })
})

test('a locked attestation refuses before broadcast', async () => {
  const flow = setup({ lock: signedLock('locked') })
  await expect(flow.sign()).rejects.toMatchObject({ code: 'LOCK_LOCKED' })
  expect(flow.broadcasts).toHaveLength(0)
  expect(flow.receipts).toHaveLength(0)
  expect(flow.ledger.rows.has(LOCK_NONCE)).toBe(false)
  expect(flow.ledger.rows.has(INTENT_NONCE)).toBe(false)
})

test('a forged or expired signature refuses before broadcast', async () => {
  const forgedIntent = sparkIntent()
  forgedIntent.backendSig = 'ab'.repeat(64)
  const forged = setup({ intent: forgedIntent })
  const forgedIo = await captureIo(async () => {
    expect(await main(['sign', REQUEST_ID, '--yes', '--json'], forged.injected)).toBe(1)
  })
  expect(forgedIo.err).toBe('INTENT_BAD_SIGNATURE\n')
  expect(forgedIo.out).toBe('')
  expectNoPhrase(forgedIo.err)
  expect(forged.broadcasts).toHaveLength(0)
  expect(forged.ledger.rows.has(INTENT_NONCE)).toBe(false)

  const expired = setup({
    clock: () => new Date('2026-10-09T12:06:00.000Z'),
    lock: signedLock('open', '2026-10-09T12:09:00.000Z'),
  })
  await expect(expired.sign()).rejects.toMatchObject({ code: 'INTENT_EXPIRED' })
  expect(expired.broadcasts).toHaveLength(0)
  expect(expired.ledger.rows.has(INTENT_NONCE)).toBe(false)
})

test('a journaled intent with a forged signature is not receipted', async () => {
  const forgedIntent = sparkIntent()
  forgedIntent.backendSig = 'cd'.repeat(64)
  const flow = setup({ intent: forgedIntent })
  flow.journal.put(INTENT_ID, SEEDED_TXID)
  await expect(flow.sign()).rejects.toMatchObject({ code: 'INTENT_BAD_SIGNATURE' })
  expect(flow.broadcasts).toHaveLength(0)
  expect(flow.receipts).toHaveLength(0)
})

test('missing policy and a WILDCARD recipient refuse before broadcast', async () => {
  const missing = setup({ pot: { ...potFor(DEST), policy: null } })
  await expect(missing.sign()).rejects.toMatchObject({ code: 'POLICY_REQUIRED' })
  expect(missing.broadcasts).toHaveLength(0)
  expect(missing.ledger.rows.has(INTENT_NONCE)).toBe(false)

  const wildcard = setup({
    intent: sparkIntent(12, 'WILDCARD'),
    view: { receiverSparkAddress: 'WILDCARD' },
  })
  await expect(wildcard.sign()).rejects.toMatchObject({ code: 'WILDCARD' })
  expect(wildcard.broadcasts).toHaveLength(0)
  expect(wildcard.ledger.rows.has(INTENT_NONCE)).toBe(false)

  const policy = freshPolicy('2026-10-09')
  const listed = setup({
    pot: {
      ...potFor(DEST),
      policy: { ...policy, destinations: { ...policy.destinations, allow: ['*'] } },
    },
  })
  await expect(listed.sign()).rejects.toMatchObject({ code: 'WILDCARD' })
  expect(listed.broadcasts).toHaveLength(0)
})

test('caps and a freeze refuse before the nonce is consumed', async () => {
  const capped = setup({
    intent: sparkIntent(100_001),
    view: { amountCents: 100_001 },
  })
  await expect(capped.sign()).rejects.toMatchObject({ code: 'LIMIT_PER_TX' })
  expect(capped.broadcasts).toHaveLength(0)
  expect(capped.ledger.rows.has(INTENT_NONCE)).toBe(false)

  const frozen = setup({ pot: { ...potFor(DEST), freeze: 'frozen_user' } })
  await expect(frozen.sign()).rejects.toMatchObject({ code: 'FROZEN' })
  expect(frozen.broadcasts).toHaveLength(0)
  expect(frozen.ledger.rows.has(INTENT_NONCE)).toBe(false)
})

test('lightning and a spark payload without a destination refuse before broadcast', async () => {
  const lightning = setup({
    intent: signedIntent({
      kind: 'lightning_pay',
      payload: { invoice: 'lnbc1ptestinvoice', maxFeeSats: 0, amountCents: 12 },
    }),
  })
  await expect(lightning.sign()).rejects.toMatchObject({ message: 'refused to spend' })
  expect(lightning.broadcasts).toHaveLength(0)
  expect(lightning.ledger.rows.has(INTENT_NONCE)).toBe(false)

  const missingTo = setup({
    intent: {
      v: 1,
      intentId: INTENT_ID,
      potId: POT_ID,
      kind: 'spark_transfer',
      payload: { amountSats: 12, maxFeeSats: 0, amountCents: 12 },
      nonce: INTENT_NONCE,
      expiresAt: EXPIRES_AT,
      keyId: KEY_ID,
      backendSig: 'aa'.repeat(64),
    },
  })
  await expect(missingTo.sign()).rejects.toMatchObject({ code: 'INTENT_MALFORMED' })
  expect(missingTo.broadcasts).toHaveLength(0)
  expect(missingTo.receipts).toHaveLength(0)
})

test('a spark transfer without amount cents refuses before broadcast', async () => {
  const flow = setup({
    intent: signedIntent({
      kind: 'spark_transfer',
      payload: { to: DEST, amountSats: 12, maxFeeSats: 0 },
    }),
  })
  await expect(flow.sign()).rejects.toMatchObject({ code: 'POLICY_AMOUNT' })
  expect(flow.broadcasts).toHaveLength(0)
  expect(flow.ledger.rows.has(INTENT_NONCE)).toBe(false)
})

test('non-TTY sign without --yes refuses before any request', async () => {
  const flow = setup()
  let confirmed = false
  await expect(
    flow.sign({
      yes: false,
      stdinIsTty: false,
      confirm: () => {
        confirmed = true
        return true
      },
    }),
  ).rejects.toMatchObject({ message: 'refused to spend' })
  expect(confirmed).toBe(false)
  expect(flow.requests).toBe(0)
  expect(flow.broadcasts).toHaveLength(0)
})

test('an injected decline refuses and an injected yes spends', async () => {
  const declined = setup()
  await expect(
    declined.sign({
      yes: false,
      stdinIsTty: true,
      confirm: () => false,
    }),
  ).rejects.toMatchObject({ message: 'refused to spend' })
  expect(declined.requests).toBe(1)
  expect(declined.authorizations).toHaveLength(0)
  expect(declined.broadcasts).toHaveLength(0)

  const accepted = setup()
  const outcome = await accepted.sign({
    yes: false,
    stdinIsTty: true,
    confirm: () => true,
  })
  expect(outcome.status).toBe('submitted')
  expect(accepted.broadcasts).toHaveLength(1)
})

test('a spend request that is not awaiting authorization is not signed', async () => {
  const flow = setup({ view: { status: 'submitted' } })
  await expect(flow.sign()).rejects.toMatchObject({ message: 'refused to spend' })
  expect(flow.requests).toBe(1)
  expect(flow.authorizations).toHaveLength(0)
  expect(flow.broadcasts).toHaveLength(0)
})

test('http and non-2xx responses refuse before a broadcast', async () => {
  const http = setup()
  let httpCalled = false
  await expect(
    http.sign({
      client: undefined,
      baseUrl: 'http://signer.example/secret',
      keystore: new MemoryKeyStore(),
      fetchImpl: (async () => {
        httpCalled = true
        return new Response('no')
      }) as typeof fetch,
    }),
  ).rejects.toMatchObject({ message: 'refused to spend' })
  expect(httpCalled).toBe(false)
  expect(http.broadcasts).toHaveLength(0)

  const down = setup()
  let sawHttps = false
  const body = JSON.stringify({ token: TOKEN, phrase: PHRASE })
  const io = await captureIo(async () => {
    const code = await main(['sign', REQUEST_ID, '--yes', '--json'], {
      ...down.injected,
      client: undefined,
      baseUrl: 'https://signer.example',
      keystore: new MemoryKeyStore(),
      fetchImpl: (async (input: RequestInfo | URL) => {
        const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
        sawHttps = url.startsWith('https://signer.example/api/signer/trust')
        return new Response(body, { status: 502 })
      }) as typeof fetch,
    })
    expect(code).toBe(1)
  })
  expect(sawHttps).toBe(true)
  expect(io.err).toBe('refused to spend\n')
  expect(io.out).toBe('')
  expectNoPhrase(io.err)
  expect(down.broadcasts).toHaveLength(0)
})

test('an unreachable signer and a trust pin mismatch refuse', async () => {
  const offline = setup()
  await expect(
    offline.sign({
      client: undefined,
      baseUrl: 'https://signer.example',
      keystore: new MemoryKeyStore(),
      fetchImpl: (async () => {
        throw new Error(`offline ${TOKEN} ${PHRASE}`)
      }) as typeof fetch,
    }),
  ).rejects.toMatchObject({ message: 'refused to spend' })
  expect(offline.broadcasts).toHaveLength(0)

  const mismatch = setup({
    trust: {
      keys: { [KEY_ID]: `03${TEST_PUBKEY.slice(2)}` },
      activeKeyId: KEY_ID,
    },
  })
  const io = await captureIo(async () => {
    expect(await main(['sign', REQUEST_ID, '--yes'], mismatch.injected)).toBe(1)
  })
  expect(io.err).toBe('TRUST_MISMATCH\n')
  expectNoPhrase(io.err)
  expect(io.out).toBe('')
  expect(mismatch.broadcasts).toHaveLength(0)
  expect(mismatch.requests).toBe(0)
})
