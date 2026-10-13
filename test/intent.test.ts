import { createHash } from 'node:crypto'
import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { secp256k1 } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha2'
import { afterEach, expect, test } from 'vitest'
import { PotError } from '../src/errors.js'
import {
  MAX_CLOCK_SKEW_MS,
  MAX_INTENT_TTL_MS,
  canonicalBindingBody,
  canonicalIntentBody,
  canonicalLockBody,
  lockIntentId,
  verifyBindingReceipt,
  verifyIntent,
  verifyLockAttestation,
  type IntentTrustStore,
  type SpendIntent,
} from '../src/intent.js'
import { NonceLedger } from '../src/intent-store.js'

/**
 * Byte-exact fixtures copied from zappi-plugin/SIGNER_PROTOCOL.md §7.
 * The test scalar is the protocol's public test key, not a production secret.
 */
const TEST_KEY = '0000000000000000000000000000000000000000000000000000000000000001'
const TEST_PUBKEY = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const KEY_ID = 'backend-secp256k1-v1'

const INTENT_BODY =
  '{"expiresAt":"2026-10-09T12:05:00.000Z","intentId":"0e2f3a4b-5c6d-4e7f-8a9b-0c1d2e3f4a5b","keyId":"backend-secp256k1-v1","kind":"spark_transfer","nonce":"5ee4d3c2b1a0-4f5e-4d3c-2b1a-0987654321fe","payload":{"amountCents":12,"amountSats":1000,"maxFeeSats":50,"to":"sparktx1qtestaddress000000000000000000000000000000000000000000"},"potId":"7f3d9c2a-1b4e-4f8a-b6c5-9d0e1f2a3b4c","v":1}'
const INTENT_HEX =
  '7b22657870697265734174223a22323032362d31302d30395431323a30353a30302e3030305a222c22696e74656e744964223a2230653266336134622d356336642d346537662d386139622d306331643265336634613562222c226b65794964223a226261636b656e642d736563703235366b312d7631222c226b696e64223a22737061726b5f7472616e73666572222c226e6f6e6365223a223565653464336332623161302d346635652d346433632d326231612d303938373635343332316665222c227061796c6f6164223a7b22616d6f756e7443656e7473223a31322c22616d6f756e7453617473223a313030302c226d617846656553617473223a35302c22746f223a22737061726b747831717465737461646472657373303030303030303030303030303030303030303030303030303030303030303030303030303030303030227d2c22706f744964223a2237663364396332612d316234652d346638612d623663352d396430653166326133623463222c2276223a317d'
const INTENT_DIGEST = '863d9d6ebb0b8d93d8ce3bf749b05d93e41e56d5e7f7a76aae5a73424e352861'
const INTENT_SIG =
  '62201813d76f7a51537e0ca66e9bbb87ed5310e97d2f1ac5a947b0191d098c7d790b12d7b84d5b38dfb5db0235bdb4828a45d4b95888ca5976ca440eb2b831d9'

const LOCK_BODY =
  '{"decision":"open","expiresAt":"2026-10-09T12:05:00.000Z","keyId":"backend-secp256k1-v1","nonce":"lock-nonce-0f1e2d3c4b5a69788796a5b4c3d2e1f0","v":1}'
const LOCK_HEX =
  '7b226465636973696f6e223a226f70656e222c22657870697265734174223a22323032362d31302d30395431323a30353a30302e3030305a222c226b65794964223a226261636b656e642d736563703235366b312d7631222c226e6f6e6365223a226c6f636b2d6e6f6e63652d3066316532643363346235613639373838373936613562346333643265316630222c2276223a317d'
const LOCK_DIGEST = '41fbbe509052ade05c358527062f0c183a6bed654e09769176161653a130c7e6'
const LOCK_SIG =
  '308d437d4d8752494f6597ab2569223de2dd171e1c21db3776278a9b38516670047df79e99c95b658fc782b5a481488a2b8e5865bfdc6800db8592a534ce021c'

const BINDING_BODY =
  '{"nonce":"binding-nonce-0f1e2d3c4b5a69788796a5b4c3d2e1f0","potId":"7f3d9c2a-1b4e-4f8a-b6c5-9d0e1f2a3b4c","provisionId":"prov_0123456789abcdef","sparkAddress":"spark1pgssyele0qrcjdheeq2a0zmpwdwvj3r4f4stkuju0fp36g6grapv2w7l8am2cp","v":1}'
const BINDING_DIGEST = '77feb108eac309aef709e779d43d4e487ef7bb56c0ad06c45a1ab953690fc219'
const BINDING_SIG =
  '8bacd4e000d70671f33beef4b3bd2d47df62aa57485e996bbd7139029f8415355476af9ba074a94bcb7c9cca924dabc2ab699158a09ee4f1b7e5f1b9dae5a0c7'

const EXPIRES_AT = '2026-10-09T12:05:00.000Z'
const VECTOR_NOW = new Date('2026-10-09T12:04:30.000Z')
const TO = 'sparktx1qtestaddress000000000000000000000000000000000000000000'
const POT_ID = '7f3d9c2a-1b4e-4f8a-b6c5-9d0e1f2a3b4c'
const INTENT_ID = '0e2f3a4b-5c6d-4e7f-8a9b-0c1d2e3f4a5b'
const NONCE = '5ee4d3c2b1a0-4f5e-4d3c-2b1a-0987654321fe'
const SPARK =
  'spark1pgssyele0qrcjdheeq2a0zmpwdwvj3r4f4stkuju0fp36g6grapv2w7l8am2cp'

const trust: IntentTrustStore = new Map([[KEY_ID, TEST_PUBKEY]])
const dirs: string[] = []

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'zappi-intent-'))
  dirs.push(dir)
  return dir
}

function digestHex(body: string): string {
  return Buffer.from(sha256(Buffer.from(body, 'utf8'))).toString('hex')
}

function compactSign(body: string): string {
  return secp256k1.sign(sha256(Buffer.from(body, 'utf8')), TEST_KEY).toHex('compact')
}

function unsignedIntent(): Omit<SpendIntent, 'backendSig'> {
  return {
    potId: POT_ID,
    v: 1,
    expiresAt: EXPIRES_AT,
    kind: 'spark_transfer',
    keyId: KEY_ID,
    nonce: NONCE,
    intentId: INTENT_ID,
    payload: {
      to: TO,
      maxFeeSats: 50,
      amountCents: 12,
      amountSats: 1000,
    },
  }
}

function vectorIntent(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    backendSig: INTENT_SIG,
    potId: POT_ID,
    payload: { maxFeeSats: 50, to: TO, amountSats: 1000, amountCents: 12 },
    v: 1,
    nonce: NONCE,
    kind: 'spark_transfer',
    expiresAt: EXPIRES_AT,
    intentId: INTENT_ID,
    keyId: KEY_ID,
    ...overrides,
  }
}

function expectCode(run: () => unknown, code: string): void {
  try {
    run()
    expect.fail('expected a refusal')
  } catch (error) {
    expect(error).toBeInstanceOf(PotError)
    expect((error as PotError).code).toBe(code)
    expect((error as PotError).message.includes(TEST_KEY)).toBe(false)
  }
}

test('§7.1 canonical intent bytes and signature', () => {
  const body = canonicalIntentBody(unsignedIntent())
  expect(body).toBe(INTENT_BODY)
  expect(Buffer.from(body, 'utf8').toString('hex')).toBe(INTENT_HEX)
  expect(digestHex(body)).toBe(INTENT_DIGEST)
  expect(createHash('sha256').update(body, 'utf8').digest('hex')).toBe(INTENT_DIGEST)
  expect(compactSign(body)).toBe(INTENT_SIG)
  expect(INTENT_SIG).toHaveLength(128)
})

test('§7.1 verifyIntent accepts the signed object and rejects mutations', () => {
  const accepted = verifyIntent({ intent: vectorIntent(), trust, now: VECTOR_NOW })
  expect(accepted.consumed).toBe(false)
  expect(accepted.replay).toBe(false)
  expect(accepted.intent.intentId).toBe(INTENT_ID)

  let consumed = false
  verifyIntent({
    intent: vectorIntent(),
    trust,
    now: VECTOR_NOW,
    ledger: {
      consume() {
        consumed = true
        throw new Error('ledger must not run')
      },
    },
  })
  expect(consumed).toBe(false)

  expectCode(
    () =>
      verifyIntent({
        intent: vectorIntent({
          payload: { to: TO, amountSats: 1001, maxFeeSats: 50, amountCents: 12 },
        }),
        trust,
        now: VECTOR_NOW,
      }),
    'INTENT_BAD_SIGNATURE',
  )
  expectCode(
    () => verifyIntent({ intent: vectorIntent({ keyId: 'backend-secp256k1-v2' }), trust, now: VECTOR_NOW }),
    'INTENT_UNTRUSTED_KEY',
  )
  expectCode(
    () =>
      verifyIntent({
        intent: vectorIntent({ backendSig: `${INTENT_SIG.slice(0, -1)}8` }),
        trust,
        now: VECTOR_NOW,
      }),
    'INTENT_BAD_SIGNATURE',
  )
})

test('DER signatures verify over the same canonical body', () => {
  const der = Buffer.from(
    secp256k1.Signature.fromBytes(Buffer.from(INTENT_SIG, 'hex'), 'compact').toBytes('der'),
  ).toString('hex')
  expect(der.length).not.toBe(128)
  const accepted = verifyIntent({
    intent: vectorIntent({ backendSig: der }),
    trust,
    now: VECTOR_NOW,
  })
  expect(accepted.intent.kind).toBe('spark_transfer')
})

test('verification order is schema, key, expiry, signature, policy, nonce', () => {
  const expiresMs = Date.parse(EXPIRES_AT)
  expectCode(
    () =>
      verifyIntent({
        intent: vectorIntent({ kind: 'wire_anything', keyId: 'missing' }),
        trust,
        now: new Date(expiresMs + 60_000),
      }),
    'INTENT_MALFORMED',
  )
  expectCode(
    () =>
      verifyIntent({
        intent: vectorIntent({ keyId: 'missing' }),
        trust,
        now: new Date(expiresMs + MAX_CLOCK_SKEW_MS),
      }),
    'INTENT_UNTRUSTED_KEY',
  )
  expectCode(
    () =>
      verifyIntent({
        intent: vectorIntent({ backendSig: 'ab'.repeat(64) }),
        trust,
        now: new Date(expiresMs + MAX_CLOCK_SKEW_MS),
      }),
    'INTENT_EXPIRED',
  )
  expectCode(
    () =>
      verifyIntent({
        intent: vectorIntent({ backendSig: 'ab'.repeat(64) }),
        trust,
        now: new Date(expiresMs - MAX_INTENT_TTL_MS - MAX_CLOCK_SKEW_MS - 1),
      }),
    'INTENT_TTL',
  )
  expectCode(
    () =>
      verifyIntent({
        intent: vectorIntent({ backendSig: 'ab'.repeat(64) }),
        trust,
        now: new Date(expiresMs + MAX_CLOCK_SKEW_MS - 1),
      }),
    'INTENT_BAD_SIGNATURE',
  )
  expectCode(
    () =>
      verifyIntent({
        intent: vectorIntent({ backendSig: 'ab'.repeat(64) }),
        trust,
        now: new Date(expiresMs - MAX_INTENT_TTL_MS - MAX_CLOCK_SKEW_MS),
      }),
    'INTENT_BAD_SIGNATURE',
  )

  let policyRan = false
  expectCode(
    () =>
      verifyIntent({
        intent: vectorIntent({ backendSig: 'ab'.repeat(64) }),
        trust,
        now: VECTOR_NOW,
        policy() {
          policyRan = true
        },
      }),
    'INTENT_BAD_SIGNATURE',
  )
  expect(policyRan).toBe(false)

  const path = join(tempDir(), 'nonces.json')
  const ledger = new NonceLedger(path)
  expect(() =>
    verifyIntent({
      intent: vectorIntent(),
      trust,
      now: VECTOR_NOW,
      policy() {
        throw new PotError('WILDCARD', 'WILDCARD')
      },
      ledger,
    }),
  ).toThrow('WILDCARD')
  expect(existsSync(path)).toBe(false)

  expectCode(
    () => verifyIntent({ intent: vectorIntent(), trust, now: VECTOR_NOW, policy() {} }),
    'INTENT_LEDGER_REQUIRED',
  )

  const calls: string[] = []
  const first = verifyIntent({
    intent: vectorIntent(),
    trust,
    now: VECTOR_NOW,
    policy() {
      calls.push('policy')
    },
    ledger: {
      consume(nonce, intentId) {
        calls.push('nonce')
        return { replay: false, record: { intentId, expiresAt: EXPIRES_AT, nonce } }
      },
    },
  })
  expect(calls).toEqual(['policy', 'nonce'])
  expect(first.consumed).toBe(true)
  expect(first.replay).toBe(false)
})

test('a real ledger consumes once and refuses a different intentId', () => {
  const ledger = new NonceLedger(join(tempDir(), 'nonces.json'))
  const first = verifyIntent({
    intent: vectorIntent(),
    trust,
    now: VECTOR_NOW,
    policy() {},
    ledger,
  })
  expect(first.replay).toBe(false)
  const second = verifyIntent({
    intent: vectorIntent(),
    trust,
    now: VECTOR_NOW,
    policy() {},
    ledger,
  })
  expect(second.replay).toBe(true)
  const otherId = '11111111-1111-4111-8111-111111111111'
  const other = { ...unsignedIntent(), intentId: otherId }
  expect(() =>
    verifyIntent({
      intent: { ...other, backendSig: compactSign(canonicalIntentBody(other)) },
      trust,
      now: VECTOR_NOW,
      policy() {},
      ledger,
    }),
  ).toThrow('Intent nonce was already used. Refusing the replay.')
})

test('schema accepts every kind and rejects unknown payload fields', () => {
  const base = {
    v: 1,
    intentId: INTENT_ID,
    potId: POT_ID,
    nonce: NONCE,
    expiresAt: EXPIRES_AT,
    keyId: KEY_ID,
    backendSig: '11'.repeat(64),
  }
  expectCode(
    () =>
      verifyIntent({
        intent: { ...base, kind: 'sweep_to_main', payload: { mainAddress: 'spark1main' } },
        trust,
        now: VECTOR_NOW,
      }),
    'INTENT_BAD_SIGNATURE',
  )
  expectCode(
    () =>
      verifyIntent({
        intent: {
          ...base,
          kind: 'spark_transfer',
          payload: { to: TO, amountSats: 1000, maxFeeSats: 50, note: 'x' },
        },
        trust,
        now: VECTOR_NOW,
      }),
    'INTENT_MALFORMED',
  )
  expectCode(
    () =>
      verifyIntent({
        intent: {
          ...base,
          kind: 'l1_withdraw',
          payload: { address: 'bc1q', amountSats: 0 },
        },
        trust,
        now: VECTOR_NOW,
      }),
    'INTENT_MALFORMED',
  )
})

test('§7.2 lock attestation bytes, open verify, and locked refusal', () => {
  const body = canonicalLockBody({
    keyId: KEY_ID,
    nonce: 'lock-nonce-0f1e2d3c4b5a69788796a5b4c3d2e1f0',
    decision: 'open',
    expiresAt: EXPIRES_AT,
  })
  expect(body).toBe(LOCK_BODY)
  expect(Buffer.from(body, 'utf8').toString('hex')).toBe(LOCK_HEX)
  expect(digestHex(body)).toBe(LOCK_DIGEST)
  expect(compactSign(body)).toBe(LOCK_SIG)

  const open = {
    decision: 'open',
    nonce: 'lock-nonce-0f1e2d3c4b5a69788796a5b4c3d2e1f0',
    expiresAt: EXPIRES_AT,
    keyId: KEY_ID,
    backendSig: LOCK_SIG,
    type: 'lock',
  }
  const verified = verifyLockAttestation({ lock: open, trust, now: VECTOR_NOW })
  expect(verified.consumed).toBe(false)
  expect(verified.lock.decision).toBe('open')

  const ledger = new NonceLedger(join(tempDir(), 'nonces.json'))
  const consumed = verifyLockAttestation({ lock: open, trust, now: VECTOR_NOW, ledger })
  expect(consumed.consumed).toBe(true)
  expect(consumed.replay).toBe(false)
  const again = verifyLockAttestation({ lock: open, trust, now: VECTOR_NOW, ledger })
  expect(again.replay).toBe(true)

  const lockedBody = canonicalLockBody({
    decision: 'locked',
    nonce: 'lock-nonce-locked',
    expiresAt: EXPIRES_AT,
    keyId: KEY_ID,
  })
  let ledgerCalled = false
  expectCode(
    () =>
      verifyLockAttestation({
        lock: {
          decision: 'locked',
          nonce: 'lock-nonce-locked',
          expiresAt: EXPIRES_AT,
          keyId: KEY_ID,
          backendSig: compactSign(lockedBody),
        },
        trust,
        now: VECTOR_NOW,
        ledger: {
          consume() {
            ledgerCalled = true
            throw new Error('locked must not consume')
          },
        },
      }),
    'LOCK_LOCKED',
  )
  expect(ledgerCalled).toBe(false)
  expect(verifyIntent({ intent: vectorIntent(), trust, now: VECTOR_NOW }).consumed).toBe(false)

  expectCode(
    () =>
      verifyLockAttestation({
        lock: { ...open, decision: 'locked' },
        trust,
        now: VECTOR_NOW,
      }),
    'LOCK_BAD_SIGNATURE',
  )
  expectCode(
    () =>
      verifyLockAttestation({
        lock: { ...open, backendSig: 'ab'.repeat(64) },
        trust,
        now: new Date(Date.parse(EXPIRES_AT) + MAX_CLOCK_SKEW_MS),
      }),
    'LOCK_EXPIRED',
  )
})

test('a lock nonce and a spend nonce share one ledger', () => {
  const ledger = new NonceLedger(join(tempDir(), 'nonces.json'))
  verifyIntent({ intent: vectorIntent(), trust, now: VECTOR_NOW, policy() {}, ledger })
  const body = canonicalLockBody({
    decision: 'open',
    nonce: NONCE,
    expiresAt: EXPIRES_AT,
    keyId: KEY_ID,
  })
  expect(() =>
    verifyLockAttestation({
      lock: {
        decision: 'open',
        nonce: NONCE,
        expiresAt: EXPIRES_AT,
        keyId: KEY_ID,
        backendSig: compactSign(body),
      },
      trust,
      now: VECTOR_NOW,
      ledger,
    }),
  ).toThrow('Intent nonce was already used. Refusing the replay.')
  expect(lockIntentId(NONCE)).toBe(`lock:${NONCE}`)
})

test('§7.4 binding receipt bytes and pin check', () => {
  const body = canonicalBindingBody({
    sparkAddress: SPARK,
    v: 1,
    nonce: 'binding-nonce-0f1e2d3c4b5a69788796a5b4c3d2e1f0',
    provisionId: 'prov_0123456789abcdef',
    potId: POT_ID,
  })
  expect(body).toBe(BINDING_BODY)
  expect(digestHex(body)).toBe(BINDING_DIGEST)
  expect(compactSign(body)).toBe(BINDING_SIG)

  const receipt = {
    v: 1,
    provisionId: 'prov_0123456789abcdef',
    potId: POT_ID,
    sparkAddress: SPARK,
    nonce: 'binding-nonce-0f1e2d3c4b5a69788796a5b4c3d2e1f0',
    backendSig: BINDING_SIG,
  }
  const verified = verifyBindingReceipt(receipt, TEST_PUBKEY, { provisionId: receipt.provisionId, potId: POT_ID })
  expect(verified.sparkAddress).toBe(SPARK)
  expectCode(() => verifyBindingReceipt({ ...receipt, sparkAddress: `${SPARK}x` }, TEST_PUBKEY), 'BINDING_BAD_SIGNATURE')
  expectCode(() => verifyBindingReceipt(receipt, `03${TEST_PUBKEY.slice(2)}`), 'BINDING_BAD_SIGNATURE')
  expectCode(() => verifyBindingReceipt(receipt, '   '), 'TRUST_UNPINNED')
  expectCode(
    () => verifyBindingReceipt(receipt, TEST_PUBKEY, { potId: 'other-pot' }),
    'BINDING_MISMATCH',
  )
  expectCode(() => verifyBindingReceipt({ ...receipt, provisionId: 'prov_ZZ' }, TEST_PUBKEY), 'BINDING_MALFORMED')
})
