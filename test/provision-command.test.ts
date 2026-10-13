import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { secp256k1 } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha2'
import { generateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
import { afterEach, expect, test } from 'vitest'
import { runProveAddress, runProvision, type ProvisionClient } from '../src/commands/provision.js'
import { PotError } from '../src/errors.js'
import { canonicalBindingBody, type NonceConsumeResult, type NonceStore } from '../src/intent.js'
import { TEST_SCRYPT } from '../src/kdf.js'
import { MemoryKeyStore } from '../src/keystore/memory.js'
import { encodeSparkAddress } from '../src/spark/address.js'
import { type SparkSigner } from '../src/spark/signer.js'
import { type PinnedTrust } from '../src/trust.js'
import { VaultStore } from '../src/vault/vault.js'

/**
 * Same public test scalar as test/intent.test.ts (§7). Not a production secret.
 */
const TEST_KEY = '0000000000000000000000000000000000000000000000000000000000000001'
const TEST_PUBKEY = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const OTHER_KEY = '0000000000000000000000000000000000000000000000000000000000000002'
const KEY_ID = 'backend-secp256k1-v1'
const NONCE = '11111111-1111-4111-8111-111111111111'
const SPARK = encodeSparkAddress(new Uint8Array(33).fill(2))
const POT_PUBKEY = `02${'ab'.repeat(32)}`

const dirs: string[] = []

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

class CountingVault extends VaultStore {
  markBoundCalls = 0

  override async markBound(potId?: string): Promise<void> {
    this.markBoundCalls += 1
    await super.markBound(potId)
  }
}

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

function openVault(): CountingVault {
  const dir = mkdtempSync(join(tmpdir(), 'zappi-cmd-'))
  dirs.push(dir)
  return new CountingVault({
    vaultPath: join(dir, 'seed-vault.json'),
    keystore: new MemoryKeyStore(),
    kdf: TEST_SCRYPT,
  })
}

function otherPubkey(): string {
  return Buffer.from(secp256k1.getPublicKey(Buffer.from(OTHER_KEY, 'hex'), true)).toString('hex')
}

function pinned(): PinnedTrust {
  return { keys: new Map([[KEY_ID, TEST_PUBKEY]]), serverPubkey: TEST_PUBKEY }
}

function trustDocument(addressChallengePubkey: string): unknown {
  return {
    keys: { [KEY_ID]: TEST_PUBKEY },
    activeKeyId: KEY_ID,
    addressChallengePubkey,
  }
}

function soon(): string {
  return new Date(Date.now() + 60_000).toISOString()
}

function challengeMessage(address: string): string {
  return `zappi-pot-address-bind:v1:native:user_1:create:${address}:${NONCE}`
}

function http(handler: (method: string, path: string, body: unknown) => unknown): {
  client: ProvisionClient
  calls: Array<{ method: string; path: string; body?: unknown }>
} {
  const calls: Array<{ method: string; path: string; body?: unknown }> = []
  return {
    calls,
    client: {
      async request(method, path, body) {
        calls.push({ method, path, body })
        if (path.includes('spend-authorizations')) throw new Error('authorization posted')
        return handler(method, path, body)
      },
    },
  }
}

function sparkFor(address = SPARK): { spark: SparkSigner; signed: string[]; phrase: () => string } {
  const signed: string[] = []
  let phrase = ''
  const spark: SparkSigner = {
    async derive(mnemonic) {
      phrase = Buffer.from(mnemonic).toString('utf8')
      return { address, pubkey: POT_PUBKEY }
    },
    async signRelay(_mnemonic, network, message) {
      if (network !== 'MAINNET') throw new Error('network')
      signed.push(message)
      return { signature: 'cd'.repeat(64), pubkey: POT_PUBKEY }
    },
    async signNonce() {
      throw new Error('signNonce')
    },
    async balanceSats() {
      throw new Error('balance')
    },
    async transfer() {
      throw new Error('transfer')
    },
  }
  return { spark, signed, phrase: () => phrase }
}

async function seed(vault: VaultStore, address = SPARK) {
  return vault.create({
    mnemonic: generateMnemonic(wordlist, 128),
    address,
    pubkey: POT_PUBKEY,
    accountIndex: 1,
    network: 'MAINNET',
    positions: [0, 1, 2],
    today: '2026-10-13',
    role: 'free',
  })
}

function bindingReceipt(potId: string, address: string, key: string) {
  const unsigned = {
    v: 1 as const,
    provisionId: 'prov_0123456789abcdef',
    potId,
    sparkAddress: address,
    nonce: 'binding-nonce-0f1e2d3c4b5a69788796a5b4c3d2e1f0',
  }
  return {
    ...unsigned,
    backendSig: secp256k1.sign(sha256(Buffer.from(canonicalBindingBody(unsigned), 'utf8')), key).toHex('compact'),
  }
}

test('provision refuses a trust mismatch and does not mark bound', async () => {
  const vault = openVault()
  const seeded = await seed(vault)
  const { client, calls } = http((method, path) => {
    if (method === 'GET' && path === '/api/signer/trust') return trustDocument(otherPubkey())
    throw new Error(`unexpected ${method} ${path}`)
  })
  const spark: SparkSigner = {
    async derive() {
      throw new Error('spark was called')
    },
    async signRelay() {
      throw new Error('spark was called')
    },
    async signNonce() {
      throw new Error('spark was called')
    },
    async balanceSats() {
      throw new Error('spark was called')
    },
    async transfer() {
      throw new Error('spark was called')
    },
  }

  await expect(
    runProvision({
      vault,
      spark,
      client,
      trust: pinned(),
      ledger: new MemoryLedger(),
    }),
  ).rejects.toMatchObject({ code: 'TRUST_MISMATCH' })

  expect(vault.markBoundCalls).toBe(0)
  expect(await vault.list()).toHaveLength(1)
  expect((await vault.snapshot(seeded.potId))?.bound).toBe(false)
  expect(calls.map((call) => `${call.method} ${call.path}`)).toEqual(['GET /api/signer/trust'])
  expect(calls.some((call) => call.path.includes('spend-authorizations'))).toBe(false)
})

test('provision returns bind material and leaves the pot unbound', async () => {
  const vault = openVault()
  const message = challengeMessage(SPARK)
  const { client, calls } = http((method, path, body) => {
    if (method === 'GET' && path === '/api/signer/trust') return trustDocument(TEST_PUBKEY)
    if (method === 'POST' && path === '/api/wallet/pots/address-proof-challenge') {
      expect(body).toEqual({ sparkAddress: SPARK })
      return { nonce: NONCE, expiresAt: soon(), message }
    }
    throw new Error(`unexpected ${method} ${path}`)
  })
  const { spark, signed, phrase } = sparkFor()
  const ledger = new MemoryLedger()

  const result = await runProvision({
    vault,
    spark,
    client,
    trust: pinned(),
    ledger,
    potLabel: 'free',
  })

  expect(result.address).toBe(SPARK)
  expect(result.pubkey).toBe(POT_PUBKEY)
  expect(result.signature).toBe('cd'.repeat(64))
  expect(result.nonce).toBe(NONCE)
  expect(result.provisionId).toMatch(/^prov_[0-9a-f]{16}$/)
  expect(signed).toEqual([message])
  expect(JSON.stringify(result)).not.toContain(phrase())
  expect(ledger.rows.has(NONCE)).toBe(true)
  expect(vault.markBoundCalls).toBe(0)
  const snapshot = await vault.snapshot(result.potId)
  expect(snapshot?.bound).toBe(false)
  expect(snapshot?.role).toBe('free')
  expect(snapshot?.label).toBe('free')
  expect(calls.map((call) => `${call.method} ${call.path}`)).toEqual([
    'GET /api/signer/trust',
    'POST /api/wallet/pots/address-proof-challenge',
  ])
  expect(calls.some((call) => call.path.includes('spend-authorizations'))).toBe(false)
})

test('a forged address-challenge signature does not mark bound', async () => {
  const vault = openVault()
  const seeded = await seed(vault)
  const { client } = http((method, path) => {
    if (method === 'GET' && path === '/api/signer/trust') return trustDocument(TEST_PUBKEY)
    if (method === 'POST' && path === '/api/wallet/pots/address-proof-challenge') {
      return {
        nonce: NONCE,
        expiresAt: soon(),
        message: challengeMessage(SPARK),
        signature: 'ab'.repeat(64),
        serverPubkey: TEST_PUBKEY,
      }
    }
    throw new Error(`unexpected ${method} ${path}`)
  })
  const { spark, signed } = sparkFor()

  await expect(
    runProvision({ vault, spark, client, trust: pinned(), ledger: new MemoryLedger() }),
  ).rejects.toMatchObject({ code: 'CHALLENGE_BAD_SIGNATURE' })

  expect(signed).toEqual([])
  expect(vault.markBoundCalls).toBe(0)
  expect(await vault.list()).toHaveLength(1)
  expect((await vault.snapshot(seeded.potId))?.bound).toBe(false)
})

test('prove-address marks bound only after a valid binding receipt', async () => {
  const vault = openVault()
  const created = await seed(vault)
  expect((await vault.snapshot(created.potId))?.bound).toBe(false)
  const trust: PinnedTrust = { keys: new Map(), serverPubkey: TEST_PUBKEY }

  const result = await runProveAddress({
    vault,
    trust,
    potId: created.potId,
    bindingReceipt: bindingReceipt(created.potId, SPARK, TEST_KEY),
  })

  expect(result).toEqual({ potId: created.potId, address: SPARK, bound: true })
  expect(vault.markBoundCalls).toBe(1)
  expect((await vault.snapshot(created.potId))?.bound).toBe(true)
})

test('a forged binding receipt does not mark bound', async () => {
  const vault = openVault()
  const created = await seed(vault)
  const trust: PinnedTrust = { keys: new Map(), serverPubkey: TEST_PUBKEY }
  const forged = bindingReceipt(created.potId, SPARK, OTHER_KEY)

  const error = await runProveAddress({
    vault,
    trust,
    potId: created.potId,
    bindingReceipt: forged,
  }).then(
    () => {
      throw new Error('forged receipt was accepted')
    },
    (caught: unknown) => caught,
  )

  expect(error).toBeInstanceOf(PotError)
  const failure = error as PotError
  expect(failure.code).toBe('BINDING_BAD_SIGNATURE')
  expect(failure.message.length).toBeLessThan(80)
  expect(failure.message).not.toContain(TEST_KEY)
  expect(failure.message).not.toContain(forged.backendSig)
  expect(vault.markBoundCalls).toBe(0)
  expect((await vault.snapshot(created.potId))?.bound).toBe(false)
})
