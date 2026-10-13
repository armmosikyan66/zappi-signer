import { mkdtempSync, rmSync, existsSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { secp256k1 } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha2'
import { afterEach, expect, test } from 'vitest'
import { runAgentProvision, runFinalize, runProveChallenge } from '../src/commands/agent.js'
import { parseSignerArgv } from '../src/index.js'
import { canonicalBindingBody } from '../src/intent.js'
import { TEST_SCRYPT } from '../src/kdf.js'
import { MemoryKeyStore } from '../src/keystore/memory.js'
import { encodeSparkAddress } from '../src/spark/address.js'
import { type SparkSigner } from '../src/spark/signer.js'
import { saveServerPubkey, type PinnedTrust } from '../src/trust.js'
import { VaultStore } from '../src/vault/vault.js'

/**
 * Same public test scalar as test/intent.test.ts (§7). Not a production secret.
 */
const SERVER_PRIV = '0000000000000000000000000000000000000000000000000000000000000001'
const SERVER_PUBKEY = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const SERVER_PUBKEY_2 = Buffer.from(
  secp256k1.getPublicKey(Buffer.from('0000000000000000000000000000000000000000000000000000000000000002', 'hex'), true),
).toString('hex')
const POT_ID = '0e5b5049-5cc1-4e0a-9f53-f398dc434ef2'
const POT_ID_2 = '11111111-2222-4333-8444-555555555555'
const PROVISION_RE = /^prov_[0-9a-f]{16}$/

const dirs: string[] = []

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

function openVault(): VaultStore {
  const dir = mkdtempSync(join(tmpdir(), 'zappi-agent-'))
  dirs.push(dir)
  return new VaultStore({
    vaultPath: join(dir, 'seed-vault.json'),
    keystore: new MemoryKeyStore(),
    kdf: TEST_SCRYPT,
  })
}

function pinned(): PinnedTrust {
  return { keys: new Map(), serverPubkey: SERVER_PUBKEY }
}

function sparkFor(address: string): { spark: SparkSigner; lastMessage: () => string } {
  let message = ''
  const spark: SparkSigner = {
    async derive() {
      return { address, pubkey: POT_PUBKEY }
    },
    async signRelay(_mnemonic, _network, text) {
      message = text
      return { signature: 'ab'.repeat(32), pubkey: POT_PUBKEY }
    },
    async signNonce() {
      throw new Error('not used')
    },
    async balanceSats() {
      return 0
    },
    async transfer() {
      throw new Error('not used')
    },
  }
  return { spark, lastMessage: () => message }
}

const POT_PUBKEY = `02${'ab'.repeat(32)}`
const SPARK = encodeSparkAddress(new Uint8Array(33).fill(2))

function serverSign(message: string, privateKeyHex = SERVER_PRIV): string {
  const digest = sha256(Buffer.from(message, 'utf8'))
  return secp256k1.sign(digest, Buffer.from(privateKeyHex, 'hex')).toHex('compact')
}

function attachChallenge(input?: { address?: string; nonce?: string; key?: string }): Record<string, unknown> {
  const address = input?.address ?? SPARK
  const nonce = input?.nonce ?? '11111111-1111-4111-8111-111111111111'
  const message = `zappi-pot-address-bind:v1:proj:user_1:attach:${address}:${nonce}`
  return {
    nonce,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    message,
    sparkAddress: address,
    action: 'attach',
    signature: serverSign(message, input?.key),
  }
}

test('provision <potId> stores the wallet under the backend pot id', async () => {
  const vault = openVault()
  const { spark } = sparkFor(SPARK)
  const result = await runAgentProvision({ vault, spark, potId: POT_ID, label: 'free-pot' })
  expect(result.potId).toBe(POT_ID)
  expect(result.provisionId).toMatch(PROVISION_RE)
  expect(result.address).toBe(SPARK)
  const snapshot = await vault.snapshot(POT_ID)
  expect(snapshot?.provisionId).toBe(result.provisionId)
  expect(snapshot?.bound).toBe(false)
  expect(snapshot?.label).toBe('free-pot')
  expect(JSON.stringify(result)).not.toContain('mnemonic')
})

test('provision <potId> is idempotent and resumes the same wallet', async () => {
  const vault = openVault()
  const first = sparkFor(SPARK)
  const second = sparkFor(encodeSparkAddress(new Uint8Array(33).fill(3)))
  await runAgentProvision({ vault, spark: first.spark, potId: POT_ID })
  const again = await runAgentProvision({ vault, spark: second.spark, potId: POT_ID })
  const snapshot = await vault.snapshot(POT_ID)
  expect(snapshot?.address).toBe(SPARK)
  expect(again.address).toBe(SPARK)
})

test('provision refuses a non-UUID pot id', async () => {
  const vault = openVault()
  const { spark } = sparkFor(SPARK)
  await expect(runAgentProvision({ vault, spark, potId: 'pot_0123456789abcdef0123456789abcdef' })).rejects.toThrow(
    'pot id is not a server pot id',
  )
})

test('prove-address signs the attach challenge and matches the provision', async () => {
  const vault = openVault()
  const { spark } = sparkFor(SPARK)
  const provisioned = await runAgentProvision({ vault, spark, potId: POT_ID })
  const challenge = attachChallenge()
  const result = await runProveChallenge({
    vault,
    spark,
    trust: pinned(),
    provisionId: provisioned.provisionId,
    challenge,
  })
  expect(result.potId).toBe(POT_ID)
  expect(result.sparkAddress).toBe(SPARK)
  expect(result.signature).toBe('ab'.repeat(32))
  expect(result.nonce).toBe(challenge.nonce)
})

test('prove-address refuses an unpinned signer and a wrong pin', async () => {
  const vault = openVault()
  const { spark } = sparkFor(SPARK)
  const provisioned = await runAgentProvision({ vault, spark, potId: POT_ID })
  await expect(
    runProveChallenge({ vault, spark, trust: { keys: new Map() }, provisionId: provisioned.provisionId, challenge: attachChallenge() }),
  ).rejects.toThrow('signer trust is not pinned')
  await expect(
    runProveChallenge({
      vault,
      spark,
      trust: { keys: new Map(), serverPubkey: SERVER_PUBKEY_2 },
      provisionId: provisioned.provisionId,
      challenge: attachChallenge(),
    }),
  ).rejects.toThrow('address challenge signature is invalid')
})

test('prove-address refuses a challenge for another address', async () => {
  const vault = openVault()
  const { spark } = sparkFor(SPARK)
  const provisioned = await runAgentProvision({ vault, spark, potId: POT_ID })
  const other = encodeSparkAddress(new Uint8Array(33).fill(4))
  await expect(
    runProveChallenge({
      vault,
      spark,
      trust: pinned(),
      provisionId: provisioned.provisionId,
      challenge: attachChallenge({ address: other }),
    }),
  ).rejects.toThrow()
})

test('prove-address refuses a serverPubkey inside the challenge', async () => {
  const vault = openVault()
  const { spark } = sparkFor(SPARK)
  const provisioned = await runAgentProvision({ vault, spark, potId: POT_ID })
  const challenge = { ...attachChallenge(), serverPubkey: SERVER_PUBKEY }
  await expect(
    runProveChallenge({ vault, spark, trust: pinned(), provisionId: provisioned.provisionId, challenge }),
  ).rejects.toThrow('address challenge is malformed')
})

test('finalize marks bound only after a valid binding receipt', async () => {
  const vault = openVault()
  const { spark } = sparkFor(SPARK)
  const provisioned = await runAgentProvision({ vault, spark, potId: POT_ID })
  const receiptBody = {
    v: 1,
    provisionId: provisioned.provisionId,
    potId: POT_ID,
    sparkAddress: SPARK,
    nonce: 'a'.repeat(32),
  } as const
  const sign = (body: typeof receiptBody) =>
    secp256k1.sign(sha256(Buffer.from(canonicalBindingBody(body), 'utf8')), Buffer.from(SERVER_PRIV, 'hex')).toHex('compact')
  const receipt = { ...receiptBody, backendSig: sign(receiptBody) }
  const wrongPot = {
    ...receiptBody,
    potId: POT_ID_2,
    backendSig: sign({ ...receiptBody, potId: POT_ID_2 }),
  }
  await expect(
    runFinalize({ vault, trust: pinned(), potId: POT_ID, bindingReceipt: wrongPot }),
  ).rejects.toThrow('binding receipt does not match the pot')
  await expect(
    runFinalize({ vault, trust: pinned(), potId: POT_ID, bindingReceipt: { ...receipt, backendSig: 'ff'.repeat(64) } }),
  ).rejects.toThrow('binding receipt signature is invalid')
  const result = await runFinalize({ vault, trust: pinned(), potId: POT_ID, bindingReceipt: receipt })
  expect(result).toEqual({ potId: POT_ID, address: SPARK, bound: true })
  const snapshot = await vault.snapshot(POT_ID)
  expect(snapshot?.bound).toBe(true)
})

test('finalize refuses a non-UUID pot id and an unknown pot', async () => {
  const vault = openVault()
  await expect(runFinalize({ vault, trust: pinned(), potId: 'pot_0123456789abcdef0123456789abcdef', bindingReceipt: {} })).rejects.toThrow(
    'no pot',
  )
  await expect(runFinalize({ vault, trust: pinned(), potId: POT_ID, bindingReceipt: {} })).rejects.toThrow('no pot')
})

test('trust-server writes the pin and loadPinnedTrust reads it back', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zappi-trust-'))
  dirs.push(dir)
  const configPath = join(dir, 'trust.json')
  const saved = saveServerPubkey({ serverPubkey: SERVER_PUBKEY, configPath })
  expect(saved.serverPubkey).toBe(SERVER_PUBKEY)
  expect(existsSync(configPath)).toBe(true)
  const parsed = JSON.parse(readFileSync(configPath, 'utf8')) as { serverPubkey?: string }
  expect(parsed.serverPubkey).toBe(SERVER_PUBKEY)
  const second = saveServerPubkey({ serverPubkey: SERVER_PUBKEY_2, configPath })
  expect(second.serverPubkey).toBe(SERVER_PUBKEY_2)
  const overwritten = JSON.parse(readFileSync(configPath, 'utf8')) as { serverPubkey?: string }
  expect(overwritten.serverPubkey).toBe(SERVER_PUBKEY_2)
})

test('parser accepts the server-pot-first shapes and rejects mixed ones', () => {
  expect(parseSignerArgv(['provision', POT_ID, '--json'])).toMatchObject({ command: 'provision', args: [POT_ID] })
  expect(parseSignerArgv(['provision', POT_ID, '--label', 'x', '--json'])).toMatchObject({
    command: 'provision',
    args: [POT_ID],
    label: 'x',
  })
  expect(parseSignerArgv(['trust-server', '--pubkey', SERVER_PUBKEY, '--json'])).toMatchObject({
    command: 'trust-server',
    args: [],
    pubkey: SERVER_PUBKEY,
  })
  expect(parseSignerArgv(['prove-address', 'prov_0123456789abcdef', '--challenge', '{"nonce":"n"}', '--json'])).toMatchObject({
    command: 'prove-address',
    args: ['prov_0123456789abcdef'],
    challenge: '{"nonce":"n"}',
  })
  expect(parseSignerArgv(['finalize', '--pot', POT_ID, '--json'])).toMatchObject({ command: 'finalize', args: [], potId: POT_ID })
  // Mixed or missing required flags are refused.
  expect(parseSignerArgv(['provision', POT_ID, '--pot', POT_ID_2])).toBeNull()
  expect(parseSignerArgv(['prove-address', 'prov_0123456789abcdef', '--pot', POT_ID])).toBeNull()
  expect(parseSignerArgv(['prove-address', 'prov_0123456789abcdef', '--label', 'x'])).toBeNull()
  expect(parseSignerArgv(['trust-server'])).toBeNull()
  expect(parseSignerArgv(['trust-server', '--pubkey'])).toBeNull()
  expect(parseSignerArgv(['finalize', '--label', 'x'])).toBeNull()
  // Receipt mode stays valid.
  expect(parseSignerArgv(['prove-address', '--pot', POT_ID, '--json'])).toMatchObject({ command: 'prove-address', args: [], potId: POT_ID })
  expect(parseSignerArgv(['provision', '--label', 'desk', '--json'])).toMatchObject({ command: 'provision', args: [], label: 'desk' })
})