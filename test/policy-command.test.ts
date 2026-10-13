import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
import { afterEach, expect, test } from 'vitest'
import { runPolicyTighten, runPolicyView } from '../src/commands/policy.js'
import { TEST_SCRYPT } from '../src/kdf.js'
import { MemoryKeyStore } from '../src/keystore/memory.js'
import type { KeyStore } from '../src/keystore/types.js'
import { encodeSparkAddress } from '../src/spark/address.js'
import { VaultStore } from '../src/vault/vault.js'

const dirs: string[] = []

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

function tempVault(keystore: KeyStore = new MemoryKeyStore()): { vault: VaultStore; keystore: KeyStore } {
  const dir = mkdtempSync(join(tmpdir(), 'zappi-signer-policy-'))
  dirs.push(dir)
  const vault = new VaultStore({
    vaultPath: join(dir, 'seed-vault.json'),
    keystore,
    kdf: TEST_SCRYPT,
  })
  return { vault, keystore }
}

const address = encodeSparkAddress(new Uint8Array(33).fill(2))
const pubkey = `02${'ab'.repeat(32)}`

async function seed(vault: VaultStore) {
  const mnemonic = generateMnemonic(wordlist, 128)
  const created = await vault.create({
    mnemonic,
    address,
    pubkey,
    accountIndex: 1,
    network: 'REGTEST',
    positions: [0, 1, 2],
    today: '2026-10-12',
  })
  return { created, mnemonic }
}

function withoutPresence(inner: KeyStore): KeyStore {
  return {
    getSecret: (account) => inner.getSecret(account),
    setSecret: (account, value) => inner.setSecret(account, value),
    deleteSecret: (account) => inner.deleteSecret(account),
    deviceFactor: () => inner.deviceFactor(),
  }
}

test('view returns the public policy and omits the mnemonic', async () => {
  const { vault } = tempVault()
  const { created, mnemonic } = await seed(vault)
  const view = await runPolicyView({ vault, potId: created.potId })
  const snap = await vault.snapshot(created.potId)
  expect(view.potId).toBe(created.potId)
  expect(view.role).toBe('free')
  expect(view.freeze).toBe('active')
  expect(view.policy).toEqual(snap?.policy)
  expect(view.policy.perTxSats).toBe(100_000)
  const encoded = JSON.stringify(view)
  expect(encoded).not.toContain(mnemonic)
  expect(encoded).not.toContain('"mnemonic"')
  expect(Object.keys(view)).not.toContain('mnemonic')
})

test('tighten succeeds after user presence', async () => {
  const inner = new MemoryKeyStore()
  let calls = 0
  const keystore: KeyStore = {
    getSecret: (account) => inner.getSecret(account),
    setSecret: (account, value) => inner.setSecret(account, value),
    deleteSecret: (account) => inner.deleteSecret(account),
    deviceFactor: () => inner.deviceFactor(),
    async confirmUserPresence(reason) {
      calls += 1
      expect(reason).toBe('Authorize Zappi')
      return true
    },
  }
  const { vault } = tempVault(keystore)
  const { created, mnemonic } = await seed(vault)
  const current = await runPolicyView({ vault, potId: created.potId })
  const nextPolicy = { ...current.policy, perTxSats: current.policy.perTxSats - 1 }
  const updated = await runPolicyTighten({
    vault,
    keystore,
    potId: created.potId,
    nextPolicy,
  })
  expect(calls).toBe(1)
  expect(updated.policy.perTxSats).toBe(99_999)
  expect(JSON.stringify(updated)).not.toContain(mnemonic)
  const stored = await vault.snapshot(created.potId)
  expect(stored?.policy.perTxSats).toBe(99_999)
  expect(stored?.policy.spentTodaySats).toBe(current.policy.spentTodaySats)
})

test('tighten refuses when user presence is missing', async () => {
  const inner = new MemoryKeyStore()
  const { vault } = tempVault(inner)
  const { created } = await seed(vault)
  const current = await runPolicyView({ vault, potId: created.potId })
  const nextPolicy = { ...current.policy, perTxSats: current.policy.perTxSats - 1 }
  await expect(
    runPolicyTighten({
      vault,
      keystore: withoutPresence(inner),
      potId: created.potId,
      nextPolicy,
    }),
  ).rejects.toThrow('keychain unavailable')
  const stored = await vault.snapshot(created.potId)
  expect(stored?.policy.perTxSats).toBe(current.policy.perTxSats)
})

test('tighten refuses when user presence returns false', async () => {
  const inner = new MemoryKeyStore()
  const keystore: KeyStore = {
    getSecret: (account) => inner.getSecret(account),
    setSecret: (account, value) => inner.setSecret(account, value),
    deleteSecret: (account) => inner.deleteSecret(account),
    deviceFactor: () => inner.deviceFactor(),
    confirmUserPresence: async () => false,
  }
  const { vault } = tempVault(inner)
  const { created } = await seed(vault)
  const current = await runPolicyView({ vault, potId: created.potId })
  await expect(
    runPolicyTighten({
      vault,
      keystore,
      potId: created.potId,
      nextPolicy: { ...current.policy, dailySats: current.policy.dailySats - 1 },
    }),
  ).rejects.toThrow('keychain unavailable')
  const stored = await vault.snapshot(created.potId)
  expect(stored?.policy.dailySats).toBe(current.policy.dailySats)
})

test('a looser policy refuses', async () => {
  const { vault, keystore } = tempVault()
  const { created } = await seed(vault)
  const current = await runPolicyView({ vault, potId: created.potId })
  await expect(
    runPolicyTighten({
      vault,
      keystore,
      potId: created.potId,
      nextPolicy: { ...current.policy, perTxSats: current.policy.perTxSats + 1 },
    }),
  ).rejects.toThrow('POLICY_LOOSER')
  await expect(
    runPolicyTighten({
      vault,
      keystore,
      potId: created.potId,
      nextPolicy: {
        ...current.policy,
        destinations: {
          ...current.policy.destinations,
          allow: [...current.policy.destinations.allow, 'spark1extra'],
        },
      },
    }),
  ).rejects.toThrow('POLICY_LOOSER')
  const stored = await vault.snapshot(created.potId)
  expect(stored?.policy).toEqual(current.policy)
})
