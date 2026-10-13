import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
import { afterEach, expect, test } from 'vitest'
import { runBackup, runRestore } from '../src/commands/backup.js'
import { TEST_SCRYPT, type Argon2Params } from '../src/kdf.js'
import { MemoryKeyStore } from '../src/keystore/memory.js'
import { encodeSparkAddress } from '../src/spark/address.js'
import { VaultStore } from '../src/vault/vault.js'

const FAST_ARGON2: Argon2Params = { t: 1, m: 8, p: 1, dkLen: 32 }

const dirs: string[] = []

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

function tempVault(): { vault: VaultStore; keystore: MemoryKeyStore } {
  const dir = mkdtempSync(join(tmpdir(), 'zappi-signer-backup-'))
  dirs.push(dir)
  const keystore = new MemoryKeyStore()
  const vault = new VaultStore({
    vaultPath: join(dir, 'seed-vault.json'),
    keystore,
    kdf: TEST_SCRYPT,
  })
  return { vault, keystore }
}

const address = encodeSparkAddress(new Uint8Array(33).fill(2))
const pubkey = `02${'cd'.repeat(32)}`

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
  return { created, mnemonic, words: mnemonic.split(' ') }
}

test('backup round-trip does not leak the phrase', async () => {
  const { vault } = tempVault()
  const { created, mnemonic, words } = await seed(vault)
  await vault.confirm([words[0] ?? '', words[1] ?? '', words[2] ?? ''], created.potId)
  const before = await vault.snapshot(created.potId)
  if (!before) throw new Error('missing pot')
  await vault.replacePolicy(created.potId, { ...before.policy, perTxSats: 1_000 })
  const recovery = { passphrase: new TextEncoder().encode('test-recovery'), kdf: FAST_ARGON2 }

  const backup = await runBackup({ vault, potId: created.potId, recoveryMaterial: recovery })
  expect(Object.keys(backup).sort()).toEqual(
    ['ciphertext', 'kdf', 'm', 'nonce', 'p', 'salt', 't', 'tag'].sort(),
  )
  expect(backup.kdf).toBe('argon2id')
  expect(JSON.stringify(backup)).not.toContain(mnemonic)
  expect(JSON.stringify(backup)).not.toContain('"mnemonic"')

  const restoredVault = tempVault()
  const restored = await runRestore({
    vault: restoredVault.vault,
    keystore: restoredVault.keystore,
    backup,
    recoveryMaterial: { passphrase: recovery.passphrase },
  })
  expect(JSON.stringify(restored)).not.toContain(mnemonic)
  expect(JSON.stringify(restored)).not.toContain('"mnemonic"')
  expect(Object.keys(restored)).not.toContain('mnemonic')

  const after = await restoredVault.vault.snapshot(restored.potId)
  expect(after?.address).toBe(address)
  expect(after?.confirmed).toBe(true)
  expect(after?.policy.perTxSats).toBe(1_000)
  expect(after?.freeze).toBe('active')
  await restoredVault.vault.withMnemonic(restored.potId, async (ctx) => {
    expect(Buffer.from(ctx.mnemonic).toString('utf8')).toBe(mnemonic)
    return 'ok'
  })
})

test('restore refuses the wrong recovery material', async () => {
  const { vault } = tempVault()
  const { created, mnemonic } = await seed(vault)
  const backup = await runBackup({
    vault,
    potId: created.potId,
    recoveryMaterial: { passphrase: 'correct-phrase', kdf: FAST_ARGON2 },
  })
  const target = tempVault()
  await expect(
    runRestore({
      vault: target.vault,
      keystore: target.keystore,
      backup,
      recoveryMaterial: 'wrong-phrase',
    }),
  ).rejects.toThrow('vault locked')
  expect(await target.vault.snapshot()).toBeNull()
  expect(JSON.stringify(backup)).not.toContain(mnemonic)
})
