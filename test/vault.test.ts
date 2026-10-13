import { createCipheriv, randomBytes } from 'node:crypto'
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
import { afterEach, expect, test } from 'vitest'
import { deriveScryptKey, TEST_SCRYPT } from '../src/kdf.js'
import { DEVICE_FACTOR_ACCOUNT, DEVICE_TOKEN_ACCOUNT, UNLOCK_ACCOUNT } from '../src/keystore/types.js'
import { MemoryKeyStore } from '../src/keystore/memory.js'
import { freshPolicy } from '../src/policy/policy.js'
import { encodeSparkAddress } from '../src/spark/address.js'
import { SEALED_ELSEWHERE, VAULT_KIND, VAULT_VERSION, VaultStore } from '../src/vault/vault.js'

const dirs: string[] = []

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

function tempVault(passphrase?: string): { vault: VaultStore; dir: string; keystore: MemoryKeyStore } {
  const dir = mkdtempSync(join(tmpdir(), 'zappi-pot-'))
  dirs.push(dir)
  const keystore = new MemoryKeyStore()
  if (passphrase) {
    awaitSet(keystore, passphrase)
  }
  const vault = new VaultStore({
    vaultPath: join(dir, 'seed-vault.json'),
    keystore,
    kdf: TEST_SCRYPT,
  })
  return { vault, dir, keystore }
}

function awaitSet(keystore: MemoryKeyStore, passphrase: string): void {
  void keystore.setSecret(UNLOCK_ACCOUNT, passphrase)
}

const address = encodeSparkAddress(new Uint8Array(33).fill(2))
const pubkey = `02${'ab'.repeat(32)}`

async function seed(vault: VaultStore, mnemonic = generateMnemonic(wordlist, 128)) {
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

test('encrypts the mnemonic and keeps the vault private', async () => {
  const { vault, dir, keystore } = tempVault()
  const { mnemonic } = await seed(vault)
  const passphrase = await keystore.getSecret(UNLOCK_ACCOUNT)
  expect(passphrase).toBeTruthy()
  const { readFileSync, statSync } = await import('node:fs')
  const file = readFileSync(join(dir, 'seed-vault.json'), 'utf8')
  expect(file).toContain('"kind":"zappi-pots-mcp"')
  expect(file).not.toContain(mnemonic)
  expect(file).not.toContain(passphrase ?? '')
  expect(file).not.toContain(address)
  expect(file).not.toContain(pubkey)
  for (const word of mnemonic.split(' ')) {
    if (word.length >= 5) expect(file).not.toContain(word)
  }
  if (process.platform !== 'win32') {
    expect(statSync(join(dir, 'seed-vault.json')).mode & 0o777).toBe(0o600)
  }
  const snapshot = await vault.snapshot()
  expect(snapshot?.address).toBe(address)
  expect(snapshot?.confirmed).toBe(false)
})

test('confirm backup does not echo the phrase', async () => {
  const { vault } = tempVault()
  const { words, mnemonic } = await seed(vault)
  await expect(vault.confirm(['nope', 'nope', 'nope'])).rejects.toThrow('backup words did not match')
  const confirmed = await vault.confirm([words[0] ?? '', words[1] ?? '', words[2] ?? ''])
  expect(confirmed.already).toBe(false)
  const again = await vault.confirm(['wrong', 'words', 'here'])
  expect(again.already).toBe(true)
  expect(JSON.stringify(again)).not.toContain(mnemonic)
})

test('five wrong backups remove the unconfirmed pot', async () => {
  const { vault, keystore } = tempVault()
  await seed(vault)
  for (let i = 0; i < 4; i += 1) {
    await expect(vault.confirm(['nope', 'nope', 'nope'])).rejects.toThrow('backup words did not match')
  }
  await expect(vault.confirm(['nope', 'nope', 'nope'])).rejects.toThrow('backup words did not match')
  expect(await vault.snapshot()).toBeNull()
  expect(await keystore.getSecret(UNLOCK_ACCOUNT)).toBeNull()
  await seed(vault)
})

test('refuses to reuse an unlock secret when no pot vault exists', async () => {
  const { vault, keystore } = tempVault()
  const existing = `${'C'.repeat(40)}=`
  await keystore.setSecret(UNLOCK_ACCOUNT, existing)
  await expect(seed(vault)).rejects.toThrow('refusing to reuse or replace it')
  expect(await keystore.getSecret(UNLOCK_ACCOUNT)).toBe(existing)
})

test('a failed keychain delete is reported without the secret', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'zappi-pot-'))
  dirs.push(dir)
  const keystore = new MemoryKeyStore()
  const sticky = {
    getSecret: (account: string) => keystore.getSecret(account),
    setSecret: (account: string, value: string) => keystore.setSecret(account, value),
    deleteSecret: () => Promise.reject(new Error('locked')),
    deviceFactor: () => keystore.deviceFactor(),
  }
  const vault = new VaultStore({
    vaultPath: join(dir, 'seed-vault.json'),
    keystore: sticky,
    kdf: TEST_SCRYPT,
  })
  await seed(vault)
  const passphrase = await keystore.getSecret(UNLOCK_ACCOUNT)
  const lines: string[] = []
  const write = process.stderr.write.bind(process.stderr)
  process.stderr.write = ((chunk: string | Uint8Array) => {
    lines.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'))
    return true
  }) as typeof process.stderr.write
  try {
    await vault.abandon()
  } finally {
    process.stderr.write = write
  }
  expect(lines.join('')).toContain('a keychain item remains after the pot was removed')
  expect(lines.join('')).not.toContain(passphrase ?? '')
  expect(await vault.snapshot()).toBeNull()
})

test('abandon removes the vault and its keychain items', async () => {
  const { vault, keystore } = tempVault()
  await seed(vault)
  await keystore.setSecret(DEVICE_TOKEN_ACCOUNT, 'device-token-value')
  await vault.abandon()
  expect(await vault.snapshot()).toBeNull()
  expect(await keystore.getSecret(UNLOCK_ACCOUNT)).toBeNull()
  expect(await keystore.getSecret(DEVICE_TOKEN_ACCOUNT)).toBeNull()
  await seed(vault)
})

test('zeros the mnemonic buffer after use', async () => {
  const { vault } = tempVault()
  await seed(vault)
  let seen = 0
  let buf: Uint8Array | undefined
  await vault.withMnemonic(undefined, async (ctx) => {
    seen = ctx.mnemonic[0] ?? 0
    buf = ctx.mnemonic
    return 'ok'
  })
  expect(seen).toBeGreaterThan(0)
  expect(buf?.every((byte) => byte === 0)).toBe(true)
})

test('refuses to overwrite a signer vault or a tampered file', async () => {
  const { vault, dir } = tempVault()
  const { writeFileSync, readFileSync } = await import('node:fs')
  const path = join(dir, 'seed-vault.json')
  const signer = `${JSON.stringify({ version: 1, pots: {} })}\n`
  writeFileSync(path, signer, { mode: 0o600 })
  await expect(vault.snapshot()).rejects.toThrow('existing signer vault found')
  expect(readFileSync(path, 'utf8')).toBe(signer)

  const { vault: other, dir: otherDir } = tempVault()
  await seed(other)
  const otherPath = join(otherDir, 'seed-vault.json')
  const body = JSON.parse(readFileSync(otherPath, 'utf8')) as {
    pots: Record<string, { fields: { record: { tag: string } } }>
  }
  const potId = Object.keys(body.pots)[0]
  const blob = potId ? body.pots[potId] : undefined
  if (!blob || !potId) throw new Error('missing pot')
  const tag = blob.fields.record.tag
  blob.fields.record.tag = tag.startsWith('A') ? `B${tag.slice(1)}` : `A${tag.slice(1)}`
  writeFileSync(otherPath, JSON.stringify(body), { mode: 0o600 })
  await expect(other.snapshot()).rejects.toThrow(SEALED_ELSEWHERE)
})

test('a different passphrase cannot open the vault', async () => {
  const { vault, dir } = tempVault()
  await seed(vault)
  const keystore = new MemoryKeyStore()
  await keystore.setSecret(UNLOCK_ACCOUNT, `${'B'.repeat(40)}=`)
  const other = new VaultStore({
    vaultPath: join(dir, 'seed-vault.json'),
    keystore,
    kdf: TEST_SCRYPT,
  })
  await expect(other.snapshot()).rejects.toThrow(SEALED_ELSEWHERE)
})

test('releases a reserved spend', async () => {
  const { vault } = tempVault()
  const { words } = await seed(vault)
  await vault.confirm([words[0] ?? '', words[1] ?? '', words[2] ?? ''])
  await vault.reserve(25, '2026-10-12')
  expect((await vault.snapshot())?.policy.spentTodaySats).toBe(25)
  await vault.release(25, '2026-10-12')
  expect((await vault.snapshot())?.policy.spentTodaySats).toBe(0)
})

test('reads a v1 vault and rewrites it as v2 on the next write', async () => {
  const { createCipheriv, randomBytes } = await import('node:crypto')
  const { chmodSync, readFileSync, writeFileSync } = await import('node:fs')
  const { deriveScryptKey } = await import('../src/kdf.js')
  const { vault, dir, keystore } = tempVault()
  const passphrase = `${'D'.repeat(40)}=`
  await keystore.setSecret(UNLOCK_ACCOUNT, passphrase)
  const mnemonic = generateMnemonic(wordlist, 128)
  const potId = `pot_${'ab'.repeat(16)}`
  const createdAt = '2026-10-12T00:00:00.000Z'
  const payload = {
    v: 1,
    mnemonic,
    address,
    pubkey,
    accountIndex: 1,
    network: 'REGTEST',
    policy: { perTxSats: 100_000, dailySats: 500_000, spentDay: '2026-10-12', spentTodaySats: 0 },
    backup: { confirmed: true, positions: [0, 1, 2], failures: 0 },
    bound: false,
  }
  const salt = randomBytes(16)
  const key = deriveScryptKey(Buffer.from(passphrase), salt, TEST_SCRYPT)
  const nonce = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  cipher.setAAD(Buffer.from(JSON.stringify({ v: 1, createdAt, potId })))
  const plaintext = Buffer.from(JSON.stringify(payload))
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
  const tag = cipher.getAuthTag()
  const path = join(dir, 'seed-vault.json')
  writeFileSync(
    path,
    `${JSON.stringify({
      version: 1,
      kind: 'zappi-pots-mcp',
      potId,
      createdAt,
      kdf: { name: 'scrypt', N: 1024, r: 8, p: 1, keyLen: 32, salt: salt.toString('base64') },
      nonce: nonce.toString('base64'),
      tag: tag.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
    })}\n`,
    { mode: 0o600 },
  )
  chmodSync(path, 0o600)
  const snap = await vault.snapshot()
  expect(snap?.potId).toBe(potId)
  expect(snap?.confirmed).toBe(true)
  expect(snap?.label).toBe('')
  expect(snap?.attachment).toEqual({ state: 'unattached' })
  await vault.reserve(1, '2026-10-12', potId)
  const rewritten = JSON.parse(readFileSync(path, 'utf8')) as { version: number; pots: Record<string, unknown> }
  expect(rewritten.version).toBe(VAULT_VERSION)
  expect(rewritten.pots[potId]).toBeTruthy()
  expect(JSON.stringify(rewritten)).not.toContain(mnemonic)
  expect((await vault.snapshot(potId))?.policy.spentTodaySats).toBe(1)
})

test('two pots keep separate budgets and an unnamed read fails closed', async () => {
  const { vault } = tempVault()
  const first = await seed(vault)
  const second = await seed(vault)
  await expect(vault.snapshot()).rejects.toThrow(
    `set ZAPPI_POT_ID to one of: ${[first.created.potId, second.created.potId].sort().join(', ')}`,
  )
  await vault.confirm(echo(first.words), first.created.potId)
  await vault.confirm(echo(second.words), second.created.potId)
  await vault.reserve(10, '2026-10-12', first.created.potId)
  await vault.reserve(7, '2026-10-12', second.created.potId)
  expect((await vault.snapshot(first.created.potId))?.policy.spentTodaySats).toBe(10)
  expect((await vault.snapshot(second.created.potId))?.policy.spentTodaySats).toBe(7)
  await vault.release(7, '2026-10-12', second.created.potId)
  expect((await vault.snapshot(first.created.potId))?.policy.spentTodaySats).toBe(10)
  expect((await vault.snapshot(second.created.potId))?.policy.spentTodaySats).toBe(0)
})

test('five failed backups remove only that pot, and the last pot clears the keychain', async () => {
  const { vault, keystore } = tempVault()
  const keep = await seed(vault)
  const drop = await seed(vault)
  await vault.confirm(echo(keep.words), keep.created.potId)
  await keystore.setSecret(DEVICE_TOKEN_ACCOUNT, 'device-token-value')
  for (let i = 0; i < 5; i += 1) {
    await expect(vault.confirm(['nope', 'nope', 'nope'], drop.created.potId)).rejects.toThrow(
      'backup words did not match',
    )
  }
  expect((await vault.list()).map((pot) => pot.potId)).toEqual([keep.created.potId])
  expect(await keystore.getSecret(UNLOCK_ACCOUNT)).toBeTruthy()
  expect(await keystore.getSecret(DEVICE_TOKEN_ACCOUNT)).toBe('device-token-value')
  let seen = ''
  await vault.withMnemonic(keep.created.potId, async (ctx) => {
    seen = Buffer.from(ctx.mnemonic).toString('utf8')
    return 'ok'
  })
  expect(seen).toBe(keep.mnemonic)
  await vault.removePot(keep.created.potId)
  expect(await vault.snapshot()).toBeNull()
  expect(await keystore.getSecret(UNLOCK_ACCOUNT)).toBeNull()
  expect(await keystore.getSecret(DEVICE_TOKEN_ACCOUNT)).toBeNull()
})

test('a copied vault does not open with another device factor', async () => {
  const home = tempVault()
  await home.keystore.setSecret(DEVICE_FACTOR_ACCOUNT, Buffer.alloc(32, 1).toString('base64'))
  const seeded = await seed(home.vault)
  const pass = await home.keystore.getSecret(UNLOCK_ACCOUNT)
  if (!pass) throw new Error('missing unlock')
  const away = new MemoryKeyStore()
  await away.setSecret(UNLOCK_ACCOUNT, pass)
  await away.setSecret(DEVICE_FACTOR_ACCOUNT, Buffer.alloc(32, 2).toString('base64'))
  await home.vault.confirm(echo(seeded.words), seeded.created.potId)
  const copy = new VaultStore({
    vaultPath: join(home.dir, 'seed-vault.json'),
    keystore: away,
    kdf: TEST_SCRYPT,
  })
  await expect(copy.list()).rejects.toThrow(SEALED_ELSEWHERE)
  expect(await home.vault.list()).toHaveLength(1)
})

test('a version 3 vault opens and the next write seals it to this device', async () => {
  const pass = 'migrate-pass'
  const { vault, dir, keystore } = tempVault(pass)
  const potId = `pot_${'ab'.repeat(16)}`
  const createdAt = '2026-10-12T00:00:00.000Z'
  const mnemonic = generateMnemonic(wordlist, 128)
  writeVersion3(join(dir, 'seed-vault.json'), pass, potId, createdAt, mnemonic)
  expect((await vault.list())[0]?.potId).toBe(potId)
  expect(JSON.parse(readFileSync(join(dir, 'seed-vault.json'), 'utf8')).version).toBe(3)
  await vault.setFreeze(potId, 'frozen_user')
  const upgraded = JSON.parse(readFileSync(join(dir, 'seed-vault.json'), 'utf8')) as { version: number }
  expect(upgraded.version).toBe(VAULT_VERSION)
  expect((await vault.list())[0]?.freeze).toBe('frozen_user')
  const away = new MemoryKeyStore()
  await away.setSecret(UNLOCK_ACCOUNT, pass)
  await away.setSecret(DEVICE_FACTOR_ACCOUNT, Buffer.alloc(32, 9).toString('base64'))
  const copy = new VaultStore({
    vaultPath: join(dir, 'seed-vault.json'),
    keystore: away,
    kdf: TEST_SCRYPT,
  })
  await expect(copy.list()).rejects.toThrow(SEALED_ELSEWHERE)
  expect(await keystore.getSecret(DEVICE_FACTOR_ACCOUNT)).toBeTruthy()
})

function writeVersion3(path: string, pass: string, potId: string, createdAt: string, mnemonic: string): void {
  const salt = randomBytes(16)
  const key = deriveScryptKey(Buffer.from(pass), salt, TEST_SCRYPT)
  const record = {
    v: 1,
    accountIndex: 1,
    network: 'REGTEST',
    label: 'old',
    attachment: { state: 'unattached' },
    policy: freshPolicy('2026-10-12', 'free'),
    backup: { confirmed: true, positions: [0, 1, 2], failures: 0 },
    bound: false,
    role: 'free',
    freeze: 'active',
    fromMaster: false,
  }
  const fields = {
    mnemonic: sealOld(key, 1, potId, createdAt, 'mnemonic', Buffer.from(mnemonic)),
    address: sealOld(key, 1, potId, createdAt, 'address', Buffer.from(address)),
    pubkey: sealOld(key, 1, potId, createdAt, 'pubkey', Buffer.from(pubkey)),
    record: sealOld(key, 1, potId, createdAt, 'record', Buffer.from(JSON.stringify(record))),
  }
  key.fill(0)
  const body = {
    version: 3,
    kind: VAULT_KIND,
    vaultVersion: 1,
    vaultCreatedAt: createdAt,
    kdf: { name: 'scrypt', N: TEST_SCRYPT.N, r: 8, p: 1, keyLen: 32, salt: salt.toString('base64') },
    pots: { [potId]: { createdAt, fields } },
  }
  writeFileSync(path, `${JSON.stringify(body)}\n`, { mode: 0o600 })
  chmodSync(path, 0o600)
}

function sealOld(
  key: Buffer,
  vaultVersion: number,
  potId: string,
  createdAt: string,
  fieldName: string,
  plaintext: Buffer,
): { nonce: string; tag: string; ciphertext: string } {
  const nonce = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  cipher.setAAD(Buffer.from(JSON.stringify({ vaultVersion, potId, fieldName, createdAt })))
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
  return {
    nonce: nonce.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  }
}

function echo(words: string[]): [string, string, string] {
  return [words[0] ?? '', words[1] ?? '', words[2] ?? '']
}
