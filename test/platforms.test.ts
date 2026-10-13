import { chmodSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { PotError } from '../src/errors.js'
import { appendNoFollow, readNoFollow } from '../src/fs-safe.js'
import { createDarwinKeyStore, createOsKeyStore } from '../src/keystore/os.js'
import { MemoryKeyStore } from '../src/keystore/memory.js'
import {
  DEVICE_FACTOR_ACCOUNT,
  DEVICE_TOKEN_ACCOUNT,
  HIGH_WATER_ACCOUNT,
  KEYCHAIN_SERVICE,
  OAUTH_CLIENT_ACCOUNT,
  PRESENCE_ACCOUNT,
  UNLOCK_ACCOUNT,
  hostKeyAccounts,
  type KeyStore,
} from '../src/keystore/types.js'
import { TEST_SCRYPT } from '../src/kdf.js'
import { defaultVaultPath } from '../src/paths.js'
import { SEALED_ELSEWHERE, VaultStore } from '../src/vault/vault.js'

const keyring = vi.hoisted(() => {
  const state: {
    mode: 'store' | 'missing' | 'message-missing' | 'win-missing' | 'locked' | 'down' | 'bad-factor'
    password: string | null
    constructed: Array<{ service: string; account: string; options?: { linux?: { store?: string } } }>
  } = { mode: 'store', password: null, constructed: [] }

  class Entry {
    constructor(service: string, account: string, options?: { linux?: { store?: string } }) {
      state.constructed.push({ service, account, options })
      if (state.mode === 'down') throw new Error('secret service unavailable')
    }

    getPassword(): string | null {
      if (state.mode === 'missing') {
        const error = new Error('NoEntry') as Error & { code: string }
        error.code = 'NoEntry'
        throw error
      }
      if (state.mode === 'message-missing') throw new Error('No matching entry')
      if (state.mode === 'win-missing') throw new Error('The specified item could not be found')
      if (state.mode === 'locked') throw new Error('secret service unavailable')
      if (state.mode === 'bad-factor') return 'YQ=='
      return state.password
    }

    setPassword(password: string): void {
      if (state.mode === 'locked') throw new Error('secret service unavailable')
      state.password = password
    }

    deletePassword(): boolean {
      if (state.mode === 'missing') {
        const error = new Error('NotFound') as Error & { code: string }
        error.code = 'NotFound'
        throw error
      }
      if (state.mode === 'locked') throw new Error('secret service unavailable')
      state.password = null
      return true
    }
  }

  return { state, Entry }
})

vi.mock('@napi-rs/keyring', () => ({ Entry: keyring.Entry }))

const HELPER_SOURCE = `#!/usr/bin/env node
import { appendFileSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const dir = dirname(fileURLToPath(import.meta.url))
const stdin = readFileSync(0)
const op = process.argv[2] ?? ''
const account = process.argv[3] ?? ''
appendFileSync(
  join(dir, 'calls.jsonl'),
  JSON.stringify({ op, account, argv: process.argv.slice(2), stdin: stdin.toString('utf8') }) + '\\n',
)
const control = JSON.parse(readFileSync(join(dir, 'control.json'), 'utf8'))
const action = control[op] ?? { status: 1 }
if (typeof action.stdout === 'string') process.stdout.write(action.stdout)
process.exit(action.status ?? 1)
`

const dirs: string[] = []
const hostPlatform = process.platform
const hostPlatformDescriptor = Object.getOwnPropertyDescriptor(process, 'platform')

afterEach(() => {
  if (hostPlatformDescriptor) Object.defineProperty(process, 'platform', hostPlatformDescriptor)
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

beforeEach(() => {
  keyring.state.mode = 'store'
  keyring.state.password = null
  keyring.state.constructed.length = 0
})

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'zappi-platforms-'))
  dirs.push(dir)
  return dir
}

async function withPlatform<T>(platform: NodeJS.Platform, run: () => Promise<T>): Promise<T> {
  const previous = Object.getOwnPropertyDescriptor(process, 'platform')
  Object.defineProperty(process, 'platform', {
    configurable: true,
    enumerable: true,
    writable: true,
    value: platform,
  })
  try {
    return await run()
  } finally {
    if (previous) Object.defineProperty(process, 'platform', previous)
  }
}

function installHelper(dir: string): string {
  const binary = join(dir, 'macos-keychain.mjs')
  writeFileSync(binary, HELPER_SOURCE, { mode: 0o700 })
  chmodSync(binary, 0o700)
  return binary
}

function arm(dir: string, control: Record<string, { status: number; stdout?: string }>): void {
  writeFileSync(join(dir, 'control.json'), JSON.stringify(control))
  const log = join(dir, 'calls.jsonl')
  if (statExists(log)) rmSync(log)
}

function statExists(path: string): boolean {
  try {
    lstatSync(path)
    return true
  } catch {
    return false
  }
}

function calls(dir: string): Array<{ op: string; account: string; argv: string[]; stdin: string }> {
  const path = join(dir, 'calls.jsonl')
  if (!statExists(path)) return []
  return readFileSync(path, 'utf8')
    .trim()
    .split('\n')
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as { op: string; account: string; argv: string[]; stdin: string })
}

function vaultAt(dir: string, keystore: KeyStore = new MemoryKeyStore()): { vault: VaultStore; path: string; keystore: KeyStore } {
  return {
    vault: new VaultStore({ vaultPath: join(dir, 'seed-vault.json'), keystore, kdf: TEST_SCRYPT }),
    path: join(dir, 'seed-vault.json'),
    keystore,
  }
}

async function seed(vault: VaultStore): Promise<string> {
  const created = await vault.create({
    mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    address: 'spark1platform',
    pubkey: 'ab'.repeat(32),
    accountIndex: 1,
    network: 'REGTEST',
    positions: [0, 1, 2],
    today: '2026-10-13',
  })
  return created.potId
}

test('keychain service and account names stay stable', () => {
  expect(KEYCHAIN_SERVICE).toBe('zappi-signer')
  expect(UNLOCK_ACCOUNT).toBe('seed-vault-unlock')
  expect(DEVICE_FACTOR_ACCOUNT).toBe('device-factor')
  expect(HIGH_WATER_ACCOUNT).toBe('vault-high-water')
  expect(PRESENCE_ACCOUNT).toBe('user-presence')
  expect(DEVICE_TOKEN_ACCOUNT).toBe('device-token')
  expect(OAUTH_CLIENT_ACCOUNT).toBe('oauth-client-id')
  expect(hostKeyAccounts('local')).toEqual({ device: 'device-token', client: 'oauth-client-id' })
  expect(hostKeyAccounts('cursor')).toEqual({ device: 'device-token-cursor', client: 'oauth-client-cursor' })
  expect(() => hostKeyAccounts('Bad')).toThrow('keychain account refused')
})

test('vault path follows APPDATA only on Windows', () => {
  const roaming = join('C:', 'Users', 'ada', 'AppData', 'Roaming')
  expect(defaultVaultPath({ APPDATA: roaming }, 'win32')).toBe(join(roaming, 'zappi-signer', 'seed-vault.json'))
  expect(defaultVaultPath({ APPDATA: '   ' }, 'win32')).toBe(
    join(homedir(), 'AppData', 'Roaming', 'zappi-signer', 'seed-vault.json'),
  )
  const unix = defaultVaultPath({ APPDATA: roaming }, 'linux')
  expect(unix.endsWith(join('.zappi-signer', 'seed-vault.json'))).toBe(true)
  expect(unix).not.toContain('AppData')
  expect(process.platform).toBe(hostPlatform)
})

test('store selection fails closed off macOS, Linux, and Windows', async () => {
  await withPlatform('freebsd', async () => {
    expect(() => createOsKeyStore()).toThrow(PotError)
    expect(() => createOsKeyStore()).toThrow('keychain unavailable')
  })
  expect(process.platform).toBe(hostPlatform)
  expect(keyring.state.constructed).toEqual([])
})

test('linux pins Secret Service and fails closed when that store is unavailable', async () => {
  await withPlatform('linux', async () => {
    const store = createOsKeyStore()
    expect(store.confirmUserPresence).toBeUndefined()
    const dir = tempDir()
    const vault = new VaultStore({
      vaultPath: join(dir, 'seed-vault.json'),
      keystore: store,
      kdf: TEST_SCRYPT,
    })
    await expect(vault.confirmPresence()).rejects.toThrow('keychain unavailable')
    expect(keyring.state.constructed).toEqual([])

    keyring.state.mode = 'missing'
    expect(await store.getSecret(UNLOCK_ACCOUNT)).toBeNull()
    await expect(store.deleteSecret(UNLOCK_ACCOUNT)).resolves.toBeUndefined()
    keyring.state.mode = 'message-missing'
    expect(await store.getSecret(UNLOCK_ACCOUNT)).toBeNull()
    keyring.state.mode = 'win-missing'
    expect(await store.getSecret(DEVICE_FACTOR_ACCOUNT)).toBeNull()
    expect(keyring.state.constructed.every((entry) => entry.service === KEYCHAIN_SERVICE)).toBe(true)
    expect(keyring.state.constructed.every((entry) => entry.options?.linux?.store === 'secret-service')).toBe(true)

    keyring.state.mode = 'down'
    await expect(store.getSecret(UNLOCK_ACCOUNT)).rejects.toThrow('keychain unavailable')
    await expect(store.setSecret(UNLOCK_ACCOUNT, 'secret')).rejects.toThrow('keychain unavailable')
    await expect(store.deleteSecret(UNLOCK_ACCOUNT)).rejects.toThrow('keychain unavailable')
    await expect(store.deviceFactor()).rejects.toThrow('keychain unavailable')

    keyring.state.mode = 'locked'
    await expect(store.setSecret(UNLOCK_ACCOUNT, 'secret')).rejects.toThrow('keychain unavailable')
    await expect(store.getSecret(UNLOCK_ACCOUNT)).rejects.toThrow('keychain unavailable')

    keyring.state.mode = 'store'
    keyring.state.password = null
    keyring.state.constructed.length = 0
    await expect(store.setSecret(UNLOCK_ACCOUNT, '')).rejects.toThrow('keychain unavailable')
    await expect(store.setSecret('NOT-AN-ACCOUNT', 'secret')).rejects.toThrow('keychain account refused')
    expect(keyring.state.constructed).toEqual([])

    const first = await store.deviceFactor()
    const second = await store.deviceFactor()
    expect(first.equals(second)).toBe(true)
    expect(first).toHaveLength(32)
    expect(keyring.state.password).toBe(first.toString('base64'))
    expect(keyring.state.constructed.some((entry) => entry.account === DEVICE_FACTOR_ACCOUNT)).toBe(true)

    keyring.state.mode = 'bad-factor'
    await expect(store.deviceFactor()).rejects.toThrow('keychain unavailable')
  })
})

test('windows uses Credential Manager without a presence check or a linux store option', async () => {
  await withPlatform('win32', async () => {
    const store = createOsKeyStore()
    expect(store.confirmUserPresence).toBeUndefined()
    const dir = tempDir()
    const vault = new VaultStore({
      vaultPath: join(dir, 'seed-vault.json'),
      keystore: store,
      kdf: TEST_SCRYPT,
    })
    await expect(vault.confirmPresence()).rejects.toThrow('keychain unavailable')

    keyring.state.mode = 'store'
    keyring.state.password = null
    expect(await store.getSecret(UNLOCK_ACCOUNT)).toBeNull()
    expect(keyring.state.constructed.at(-1)).toEqual({
      service: KEYCHAIN_SERVICE,
      account: UNLOCK_ACCOUNT,
      options: undefined,
    })

    keyring.state.mode = 'down'
    await expect(store.getSecret(UNLOCK_ACCOUNT)).rejects.toThrow('keychain unavailable')
    await expect(store.deviceFactor()).rejects.toThrow('keychain unavailable')
  })
})

test('the host store exposes user presence only on macOS', () => {
  const store = createOsKeyStore()
  if (hostPlatform === 'darwin') expect(typeof store.confirmUserPresence).toBe('function')
  else expect(store.confirmUserPresence).toBeUndefined()
})

test('macOS presence and helper failures refuse without a second keychain', async () => {
  const quiet = createDarwinKeyStore(() => {
    throw new Error('helper invoked')
  })
  await expect(quiet.confirmUserPresence('')).resolves.toBe(false)
  await expect(quiet.confirmUserPresence('x'.repeat(81))).resolves.toBe(false)

  const dir = tempDir()
  const missing = createDarwinKeyStore(() => join(dir, 'missing-macos-keychain'))
  await expect(missing.confirmUserPresence('Authorize Zappi')).rejects.toThrow('keychain unavailable')
  await expect(missing.getSecret(UNLOCK_ACCOUNT)).rejects.toThrow('keychain unavailable')
  await expect(missing.deviceFactor()).rejects.toThrow('keychain unavailable')

  const junk = join(dir, 'not-a-helper')
  writeFileSync(junk, 'not-a-mach-o')
  chmodSync(junk, 0o700)
  const broken = createDarwinKeyStore(() => junk)
  await expect(broken.confirmUserPresence('Authorize Zappi')).rejects.toThrow('keychain unavailable')
  await expect(broken.getSecret(UNLOCK_ACCOUNT)).rejects.toThrow('keychain unavailable')
})

// The stand-in helper is a POSIX shebang script. Windows spawn throws EFTYPE
// for that file instead of running it. Darwin and Linux cover this protocol.
test.skipIf(process.platform === 'win32')('macOS helper protocol follows the stand-in helper', async () => {
  const dir = tempDir()
  const binary = installHelper(dir)
  const store = createDarwinKeyStore(() => binary)
  arm(dir, { presence: { status: 0 } })
  await expect(store.confirmUserPresence('Authorize Zappi')).resolves.toBe(true)
  expect(calls(dir)).toEqual([{ op: 'presence', account: PRESENCE_ACCOUNT, argv: ['presence', PRESENCE_ACCOUNT], stdin: '' }])

  arm(dir, { presence: { status: 1 } })
  await expect(store.confirmUserPresence('Authorize Zappi')).resolves.toBe(false)

  arm(dir, { get: { status: 2 } })
  expect(await store.getSecret(UNLOCK_ACCOUNT)).toBeNull()
  arm(dir, { get: { status: 1 } })
  await expect(store.getSecret(UNLOCK_ACCOUNT)).rejects.toThrow('keychain unavailable')
  arm(dir, { get: { status: 0, stdout: '' } })
  expect(await store.getSecret(UNLOCK_ACCOUNT)).toBeNull()

  arm(dir, { set: { status: 0 } })
  await expect(store.setSecret(UNLOCK_ACCOUNT, '')).rejects.toThrow('keychain unavailable')
  await expect(store.setSecret(UNLOCK_ACCOUNT, 'a'.repeat(8193))).rejects.toThrow('keychain unavailable')
  expect(calls(dir)).toEqual([])
  const secret = 'a'.repeat(8192)
  await store.setSecret(UNLOCK_ACCOUNT, secret)
  const logged = calls(dir)
  expect(logged).toHaveLength(1)
  expect(logged[0]?.stdin).toBe(secret)
  expect(logged[0]?.argv.join(' ')).not.toContain(secret)

  arm(dir, { delete: { status: 1 } })
  await expect(store.deleteSecret(UNLOCK_ACCOUNT)).rejects.toThrow('keychain unavailable')

  const factor = Buffer.alloc(32, 9)
  arm(dir, { factor: { status: 0, stdout: factor.toString('base64') } })
  expect((await store.deviceFactor()).equals(factor)).toBe(true)
  arm(dir, { factor: { status: 0, stdout: Buffer.alloc(31, 1).toString('base64') } })
  await expect(store.deviceFactor()).rejects.toThrow('keychain unavailable')
  arm(dir, { factor: { status: 1, stdout: factor.toString('base64') } })
  await expect(store.deviceFactor()).rejects.toThrow('keychain unavailable')

  await expect(store.getSecret('UPPER')).rejects.toThrow('keychain account refused')
})

test('presence denial fails closed', async () => {
  const dir = tempDir()
  const denying: KeyStore = {
    async getSecret() {
      return null
    },
    async setSecret() {},
    async deleteSecret() {},
    async confirmUserPresence() {
      return false
    },
    async deviceFactor() {
      return Buffer.alloc(32, 4)
    },
  }
  const vault = new VaultStore({ vaultPath: join(dir, 'seed-vault.json'), keystore: denying, kdf: TEST_SCRYPT })
  await expect(vault.confirmPresence()).rejects.toThrow('keychain unavailable')
})

test('filesystem helpers refuse symlinks and loose modes', () => {
  const dir = tempDir()
  const body = join(dir, 'body')
  writeFileSync(body, 'vault-body', { mode: 0o600 })
  chmodSync(body, 0o600)
  expect(readNoFollow(body, 100)).toBe('vault-body')
  expect(() => readNoFollow(body, 4)).toThrow('vault locked')
  expect(() => readNoFollow(join(dir, 'missing'), 10)).toThrow('ENOENT')
  expect(() => readNoFollow(dir, 100)).toThrow('vault locked')

  chmodSync(body, 0o640)
  if (process.platform === 'win32') expect(readNoFollow(body, 100)).toBe('vault-body')
  else expect(() => readNoFollow(body, 100)).toThrow('vault locked')
  chmodSync(body, 0o600)

  const link = join(dir, 'link')
  symlinkSync(body, link)
  if (process.platform === 'win32') expect(readNoFollow(link, 100)).toBe('vault-body')
  else expect(() => readNoFollow(link, 100)).toThrow('vault locked')

  const logDir = join(dir, 'logs')
  appendNoFollow(join(logDir, 'audit'), 'line\n')
  if (process.platform !== 'win32') {
    expect(statSync(logDir).mode & 0o777).toBe(0o700)
    expect(statSync(join(logDir, 'audit')).mode & 0o777).toBe(0o600)
  }
  const audit = join(logDir, 'audit-real')
  writeFileSync(audit, 'x', { mode: 0o600 })
  const auditLink = join(logDir, 'audit-link')
  symlinkSync(audit, auditLink)
  if (process.platform !== 'win32') {
    expect(() => appendNoFollow(auditLink, 'y\n')).toThrow('vault locked')
    expect(readFileSync(audit, 'utf8')).toBe('x')
  }
})

test('windows mode skip still refuses a vault symlink', async () => {
  const dir = tempDir()
  const body = join(dir, 'body')
  writeFileSync(body, 'followed', { mode: 0o640 })
  const link = join(dir, 'link')
  symlinkSync(body, link)
  await withPlatform('win32', async () => {
    expect(readNoFollow(link, 100)).toBe('followed')
    expect(readNoFollow(body, 100)).toBe('followed')
  })
  if (process.platform !== 'win32') expect(() => readNoFollow(body, 100)).toThrow('vault locked')
})

test('vault directory is 0700, the file is 0600, and a symlink or loose mode stays closed', async () => {
  const dir = tempDir()
  chmodSync(dir, 0o755)
  const { vault, path } = vaultAt(dir)
  expect(await vault.list()).toEqual([])
  if (process.platform !== 'win32') expect(statSync(dir).mode & 0o777).toBe(0o700)
  const potId = await seed(vault)
  if (process.platform !== 'win32') expect(statSync(path).mode & 0o777).toBe(0o600)

  chmodSync(path, 0o640)
  if (process.platform === 'win32') {
    expect(await vault.list()).toHaveLength(1)
  } else {
    await expect(vault.list()).rejects.toThrow('vault locked')
    await withPlatform('win32', async () => {
      expect(await vault.list()).toHaveLength(1)
    })
    await expect(vault.list()).rejects.toThrow('vault locked')
  }
  chmodSync(path, 0o600)
  expect((await vault.list()).map((pot) => pot.potId)).toEqual([potId])

  const sentinel = join(dir, 'sentinel')
  const body = readFileSync(path)
  writeFileSync(sentinel, body)
  rmSync(path)
  symlinkSync(sentinel, path)
  await expect(vault.setFreeze(potId, 'frozen_user')).rejects.toThrow('vault locked')
  expect(lstatSync(path).isSymbolicLink()).toBe(true)
  expect(readFileSync(sentinel)).toEqual(body)
  await withPlatform('win32', async () => {
    await expect(vault.list()).rejects.toThrow('vault locked')
  })
  expect(readFileSync(sentinel)).toEqual(body)

  const root = tempDir()
  const real = join(root, 'real')
  mkdirSync(real, { mode: 0o700 })
  const linked = join(root, 'linked')
  symlinkSync(real, linked)
  const linkedVault = vaultAt(linked)
  await expect(linkedVault.vault.list()).rejects.toThrow('vault locked')
})

test('a copied vault is sealed to another device', async () => {
  const dir = tempDir()
  const homeKey = new MemoryKeyStore()
  await homeKey.setSecret(DEVICE_FACTOR_ACCOUNT, Buffer.alloc(32, 1).toString('base64'))
  const home = vaultAt(dir, homeKey)
  await seed(home.vault)
  const pass = await homeKey.getSecret(UNLOCK_ACCOUNT)
  if (!pass) throw new Error('missing unlock')
  const away = new MemoryKeyStore()
  await away.setSecret(UNLOCK_ACCOUNT, pass)
  await away.setSecret(DEVICE_FACTOR_ACCOUNT, Buffer.alloc(32, 2).toString('base64'))
  const copy = new VaultStore({ vaultPath: home.path, keystore: away, kdf: TEST_SCRYPT })
  await expect(copy.list()).rejects.toThrow(SEALED_ELSEWHERE)
  expect(await home.vault.list()).toHaveLength(1)
})
