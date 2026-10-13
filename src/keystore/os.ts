import { spawn, spawnSync } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { PotError } from '../errors.js'
import { defaultVaultPath } from '../paths.js'
import { stableDeviceFactor } from './factor.js'
import {
  assertKeychainAccount,
  DEVICE_FACTOR_ACCOUNT,
  KEYCHAIN_SERVICE,
  type KeyStore,
} from './types.js'

// The npm package ships the helper source next to dist/. A standalone binary
// does not, and a CJS bundle has no import.meta.url, so resolution is guarded.
const HELPER_SOURCE = resolveHelperSource()

function resolveHelperSource(): string {
  try {
    return fileURLToPath(new URL('../../native/macos-keychain.c', import.meta.url))
  } catch {
    return ''
  }
}

export function createOsKeyStore(): KeyStore {
  if (process.platform === 'darwin') return createDarwinKeyStore()
  if (process.platform === 'linux' || process.platform === 'win32') return new NapiKeyStore()
  throw new PotError('keychain unavailable')
}

/**
 * macOS uses the local keychain helper only. A missing or broken helper
 * refuses the operation. There is no login-keychain fallback.
 */
export function createDarwinKeyStore(resolveHelper: () => string = helperBinary): KeyStore {
  return new DarwinKeyStore(resolveHelper)
}

class DarwinKeyStore implements KeyStore {
  constructor(private readonly resolveHelper: () => string) {}

  async getSecret(account: string): Promise<string | null> {
    assertKeychainAccount(account)
    const result = await runHelper(this.helper(), 'get', account)
    if (result.status === 2) return null
    if (result.status !== 0) throw new PotError('keychain unavailable')
    const text = result.stdout.toString('utf8')
    return text.length > 0 ? text : null
  }

  async setSecret(account: string, value: string): Promise<void> {
    assertKeychainAccount(account)
    if (!value || value.length > 8192) throw new PotError('keychain unavailable')
    const result = await runHelper(this.helper(), 'set', account, value)
    if (result.status !== 0) throw new PotError('keychain unavailable')
  }

  async deleteSecret(account: string): Promise<void> {
    assertKeychainAccount(account)
    const result = await runHelper(this.helper(), 'delete', account)
    if (result.status !== 0) throw new PotError('keychain unavailable')
  }

  async confirmUserPresence(reason: string): Promise<boolean> {
    if (!reason || reason.length > 80) return false
    const result = await runHelper(this.helper(), 'presence', 'user-presence')
    return result.status === 0
  }

  async deviceFactor(): Promise<Buffer> {
    const result = await runHelper(this.helper(), 'factor', DEVICE_FACTOR_ACCOUNT)
    if (result.status !== 0) throw new PotError('keychain unavailable')
    const raw = Buffer.from(result.stdout.toString('utf8').trim(), 'base64')
    if (raw.length !== 32) throw new PotError('keychain unavailable')
    return raw
  }

  private helper(): string {
    try {
      return this.resolveHelper()
    } catch (error) {
      if (error instanceof PotError) throw error
      throw new PotError('keychain unavailable')
    }
  }
}

class NapiKeyStore implements KeyStore {
  async getSecret(account: string): Promise<string | null> {
    assertKeychainAccount(account)
    try {
      const entry = await napiEntry(account)
      return entry.getPassword()
    } catch (error) {
      if (isNotFound(error)) return null
      throw new PotError('keychain unavailable')
    }
  }

  async setSecret(account: string, value: string): Promise<void> {
    assertKeychainAccount(account)
    if (!value || value.length > 8192) throw new PotError('keychain unavailable')
    try {
      const entry = await napiEntry(account)
      entry.setPassword(value)
    } catch {
      throw new PotError('keychain unavailable')
    }
  }

  async deleteSecret(account: string): Promise<void> {
    assertKeychainAccount(account)
    try {
      const entry = await napiEntry(account)
      entry.deletePassword()
    } catch (error) {
      if (isNotFound(error)) return
      throw new PotError('keychain unavailable')
    }
  }

  async deviceFactor(): Promise<Buffer> {
    return stableDeviceFactor(this)
  }
}

interface NapiEntry {
  getPassword(): string | null
  setPassword(password: string): void
  deletePassword(): boolean
}

async function napiEntry(account: string): Promise<NapiEntry> {
  const mod = (await import('@napi-rs/keyring')) as {
    Entry: new (service: string, username: string, options?: { linux?: { store?: 'secret-service' } }) => NapiEntry
  }
  const options = process.platform === 'linux' ? { linux: { store: 'secret-service' as const } } : undefined
  return new mod.Entry(KEYCHAIN_SERVICE, account, options)
}

function isNotFound(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false
  const code = String((error as { code?: unknown }).code ?? '')
  if (code === 'NoEntry' || code === 'NotFound') return true
  const message = error instanceof Error ? error.message : ''
  return (
    message.startsWith('NoEntry') ||
    message.includes('No matching entry') ||
    message.includes('The specified item could not be found')
  )
}

function helperBinary(): string {
  // An explicit override always wins (tests and custom installs).
  const override = process.env.ZAPPI_SIGNER_KEYCHAIN_HELPER
  if (override) return override
  const vaultDir = dirname(defaultVaultPath())
  // The signed binary distribution ships a prebuilt helper installed by the
  // one-line installer at ~/.zappi-signer/macos-keychain. It matches the
  // pinned release and is verified there, so it wins over anything else.
  const prebuilt = join(vaultDir, 'macos-keychain')
  if (isExecutableFile(prebuilt)) return prebuilt
  const binary = join(vaultDir, 'bin', 'macos-keychain')
  const dir = dirname(binary)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  if (process.platform !== 'win32') chmodSync(dir, 0o700)
  // The npm package ships the helper source. A standalone binary does not,
  // so a missing source only disables the compile-from-source path.
  const sourceTime = statTime(HELPER_SOURCE)
  const binaryTime = existsSync(binary) ? statSync(binary).mtimeMs : 0
  if (sourceTime > 0 && binaryTime < sourceTime) {
    const compiled = spawnSync(
      'clang',
      ['-O2', '-o', binary, HELPER_SOURCE, '-framework', 'Security', '-framework', 'CoreFoundation'],
      { stdio: 'pipe', timeout: 120_000 },
    )
    if (compiled.status !== 0) throw new PotError('keychain unavailable')
    chmodSync(binary, 0o700)
  }
  return binary
}

function isExecutableFile(path: string): boolean {
  try {
    return (statSync(path).mode & 0o111) !== 0
  } catch {
    return false
  }
}

function statTime(path: string): number {
  try {
    return statSync(path).mtimeMs
  } catch {
    return 0
  }
}

function runHelper(
  binary: string,
  op: 'get' | 'set' | 'delete' | 'presence' | 'factor',
  account: string,
  secret?: string,
): Promise<{ status: number; stdout: Buffer }> {
  return new Promise((resolve, reject) => {
    const child = spawn(binary, [op, account], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: {
        PATH: process.env.PATH ?? '',
        HOME: process.env.HOME ?? '',
        USER: process.env.USER ?? '',
        LOGNAME: process.env.LOGNAME ?? '',
      },
    })
    const stdout: Buffer[] = []
    child.stdout.on('data', (chunk: Buffer) => {
      stdout.push(chunk)
    })
    child.on('error', () => reject(new PotError('keychain unavailable')))
    const timer = setTimeout(() => {
      child.kill()
      reject(new PotError('keychain unavailable'))
    }, op === 'presence' ? 120_000 : 60_000)
    child.on('close', (status) => {
      clearTimeout(timer)
      resolve({ status: status ?? 1, stdout: Buffer.concat(stdout) })
    })
    if (secret !== undefined) {
      const buf = Buffer.from(secret, 'utf8')
      child.stdin.write(buf)
      buf.fill(0)
    }
    child.stdin.end()
  })
}
