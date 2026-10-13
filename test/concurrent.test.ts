import { spawn } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, expect, test } from 'vitest'
import { generateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
import { TEST_SCRYPT } from '../src/kdf.js'
import { stableDeviceFactor } from '../src/keystore/factor.js'
import { assertKeychainAccount, type KeyStore } from '../src/keystore/types.js'
import { encodeSparkAddress } from '../src/spark/address.js'
import { VaultStore } from '../src/vault/vault.js'

const dirs: string[] = []
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

test('two processes cannot lose a vault update', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'zappi-lock-'))
  dirs.push(dir)
  const mnemonic = generateMnemonic(wordlist, 128)
  const words = mnemonic.split(' ')
  const vault = new VaultStore({
    vaultPath: join(dir, 'seed-vault.json'),
    keystore: new FileKeyStore(join(dir, 'secrets.json')),
    kdf: TEST_SCRYPT,
  })
  await vault.create({
    mnemonic,
    address: encodeSparkAddress(new Uint8Array(33).fill(9)),
    pubkey: `03${'11'.repeat(32)}`,
    accountIndex: 1,
    network: 'REGTEST',
    positions: [0, 1, 2],
    today: '2026-10-12',
  })
  await vault.confirm([words[0] ?? '', words[1] ?? '', words[2] ?? ''])
  const script = fileURLToPath(new URL('./contend.ts', import.meta.url))
  await Promise.all(Array.from({ length: 8 }, () => run(script, dir)))
  const snapshot = await vault.snapshot()
  expect(snapshot?.policy.spentTodaySats).toBe(8)
})

function run(script: string, dir: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--import', 'tsx', script, dir], {
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let err = ''
    child.stderr.on('data', (chunk: Buffer) => {
      err += chunk.toString('utf8')
    })
    child.on('close', (code) => {
      if (code === 0) resolve()
      else reject(new Error(err || `exit ${code}`))
    })
  })
}

class FileKeyStore implements KeyStore {
  constructor(private readonly path: string) {}

  async getSecret(account: string): Promise<string | null> {
    assertKeychainAccount(account)
    return this.read()[account] ?? null
  }

  async setSecret(account: string, value: string): Promise<void> {
    assertKeychainAccount(account)
    const values = this.read()
    values[account] = value
    writeFileSync(this.path, JSON.stringify(values), { mode: 0o600 })
  }

  async deleteSecret(account: string): Promise<void> {
    assertKeychainAccount(account)
    const values = this.read()
    delete values[account]
    writeFileSync(this.path, JSON.stringify(values), { mode: 0o600 })
  }

  async deviceFactor(): Promise<Buffer> {
    return stableDeviceFactor(this)
  }

  private read(): Record<string, string> {
    try {
      return JSON.parse(readFileSync(this.path, 'utf8')) as Record<string, string>
    } catch {
      return {}
    }
  }
}
