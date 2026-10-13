import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { TEST_SCRYPT } from '../src/kdf.js'
import { stableDeviceFactor } from '../src/keystore/factor.js'
import { assertKeychainAccount, type KeyStore } from '../src/keystore/types.js'
import { VaultStore } from '../src/vault/vault.js'

class FileKeyStore implements KeyStore {
  constructor(private readonly path: string) {}

  async getSecret(account: string): Promise<string | null> {
    assertKeychainAccount(account)
    const values = this.read()
    return values[account] ?? null
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

const dir = process.argv[2]
if (!dir) {
  process.stderr.write('missing directory\n')
  process.exit(1)
}

const vault = new VaultStore({
  vaultPath: join(dir, 'seed-vault.json'),
  keystore: new FileKeyStore(join(dir, 'secrets.json')),
  kdf: TEST_SCRYPT,
})

try {
  await vault.reserve(1, '2026-10-12')
} catch (error) {
  process.stderr.write(error instanceof Error ? error.name : 'failed')
  process.exit(1)
}
