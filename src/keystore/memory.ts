import { stableDeviceFactor } from './factor.js'
import { assertKeychainAccount, type KeyStore } from './types.js'

/** Test double. Production never falls back to an in-memory keychain. */
export class MemoryKeyStore implements KeyStore {
  private readonly values = new Map<string, string>()

  async getSecret(account: string): Promise<string | null> {
    assertKeychainAccount(account)
    return this.values.get(account) ?? null
  }

  async setSecret(account: string, value: string): Promise<void> {
    assertKeychainAccount(account)
    this.values.set(account, value)
  }

  async deleteSecret(account: string): Promise<void> {
    assertKeychainAccount(account)
    this.values.delete(account)
  }

  async confirmUserPresence(): Promise<boolean> {
    return true
  }

  async deviceFactor(): Promise<Buffer> {
    return stableDeviceFactor(this)
  }
}
