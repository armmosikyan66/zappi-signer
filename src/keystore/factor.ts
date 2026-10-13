import { randomBytes } from 'node:crypto'
import { PotError } from '../errors.js'
import { DEVICE_FACTOR_ACCOUNT, type KeyStore } from './types.js'

/** Software device factor for tests and for systems without a Secure Enclave. */
export async function stableDeviceFactor(store: Pick<KeyStore, 'getSecret' | 'setSecret'>): Promise<Buffer> {
  const existing = await store.getSecret(DEVICE_FACTOR_ACCOUNT)
  if (existing) {
    const buf = Buffer.from(existing, 'base64')
    if (buf.length !== 32) throw new PotError('keychain unavailable')
    return buf
  }
  const created = randomBytes(32)
  await store.setSecret(DEVICE_FACTOR_ACCOUNT, created.toString('base64'))
  return created
}
