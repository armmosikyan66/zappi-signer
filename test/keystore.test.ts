import { createCipheriv, randomBytes } from 'node:crypto'
import { expect, test } from 'vitest'
import { PotError } from '../src/errors.js'
import { MemoryKeyStore } from '../src/keystore/memory.js'
import { createDarwinKeyStore } from '../src/keystore/os.js'
import { UNLOCK_ACCOUNT } from '../src/keystore/types.js'
import { deviceBoundKey } from '../src/vault/vault.js'

test('macOS fails closed when the keychain helper cannot be compiled', async () => {
  const store = createDarwinKeyStore(() => {
    throw new Error('clang missing')
  })
  await expect(store.setSecret(UNLOCK_ACCOUNT, 'fallback-secret')).rejects.toThrow(PotError)
  await expect(store.setSecret(UNLOCK_ACCOUNT, 'fallback-secret')).rejects.toThrow('keychain unavailable')
  await expect(store.getSecret(UNLOCK_ACCOUNT)).rejects.toThrow('keychain unavailable')
  await expect(store.deviceFactor()).rejects.toThrow('keychain unavailable')
})

test('two device factors seal the same plaintext differently and one factor stays stable', async () => {
  const store = new MemoryKeyStore()
  const first = await store.deviceFactor()
  const second = await store.deviceFactor()
  expect(first.equals(second)).toBe(true)
  const other = await new MemoryKeyStore().deviceFactor()
  expect(first.equals(other)).toBe(false)
  const scryptKey = randomBytes(32)
  const nonce = randomBytes(12)
  const plain = Buffer.from('same-plaintext')
  const seal = (factor: Buffer) => {
    const key = deviceBoundKey(scryptKey, factor)
    const cipher = createCipheriv('aes-256-gcm', key, nonce)
    const body = Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()])
    key.fill(0)
    return body.toString('base64')
  }
  expect(seal(first)).toBe(seal(Buffer.from(second)))
  expect(seal(first)).not.toBe(seal(other))
})
