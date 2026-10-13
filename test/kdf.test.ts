import { expect, test } from 'vitest'
import { PRODUCTION_ARGON2, PRODUCTION_SCRYPT } from '../src/kdf.js'
import { openUserBackup, sealUserBackup } from '../src/vault/user-backup.js'
import { zeroize } from '../src/zeroize.js'

test('production KDF costs stay high', () => {
  expect(PRODUCTION_SCRYPT.N).toBeGreaterThanOrEqual(16_384)
  expect(PRODUCTION_ARGON2.m).toBeGreaterThanOrEqual(65_536)
  expect(PRODUCTION_ARGON2.t).toBeGreaterThanOrEqual(3)
})

test('argon2id seals a user backup passphrase', async () => {
  const plaintext = new TextEncoder().encode('backup-envelope')
  const passphrase = new TextEncoder().encode('correct horse battery')
  const envelope = await sealUserBackup(plaintext, passphrase, { t: 1, m: 8, p: 1, dkLen: 32 })
  expect(envelope).not.toContain('backup-envelope')
  expect(envelope).toContain('"kdf":"argon2id"')
  const opened = await openUserBackup(envelope, passphrase)
  expect(Buffer.from(opened).toString('utf8')).toBe('backup-envelope')
  zeroize(opened)
  await expect(openUserBackup(envelope, new TextEncoder().encode('nope'))).rejects.toThrow('vault locked')
})

test('zeroize clears a buffer', () => {
  const buf = Buffer.from('secret-bytes')
  zeroize(buf)
  expect(buf.every((byte) => byte === 0)).toBe(true)
})
