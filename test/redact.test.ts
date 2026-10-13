import { expect, test } from 'vitest'
import { logLine } from '../src/log.js'
import { encodeSparkAddress } from '../src/spark/address.js'

test('stderr redacts phrases and bearer tokens but keeps spark addresses', () => {
  const phrase =
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
  const address = encodeSparkAddress(new Uint8Array(33).fill(3))
  let captured = ''
  const original = process.stderr.write.bind(process.stderr)
  process.stderr.write = ((chunk: string | Uint8Array) => {
    captured += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8')
    return true
  }) as typeof process.stderr.write
  try {
    logLine(`note ${phrase} Bearer super-secret-token ${address}`)
    logLine(`pass ${Buffer.from('x'.repeat(32)).toString('base64')}`)
  } finally {
    process.stderr.write = original
  }
  expect(captured).not.toContain('abandon abandon')
  expect(captured).not.toContain('super-secret-token')
  expect(captured).toContain(address)
  expect(captured).toContain('[redacted]')
})
