import { expect, test } from 'vitest'
import { readBalanceSats, readTransferId } from '../src/spark/sdk.js'
import { assertSparkAddress, encodeSparkAddress } from '../src/spark/address.js'

test('reads current and legacy Spark balance shapes', () => {
  expect(readBalanceSats({ satsBalance: { available: 25n } })).toBe(25)
  expect(readBalanceSats({ balance: 8 })).toBe(8)
  expect(readTransferId({ id: 'tx-1' })).toBe('tx-1')
  expect(readTransferId('tx-2')).toBe('tx-2')
  expect(() => readBalanceSats({})).toThrow('balance unavailable')
  expect(() => readTransferId({})).toThrow('payment failed')
})

test('accepts a spark bech32m address', () => {
  const address = encodeSparkAddress(new Uint8Array(33).fill(4))
  expect(() => assertSparkAddress(address)).not.toThrow()
  expect(() => assertSparkAddress('not-an-address')).toThrow('destination is not a Spark address')
})
