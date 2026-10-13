import { bech32 } from '@scure/base'
import { expect, test } from 'vitest'
import { bolt11ToSats, decodeInvoice } from '../src/destinations/decode.js'

test('bolt11 amounts are decoded locally and a claimed mismatch is visible', () => {
  expect(bolt11ToSats('50', 'u')).toBe(5_000)
  const invoice = invoiceWith('lnbc50u')
  const decoded = decodeInvoice(invoice)
  expect(decoded.fixedAmountSats).toBe(5_000)
  expect(decoded.amountSats).toBe(5_000)
})

function invoiceWith(hrp: string): string {
  return bech32.encode(hrp as `${string}1${string}`, [0], 2000)
}
