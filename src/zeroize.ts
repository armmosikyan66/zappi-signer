import { PotError } from './errors.js'

export function zeroize(buffer: Uint8Array | null | undefined): void {
  if (!buffer) return
  buffer.fill(0)
}

/** Reject a result that accidentally contains the full mnemonic phrase. */
export function assertResultHasNoMnemonic(result: unknown, mnemonic: string): void {
  if (!mnemonic) return
  let encoded: string
  try {
    encoded = JSON.stringify(result)
  } catch {
    throw new PotError('request failed')
  }
  if (typeof encoded !== 'string') return
  if (encoded.includes(mnemonic)) {
    throw new PotError('request failed')
  }
}
