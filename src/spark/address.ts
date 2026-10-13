import { bech32m } from '@scure/base'
import { PotError } from '../errors.js'

const MIN_LENGTH = 40
const MAX_LENGTH = 90

export function encodeSparkAddress(payload: Uint8Array): string {
  return bech32m.encode('spark', bech32m.toWords(payload))
}

export function assertSparkAddress(address: string): void {
  if (typeof address !== 'string' || address.length < MIN_LENGTH || address.length > MAX_LENGTH) {
    throw new PotError('destination is not a Spark address')
  }
  if (address !== address.toLowerCase()) {
    throw new PotError('destination is not a Spark address')
  }
  try {
    const decoded = bech32m.decode(address as `${string}1${string}`)
    if (decoded.prefix !== 'spark') {
      throw new PotError('destination is not a Spark address')
    }
  } catch (error) {
    if (error instanceof PotError) throw error
    throw new PotError('destination is not a Spark address')
  }
}
