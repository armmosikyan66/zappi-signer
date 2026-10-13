import { bech32 } from '@scure/base'
import { PotError } from '../errors.js'
import { assertSparkAddress } from '../spark/address.js'

export interface DecodedDestination {
  payee: string
  amountSats: number
  /** Set when the destination itself names the amount. The claimed amount is then ignored. */
  fixedAmountSats?: number
  kind: 'spark' | 'invoice' | 'lnurl'
}

export interface LnurlResolved {
  payee: string
  minSats: number
  maxSats: number
  fixedAmountSats?: number
}

const HRP_RE = /^ln(bc|tb|bcrt)(\d+)([munp])?$/

/**
 * Decode a destination locally. Invoice and LNURL amounts come from the
 * decoded payload. The amount the agent claims is not authoritative.
 */
export async function decodeDestination(
  destination: string,
  claimedAmount: number,
  resolveLnurl?: (destination: string) => Promise<LnurlResolved>,
): Promise<DecodedDestination> {
  if (destination.startsWith('ln') && destination.includes('1')) {
    return decodeInvoice(destination)
  }
  if (destination.toLowerCase().startsWith('lnurl') || destination.includes('@')) {
    if (!resolveLnurl) throw new PotError('DESTINATION_NOT_ALLOWED', 'DESTINATION_NOT_ALLOWED')
    const resolved = await resolveLnurl(destination)
    if (resolved.fixedAmountSats !== undefined) {
      return {
        payee: resolved.payee,
        amountSats: resolved.fixedAmountSats,
        fixedAmountSats: resolved.fixedAmountSats,
        kind: 'lnurl',
      }
    }
    if (claimedAmount < resolved.minSats || claimedAmount > resolved.maxSats) {
      throw new PotError('DESTINATION_NOT_ALLOWED', 'DESTINATION_NOT_ALLOWED')
    }
    return { payee: resolved.payee, amountSats: claimedAmount, kind: 'lnurl' }
  }
  assertSparkAddress(destination)
  return { payee: destination, amountSats: claimedAmount, kind: 'spark' }
}

export function decodeInvoice(invoice: string): DecodedDestination {
  let decoded: { prefix: string }
  try {
    decoded = bech32.decode(invoice as `${string}1${string}`, 2000)
  } catch {
    throw new PotError('DESTINATION_NOT_ALLOWED', 'DESTINATION_NOT_ALLOWED')
  }
  const match = HRP_RE.exec(decoded.prefix)
  if (!match) throw new PotError('DESTINATION_NOT_ALLOWED', 'DESTINATION_NOT_ALLOWED')
  const whole = match[2]
  const unit = match[3]
  if (!whole) throw new PotError('DESTINATION_NOT_ALLOWED', 'DESTINATION_NOT_ALLOWED')
  const amount = bolt11ToSats(whole, unit)
  if (amount === null) throw new PotError('DESTINATION_NOT_ALLOWED', 'DESTINATION_NOT_ALLOWED')
  return {
    payee: invoice.toLowerCase(),
    amountSats: amount,
    fixedAmountSats: amount,
    kind: 'invoice',
  }
}

/** milli/micro/nano/pico-bitcoin to integer sats. Fractional sats are refused. */
export function bolt11ToSats(whole: string, unit: string | undefined): number | null {
  const value = Number(whole)
  if (!Number.isSafeInteger(value) || value <= 0) return null
  const factor = unit === 'm' ? 100_000 : unit === 'u' ? 100 : unit === 'n' ? 0.1 : unit === 'p' ? 0.0001 : 100_000_000
  const sats = value * factor
  if (!Number.isSafeInteger(sats) || sats <= 0) return null
  return sats
}
