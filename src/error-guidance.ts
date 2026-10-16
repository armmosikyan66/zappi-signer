import { PotError } from './errors.js'

export interface SignerFailureGuidance {
  code: string | null
  next: string | null
  hint: string | null
}

const TRUST = {
  next: 'trust-server --pubkey <serverPubkey> --json',
  hint: 'Use the serverPubkey from the MCP result, not from a challenge body.',
} as const

const STOP_HUMAN = {
  next: null,
  hint: 'Stop and tell the human.',
} as const

const UNCERTAIN = {
  next: null,
  hint: 'Report uncertain and do not send again.',
} as const

const BY_CODE: Record<string, { next: string | null; hint: string | null }> = {
  TRUST_UNPINNED: TRUST,
  TRUST_MISMATCH: TRUST,
  POLICY_REQUIRED: {
    next: null,
    hint: 'Run the provision ceremony. Call read_skill with zappi-signer.',
  },
  LIMIT_PER_TX: STOP_HUMAN,
  LIMIT_DAILY: STOP_HUMAN,
  LIMIT_MONTHLY: STOP_HUMAN,
  LIMIT_SESSION: STOP_HUMAN,
  COOLING_LIMIT: STOP_HUMAN,
  DESTINATION_NOT_ALLOWED: STOP_HUMAN,
  VELOCITY_TRIPPED: STOP_HUMAN,
  BROADCAST_UNCERTAIN: UNCERTAIN,
  SPEND_JOURNAL: UNCERTAIN,
}

const REFUSED_HINT = 'Set ZAPPI_POT_ID from the spend result and rerun with --json.'

/**
 * Maps a signer failure to the next command. Does not invent a code the
 * error did not set. Uncoded `refused to spend` covers a missing pot id,
 * a missing --yes, and a bad id — the hint covers the pot id, which is the
 * case an agent can fix.
 */
export function guidanceFor(error: unknown): SignerFailureGuidance {
  const code = error instanceof PotError && error.code ? error.code : null
  const mapped = code ? BY_CODE[code] : undefined
  if (mapped) return { code, next: mapped.next, hint: mapped.hint }
  if (error instanceof PotError && !error.code && error.message === 'refused to spend') {
    return { code: null, next: null, hint: REFUSED_HINT }
  }
  return { code, next: null, hint: null }
}
