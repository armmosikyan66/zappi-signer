import { PotError } from '../errors.js'
import type { FreezeState } from '../guards.js'
import { authorizeSpend, utcDay, type PotRole, type SpendingPolicy } from './policy.js'
import { inspectSparkAddress } from '../spark/usdb.js'
import type { SparkNetworkName } from '../vault/vault.js'

/**
 * Sealed-policy check used as the `verifyIntent` policy hook.
 * Caps are the numbers already stored on `SpendingPolicy` (`perTxSats` and
 * the daily / monthly counters). The value compared is `amountCents`.
 * The intent's `amountSats` is never compared to those caps.
 * A throw here is what stops nonce consumption.
 */
export function assertSealedPolicy(input: {
  policy: SpendingPolicy | null
  role: PotRole
  freeze: FreezeState
  network: SparkNetworkName
  amountCents: number
  receiver: string
  now: Date
}): void {
  if (!input.policy) throw new PotError('no sealed policy', 'POLICY_REQUIRED')
  if (namesWildcard(input.receiver) || policyHasWildcard(input.policy)) {
    throw new PotError('WILDCARD', 'WILDCARD')
  }
  if (!Number.isSafeInteger(input.amountCents) || input.amountCents <= 0) {
    throw new PotError('amount cents required', 'POLICY_AMOUNT')
  }
  if (input.network !== 'MAINNET') throw new PotError('refused to spend')
  const inspected = inspectSparkAddress(input.receiver)
  if (!inspected.valid || inspected.network !== 'MAINNET') throw new PotError('refused to spend')
  authorizeSpend({
    role: input.role,
    freeze: input.freeze,
    policy: input.policy,
    amountSats: input.amountCents,
    payee: input.receiver,
    today: utcDay(input.now),
    nowMs: input.now.getTime(),
    scope: input.policy.tokenScope,
  })
}

function policyHasWildcard(policy: SpendingPolicy): boolean {
  return [...policy.destinations.allow, ...policy.destinations.block].some(namesWildcard)
}

function namesWildcard(value: string): boolean {
  const trimmed = value.trim()
  return trimmed === '*' || trimmed.toUpperCase() === 'WILDCARD'
}
