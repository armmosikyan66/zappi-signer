/**
 * Local policy commands.
 * A tighten may only narrow caps, destinations, and guards. Spend counters
 * stay on the pot record. User presence is required and fails closed when
 * the keystore cannot confirm it.
 */
import { coded, PotError } from '../errors.js'
import type { FreezeState } from '../guards.js'
import type { KeyStore } from '../keystore/types.js'
import { policySchema, type PotRole, type SpendingPolicy } from '../policy/policy.js'
import type { PotSnapshot } from '../vault/vault.js'

const PRESENCE_REASON = 'Authorize Zappi'

const MODE_RANK = { any: 0, blocklist: 1, allowlist: 2 } as const

export interface PolicyCommandVault {
  snapshot(potId?: string): Promise<PotSnapshot | null>
  replacePolicy(potId: string, policy: SpendingPolicy): Promise<void>
}

export interface PolicyView {
  potId: string
  role: PotRole
  freeze: FreezeState
  policy: SpendingPolicy
}

export interface PolicyViewInput {
  vault: PolicyCommandVault
  potId: string
}

export interface PolicyTightenInput {
  vault: PolicyCommandVault
  keystore: KeyStore
  potId: string
  nextPolicy: SpendingPolicy
  /** Extra user acceptance. Never replaces `keystore.confirmUserPresence`. */
  confirm?: (nextPolicy: SpendingPolicy) => boolean | Promise<boolean>
}

export async function runPolicyView(input: PolicyViewInput): Promise<PolicyView> {
  const snapshot = await loadPot(input.vault, input.potId)
  return toView(snapshot)
}

export async function runPolicyTighten(input: PolicyTightenInput): Promise<PolicyView> {
  const snapshot = await loadPot(input.vault, input.potId)
  const next = parsePolicy(input.nextPolicy)
  assertMonotonicTighten(snapshot.policy, next)
  const sealed = retainCounters(snapshot.policy, next)
  if (input.confirm) {
    const accepted = await input.confirm(structuredClone(sealed))
    if (accepted !== true) throw new PotError('policy refused')
  }
  await requirePresence(input.keystore)
  await input.vault.replacePolicy(snapshot.potId, sealed)
  const updated = await loadPot(input.vault, snapshot.potId)
  return toView(updated)
}

async function loadPot(vault: PolicyCommandVault, potId: string): Promise<PotSnapshot> {
  const id = potId.trim()
  if (!id) throw new PotError('no pot')
  const snapshot = await vault.snapshot(id)
  if (!snapshot) throw new PotError('no pot')
  return snapshot
}

function parsePolicy(value: SpendingPolicy): SpendingPolicy {
  const parsed = policySchema.safeParse(value)
  if (!parsed.success) throw new PotError('policy refused')
  return parsed.data
}

function toView(snapshot: PotSnapshot): PolicyView {
  return {
    potId: snapshot.potId,
    role: snapshot.role,
    freeze: snapshot.freeze,
    policy: structuredClone(snapshot.policy),
  }
}

/** Caps and rules come from `next`. Counters stay put so a tighten cannot reset spend. */
function retainCounters(current: SpendingPolicy, next: SpendingPolicy): SpendingPolicy {
  return {
    ...next,
    spentDay: current.spentDay,
    spentTodaySats: current.spentTodaySats,
    monthKey: current.monthKey,
    monthSpent: current.monthSpent,
    sessionKey: current.sessionKey,
    sessionSpent: current.sessionSpent,
    txTimestamps: [...current.txTimestamps],
    failureTimestamps: [...current.failureTimestamps],
    destinations: {
      mode: next.destinations.mode,
      allow: [...next.destinations.allow],
      block: [...next.destinations.block],
      ...(next.destinations.newDestination
        ? { newDestination: { perTxCapSats: next.destinations.newDestination.perTxCapSats } }
        : {}),
    },
    guard: { ...next.guard },
  }
}

function assertMonotonicTighten(current: SpendingPolicy, next: SpendingPolicy): void {
  if (next.tokenScope !== current.tokenScope) looser()
  if (next.perTxSats > current.perTxSats) looser()
  if (next.dailySats > current.dailySats) looser()
  if (next.monthlySats > current.monthlySats) looser()
  if (next.floatCapSats > current.floatCapSats) looser()
  if (!optionalCapTightens(current.sessionSats, next.sessionSats)) looser()
  if (!optionalCapTightens(current.stepUpAboveSats, next.stepUpAboveSats)) looser()
  if (next.guard.maxTxPerHour > current.guard.maxTxPerHour) looser()
  if (next.guard.maxFailuresPerHour > current.guard.maxFailuresPerHour) looser()
  if (next.guard.onTrip !== 'freeze') looser()
  assertDestinations(current, next)
}

function optionalCapTightens(current: number | undefined, next: number | undefined): boolean {
  if (next === undefined) return current === undefined
  if (current === undefined) return true
  return next <= current
}

function assertDestinations(current: SpendingPolicy, next: SpendingPolicy): void {
  const from = current.destinations
  const to = next.destinations
  if (MODE_RANK[to.mode] < MODE_RANK[from.mode]) looser()
  if (from.mode === 'allowlist' && to.mode !== 'allowlist') looser()
  if (from.mode === 'blocklist' && to.mode !== 'blocklist') looser()
  if (from.mode === 'any' && to.mode === 'blocklist' && from.newDestination) looser()
  if (!isSubset(to.allow, from.allow)) looser()
  if (!isSubset(from.block, to.block)) looser()
  const fromCooling = from.newDestination?.perTxCapSats
  const toCooling = to.newDestination?.perTxCapSats
  if (toCooling === undefined) return
  if (fromCooling === undefined || toCooling > fromCooling) looser()
}

function isSubset(next: readonly string[], current: readonly string[]): boolean {
  return next.every((entry) => current.includes(entry))
}

function looser(): never {
  throw coded('POLICY_LOOSER')
}

async function requirePresence(keystore: KeyStore): Promise<void> {
  const confirm = keystore.confirmUserPresence
  if (typeof confirm !== 'function') throw new PotError('keychain unavailable')
  const ok = await confirm.call(keystore, PRESENCE_REASON)
  if (ok !== true) throw new PotError('keychain unavailable')
}
