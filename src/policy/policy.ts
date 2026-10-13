import { z } from 'zod'
import { coded, PotError } from '../errors.js'
import { freezeAfterTrip, velocityTripped, withinHour, type FreezeState } from '../guards.js'

export const DEFAULT_PER_TX_SATS = 100_000
export const DEFAULT_DAILY_SATS = 500_000
export const DEFAULT_MONTHLY_SATS = 3_000_000
export const DEFAULT_FLOAT_CAP_SATS = 250_000
export const DEFAULT_COOLING_SATS = 5_000
export const DEFAULT_MAX_TX_PER_HOUR = 10
export const DEFAULT_MAX_FAILURES_PER_HOUR = 5
export const MIN_SWEEP_SATS = 1_000
export const SWEEP_COOLDOWN_MS = 30 * 60 * 1000
export const BACKUP_ATTEMPT_LIMIT = 5

export const CLOUD_PER_TX_SATS = 10_000
export const CLOUD_DAILY_SATS = 50_000
export const CLOUD_SESSION_SATS = 20_000
export const CLOUD_FLOAT_CAP_SATS = 60_000
export const CLOUD_STEP_UP_SATS = 5_000
export const CLOUD_MAX_TX_PER_HOUR = 6
export const CLOUD_MAX_FAILURES_PER_HOUR = 3

export type PotRole = 'free' | 'vault' | 'cloud'
export type TokenScope = 'local' | 'cloud'
export type DestinationMode = 'allowlist' | 'blocklist' | 'any'

export interface DestinationRule {
  mode: DestinationMode
  allow: string[]
  block: string[]
  newDestination?: { perTxCapSats: number }
}

export interface GuardRule {
  maxTxPerHour: number
  maxFailuresPerHour: number
  onTrip: 'freeze'
}

export interface SpendingPolicy {
  perTxSats: number
  dailySats: number
  spentDay: string
  spentTodaySats: number
  monthlySats: number
  monthKey: string
  monthSpent: number
  floatCapSats: number
  sessionSats?: number
  sessionKey: string
  sessionSpent: number
  destinations: DestinationRule
  guard: GuardRule
  txTimestamps: number[]
  failureTimestamps: number[]
  stepUpAboveSats?: number
  tokenScope: TokenScope
}

export interface SpendCheck {
  role: PotRole
  freeze: FreezeState
  policy: SpendingPolicy
  amountSats: number
  payee: string
  today: string
  nowMs: number
  scope: TokenScope
  sessionKey?: string
  internal?: boolean
}

export interface SpendDecision {
  policy: SpendingPolicy
  stepUp: boolean
}

export class PolicyRefusal extends PotError {
  readonly freezeTo: FreezeState | undefined

  constructor(code: string, freezeTo?: FreezeState) {
    super(code, code)
    this.name = 'PolicyRefusal'
    this.freezeTo = freezeTo
  }
}

export const policySchema = z
  .object({
    perTxSats: z.number().int().positive(),
    dailySats: z.number().int().positive(),
    spentDay: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
    spentTodaySats: z.number().int().nonnegative(),
    monthlySats: z.number().int().positive().optional(),
    monthKey: z.string().optional(),
    monthSpent: z.number().int().nonnegative().optional(),
    floatCapSats: z.number().int().positive().optional(),
    sessionSats: z.number().int().positive().optional(),
    sessionKey: z.string().max(80).optional(),
    sessionSpent: z.number().int().nonnegative().optional(),
    destinations: z
      .object({
        mode: z.enum(['allowlist', 'blocklist', 'any']),
        allow: z.array(z.string().max(2000)).max(64).optional().default([]),
        block: z.array(z.string().max(2000)).max(64).optional().default([]),
        newDestination: z.object({ perTxCapSats: z.number().int().positive() }).optional(),
      })
      .optional(),
    guard: z
      .object({
        maxTxPerHour: z.number().int().positive(),
        maxFailuresPerHour: z.number().int().positive(),
        onTrip: z.literal('freeze'),
      })
      .optional(),
    txTimestamps: z.array(z.number().int().nonnegative()).max(240).optional(),
    failureTimestamps: z.array(z.number().int().nonnegative()).max(240).optional(),
    stepUpAboveSats: z.number().int().positive().optional(),
    tokenScope: z.enum(['local', 'cloud']).optional(),
  })
  .transform((value): SpendingPolicy => ({
    perTxSats: value.perTxSats,
    dailySats: value.dailySats,
    spentDay: value.spentDay,
    spentTodaySats: value.spentTodaySats,
    monthlySats: value.monthlySats ?? DEFAULT_MONTHLY_SATS,
    monthKey: value.monthKey && value.monthKey.length > 0 ? value.monthKey : value.spentDay.slice(0, 7),
    monthSpent: value.monthSpent ?? 0,
    floatCapSats: value.floatCapSats ?? DEFAULT_FLOAT_CAP_SATS,
    ...(value.sessionSats !== undefined ? { sessionSats: value.sessionSats } : {}),
    sessionKey: value.sessionKey ?? '',
    sessionSpent: value.sessionSpent ?? 0,
    destinations: {
      mode: value.destinations?.mode ?? 'allowlist',
      allow: value.destinations?.allow ?? [],
      block: value.destinations?.block ?? [],
      ...(value.destinations?.newDestination ? { newDestination: value.destinations.newDestination } : value.destinations ? {} : { newDestination: { perTxCapSats: DEFAULT_COOLING_SATS } }),
    },
    guard: value.guard ?? {
      maxTxPerHour: DEFAULT_MAX_TX_PER_HOUR,
      maxFailuresPerHour: DEFAULT_MAX_FAILURES_PER_HOUR,
      onTrip: 'freeze',
    },
    txTimestamps: value.txTimestamps ?? [],
    failureTimestamps: value.failureTimestamps ?? [],
    ...(value.stepUpAboveSats !== undefined ? { stepUpAboveSats: value.stepUpAboveSats } : {}),
    tokenScope: value.tokenScope ?? 'local',
  }))

export function utcDay(now: Date): string {
  return now.toISOString().slice(0, 10)
}

export function utcMonth(day: string): string {
  return day.slice(0, 7)
}

export function freshPolicy(today: string, role: PotRole = 'free'): SpendingPolicy {
  const cloud = role === 'cloud'
  return {
    perTxSats: cloud ? CLOUD_PER_TX_SATS : DEFAULT_PER_TX_SATS,
    dailySats: cloud ? CLOUD_DAILY_SATS : DEFAULT_DAILY_SATS,
    spentDay: today,
    spentTodaySats: 0,
    monthlySats: DEFAULT_MONTHLY_SATS,
    monthKey: utcMonth(today),
    monthSpent: 0,
    floatCapSats: cloud ? CLOUD_FLOAT_CAP_SATS : DEFAULT_FLOAT_CAP_SATS,
    ...(cloud ? { sessionSats: CLOUD_SESSION_SATS } : {}),
    sessionKey: '',
    sessionSpent: 0,
    destinations: cloud
      ? { mode: 'allowlist', allow: [], block: [] }
      : {
          mode: 'allowlist',
          allow: [],
          block: [],
          newDestination: { perTxCapSats: DEFAULT_COOLING_SATS },
        },
    guard: {
      maxTxPerHour: cloud ? CLOUD_MAX_TX_PER_HOUR : DEFAULT_MAX_TX_PER_HOUR,
      maxFailuresPerHour: cloud ? CLOUD_MAX_FAILURES_PER_HOUR : DEFAULT_MAX_FAILURES_PER_HOUR,
      onTrip: 'freeze',
    },
    txTimestamps: [],
    failureTimestamps: [],
    ...(cloud ? { stepUpAboveSats: CLOUD_STEP_UP_SATS } : {}),
    tokenScope: cloud ? 'cloud' : 'local',
  }
}

export function normalizePolicy(policy: SpendingPolicy, today: string): SpendingPolicy {
  const month = utcMonth(today)
  let next = policy
  if (next.spentDay !== today) next = { ...next, spentDay: today, spentTodaySats: 0 }
  if (next.monthKey !== month) next = { ...next, monthKey: month, monthSpent: 0 }
  return next
}

export function dailyRemaining(policy: SpendingPolicy, today: string): number {
  const current = normalizePolicy(policy, today)
  return Math.max(0, current.dailySats - current.spentTodaySats)
}

function assertAmount(amount: number): void {
  if (!Number.isSafeInteger(amount) || amount <= 0) {
    throw new PotError('amount must be a positive integer number of sats')
  }
}

export function commitSpend(policy: SpendingPolicy, amount: number, today: string): SpendingPolicy {
  assertAmount(amount)
  const current = normalizePolicy(policy, today)
  if (amount > current.perTxSats) throw coded('LIMIT_PER_TX')
  if (amount > current.dailySats - current.spentTodaySats) throw coded('LIMIT_DAILY')
  const monthSpent = current.monthSpent + amount
  if (monthSpent > current.monthlySats) throw coded('LIMIT_MONTHLY')
  return {
    ...current,
    spentTodaySats: current.spentTodaySats + amount,
    monthSpent,
  }
}

export function rollbackSpend(policy: SpendingPolicy, amount: number, today: string): SpendingPolicy {
  const current = normalizePolicy(policy, today)
  return {
    ...current,
    spentTodaySats: Math.max(0, current.spentTodaySats - amount),
    monthSpent: Math.max(0, current.monthSpent - amount),
    sessionSpent: Math.max(0, current.sessionSpent - amount),
    txTimestamps: current.txTimestamps.slice(0, -1),
  }
}

export function authorizeSpend(input: SpendCheck): SpendDecision {
  assertAmount(input.amountSats)
  if (!input.internal && input.role === 'vault') throw new PolicyRefusal('POT_NOT_SPENDABLE')
  if (input.freeze !== 'active') throw new PolicyRefusal('FROZEN')
  if (!input.internal && input.scope !== input.policy.tokenScope) {
    throw new PolicyRefusal('TOKEN_INVALID')
  }
  if (input.internal) {
    return { policy: input.policy, stepUp: false }
  }

  let policy = normalizePolicy(input.policy, input.today)
  if (input.role === 'cloud' && policy.destinations.mode === 'any') {
    policy = { ...policy, destinations: { ...policy.destinations, mode: 'allowlist' } }
  }
  const sessionCap = policy.sessionSats
  if (sessionCap !== undefined) {
    const key = input.sessionKey ?? ''
    if (policy.sessionKey !== key) policy = { ...policy, sessionKey: key, sessionSpent: 0 }
    if (policy.sessionSpent + input.amountSats > sessionCap) throw new PolicyRefusal('LIMIT_SESSION')
  }
  if (input.amountSats > policy.perTxSats) throw new PolicyRefusal('LIMIT_PER_TX')
  if (input.amountSats > policy.dailySats - policy.spentTodaySats) throw new PolicyRefusal('LIMIT_DAILY')
  if (policy.monthSpent + input.amountSats > policy.monthlySats) throw new PolicyRefusal('LIMIT_MONTHLY')
  checkDestination(policy, input.payee, input.amountSats)
  const txTimestamps = withinHour(policy.txTimestamps, input.nowMs)
  if (velocityTripped(txTimestamps, input.nowMs, policy.guard.maxTxPerHour)) {
    throw new PolicyRefusal('VELOCITY_TRIPPED', freezeAfterTrip(input.freeze))
  }
  const next: SpendingPolicy = {
    ...policy,
    spentTodaySats: policy.spentTodaySats + input.amountSats,
    monthSpent: policy.monthSpent + input.amountSats,
    sessionSpent: policy.sessionSats !== undefined ? policy.sessionSpent + input.amountSats : policy.sessionSpent,
    txTimestamps: [...txTimestamps, input.nowMs],
  }
  const stepUp =
    input.role === 'cloud' &&
    policy.stepUpAboveSats !== undefined &&
    input.amountSats > policy.stepUpAboveSats
  return { policy: next, stepUp }
}

export function noteFailure(policy: SpendingPolicy, nowMs: number): { policy: SpendingPolicy; freeze: boolean } {
  const failureTimestamps = [...withinHour(policy.failureTimestamps, nowMs), nowMs]
  const freeze = velocityTripped(failureTimestamps, nowMs, policy.guard.maxFailuresPerHour)
  return { policy: { ...policy, failureTimestamps }, freeze }
}

function checkDestination(policy: SpendingPolicy, payee: string, amount: number): void {
  const { destinations: rule } = policy
  if (rule.mode === 'blocklist') {
    if (rule.block.includes(payee)) throw new PolicyRefusal('DESTINATION_NOT_ALLOWED')
    return
  }
  const known = rule.allow.includes(payee)
  if (rule.mode === 'any') {
    if (!known && rule.newDestination && amount > rule.newDestination.perTxCapSats) {
      throw new PolicyRefusal('COOLING_LIMIT')
    }
    return
  }
  if (known) return
  if (!rule.newDestination) throw new PolicyRefusal('DESTINATION_NOT_ALLOWED')
  if (amount > rule.newDestination.perTxCapSats) throw new PolicyRefusal('COOLING_LIMIT')
}

/** Server-side caps are applied as well as the local policy. The tighter number wins. */
export function assertServerLimits(
  amount: number,
  limits: { perTxSats?: number; dailyRemainingSats?: number; killed?: boolean },
): void {
  assertAmount(amount)
  if (limits.killed) throw new PotError('payment refused by relay')
  if (limits.perTxSats !== undefined && amount > limits.perTxSats) throw coded('LIMIT_PER_TX')
  if (limits.dailyRemainingSats !== undefined && amount > limits.dailyRemainingSats) {
    throw coded('LIMIT_DAILY')
  }
}
