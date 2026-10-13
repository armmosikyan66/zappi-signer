import { expect, test } from 'vitest'
import { authorizeSpend, commitSpend, dailyRemaining, freshPolicy, rollbackSpend } from '../src/policy/policy.js'

test('per-transaction and daily limits use opaque codes', () => {
  const policy = freshPolicy('2026-10-12')
  expect(() => commitSpend(policy, 100_001, '2026-10-12')).toThrow('LIMIT_PER_TX')
  const spent = commitSpend(policy, 100_000, '2026-10-12')
  const almost = { ...spent, spentTodaySats: 499_000 }
  expect(() => commitSpend(almost, 2_000, '2026-10-12')).toThrow('LIMIT_DAILY')
})

test('a new UTC day restores the daily budget', () => {
  const spent = commitSpend(freshPolicy('2026-10-12'), 50_000, '2026-10-12')
  expect(dailyRemaining(spent, '2026-10-13')).toBe(500_000)
  const next = commitSpend(spent, 1, '2026-10-13')
  expect(next.spentDay).toBe('2026-10-13')
  expect(next.spentTodaySats).toBe(1)
  expect(rollbackSpend(next, 1, '2026-10-13').spentTodaySats).toBe(0)
})

test('a vault role cannot spend', () => {
  expect(() =>
    authorizeSpend({
      role: 'vault',
      freeze: 'active',
      policy: freshPolicy('2026-10-12', 'vault'),
      amountSats: 1,
      payee: 'spark1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq',
      today: '2026-10-12',
      nowMs: 0,
      scope: 'local',
    }),
  ).toThrow('POT_NOT_SPENDABLE')
})
