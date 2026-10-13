export type FreezeState = 'active' | 'frozen_guard' | 'frozen_user'

const HOUR_MS = 60 * 60 * 1000

/** Guard trip freezes an active pot. A user freeze is not downgraded. */
export function freezeAfterTrip(state: FreezeState): FreezeState {
  if (state === 'frozen_user') return state
  return 'frozen_guard'
}

export function withinHour(timestamps: readonly number[], now: number): number[] {
  return timestamps.filter((stamp) => now - stamp < HOUR_MS && stamp <= now)
}

export function velocityTripped(timestamps: readonly number[], now: number, max: number): boolean {
  if (!Number.isInteger(max) || max <= 0) return true
  return withinHour(timestamps, now).length >= max
}
