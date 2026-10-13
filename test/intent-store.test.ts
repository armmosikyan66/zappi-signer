import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, expect, test } from 'vitest'
import { PotError } from '../src/errors.js'
import { defaultVaultPath, defaultStateDir } from '../src/paths.js'
import { NonceLedger, defaultNonceLedgerPath } from '../src/intent-store.js'

const dirs: string[] = []

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'zappi-nonce-'))
  dirs.push(dir)
  return dir
}

const EXPIRES = '2026-10-09T12:05:00.000Z'
const EARLY = new Date('2026-10-09T12:04:30.000Z')

test('default ledger path sits beside the vault', () => {
  expect(defaultNonceLedgerPath()).toBe(join(defaultStateDir(defaultVaultPath()), 'intent-nonces.json'))
  expect(defaultNonceLedgerPath({ APPDATA: 'C:\\Users\\me\\AppData\\Roaming' }, 'win32')).toBe(
    join('C:\\Users\\me\\AppData\\Roaming', 'zappi-signer', 'intent-nonces.json'),
  )
})

test('records a nonce once, replays the same intent, and refuses reuse', () => {
  const path = join(tempDir(), 'nested', 'intent-nonces.json')
  const ledger = new NonceLedger(path)
  const first = ledger.consume('nonce-a', 'intent-a', EXPIRES, EARLY)
  expect(first.replay).toBe(false)
  expect(first.record).toEqual({ intentId: 'intent-a', expiresAt: EXPIRES })

  const later = '2026-10-09T12:06:00.000Z'
  const again = ledger.consume('nonce-a', 'intent-a', later, EARLY)
  expect(again.replay).toBe(true)
  expect(again.record.expiresAt).toBe(EXPIRES)

  const stored = JSON.parse(readFileSync(path, 'utf8')) as Record<string, { intentId: string; expiresAt: string }>
  expect(stored['nonce-a']).toEqual({ expiresAt: EXPIRES, intentId: 'intent-a' })

  expect(() => ledger.consume('nonce-a', 'intent-b', EXPIRES, EARLY)).toThrow(
    'Intent nonce was already used. Refusing the replay.',
  )
  expect(() => ledger.consume('nonce-b', 'intent-a', EXPIRES, EARLY)).toThrow(
    'Intent id is already bound to another nonce.',
  )
  const after = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>
  expect(Object.keys(after)).toEqual(['nonce-a'])

  if (process.platform !== 'win32') {
    expect(statSync(path).mode & 0o777).toBe(0o600)
    expect(statSync(join(path, '..')).mode & 0o777).toBe(0o700)
  }
})

test('prunes expired nonces on the next load', () => {
  const path = join(tempDir(), 'intent-nonces.json')
  const ledger = new NonceLedger(path)
  ledger.consume('old', 'intent-old', EXPIRES, EARLY)
  const late = new Date('2026-10-09T12:05:30.000Z')
  ledger.consume('fresh', 'intent-fresh', '2026-10-09T12:10:00.000Z', late)
  const stored = JSON.parse(readFileSync(path, 'utf8')) as Record<string, { intentId: string }>
  expect(stored.old).toBeUndefined()
  expect(stored.fresh?.intentId).toBe('intent-fresh')
})

test('refuses a loose, corrupt, or linked ledger file', () => {
  const dir = tempDir()
  const loose = join(dir, 'loose.json')
  writeFileSync(loose, '{}')
  if (process.platform !== 'win32') chmodSync(loose, 0o644)
  const ledger = new NonceLedger(loose)
  if (process.platform === 'win32') {
    expect(ledger.consume('n', 'intent', EXPIRES, EARLY).replay).toBe(false)
  } else {
    expect(() => ledger.consume('n', 'intent', EXPIRES, EARLY)).toThrow('vault locked')
  }

  const corrupt = join(dir, 'corrupt.json')
  writeFileSync(corrupt, '{', { mode: 0o600 })
  if (process.platform !== 'win32') chmodSync(corrupt, 0o600)
  try {
    new NonceLedger(corrupt).consume('n', 'intent', EXPIRES, EARLY)
    expect.fail('expected a refusal')
  } catch (error) {
    expect(error).toBeInstanceOf(PotError)
    expect((error as PotError).code).toBe('INTENT_NONCE_STORE')
  }

  if (process.platform !== 'win32') {
    const target = join(dir, 'target.json')
    const link = join(dir, 'link.json')
    writeFileSync(target, '{}', { mode: 0o600 })
    chmodSync(target, 0o600)
    symlinkSync(target, link)
    expect(() => new NonceLedger(link).consume('n', 'intent', EXPIRES, EARLY)).toThrow(PotError)
  }
})
