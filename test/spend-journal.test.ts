import { chmodSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, expect, test } from 'vitest'
import { PotError } from '../src/errors.js'
import { defaultStateDir, defaultVaultPath } from '../src/paths.js'
import { FileSpendJournal, defaultSpendJournalPath } from '../src/spend-journal.js'

const dirs: string[] = []
const TX_A = 'a'.repeat(64)
const TX_B = 'b'.repeat(64)
const TX_C = 'c'.repeat(64)

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'zappi-spend-journal-'))
  dirs.push(dir)
  return dir
}

test('default journal path sits beside the vault', () => {
  expect(defaultSpendJournalPath()).toBe(join(defaultStateDir(defaultVaultPath()), 'spend-journal.json'))
  expect(defaultSpendJournalPath({ APPDATA: 'C:\\Users\\me\\AppData\\Roaming' }, 'win32')).toBe(
    join('C:\\Users\\me\\AppData\\Roaming', 'zappi-signer', 'spend-journal.json'),
  )
})

test('round-trips an intent record and keeps the journal private', () => {
  const path = join(tempDir(), 'nested', 'spend-journal.json')
  const journal = new FileSpendJournal(path)
  expect(journal.get('intent-a')).toBeNull()
  journal.put('intent-a', TX_A)
  journal.markReceipted('intent-a')

  const again = new FileSpendJournal(path)
  expect(again.get('intent-a')).toEqual({ txid: TX_A, receipted: true })
  const stored = JSON.parse(readFileSync(path, 'utf8')) as Record<string, { txid: string; receipted: boolean }>
  expect(stored['intent-a']).toEqual({ receipted: true, txid: TX_A })
  expect(readdirSync(join(path, '..')).filter((name) => name.endsWith('.tmp'))).toEqual([])

  if (process.platform !== 'win32') {
    expect(statSync(path).mode & 0o777).toBe(0o600)
    expect(statSync(join(path, '..')).mode & 0o777).toBe(0o700)
  }
})

test('refuses a loose mode or a symlink when the filesystem helper does', () => {
  const dir = tempDir()
  const loose = join(dir, 'loose.json')
  writeFileSync(loose, '{}')
  if (process.platform !== 'win32') chmodSync(loose, 0o644)
  if (process.platform === 'win32') {
    expect(new FileSpendJournal(loose).get('intent-a')).toBeNull()
  } else {
    expect(() => new FileSpendJournal(loose).get('intent-a')).toThrow('vault locked')
    expect(readFileSync(loose, 'utf8')).toBe('{}')
  }

  if (process.platform !== 'win32') {
    const target = join(dir, 'target.json')
    const link = join(dir, 'link.json')
    writeFileSync(target, '{}', { mode: 0o600 })
    chmodSync(target, 0o600)
    symlinkSync(target, link)
    expect(() => new FileSpendJournal(link).put('intent-a', TX_A)).toThrow(PotError)
    expect(readFileSync(target, 'utf8')).toBe('{}')

    const real = join(dir, 'real')
    mkdirSync(real, { mode: 0o700 })
    const linked = join(dir, 'linked')
    symlinkSync(real, linked)
    expect(() => new FileSpendJournal(join(linked, 'spend-journal.json')).put('intent-a', TX_A)).toThrow(PotError)
    expect(readdirSync(real)).toEqual([])
  }
})

test('put is idempotent for the same txid', () => {
  const path = join(tempDir(), 'spend-journal.json')
  const journal = new FileSpendJournal(path)
  journal.put('intent-a', TX_A)
  journal.put('intent-a', TX_A)
  journal.markReceipted('intent-a')
  journal.put('intent-a', `0x${TX_A.toUpperCase()}`)
  expect(journal.get('intent-a')).toEqual({ txid: TX_A, receipted: true })
  const stored = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>
  expect(Object.keys(stored)).toEqual(['intent-a'])
})

test('a different txid for the same intent throws and leaves the record', () => {
  const path = join(tempDir(), 'spend-journal.json')
  const journal = new FileSpendJournal(path)
  journal.put('intent-a', TX_A)
  try {
    journal.put('intent-a', TX_B)
    expect.fail('expected a refusal')
  } catch (error) {
    expect(error).toBeInstanceOf(PotError)
    expect((error as PotError).code).toBe('SPEND_JOURNAL')
  }
  expect(journal.get('intent-a')).toEqual({ txid: TX_A, receipted: false })
})

test('lists only unreceipted entries', () => {
  const path = join(tempDir(), 'spend-journal.json')
  const journal = new FileSpendJournal(path)
  journal.put('b', TX_B)
  journal.put('a', TX_A)
  journal.put('c', TX_C)
  journal.markReceipted('b')
  journal.markReceipted('b')
  expect(journal.listUnreceipted()).toEqual([
    { intentId: 'a', txid: TX_A, receipted: false },
    { intentId: 'c', txid: TX_C, receipted: false },
  ])
  expect(journal.get('b')).toEqual({ txid: TX_B, receipted: true })
})
