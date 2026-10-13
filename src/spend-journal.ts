/**
 * Local spend journal. This does not broadcast and does not read a mnemonic.
 * `~/.zappi-signer/spend-journal.json` (mode 0600) maps intentId → { txid, receipted }.
 * `put` is idempotent for the same txid and refuses a different txid.
 */
import { randomBytes } from 'node:crypto'
import {
  chmodSync,
  closeSync,
  constants,
  fsyncSync,
  lstatSync,
  mkdirSync,
  renameSync,
  unlinkSync,
  writeSync,
} from 'node:fs'
import { dirname, join } from 'node:path'
import { PotError } from './errors.js'
import { openNoFollow, readNoFollow } from './fs-safe.js'
import { defaultStateDir, defaultVaultPath } from './paths.js'

const MAX_JOURNAL_BYTES = 1_048_576
const MAX_ENTRIES = 4096
const TXID_RE = /^[0-9a-f]{64}$/

export interface SpendJournalRecord {
  txid: string
  receipted: boolean
}

export interface UnreceiptedSpend {
  intentId: string
  txid: string
  receipted: false
}

export interface SpendJournal {
  put(intentId: string, txid: string): void
  markReceipted(intentId: string): void
  get(intentId: string): SpendJournalRecord | null
  listUnreceipted(): readonly UnreceiptedSpend[]
}

/** `~/.zappi-signer/spend-journal.json` (Windows: `%APPDATA%\\zappi-signer\\spend-journal.json`). */
export function defaultSpendJournalPath(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): string {
  return join(defaultStateDir(defaultVaultPath(env, platform)), 'spend-journal.json')
}

export class FileSpendJournal implements SpendJournal {
  constructor(readonly filePath: string) {}

  put(intentId: string, txid: string): void {
    assertIntentId(intentId)
    const normalized = assertSpendTxid(txid)
    const store = readStore(this.filePath)
    const existing = store.get(intentId)
    if (existing) {
      if (existing.txid === normalized) return
      throw new PotError('refused to spend', 'SPEND_JOURNAL')
    }
    if (store.size >= MAX_ENTRIES) throw new PotError('refused to spend', 'SPEND_JOURNAL')
    store.set(intentId, { txid: normalized, receipted: false })
    writeStore(this.filePath, store)
  }

  markReceipted(intentId: string): void {
    assertIntentId(intentId)
    const store = readStore(this.filePath)
    const existing = store.get(intentId)
    if (!existing) throw new PotError('refused to spend', 'SPEND_JOURNAL')
    if (existing.receipted) return
    store.set(intentId, { txid: existing.txid, receipted: true })
    writeStore(this.filePath, store)
  }

  get(intentId: string): SpendJournalRecord | null {
    assertIntentId(intentId)
    const entry = readStore(this.filePath).get(intentId)
    if (!entry) return null
    return { txid: entry.txid, receipted: entry.receipted }
  }

  listUnreceipted(): readonly UnreceiptedSpend[] {
    const store = readStore(this.filePath)
    const rows: UnreceiptedSpend[] = []
    for (const intentId of [...store.keys()].sort()) {
      const entry = store.get(intentId)
      if (!entry || entry.receipted) continue
      rows.push({ intentId, txid: entry.txid, receipted: false })
    }
    return rows
  }
}

function assertSpendTxid(value: string): string {
  if (typeof value !== 'string') throw new PotError('refused to spend', 'SPEND_JOURNAL')
  const txid = value.trim().toLowerCase().replace(/^0x/, '')
  if (!TXID_RE.test(txid)) throw new PotError('refused to spend', 'SPEND_JOURNAL')
  return txid
}

function assertIntentId(value: string): void {
  if (
    typeof value !== 'string' ||
    value.length < 1 ||
    value.length > 128 ||
    hasControlChar(value) ||
    value.includes('/') ||
    value.includes('\\') ||
    value === '.' ||
    value === '..'
  ) {
    throw new PotError('refused to spend', 'SPEND_JOURNAL')
  }
}

function readStore(path: string): Map<string, SpendJournalRecord> {
  try {
    const existing = lstatSync(path)
    if (existing.isSymbolicLink() || !existing.isFile()) {
      throw new PotError('refused to spend', 'SPEND_JOURNAL')
    }
  } catch (error) {
    if (error instanceof PotError) throw error
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return new Map()
    throw new PotError('refused to spend', 'SPEND_JOURNAL')
  }
  let text: string
  try {
    text = readNoFollow(path, MAX_JOURNAL_BYTES)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return new Map()
    if (error instanceof PotError) throw error
    throw new PotError('refused to spend', 'SPEND_JOURNAL')
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(text) as unknown
  } catch {
    throw new PotError('refused to spend', 'SPEND_JOURNAL')
  }
  if (!isRecord(parsed)) throw new PotError('refused to spend', 'SPEND_JOURNAL')
  const entries = Object.entries(parsed)
  if (entries.length > MAX_ENTRIES) throw new PotError('refused to spend', 'SPEND_JOURNAL')
  const store = new Map<string, SpendJournalRecord>()
  for (const [intentId, value] of entries) {
    assertIntentId(intentId)
    store.set(intentId, parseEntry(value))
  }
  return store
}

function parseEntry(value: unknown): SpendJournalRecord {
  if (!isRecord(value)) throw new PotError('refused to spend', 'SPEND_JOURNAL')
  const keys = Object.keys(value).sort()
  if (keys.length !== 2 || keys[0] !== 'receipted' || keys[1] !== 'txid') {
    throw new PotError('refused to spend', 'SPEND_JOURNAL')
  }
  if (typeof value.receipted !== 'boolean') throw new PotError('refused to spend', 'SPEND_JOURNAL')
  if (typeof value.txid !== 'string') throw new PotError('refused to spend', 'SPEND_JOURNAL')
  return { txid: assertSpendTxid(value.txid), receipted: value.receipted }
}

function writeStore(path: string, store: ReadonlyMap<string, SpendJournalRecord>): void {
  const body: Record<string, SpendJournalRecord> = {}
  for (const intentId of [...store.keys()].sort()) {
    const entry = store.get(intentId)
    if (!entry) continue
    body[intentId] = { receipted: entry.receipted, txid: entry.txid }
  }
  writeAtomic0600(path, JSON.stringify(body))
}

function writeAtomic0600(path: string, body: string): void {
  const dir = dirname(path)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  const dirStat = lstatSync(dir)
  if (dirStat.isSymbolicLink() || !dirStat.isDirectory()) {
    throw new PotError('refused to spend', 'SPEND_JOURNAL')
  }
  if (process.platform !== 'win32') chmodSync(dir, 0o700)
  const tmp = join(dir, `.${randomBytes(8).toString('hex')}.tmp`)
  const flags = constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY
  let fd: number | undefined
  try {
    fd = openNoFollow(tmp, flags, 0o600)
    const buf = Buffer.from(body, 'utf8')
    let offset = 0
    while (offset < buf.length) offset += writeSync(fd, buf, offset)
    fsyncSync(fd)
    closeSync(fd)
    fd = undefined
  } catch (error) {
    if (fd !== undefined) closeSync(fd)
    try {
      unlinkSync(tmp)
    } catch {
      // The temp file was not created.
    }
    if (error instanceof PotError) throw error
    throw new PotError('refused to spend', 'SPEND_JOURNAL')
  }
  if (process.platform !== 'win32') chmodSync(tmp, 0o600)
  try {
    assertReplaceable(path)
    renameSync(tmp, path)
  } catch (error) {
    try {
      unlinkSync(tmp)
    } catch {
      // Already gone.
    }
    if (error instanceof PotError) throw error
    throw new PotError('refused to spend', 'SPEND_JOURNAL')
  }
  if (process.platform !== 'win32') chmodSync(path, 0o600)
}

function assertReplaceable(path: string): void {
  try {
    const existing = lstatSync(path)
    if (existing.isSymbolicLink() || !existing.isFile()) {
      throw new PotError('refused to spend', 'SPEND_JOURNAL')
    }
  } catch (error) {
    if (error instanceof PotError) throw error
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      throw new PotError('refused to spend', 'SPEND_JOURNAL')
    }
  }
}

function hasControlChar(value: string): boolean {
  for (const char of value) {
    if (char.charCodeAt(0) <= 0x1f) return true
  }
  return false
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
