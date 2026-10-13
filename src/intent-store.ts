/**
 * Durable nonce ledger (SIGNER_PROTOCOL §3.4).
 * Maps nonce → { intentId, expiresAt } in a mode-0600 file.
 * This module only records nonces. It does not broadcast.
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
import {
  assertWithinExpiryWindow,
  isPastExpiry,
  parseExpiresAt,
  type NonceConsumeResult,
  type NonceRecord,
  type NonceStore,
} from './intent.js'
import { defaultStateDir, defaultVaultPath } from './paths.js'

export type { NonceConsumeResult, NonceRecord, NonceStore }

const MAX_LEDGER_BYTES = 1_048_576
const MAX_LEDGER_INTENT_ID = 160

/** `~/.zappi-signer/intent-nonces.json` (Windows: `%APPDATA%\\zappi-signer\\intent-nonces.json`). */
export function defaultNonceLedgerPath(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): string {
  return join(defaultStateDir(defaultVaultPath(env, platform)), 'intent-nonces.json')
}

export class NonceLedger implements NonceStore {
  constructor(readonly filePath: string) {}

  /**
   * Fresh nonce: bind it. Same nonce and same intentId: return the recorded
   * entry. Same nonce and a different intentId: hard error. Same intentId
   * under a different nonce: hard error. Expired rows are dropped on load.
   */
  consume(nonce: string, intentId: string, expiresAt: string, now: Date = new Date()): NonceConsumeResult {
    assertToken(nonce, 128, 'intent is malformed', 'INTENT_MALFORMED')
    assertToken(intentId, MAX_LEDGER_INTENT_ID, 'intent is malformed', 'INTENT_MALFORMED')
    const expiresAtMs = parseExpiresAt(expiresAt, 'intent')
    const nowMs = now.getTime()
    const loaded = readLedger(this.filePath, nowMs)
    if (loaded.pruned) writeLedger(this.filePath, loaded.store)

    const existing = loaded.store.get(nonce)
    if (existing) {
      if (existing.intentId !== intentId) {
        throw new PotError('Intent nonce was already used. Refusing the replay.', 'INTENT_NONCE_REUSED')
      }
      return { replay: true, record: { intentId: existing.intentId, expiresAt: existing.expiresAt } }
    }
    for (const record of loaded.store.values()) {
      if (record.intentId === intentId) {
        throw new PotError('Intent id is already bound to another nonce.', 'INTENT_ID_CONFLICT')
      }
    }
    assertWithinExpiryWindow(expiresAtMs, nowMs, 'intent')
    const record = { intentId, expiresAt }
    loaded.store.set(nonce, record)
    writeLedger(this.filePath, loaded.store)
    return { replay: false, record }
  }
}

function assertToken(value: string, max: number, message: string, code: string): void {
  if (typeof value !== 'string' || value.length < 1 || value.length > max || hasControlChar(value)) {
    throw new PotError(message, code)
  }
}

function readLedger(path: string, nowMs: number): { store: Map<string, NonceRecord>; pruned: boolean } {
  let text: string
  try {
    text = readNoFollow(path, MAX_LEDGER_BYTES)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { store: new Map(), pruned: false }
    throw error
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(text) as unknown
  } catch {
    throw new PotError('intent nonce store is unreadable', 'INTENT_NONCE_STORE')
  }
  if (!isRecord(parsed)) throw new PotError('intent nonce store is unreadable', 'INTENT_NONCE_STORE')
  const store = new Map<string, NonceRecord>()
  let pruned = false
  for (const [nonce, value] of Object.entries(parsed)) {
    const record = parseRecord(nonce, value)
    let expiresAtMs: number
    try {
      expiresAtMs = parseExpiresAt(record.expiresAt, 'intent')
    } catch {
      throw new PotError('intent nonce store is unreadable', 'INTENT_NONCE_STORE')
    }
    if (isPastExpiry(expiresAtMs, nowMs)) {
      pruned = true
      continue
    }
    store.set(nonce, record)
  }
  return { store, pruned }
}

function parseRecord(nonce: string, value: unknown): NonceRecord {
  assertToken(nonce, 128, 'intent nonce store is unreadable', 'INTENT_NONCE_STORE')
  if (!isRecord(value)) throw new PotError('intent nonce store is unreadable', 'INTENT_NONCE_STORE')
  const keys = Object.keys(value).sort()
  if (keys.length !== 2 || keys[0] !== 'expiresAt' || keys[1] !== 'intentId') {
    throw new PotError('intent nonce store is unreadable', 'INTENT_NONCE_STORE')
  }
  const intentId = value.intentId
  const expiresAt = value.expiresAt
  if (typeof intentId !== 'string' || typeof expiresAt !== 'string') {
    throw new PotError('intent nonce store is unreadable', 'INTENT_NONCE_STORE')
  }
  assertToken(intentId, MAX_LEDGER_INTENT_ID, 'intent nonce store is unreadable', 'INTENT_NONCE_STORE')
  return { intentId, expiresAt }
}

function writeLedger(path: string, store: ReadonlyMap<string, NonceRecord>): void {
  const body: Record<string, NonceRecord> = {}
  for (const nonce of [...store.keys()].sort()) {
    const record = store.get(nonce)
    if (!record) continue
    body[nonce] = { expiresAt: record.expiresAt, intentId: record.intentId }
  }
  writeAtomic0600(path, JSON.stringify(body))
}

function writeAtomic0600(path: string, body: string): void {
  const dir = dirname(path)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
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
    throw error
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
    throw error
  }
  if (process.platform !== 'win32') chmodSync(path, 0o600)
}

function assertReplaceable(path: string): void {
  try {
    const existing = lstatSync(path)
    if (existing.isSymbolicLink() || !existing.isFile()) {
      throw new PotError('intent nonce store is unreadable', 'INTENT_NONCE_STORE')
    }
  } catch (error) {
    if (error instanceof PotError) throw error
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      throw new PotError('intent nonce store is unreadable', 'INTENT_NONCE_STORE')
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
