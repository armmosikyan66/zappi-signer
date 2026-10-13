/**
 * Install-time trust pins. This module never opens a socket.
 * A fetched GET /api/signer/trust document can only confirm pins.
 */
import {
  chmodSync,
  closeSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  renameSync,
  unlinkSync,
  writeSync,
} from 'node:fs'
import { dirname, join } from 'node:path'
import { PotError } from './errors.js'
import { readNoFollow } from './fs-safe.js'
import {
  MAX_ID_LEN,
  normalizeSecp256k1Pubkey,
  type IntentTrustStore,
} from './intent.js'
import { defaultStateDir, defaultVaultPath } from './paths.js'

export const SIGNER_SERVER_PUBKEY_ENV = 'ZAPPI_SIGNER_SERVER_PUBKEY'
const MAX_CONFIG_BYTES = 64 * 1024
const MAX_PINNED_KEYS = 16
const MAX_ADVERTISED_KEYS = 32

export interface PinnedTrust {
  /** Intent and lock keys from the install config. */
  keys: IntentTrustStore
  /**
   * Binding-receipt pin from `ZAPPI_SIGNER_SERVER_PUBKEY` or the config file.
   * The env value wins when both are set.
   */
  serverPubkey?: string
}

/** `~/.zappi-signer/trust.json` (Windows: `%APPDATA%\\zappi-signer\\trust.json`). */
export function defaultTrustConfigPath(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): string {
  return join(defaultStateDir(defaultVaultPath(env, platform)), 'trust.json')
}

/**
 * Load pins from a mode-0600 config file and/or `ZAPPI_SIGNER_SERVER_PUBKEY`.
 * A missing file is an empty key map, not an error. A present file that is
 * unreadable, loose, or malformed refuses.
 *
 * Config shape: `{ "keys": { "<keyId>": "<hex pubkey>" }, "serverPubkey"?: "<hex>" }`.
 */
export function loadPinnedTrust(options?: {
  env?: NodeJS.ProcessEnv
  configPath?: string
  platform?: NodeJS.Platform
}): PinnedTrust {
  const env = options?.env ?? process.env
  const platform = options?.platform ?? process.platform
  const configPath = options?.configPath ?? defaultTrustConfigPath(env, platform)
  const fromFile = readTrustConfig(configPath)
  const envValue = env[SIGNER_SERVER_PUBKEY_ENV]
  const envPin =
    typeof envValue === 'string' && envValue.trim() !== '' ? normalizeSecp256k1Pubkey(envValue) : undefined
  const serverPubkey = envPin ?? fromFile.serverPubkey
  return serverPubkey ? { keys: fromFile.keys, serverPubkey } : { keys: fromFile.keys }
}

/**
 * `trust-server --pubkey <hex>`: persist the binding-receipt pin to the trust
 * config (mode 0600). Existing key pins are kept; `serverPubkey` is replaced.
 * The pin never comes from a fetched document — only from this explicit call
 * or the install-time environment variable.
 */
export function saveServerPubkey(options: {
  serverPubkey: string
  configPath?: string
  env?: NodeJS.ProcessEnv
  platform?: NodeJS.Platform
}): { serverPubkey: string; configPath: string } {
  const env = options.env ?? process.env
  const platform = options.platform ?? process.platform
  const configPath = options.configPath ?? defaultTrustConfigPath(env, platform)
  const serverPubkey = normalizeSecp256k1Pubkey(options.serverPubkey)
  const existing = readTrustConfig(configPath)
  const body = `${JSON.stringify({
    ...(existing.keys.size > 0 ? { keys: Object.fromEntries(existing.keys) } : {}),
    serverPubkey,
  })}\n`
  writeTrustConfig(configPath, body)
  return { serverPubkey, configPath }
}

function writeTrustConfig(path: string, body: string): void {
  const dir = dirname(path)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  if (process.platform !== 'win32') chmodSync(dir, 0o700)
  const tmp = join(dir, `.${randomName()}.tmp`)
  const fd = openSync(tmp, 'w', 0o600)
  try {
    const buf = Buffer.from(body, 'utf8')
    let offset = 0
    while (offset < buf.length) offset += writeSync(fd, buf, offset)
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }
  if (process.platform !== 'win32') chmodSync(tmp, 0o600)
  try {
    const existing = lstatSync(path)
    if (existing.isSymbolicLink()) {
      unlinkSync(tmp)
      throw new PotError('signer trust config is unreadable', 'TRUST_CONFIG')
    }
  } catch (error) {
    if (error instanceof PotError) throw error
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      unlinkSync(tmp)
      throw new PotError('signer trust config is unreadable', 'TRUST_CONFIG')
    }
  }
  renameSync(tmp, path)
  if (process.platform !== 'win32') chmodSync(path, 0o600)
}

function randomName(): string {
  const bytes = new Uint8Array(8)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

/**
 * Compare `document` to install pins. Extra advertised keys are ignored.
 * A pinned key that is missing or different refuses. Nothing in the
 * document is added except one case: when the config map is empty and
 * `keys[activeKeyId]` equals the already-pinned server pubkey, that single
 * id is bound to the pin. The key bytes were pinned before the fetch.
 */
export function verifyPinnedTrust(pinned: PinnedTrust, document: unknown): IntentTrustStore {
  const doc = parseTrustDocument(document)
  const keys = new Map<string, string>()
  for (const [keyId, pubkey] of pinned.keys) {
    assertKeyId(keyId, 'signer trust pin is invalid', 'TRUST_PIN_INVALID')
    keys.set(keyId, normalizeSecp256k1Pubkey(pubkey))
  }
  const serverPubkey = pinned.serverPubkey ? normalizeSecp256k1Pubkey(pinned.serverPubkey) : undefined
  if (keys.size === 0 && !serverPubkey) {
    throw new PotError('signer trust is not pinned', 'TRUST_UNPINNED')
  }
  for (const [keyId, pubkey] of keys) {
    if (!advertisedMatches(pubkey, doc.keys.get(keyId))) {
      throw new PotError('signer trust pin mismatch', 'TRUST_MISMATCH')
    }
  }
  if (serverPubkey && !serverPubkeyConfirmed(doc, serverPubkey, keys)) {
    throw new PotError('signer trust pin mismatch', 'TRUST_MISMATCH')
  }
  if (serverPubkey && keys.size === 0) {
    const active = doc.keys.get(doc.activeKeyId)
    if (active !== undefined && advertisedMatches(serverPubkey, active)) {
      keys.set(doc.activeKeyId, serverPubkey)
    }
  }
  return keys
}

function readTrustConfig(path: string): { keys: Map<string, string>; serverPubkey?: string } {
  let text: string
  try {
    text = readNoFollow(path, MAX_CONFIG_BYTES)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { keys: new Map() }
    throw error
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(text) as unknown
  } catch {
    throw new PotError('signer trust config is unreadable', 'TRUST_CONFIG')
  }
  if (!isRecord(parsed)) throw new PotError('signer trust config is unreadable', 'TRUST_CONFIG')
  for (const key of Object.keys(parsed)) {
    if (key !== 'keys' && key !== 'serverPubkey') {
      throw new PotError('signer trust config is unreadable', 'TRUST_CONFIG')
    }
  }
  const keys = new Map<string, string>()
  if (parsed.keys !== undefined) {
    if (!isRecord(parsed.keys)) throw new PotError('signer trust config is unreadable', 'TRUST_CONFIG')
    const entries = Object.entries(parsed.keys)
    if (entries.length > MAX_PINNED_KEYS) throw new PotError('signer trust config is unreadable', 'TRUST_CONFIG')
    for (const [keyId, pubkey] of entries) {
      assertKeyId(keyId, 'signer trust pin is invalid', 'TRUST_PIN_INVALID')
      if (typeof pubkey !== 'string') throw new PotError('signer trust pin is invalid', 'TRUST_PIN_INVALID')
      keys.set(keyId, normalizeSecp256k1Pubkey(pubkey))
    }
  }
  if (parsed.serverPubkey === undefined) return { keys }
  if (typeof parsed.serverPubkey !== 'string') {
    throw new PotError('signer trust pin is invalid', 'TRUST_PIN_INVALID')
  }
  return { keys, serverPubkey: normalizeSecp256k1Pubkey(parsed.serverPubkey) }
}

interface ParsedTrustDocument {
  keys: Map<string, string>
  activeKeyId: string
  addressChallengePubkey?: string
}

function parseTrustDocument(value: unknown): ParsedTrustDocument {
  if (!isRecord(value)) throw new PotError('signer trust document is malformed', 'TRUST_MALFORMED')
  if (!isRecord(value.keys)) throw new PotError('signer trust document is malformed', 'TRUST_MALFORMED')
  const entries = Object.entries(value.keys)
  if (entries.length < 1 || entries.length > MAX_ADVERTISED_KEYS) {
    throw new PotError('signer trust document is malformed', 'TRUST_MALFORMED')
  }
  const keys = new Map<string, string>()
  for (const [keyId, pubkey] of entries) {
    assertKeyId(keyId, 'signer trust document is malformed', 'TRUST_MALFORMED')
    if (typeof pubkey !== 'string' || pubkey.length < 1 || pubkey.length > 200) {
      throw new PotError('signer trust document is malformed', 'TRUST_MALFORMED')
    }
    keys.set(keyId, pubkey)
  }
  if (typeof value.activeKeyId !== 'string' || !keys.has(value.activeKeyId)) {
    throw new PotError('signer trust document is malformed', 'TRUST_MALFORMED')
  }
  assertKeyId(value.activeKeyId, 'signer trust document is malformed', 'TRUST_MALFORMED')
  if (value.addressChallengePubkey === undefined) {
    return { keys, activeKeyId: value.activeKeyId }
  }
  if (typeof value.addressChallengePubkey !== 'string' || value.addressChallengePubkey.trim() === '') {
    throw new PotError('signer trust document is malformed', 'TRUST_MALFORMED')
  }
  return {
    keys,
    activeKeyId: value.activeKeyId,
    addressChallengePubkey: value.addressChallengePubkey,
  }
}

function serverPubkeyConfirmed(
  doc: ParsedTrustDocument,
  serverPubkey: string,
  pinnedKeys: ReadonlyMap<string, string>,
): boolean {
  if (doc.addressChallengePubkey !== undefined) {
    return advertisedMatches(serverPubkey, doc.addressChallengePubkey)
  }
  const active = doc.keys.get(doc.activeKeyId)
  if (active !== undefined && advertisedMatches(serverPubkey, active)) return true
  for (const pubkey of pinnedKeys.values()) {
    if (advertisedMatches(serverPubkey, pubkey)) return true
  }
  return false
}

function advertisedMatches(pin: string, advertised: unknown): boolean {
  if (typeof advertised !== 'string') return false
  try {
    return normalizeSecp256k1Pubkey(advertised) === pin
  } catch {
    return false
  }
}

function assertKeyId(value: string, message: string, code: string): void {
  if (value.length < 1 || value.length > MAX_ID_LEN || hasControlChar(value)) {
    throw new PotError(message, code)
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
