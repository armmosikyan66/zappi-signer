import { chmodSync, closeSync, fsyncSync, lstatSync, mkdirSync, openSync, renameSync, unlinkSync, writeSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { PotError } from './errors.js'
import { readNoFollow } from './fs-safe.js'
import { defaultStateDir, defaultVaultPath } from './paths.js'

/** Env var for the signer API origin. Paths in the client already include `/api`. */
export const SIGNER_API_URL_ENV = 'ZAPPI_SIGNER_API_URL'

/** Built-in origin when no env value and no install-time pin exists. */
export const DEFAULT_SIGNER_API_URL = 'https://api.zappi.money'

/** Highest API config bytes. One short JSON object; anything more refuses. */
const MAX_API_CONFIG_BYTES = 4 * 1024

const REFUSE = 'refused to spend'

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]'])

/** True only for the literal loopback names. Decimal and hex forms of 127.0.0.1 are refused. */
export function isLoopbackSignerHost(hostname: string): boolean {
  return LOOPBACK_HOSTS.has(hostname.toLowerCase())
}

/**
 * Accept https, or http when the host is loopback (local Nest on this machine).
 * Userinfo, query, and fragment are rejected so a URL secret is never sent
 * and never copied into an error.
 */
export function assertSignerBaseUrl(url: URL): void {
  if (url.username !== '' || url.password !== '' || url.search !== '' || url.hash !== '') {
    throw new PotError(REFUSE)
  }
  if (url.hostname === '') throw new PotError(REFUSE)
  if (url.protocol === 'https:') return
  if (url.protocol === 'http:' && isLoopbackSignerHost(url.hostname)) return
  throw new PotError(REFUSE)
}

/** Host as written, before the URL parser turns decimal 2130706433 into 127.0.0.1. */
function writtenHttpHost(raw: string): string | null {
  const match = /^http:\/\/(\[[^\]]+\]|[^/?#:@]+)/i.exec(raw.trim())
  return match?.[1] ?? null
}

/**
 * Origin (optional base path) for the signer API.
 * Public `http://` is rejected before a request is made. Loopback `http://`
 * is allowed so a local Nest on 127.0.0.1:3011 can be used. The host must be
 * written as `127.0.0.1`, `localhost`, or `[::1]`.
 */
export function signerApiBaseUrl(raw: string | undefined): string {
  if (typeof raw !== 'string') throw new PotError(REFUSE)
  const trimmed = raw.trim()
  if (trimmed === '') throw new PotError(REFUSE)
  let url: URL
  try {
    url = new URL(trimmed)
  } catch {
    throw new PotError(REFUSE)
  }
  if (url.protocol === 'http:') {
    const written = writtenHttpHost(trimmed)
    if (written === null || !isLoopbackSignerHost(written)) throw new PotError(REFUSE)
  }
  assertSignerBaseUrl(url)
  const path = url.pathname.replace(/\/+$/, '')
  return `${url.origin}${path === '' || path === '/' ? '' : path}`
}

/**
 * `~/.zappi-signer/api.json` — the install-time API origin pin. The staging
 * installer writes the staging origin here; the production installer writes
 * the production origin. An explicit env value still wins.
 */
export function defaultApiConfigPath(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): string {
  return join(defaultStateDir(defaultVaultPath(env, platform)), 'api.json')
}

/**
 * Load the install-time origin pin. A missing file is undefined (the caller
 * falls through to {@link DEFAULT_SIGNER_API_URL}). A present file that is
 * unreadable, loose, or malformed refuses — same fail-closed rule as the
 * trust pin.
 *
 * File shape: `{ "apiBaseUrl": "<origin>" }`.
 */
export function loadPinnedApiBaseUrl(options?: {
  env?: NodeJS.ProcessEnv
  platform?: NodeJS.Platform
  configPath?: string
}): string | undefined {
  const env = options?.env ?? process.env
  const platform = options?.platform ?? process.platform
  const configPath = options?.configPath ?? defaultApiConfigPath(env, platform)
  let text: string
  try {
    text = readNoFollow(configPath, MAX_API_CONFIG_BYTES)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    throw error
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(text) as unknown
  } catch {
    throw new PotError('signer api config is unreadable', 'API_CONFIG')
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new PotError('signer api config is unreadable', 'API_CONFIG')
  }
  for (const key of Object.keys(parsed as Record<string, unknown>)) {
    if (key !== 'apiBaseUrl') throw new PotError('signer api config is unreadable', 'API_CONFIG')
  }
  const value = (parsed as Record<string, unknown>).apiBaseUrl
  if (typeof value !== 'string' || value.trim() === '') {
    throw new PotError('signer api config is unreadable', 'API_CONFIG')
  }
  return signerApiBaseUrl(value)
}

/**
 * Persist the install-time origin pin (mode 0600). The installer calls this;
 * `trust-server` stays separate because the trust pin and the origin pin
 * rotate on different schedules.
 */
export function saveApiBaseUrl(options: {
  apiBaseUrl: string
  configPath?: string
  env?: NodeJS.ProcessEnv
  platform?: NodeJS.Platform
}): { apiBaseUrl: string; configPath: string } {
  const env = options.env ?? process.env
  const platform = options.platform ?? process.platform
  const configPath = options.configPath ?? defaultApiConfigPath(env, platform)
  const apiBaseUrl = signerApiBaseUrl(options.apiBaseUrl)
  writeApiConfig(configPath, `${JSON.stringify({ apiBaseUrl })}\n`)
  return { apiBaseUrl, configPath }
}

function writeApiConfig(path: string, body: string): void {
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
      throw new PotError('signer api config is unreadable', 'API_CONFIG')
    }
  } catch (error) {
    if (error instanceof PotError) throw error
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      unlinkSync(tmp)
      throw new PotError('signer api config is unreadable', 'API_CONFIG')
    }
  }
  renameSync(tmp, path)
}

function randomName(): string {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`
}
