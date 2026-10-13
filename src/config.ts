import { PotError } from './errors.js'

/** Env var for the signer API origin. Paths in the client already include `/api`. */
export const SIGNER_API_URL_ENV = 'ZAPPI_SIGNER_API_URL'

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
