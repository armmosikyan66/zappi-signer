/**
 * Stderr only. stdout is the MCP protocol channel.
 * Redacts 12-word phrases, padded base64 (machine passphrases), and bearer tokens.
 */
import { PotError } from './errors.js'

const MNEMONIC_RE = /\b(?:[a-z]{3,8} ){11}[a-z]{3,8}\b/gi
const PADDED_SECRET_RE = /\b[A-Za-z0-9+/]{40,}={1,2}\b/g
const BEARER_RE = /Bearer\s+\S+/gi

export function redact(line: string): string {
  return line
    .replace(MNEMONIC_RE, '[redacted]')
    .replace(PADDED_SECRET_RE, '[redacted]')
    .replace(BEARER_RE, 'Bearer [redacted]')
}

export function logLine(line: string): void {
  const safe = redact(line)
  process.stderr.write(safe.endsWith('\n') ? safe : `${safe}\n`)
}

/** gRPC and OS status tokens that are safe to surface on their own. */
const STATUS_RE =
  /\b(?:DEADLINE_EXCEEDED|UNAVAILABLE|UNAUTHENTICATED|PERMISSION_DENIED|NOT_FOUND|INVALID_ARGUMENT|INTERNAL|UNIMPLEMENTED|CANCELLED|UNKNOWN|ECONNREFUSED|ECONNRESET|ETIMEDOUT|ENOTFOUND|EAI_AGAIN)\b/g

/**
 * Opt-in diagnostic for swallowed causes (`ZAPPI_SIGNER_DEBUG=1`).
 * Writes only the error name, a PotError code if set, and standalone gRPC/OS
 * status tokens found in the message. Never the raw message, which can carry
 * endpoint URLs, public keys, or worse.
 */
export function debugCause(error: unknown, env: NodeJS.ProcessEnv = process.env): void {
  if (env.ZAPPI_SIGNER_DEBUG !== '1' || error === null || error === undefined) return
  const parts: string[] = []
  if (error instanceof Error && error.name !== 'Error') parts.push(error.name)
  if (error instanceof PotError && error.code) parts.push(error.code)
  if (error instanceof Error) {
    const statuses = error.message.match(STATUS_RE)
    if (statuses) parts.push(...new Set(statuses))
  }
  if (parts.length === 0) return
  process.stderr.write(`zappi-signer: cause: ${parts.join(' ')}\n`)
}
