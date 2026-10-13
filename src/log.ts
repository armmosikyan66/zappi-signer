/**
 * Stderr only. stdout is the MCP protocol channel.
 * Redacts 12-word phrases, padded base64 (machine passphrases), and bearer tokens.
 */

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
