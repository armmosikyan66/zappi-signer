/**
 * Actionable failures safe to show to an agent.
 * The message must never contain a mnemonic, seed, passphrase, token, or stack.
 * Policy failures set `code` and that code is the only text the agent sees.
 */
export class PotError extends Error {
  readonly code: string | undefined

  constructor(message: string, code?: string) {
    super(message)
    this.name = 'PotError'
    this.code = code
  }
}

export function coded(code: string): PotError {
  return new PotError(code, code)
}

export function publicMessage(error: unknown): string {
  if (error instanceof PotError) return error.code ?? error.message
  return 'request failed'
}
