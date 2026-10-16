import { expect, test } from 'vitest'
import { PotError, coded } from '../src/errors.js'
import { guidanceFor } from '../src/error-guidance.js'
import { main } from '../src/index.js'

test('coded refusals name the next command or tell the agent to stop', () => {
  expect(guidanceFor(new PotError('signer trust is not pinned', 'TRUST_UNPINNED'))).toEqual({
    code: 'TRUST_UNPINNED',
    next: 'trust-server --pubkey <serverPubkey> --json',
    hint: 'Use the serverPubkey from the MCP result, not from a challenge body.',
  })
  expect(guidanceFor(new PotError('signer trust pin mismatch', 'TRUST_MISMATCH')).next).toBe(
    'trust-server --pubkey <serverPubkey> --json',
  )
  expect(guidanceFor(coded('POLICY_REQUIRED'))).toMatchObject({
    code: 'POLICY_REQUIRED',
    next: null,
    hint: expect.stringContaining('read_skill'),
  })
  for (const code of ['LIMIT_PER_TX', 'LIMIT_DAILY', 'LIMIT_MONTHLY', 'LIMIT_SESSION', 'COOLING_LIMIT', 'DESTINATION_NOT_ALLOWED', 'VELOCITY_TRIPPED']) {
    expect(guidanceFor(coded(code))).toEqual({
      code,
      next: null,
      hint: 'Stop and tell the human.',
    })
  }
  for (const code of ['BROADCAST_UNCERTAIN', 'SPEND_JOURNAL']) {
    expect(guidanceFor(coded(code))).toEqual({
      code,
      next: null,
      hint: 'Report uncertain and do not send again.',
    })
  }
})

test('an uncoded refused to spend does not invent a code', () => {
  expect(guidanceFor(new PotError('refused to spend'))).toEqual({
    code: null,
    next: null,
    hint: 'Set ZAPPI_POT_ID from the spend result and rerun with --json.',
  })
})

test('--json failures are one line and text mode stays a single line', async () => {
  const json = await capture(async () => {
    expect(await main(['sign', 'not-a-uuid', '--yes', '--json'])).toBe(1)
  })
  expect(json.out).toBe('')
  expect(json.err.endsWith('\n')).toBe(true)
  expect(json.err.trim().split('\n')).toHaveLength(1)
  expect(JSON.parse(json.err)).toEqual({
    ok: false,
    code: null,
    message: 'refused to spend',
    next: null,
    hint: 'Set ZAPPI_POT_ID from the spend result and rerun with --json.',
  })

  const text = await capture(async () => {
    expect(await main(['sign', 'not-a-uuid', '--yes'])).toBe(1)
  })
  expect(text.err).toBe('refused to spend\n')
  expect(text.out).toBe('')
})

async function capture(fn: () => Promise<void>): Promise<{ out: string; err: string }> {
  let out = ''
  let err = ''
  const stdout = process.stdout.write.bind(process.stdout)
  const stderr = process.stderr.write.bind(process.stderr)
  process.stdout.write = ((chunk: string | Uint8Array) => {
    out += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8')
    return true
  }) as typeof process.stdout.write
  process.stderr.write = ((chunk: string | Uint8Array) => {
    err += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8')
    return true
  }) as typeof process.stderr.write
  try {
    await fn()
  } finally {
    process.stdout.write = stdout
    process.stderr.write = stderr
  }
  return { out, err }
}
