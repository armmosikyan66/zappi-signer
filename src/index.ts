#!/usr/bin/env node
import { realpathSync } from 'node:fs'
import { pathToFileURL } from 'node:url'
import { runCliCommand, type CliInjected } from './cli-dispatch.js'
import { publicMessage } from './errors.js'
import { redact } from './log.js'
import { signCommand, type SignOutcome } from './sign-flow.js'

const COMMANDS = ['sign', 'status', 'policy', 'provision', 'prove-address', 'backup', 'restore'] as const

type Command = (typeof COMMANDS)[number]

const COMMAND_SET = new Set<string>(COMMANDS)

export interface CliInvocation {
  json: boolean
  yes: boolean
  command: Command
  args: readonly string[]
  potId?: string
  label?: string
}

export type { CliInjected }

export async function main(
  argv: readonly string[] = process.argv.slice(2),
  injected?: CliInjected,
): Promise<number> {
  if (argv.includes('--help')) {
    process.stdout.write(`${usage()}\n`)
    return 0
  }
  const parsed = parseSignerArgv(argv)
  if (!parsed) {
    process.stderr.write('unknown command\n')
    return 1
  }
  try {
    if (parsed.command === 'sign') {
      const outcome = await signCommand({
        stdinIsTty: Boolean(process.stdin.isTTY),
        ...injected,
        requestId: parsed.args[0] ?? '',
        yes: parsed.yes,
      } as Parameters<typeof signCommand>[0])
      process.stdout.write(`${formatSignOutcome(outcome, parsed.json)}\n`)
      return 0
    }
    await runCliCommand(parsed, injected ?? {})
    return 0
  } catch (error) {
    process.stderr.write(`${safeFailure(error)}\n`)
    return 1
  }
}

function formatSignOutcome(outcome: SignOutcome, json: boolean): string {
  if (json) return JSON.stringify(outcome)
  if (outcome.txid) return `${outcome.status} ${outcome.txid}`
  return outcome.status
}

function safeFailure(error: unknown): string {
  const message = redact(publicMessage(error))
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .trim()
  if (!message) return 'request failed'
  return message.length > 200 ? message.slice(0, 200) : message
}

export function parseSignerArgv(argv: readonly string[]): CliInvocation | null {
  let json = false
  let yes = false
  let potId: string | undefined
  let label: string | undefined
  const positionals: string[] = []
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index]
    if (token === undefined) return null
    if (token === '--json') {
      json = true
      continue
    }
    if (token === '--yes') {
      yes = true
      continue
    }
    if (token === '--pot' || token === '--label') {
      const value = argv[index + 1]
      if (value === undefined || value === '' || value.startsWith('-')) return null
      index += 1
      if (token === '--pot') {
        if (potId !== undefined) return null
        potId = value
      } else {
        if (label !== undefined) return null
        label = value
      }
      continue
    }
    if (token.startsWith('-')) return null
    positionals.push(token)
  }
  const command = positionals[0]
  if (!command || !COMMAND_SET.has(command)) return null
  const name = command as Command
  const args = positionals.slice(1)
  if (!acceptedShape(name, args) || !flagsAllowed(name, potId, label)) return null
  return {
    json,
    yes,
    command: name,
    args,
    ...(potId !== undefined ? { potId } : {}),
    ...(label !== undefined ? { label } : {}),
  }
}

function acceptedShape(command: Command, args: readonly string[]): boolean {
  if (command === 'sign' || command === 'status') return args.length === 1 && args[0] !== ''
  if (command === 'policy') return args.length === 1 && (args[0] === 'view' || args[0] === 'tighten')
  return args.length === 0
}

function flagsAllowed(command: Command, potId: string | undefined, label: string | undefined): boolean {
  if (command === 'provision') return potId === undefined
  if (command === 'policy' || command === 'prove-address' || command === 'backup' || command === 'restore') {
    return label === undefined
  }
  return potId === undefined && label === undefined
}

function usage(): string {
  return [
    'zappi-signer sign <requestId> [--yes] [--json]',
    'zappi-signer status <requestId> [--json]',
    'zappi-signer policy view --pot <id> [--json]',
    'zappi-signer policy tighten --pot <id> [--json]',
    'zappi-signer provision [--label <text>] [--json]',
    'zappi-signer prove-address --pot <id> [--json]',
    'zappi-signer backup --pot <id> [--json]',
    'zappi-signer restore --pot <id> [--json]',
  ].join('\n')
}

function isDirectInvocation(argv1: string | undefined): boolean {
  // The standalone binary (scripts/build-bin.mjs) defines this variable to the
  // literal "1": there is no source file whose URL could match argv[1].
  if (process.env.ZAPPI_SIGNER_STANDALONE === '1') return true
  if (!argv1) return false
  try {
    return import.meta.url === pathToFileURL(realpathSync(argv1)).href
  } catch {
    return false
  }
}

if (isDirectInvocation(process.argv[1])) {
  main().then(
    (code) => {
      if (code !== 0) process.exitCode = code
    },
    () => {
      process.stderr.write('request failed\n')
      process.exitCode = 1
    },
  )
}
