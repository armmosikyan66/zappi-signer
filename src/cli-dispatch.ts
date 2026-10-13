/**
 * CLI wiring for status, policy, provision, prove-address, backup, and restore.
 * Crypto, policy checks, backup sealing, and address proofs stay in the command modules.
 */
import { SignerBackendClient } from './client.js'
import {
  runBackup,
  runRestore,
  type BackupCommandVault,
  type RecoveryMaterial,
  type RestoreCommandVault,
} from './commands/backup.js'
import {
  runPolicyTighten,
  runPolicyView,
  type PolicyCommandVault,
  type PolicyView,
} from './commands/policy.js'
import { runProveAddress, runProvision, type ProvisionClient } from './commands/provision.js'
import { runStatus, type StatusClient } from './commands/status.js'
import { PotError } from './errors.js'
import type { KeyStore } from './keystore/types.js'
import type { SpendingPolicy } from './policy/policy.js'
import type { SparkSigner } from './spark/signer.js'
import { type SignCommandOptions, type SignVault, type SpendClient } from './sign-flow.js'
import { loadPinnedTrust, type PinnedTrust } from './trust.js'
import type { NonceStore } from './intent.js'
import type { VaultStore } from './vault/vault.js'

const RECOVERY_ENV = 'ZAPPI_SIGNER_RECOVERY'
const POT_ID_ENV = 'ZAPPI_POT_ID'
const MAX_STDIN_BYTES = 1_048_576

type CommandName = 'status' | 'policy' | 'provision' | 'prove-address' | 'backup' | 'restore'

export interface ParsedSignerCommand {
  json: boolean
  command: CommandName | 'sign'
  args: readonly string[]
  potId?: string
  label?: string
}

/** Sign dependencies plus the fakes the other commands accept in tests. */
export interface CliInjected extends Partial<Omit<SignCommandOptions, 'requestId' | 'yes' | 'vault' | 'client'>> {
  vault?: SignVault | PolicyCommandVault | BackupCommandVault | RestoreCommandVault | ProvisionVault
  client?: SpendClient | StatusClient | ProvisionClient
  spark?: SparkSigner
  readStdin?: () => Promise<string>
  /** Test seam. Production reads `ZAPPI_SIGNER_RECOVERY` or prompts on a TTY. */
  recoveryMaterial?: RecoveryMaterial
  promptRecovery?: () => Promise<string>
}

interface ProvisionVault {
  create: VaultStore['create']
  snapshot: VaultStore['snapshot']
  markBound: VaultStore['markBound']
}

type CommandVault = PolicyCommandVault | BackupCommandVault | RestoreCommandVault | ProvisionVault

interface BackendRequest {
  request(method: 'GET' | 'POST', path: string, potId: string | null, body?: unknown): Promise<unknown>
}

export async function runCliCommand(parsed: ParsedSignerCommand, injected: CliInjected): Promise<void> {
  switch (parsed.command) {
    case 'status':
      await emitStatus(parsed, injected)
      return
    case 'policy':
      await emitPolicy(parsed, injected)
      return
    case 'provision':
      await emitProvision(parsed, injected)
      return
    case 'prove-address':
      await emitProveAddress(parsed, injected)
      return
    case 'backup':
      await emitBackup(parsed, injected)
      return
    case 'restore':
      await emitRestore(parsed, injected)
      return
    default:
      throw new PotError('request failed')
  }
}

async function emitStatus(parsed: ParsedSignerCommand, injected: CliInjected): Promise<void> {
  const view = await runStatus({
    client: statusClient(injected, envOf(injected)),
    requestId: parsed.args[0] ?? '',
  })
  writeStdout(parsed.json ? JSON.stringify(view) : view.status)
}

async function emitPolicy(parsed: ParsedSignerCommand, injected: CliInjected): Promise<void> {
  const potId = requirePot(parsed)
  const tighten = parsed.args[0] === 'tighten'
  const nextPolicy = tighten ? await policyFromStdin(injected) : undefined
  const vault = asPolicyVault(await resolveVault(injected), tighten)
  const view = tighten
    ? await runPolicyTighten({
        vault,
        keystore: await openKeyStore(injected),
        potId,
        nextPolicy: policyValue(nextPolicy),
      })
    : await runPolicyView({ vault, potId })
  writeStdout(parsed.json ? JSON.stringify(view) : policyLine(view))
}

async function emitProvision(parsed: ParsedSignerCommand, injected: CliInjected): Promise<void> {
  const env = envOf(injected)
  const vault = asProvisionVault(await resolveVault(injected))
  const result = await runProvision({
    vault,
    spark: await sparkOf(injected),
    client: provisionClient(injected, env),
    trust: trustOf(injected, env),
    ledger: await ledgerOf(injected),
    ...(parsed.label !== undefined ? { potLabel: parsed.label } : {}),
  })
  writeStdout(parsed.json ? JSON.stringify(result) : `${result.potId} ${result.address}`)
}

async function emitProveAddress(parsed: ParsedSignerCommand, injected: CliInjected): Promise<void> {
  const potId = requirePot(parsed)
  const vault = asProveVault(await resolveVault(injected))
  const bindingReceipt = parseStdinJson(await readStdinText(injected), 'binding receipt is malformed')
  const result = await runProveAddress({
    vault,
    trust: trustOf(injected, envOf(injected)),
    bindingReceipt,
    potId,
  })
  writeStdout(parsed.json ? JSON.stringify(result) : `${result.potId} bound`)
}

async function emitBackup(parsed: ParsedSignerCommand, injected: CliInjected): Promise<void> {
  const potId = requirePot(parsed)
  const recoveryMaterial = await recoveryFrom(injected)
  const envelope = await runBackup({
    vault: asBackupVault(await resolveVault(injected)),
    potId,
    recoveryMaterial,
  })
  writeStdout(JSON.stringify(envelope))
}

async function emitRestore(parsed: ParsedSignerCommand, injected: CliInjected): Promise<void> {
  // runRestore creates the pot and returns its id. --pot is the argv shape and is not forwarded.
  requirePot(parsed)
  const recoveryMaterial = await recoveryFrom(injected)
  const backup = (await readStdinText(injected)).trim()
  const restored = await runRestore({
    vault: asRestoreVault(await resolveVault(injected)),
    keystore: await openKeyStore(injected),
    backup,
    recoveryMaterial,
  })
  writeStdout(parsed.json ? JSON.stringify(restored) : restored.potId)
}

function requirePot(parsed: ParsedSignerCommand): string {
  const potId = parsed.potId?.trim() ?? ''
  if (potId === '') throw new PotError('no pot')
  return potId
}

function envOf(injected: CliInjected): NodeJS.ProcessEnv {
  return injected.env ?? process.env
}

async function recoveryFrom(injected: CliInjected): Promise<RecoveryMaterial> {
  if (injected.recoveryMaterial !== undefined) return injected.recoveryMaterial
  const fromEnv = envOf(injected)[RECOVERY_ENV]
  if (typeof fromEnv === 'string' && fromEnv.length > 0) return fromEnv
  const tty = injected.stdinIsTty ?? Boolean(process.stdin.isTTY)
  if (!tty) throw new PotError('vault locked')
  if (injected.promptRecovery) return injected.promptRecovery()
  if (!process.stdin.isTTY) throw new PotError('vault locked')
  return readHiddenLine('Recovery passphrase: ')
}

async function policyFromStdin(injected: CliInjected): Promise<SpendingPolicy> {
  return policyValue(parseStdinJson(await readStdinText(injected), 'policy refused'))
}

function policyValue(value: unknown): SpendingPolicy {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new PotError('policy refused')
  return value as SpendingPolicy
}

function parseStdinJson(text: string, message: string): unknown {
  const trimmed = text.trim()
  if (trimmed === '') throw new PotError(message)
  try {
    return JSON.parse(trimmed) as unknown
  } catch {
    throw new PotError(message)
  }
}

async function readStdinText(injected: CliInjected): Promise<string> {
  const text = injected.readStdin ? await injected.readStdin() : await readProcessStdin()
  if (Buffer.byteLength(text) > MAX_STDIN_BYTES) throw new PotError('request failed')
  return text
}

async function readProcessStdin(): Promise<string> {
  const chunks: Buffer[] = []
  let total = 0
  for await (const chunk of process.stdin) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    total += buf.length
    if (total > MAX_STDIN_BYTES) throw new PotError('request failed')
    chunks.push(buf)
  }
  return Buffer.concat(chunks).toString('utf8')
}

function readHiddenLine(prompt: string): Promise<string> {
  const stdin = process.stdin
  if (!stdin.isTTY || typeof stdin.setRawMode !== 'function') return Promise.reject(new PotError('vault locked'))
  return new Promise((resolve, reject) => {
    const previous = stdin.isRaw
    let value = ''
    let settled = false
    const finish = (fn: () => void) => {
      if (settled) return
      settled = true
      stdin.off('data', onData)
      stdin.setRawMode(previous === true)
      stdin.pause()
      fn()
    }
    const onData = (chunk: Buffer | string) => {
      const text = typeof chunk === 'string' ? chunk : chunk.toString('utf8')
      for (const char of text) {
        if (char === '\u0003') {
          finish(() => {
            process.stderr.write('\n')
            reject(new PotError('vault locked'))
          })
          return
        }
        if (char === '\n' || char === '\r') {
          finish(() => {
            process.stderr.write('\n')
            if (value.length === 0) reject(new PotError('vault locked'))
            else resolve(value)
          })
          return
        }
        if (char === '\u007f' || char === '\b') {
          value = value.slice(0, -1)
          continue
        }
        const code = char.charCodeAt(0)
        if (code < 0x20) continue
        value += char
      }
    }
    process.stderr.write(prompt)
    stdin.setRawMode(true)
    stdin.resume()
    stdin.on('data', onData)
  })
}

function statusClient(injected: CliInjected, env: NodeJS.ProcessEnv): StatusClient {
  if (isHttpClient(injected.client)) return injected.client
  return {
    async request(method, path, body) {
      const potId = (injected.potId ?? env[POT_ID_ENV] ?? '').trim()
      if (potId === '') throw new PotError('spend status is unavailable')
      return backendRequest(await openBackend(injected, env), method, path, potId, body)
    },
  }
}

function provisionClient(injected: CliInjected, env: NodeJS.ProcessEnv): ProvisionClient {
  if (isHttpClient(injected.client)) return injected.client
  return {
    async request(method, path, body) {
      return backendRequest(await openBackend(injected, env), method, path, null, body)
    },
  }
}

function isHttpClient(client: CliInjected['client']): client is StatusClient & ProvisionClient {
  return typeof client === 'object' && client !== null && typeof (client as StatusClient).request === 'function'
}

function isSignVault(vault: CliInjected['vault']): vault is SignVault {
  return typeof vault === 'object' && vault !== null && typeof (vault as SignVault).read === 'function' && !hasCommandVaultMethod(vault)
}

function hasCommandVaultMethod(vault: object): boolean {
  const candidate = vault as { snapshot?: unknown; create?: unknown; markBound?: unknown }
  return (
    typeof candidate.snapshot === 'function' ||
    typeof candidate.create === 'function' ||
    typeof candidate.markBound === 'function'
  )
}

async function resolveVault(injected: CliInjected): Promise<CommandVault> {
  const vault = injected.vault
  if (vault && !isSignVault(vault)) return vault
  const { VaultStore } = await import('./vault/vault.js')
  const { defaultVaultPath } = await import('./paths.js')
  return new VaultStore({
    vaultPath: injected.vaultPath ?? defaultVaultPath(envOf(injected)),
    keystore: await openKeyStore(injected),
  })
}

async function openKeyStore(injected: CliInjected): Promise<KeyStore> {
  if (injected.keystore) return injected.keystore
  const { createOsKeyStore } = await import('./keystore/os.js')
  return createOsKeyStore()
}

async function openBackend(injected: CliInjected, env: NodeJS.ProcessEnv): Promise<SignerBackendClient> {
  return new SignerBackendClient({
    keystore: await openKeyStore(injected),
    fetch: injected.fetchImpl,
    baseUrl: injected.baseUrl,
    env,
    ...(injected.timeoutMs !== undefined ? { timeoutMs: injected.timeoutMs } : {}),
  })
}

function backendRequest(
  client: SignerBackendClient,
  method: 'GET' | 'POST',
  path: string,
  potId: string | null,
  body?: unknown,
): Promise<unknown> {
  return (client as unknown as BackendRequest).request(method, path, potId, body)
}

async function sparkOf(injected: CliInjected): Promise<SparkSigner> {
  if (injected.spark) return injected.spark
  const { createSdkSparkSigner } = await import('./spark/sdk.js')
  return createSdkSparkSigner()
}

function trustOf(injected: CliInjected, env: NodeJS.ProcessEnv): PinnedTrust {
  if (injected.pinnedTrust) return injected.pinnedTrust
  return loadPinnedTrust({
    env,
    ...(injected.trustConfigPath !== undefined ? { configPath: injected.trustConfigPath } : {}),
  })
}

async function ledgerOf(injected: CliInjected): Promise<NonceStore> {
  if (injected.ledger) return injected.ledger
  const { NonceLedger, defaultNonceLedgerPath } = await import('./intent-store.js')
  return new NonceLedger(defaultNonceLedgerPath(envOf(injected)))
}

function asPolicyVault(vault: CommandVault, tighten: boolean): PolicyCommandVault {
  if (!hasMethod(vault, 'snapshot')) throw new PotError('no pot')
  if (tighten && !hasMethod(vault, 'replacePolicy')) throw new PotError('no pot')
  return vault as PolicyCommandVault
}

function asBackupVault(vault: CommandVault): BackupCommandVault {
  if (!hasMethod(vault, 'snapshot') || !hasMethod(vault, 'withMnemonic')) throw new PotError('no pot')
  return vault as BackupCommandVault
}

function asRestoreVault(vault: CommandVault): RestoreCommandVault {
  if (
    !hasMethod(vault, 'create') ||
    !hasMethod(vault, 'replacePolicy') ||
    !hasMethod(vault, 'setFreeze') ||
    !hasMethod(vault, 'confirm') ||
    !hasMethod(vault, 'removePot')
  ) {
    throw new PotError('no pot')
  }
  return vault as RestoreCommandVault
}

function asProvisionVault(vault: CommandVault): VaultStore {
  if (!hasMethod(vault, 'create') || !hasMethod(vault, 'snapshot') || !hasMethod(vault, 'markBound')) {
    throw new PotError('no pot')
  }
  return vault as VaultStore
}

function asProveVault(vault: CommandVault): VaultStore {
  if (!hasMethod(vault, 'snapshot') || !hasMethod(vault, 'markBound')) throw new PotError('no pot')
  return vault as VaultStore
}

function hasMethod(vault: object, name: string): boolean {
  return typeof (vault as Record<string, unknown>)[name] === 'function'
}

function policyLine(view: PolicyView): string {
  return `${view.potId} ${view.role} ${view.freeze}`
}

function writeStdout(line: string): void {
  process.stdout.write(`${line}\n`)
}
