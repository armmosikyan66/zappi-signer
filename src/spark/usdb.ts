import type { Bech32mTokenIdentifier } from '@buildonspark/spark-sdk'
import { bech32m } from '@scure/base'
import { PotError } from '../errors.js'
import { redact } from '../log.js'
import type { SparkNetworkName } from '../vault/vault.js'
import { readTransferId } from './sdk.js'

/**
 * USDB token transfer for the signer.
 *
 * Do not call `SparkSigner.transfer`. That method sends sats.
 * This module does not call it, and it does not call `wallet.transfer`.
 * A spend moves USDB: the server signs an intent that carries the recipient,
 * token identifier, and base-unit token amount (`amountCents × 10_000`, 6
 * decimals); this module verifies those parameters against the pot wallet and
 * broadcasts exactly what the server created. It never invents parameters.
 * Params are optional so legacy intents still broadcast with local selection.
 * The recipient address must decode as Spark MAINNET.
 */

export const USDB_MICRO_UNITS_PER_CENT = 10_000
/** USDB is 6 decimals, 1:1 with USD. 1 cent = 10_000 base units. */
export const USDB_DECIMALS = 6

/** Longest HRP first so `sparkrt` is not classified as `spark`. */
const SPARK_HRPS = ['sparkrt', 'sparkt', 'sparks', 'sparkl', 'spark', 'sprt', 'sp'] as const

type SparkDecodedNetwork = 'MAINNET' | 'REGTEST' | 'FOREIGN'

const MAINNET_HRPS = new Set(['spark', 'sp'])
const REGTEST_HRPS = new Set(['sparkrt', 'sprt', 'sparkl'])

export interface InspectedSparkAddress {
  valid: boolean
  network: SparkDecodedNetwork | null
}

export interface SendUsdbFromPotInput {
  mnemonic: string
  destination: string
  amountCents: number
  network: SparkNetworkName
  /** Spark account. Defaults to 1, the account `createSdkSparkSigner` opens. */
  accountNumber?: number
  /**
   * Server-created tx params. When present the signer verifies them against
   * the pot wallet and broadcasts exactly what the server signed; it never
   * invents parameters. When absent, the canonical USDB token is selected
   * locally (legacy intents issued before token params existed).
   */
  tokenIdentifier?: string
  tokenAmount?: number | string | bigint
}

export interface SendUsdbFromPotResult {
  txid: string
}

export interface UsdbBroadcastInput {
  mnemonic: Uint8Array
  accountIndex: number
  receiverSparkAddress: string
  amountCents: number
  /** Optional server-created tx params, verified like `sendUsdbFromPot`. */
  tokenIdentifier?: string
  tokenAmount?: number | string | bigint
}

export interface UsdbBroadcastResult {
  txid: string
  /** True only when the broadcaster actually observed confirmation. */
  confirmed?: boolean
}

interface UsdbWallet {
  getBalance(): Promise<unknown>
  transferTokens(input: {
    tokenIdentifier: Bech32mTokenIdentifier
    tokenAmount: bigint
    receiverSparkAddress: string
  }): Promise<unknown>
  cleanup?: () => Promise<void>
  cleanupConnections?: () => Promise<void>
}

interface UsdbSdkModule {
  SparkWallet: {
    initialize(props: {
      mnemonicOrSeed: string
      accountNumber: number
      options: {
        network: 'MAINNET'
        optimizationOptions: { auto: boolean; multiplicity: number }
        tokenOptimizationOptions: { enabled: boolean }
      }
    }): Promise<{ wallet: UsdbWallet; mnemonic?: string }>
  }
}

export function usdbBaseUnits(amountCents: number): bigint {
  if (!Number.isSafeInteger(amountCents) || amountCents <= 0) {
    throw new Error('Price must be greater than zero.')
  }
  return BigInt(amountCents) * BigInt(USDB_MICRO_UNITS_PER_CENT)
}

export function inspectSparkAddress(address: string): InspectedSparkAddress {
  const trimmed = address.trim()
  if (!looksLikeSparkAddress(trimmed)) return { valid: false, network: null }
  const decoded = bech32m.decodeUnsafe(trimmed.toLowerCase(), 128)
  if (!decoded) {
    const hrp = sparkHrp(trimmed)
    return { valid: false, network: hrp ? sparkNetworkFromHrp(hrp) : null }
  }
  const network = sparkNetworkFromHrp(decoded.prefix)
  const program = bech32m.fromWordsUnsafe(decoded.words)
  if (!network || !program || program.length < 16) return { valid: false, network }
  return { valid: true, network }
}

/** Normalize Spark tokenBalances (Map or record) to string entries. */
export function tokenBalanceEntries(tokenBalances: unknown): Array<[string, unknown]> {
  if (!tokenBalances || typeof tokenBalances !== 'object') return []
  if (tokenBalances instanceof Map) {
    return [...tokenBalances.entries()].map(([key, value]) => [String(key), value])
  }
  return Object.entries(tokenBalances as Record<string, unknown>)
}

/**
 * The one USDB token on MAINNET. Ticker must be USDB, decimals must be 6,
 * and the identifier must be `btkn1…`. The first `btkn` key is not enough.
 * Any other token id is refused.
 */
export function selectCanonicalUsdbToken(tokenBalances: unknown, network: 'MAINNET'): string {
  const matches: string[] = []
  for (const [tokenIdentifier, value] of tokenBalanceEntries(tokenBalances)) {
    const hrpNetwork = tokenHrpNetwork(tokenIdentifier)
    if (!hrpNetwork) continue
    const meta = tokenMetadata(value)
    const ticker = textField(meta, ['tokenTicker', 'ticker', 'symbol'])
    const name = textField(meta, ['tokenName', 'name'])
    const label = (ticker ?? name ?? '').toUpperCase()
    if (label !== 'USDB') continue
    const decimals = meta.decimals
    if (typeof decimals !== 'number' || decimals !== USDB_DECIMALS) {
      throw new Error(
        `USDB token ${tokenIdentifier} decimals are ${String(decimals)}; expected ${USDB_DECIMALS}. Refusing to sign.`,
      )
    }
    const metaNetwork = textField(meta, ['network'])?.toUpperCase()
    if (metaNetwork && metaNetwork !== network) {
      throw new Error(
        `USDB token ${tokenIdentifier} metadata network is ${metaNetwork} but the pot network is ${network}. Refusing to sign.`,
      )
    }
    if (hrpNetwork !== network) {
      throw new Error(
        `USDB token ${tokenIdentifier} is a ${hrpNetwork} identifier but the pot network is ${network}. Refusing to sign.`,
      )
    }
    matches.push(tokenIdentifier)
  }
  if (matches.length === 0) {
    throw new Error(
      'No canonical USDB token (ticker USDB, 6 decimals, matching network) in the pot balance. Refusing to sign.',
    )
  }
  if (matches.length > 1) throw new Error('More than one canonical USDB token. Refusing to sign.')
  const selected = matches[0]
  if (!selected) throw new Error('No canonical USDB token. Refusing to sign.')
  if (!selected.startsWith('btkn1')) {
    throw new Error(`USDB token ${selected} is not a canonical btkn1 identifier. Refusing to sign.`)
  }
  return selected
}

/**
 * Resolve the tx parameters for one USDB transfer. The server's signed intent
 * may carry `tokenIdentifier` and `tokenAmount`; both are verified here before
 * broadcast. `tokenAmount` must be exactly `amountCents × 10_000` so the
 * policy-checked cents stay the only source of truth. `tokenIdentifier` must
 * be the canonical USDB token held by the pot. Params are optional so intents
 * issued before token params existed still broadcast with local selection.
 */
function resolveTxParams(
  input: SendUsdbFromPotInput,
  canonical: string,
  expected: bigint,
): { tokenIdentifier: string; tokenAmount: bigint } {
  if (input.tokenIdentifier !== undefined && input.tokenIdentifier !== canonical) {
    throw new Error(
      `Server tx names token ${input.tokenIdentifier} but the pot holds ${canonical}. Refusing to sign.`,
    )
  }
  if (input.tokenAmount === undefined || input.tokenAmount === '') {
    return { tokenIdentifier: canonical, tokenAmount: expected }
  }
  let provided: bigint
  try {
    provided = typeof input.tokenAmount === 'bigint' ? input.tokenAmount : BigInt(input.tokenAmount)
  } catch {
    throw new Error('Server tokenAmount is not an integer. Refusing to sign.')
  }
  if (provided !== expected) {
    throw new Error(
      `Server tokenAmount ${provided} does not match amountCents ${input.amountCents} × ${USDB_MICRO_UNITS_PER_CENT}. Refusing to sign.`,
    )
  }
  return { tokenIdentifier: canonical, tokenAmount: expected }
}

export async function sendUsdbFromPot(input: SendUsdbFromPotInput): Promise<SendUsdbFromPotResult> {
  // Validate cents before any wallet is opened so bad input never initializes.
  const amountBase = usdbBaseUnits(input.amountCents)
  const destination = mainnetDestination(input.destination)
  if (input.network !== 'MAINNET') throw new Error('Network must be MAINNET. Refusing to sign.')
  const accountNumber = input.accountNumber ?? 1
  let transferStarted = false
  try {
    return await withUsdbWallet(input.mnemonic, accountNumber, async (wallet) => {
      // The canonical token is still resolved from the live balance so the
      // server-named token can be verified, not trusted blindly.
      const canonical = selectCanonicalUsdbToken(tokenBalancesOf(await wallet.getBalance()), 'MAINNET')
      const { tokenIdentifier, tokenAmount } = resolveTxParams(input, canonical, amountBase)
      transferStarted = true
      const raw = await wallet.transferTokens({
        tokenIdentifier: tokenIdentifier as Bech32mTokenIdentifier,
        tokenAmount,
        receiverSparkAddress: destination,
      })
      return { txid: readTransferId(raw) }
    })
  } catch (error) {
    if (!transferStarted) throw error
    if (error instanceof PotError && error.code === 'BROADCAST_UNCERTAIN') throw error
    throw new PotError('refused to spend', 'BROADCAST_UNCERTAIN')
  }
}

export async function readUsdbTokenIdentifier(
  mnemonic: string,
  accountNumber: number,
  network: 'MAINNET',
): Promise<string> {
  if (network !== 'MAINNET') throw new Error('Network must be MAINNET. Refusing to sign.')
  return withUsdbWallet(mnemonic, accountNumber, async (wallet) =>
    selectCanonicalUsdbToken(tokenBalancesOf(await wallet.getBalance()), 'MAINNET'),
  )
}

/**
 * Broadcast one USDB transfer. The mnemonic buffer passed in is not retained.
 * `SparkSigner.transfer` sends sats; this function does not use it.
 * A failure after the token transfer is attempted is `BROADCAST_UNCERTAIN`
 * so the caller journals it and does not broadcast again.
 */
export async function broadcastUsdbFromMnemonic(input: UsdbBroadcastInput): Promise<UsdbBroadcastResult> {
  const inspected = inspectSparkAddress(input.receiverSparkAddress)
  if (!inspected.valid || inspected.network !== 'MAINNET') throw new PotError('refused to spend')
  const phraseBytes = Buffer.from(input.mnemonic)
  const phrase = phraseBytes.toString('utf8')
  try {
    const sent = await sendUsdbFromPot({
      mnemonic: phrase,
      destination: input.receiverSparkAddress.trim(),
      amountCents: input.amountCents,
      network: 'MAINNET',
      accountNumber: input.accountIndex,
      ...(input.tokenIdentifier !== undefined ? { tokenIdentifier: input.tokenIdentifier } : {}),
      ...(input.tokenAmount !== undefined ? { tokenAmount: input.tokenAmount } : {}),
    })
    return { txid: sent.txid }
  } catch (error) {
    if (error instanceof PotError && error.code === 'BROADCAST_UNCERTAIN') throw error
    throw new PotError('refused to spend')
  } finally {
    phraseBytes.fill(0)
  }
}

function mainnetDestination(destination: string): string {
  if (typeof destination !== 'string' || destination.trim() === '') {
    throw new Error('Destination is empty. Refusing to sign.')
  }
  const trimmed = destination.trim()
  const inspected = inspectSparkAddress(trimmed)
  if (!inspected.valid || inspected.network !== 'MAINNET') {
    throw new Error('Recipient network must be MAINNET. Refusing to sign.')
  }
  return trimmed
}

function tokenBalancesOf(balance: unknown): unknown {
  if (!balance || typeof balance !== 'object') return undefined
  return (balance as { tokenBalances?: unknown }).tokenBalances
}

/**
 * Same `SparkWallet.initialize` options as `createSdkSparkSigner` in sdk.ts.
 * `SparkSigner.transfer` is not used; USDB leaves through `transferTokens`.
 */
async function withUsdbWallet<T>(
  mnemonic: string,
  accountNumber: number,
  fn: (wallet: UsdbWallet) => Promise<T>,
): Promise<T> {
  const phraseBytes = Buffer.from(mnemonic, 'utf8')
  const phrase = phraseBytes.toString('utf8')
  try {
    return await muteSdkConsole(async () => {
      const { SparkWallet } = (await import('@buildonspark/spark-sdk')) as UsdbSdkModule
      const opened = await SparkWallet.initialize({
        mnemonicOrSeed: phrase,
        accountNumber,
        options: {
          network: 'MAINNET',
          optimizationOptions: { auto: false, multiplicity: 0 },
          tokenOptimizationOptions: { enabled: false },
        },
      })
      try {
        return await fn(opened.wallet)
      } finally {
        await closeWallet(opened.wallet)
      }
    })
  } finally {
    phraseBytes.fill(0)
  }
}

async function closeWallet(wallet: UsdbWallet): Promise<void> {
  try {
    if (typeof wallet.cleanup === 'function') await wallet.cleanup()
    else if (typeof wallet.cleanupConnections === 'function') await wallet.cleanupConnections()
  } catch {
    // Closing the session must not replace a successful payment result.
  }
}

function looksLikeSparkAddress(address: string): boolean {
  const lower = address.trim().toLowerCase()
  return SPARK_HRPS.some((hrp) => lower.startsWith(`${hrp}1`))
}

function sparkHrp(address: string): string | null {
  const lower = address.trim().toLowerCase()
  return SPARK_HRPS.find((hrp) => lower.startsWith(`${hrp}1`)) ?? null
}

function sparkNetworkFromHrp(hrp: string): SparkDecodedNetwork | null {
  if (MAINNET_HRPS.has(hrp)) return 'MAINNET'
  if (REGTEST_HRPS.has(hrp)) return 'REGTEST'
  if (hrp === 'sparkt' || hrp === 'sparks') return 'FOREIGN'
  return null
}

function tokenHrpNetwork(tokenIdentifier: string): 'MAINNET' | null {
  if (tokenIdentifier.startsWith('btkn1')) return 'MAINNET'
  return null
}

function tokenMetadata(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object') return {}
  const record = value as Record<string, unknown>
  const nested = record.tokenMetadata ?? record.tokenInfo ?? record.metadata
  if (nested && typeof nested === 'object' && !Array.isArray(nested)) {
    return nested as Record<string, unknown>
  }
  return record
}

function textField(meta: Record<string, unknown>, keys: string[]): string | undefined {
  for (const key of keys) {
    const value = meta[key]
    if (typeof value === 'string' && value.trim()) return value.trim()
  }
  return undefined
}

type ConsoleMethod = (...args: unknown[]) => void

/* eslint-disable no-console -- Spark SDK writes to console; keep phrases off stdout. */
async function muteSdkConsole<T>(fn: () => Promise<T>): Promise<T> {
  const methods = ['log', 'info', 'debug', 'warn', 'error'] as const
  const original = new Map<string, ConsoleMethod>()
  const stdoutWrite = process.stdout.write.bind(process.stdout)
  const sink: ConsoleMethod = (...args) => {
    const text = args.map((part) => (typeof part === 'string' ? part : '')).join(' ')
    if (text) process.stderr.write(`${redact(text)}\n`)
  }
  for (const method of methods) {
    original.set(method, console[method] as ConsoleMethod)
    console[method] = sink as (typeof console)['log']
  }
  process.stdout.write = ((chunk: string | Uint8Array) => {
    const text = typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8')
    if (text) process.stderr.write(redact(text))
    return true
  }) as typeof process.stdout.write
  try {
    return await fn()
  } finally {
    for (const method of methods) {
      const restored = original.get(method)
      if (restored) console[method] = restored as (typeof console)['log']
    }
    process.stdout.write = stdoutWrite
  }
}
/* eslint-enable no-console */
