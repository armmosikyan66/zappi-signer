import { PotError } from '../errors.js'
import { redact } from '../log.js'
import type { SparkNetworkName } from '../vault/vault.js'
import type { SparkSigner } from './signer.js'

interface SdkWallet {
  getSparkAddress(): Promise<string>
  getIdentityPublicKey(): Promise<string>
  signMessageWithIdentityKey(message: string, compact?: boolean): Promise<string>
  getBalance(): Promise<unknown>
  transfer(input: { receiverSparkAddress: string; amountSats: number }): Promise<unknown>
  cleanup?: () => Promise<void>
  cleanupConnections?: () => Promise<void>
}

interface SdkModule {
  SparkWallet: {
    initialize(props: {
      mnemonicOrSeed: string
      accountNumber: number
      options: {
        network: SparkNetworkName
        optimizationOptions: { auto: boolean; multiplicity: number }
        tokenOptimizationOptions: { enabled: boolean }
      }
    }): Promise<{ wallet: SdkWallet; mnemonic?: string }>
  }
}

type ConsoleMethod = (...args: unknown[]) => void

/**
 * Adapter over @buildonspark/spark-sdk, checked against
 * https://docs.spark.money/api-reference/wallet/transfer and getBalance.
 * initialize starts background work; cleanup() always runs.
 * SDK console output is diverted to stderr and redacted so it cannot
 * corrupt the MCP stdout channel or echo a phrase.
 */
export function createSdkSparkSigner(): SparkSigner {
  return {
    derive: (mnemonic, network) =>
      withWallet(mnemonic, network, async (wallet) => ({
        address: await wallet.getSparkAddress(),
        pubkey: await wallet.getIdentityPublicKey(),
      })),
    signNonce: (mnemonic, network, nonce) =>
      withWallet(mnemonic, network, async (wallet) => ({
        signature: await wallet.signMessageWithIdentityKey(nonce, true),
        pubkey: await wallet.getIdentityPublicKey(),
        address: await wallet.getSparkAddress(),
      })),
    signRelay: (mnemonic, network, message) =>
      withWallet(mnemonic, network, async (wallet) => ({
        signature: await wallet.signMessageWithIdentityKey(message, true),
        pubkey: await wallet.getIdentityPublicKey(),
      })),
    balanceSats: (mnemonic, network) =>
      withWallet(mnemonic, network, async (wallet) => readBalanceSats(await wallet.getBalance())),
    transfer: (mnemonic, network, input) =>
      withWallet(mnemonic, network, async (wallet) => ({
        txid: readTransferId(await wallet.transfer({
          receiverSparkAddress: input.destination,
          amountSats: input.amountSats,
        })),
      })),
  }
}

async function withWallet<T>(
  mnemonic: Uint8Array,
  network: SparkNetworkName,
  fn: (wallet: SdkWallet) => Promise<T>,
): Promise<T> {
  const phrase = Buffer.from(mnemonic).toString('utf8')
  const phraseBytes = Buffer.from(phrase, 'utf8')
  try {
    return await muteSdkConsole(async () => {
      const { SparkWallet } = (await import('@buildonspark/spark-sdk')) as SdkModule
      const opened = await SparkWallet.initialize({
        mnemonicOrSeed: phrase,
        accountNumber: 1,
        options: {
          network,
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
  } catch (error) {
    if (error instanceof PotError) throw error
    throw new PotError('could not reach Spark')
  } finally {
    phraseBytes.fill(0)
  }
}

async function closeWallet(wallet: SdkWallet): Promise<void> {
  try {
    if (typeof wallet.cleanup === 'function') await wallet.cleanup()
    else if (typeof wallet.cleanupConnections === 'function') await wallet.cleanupConnections()
  } catch {
    // Closing the session must not replace a successful payment result.
  }
}

export function readBalanceSats(balance: unknown): number {
  const available = pickAvailable(balance)
  if (typeof available === 'bigint') {
    if (available < 0n || available > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new PotError('balance unavailable')
    }
    return Number(available)
  }
  if (typeof available === 'number' && Number.isSafeInteger(available) && available >= 0) {
    return available
  }
  if (typeof available === 'string' && /^\d+$/.test(available)) {
    const parsed = Number(available)
    if (Number.isSafeInteger(parsed)) return parsed
  }
  throw new PotError('balance unavailable')
}

function pickAvailable(balance: unknown): bigint | number | string | undefined {
  if (!balance || typeof balance !== 'object') return undefined
  const record = balance as Record<string, unknown>
  const sats = record.satsBalance
  if (sats && typeof sats === 'object') {
    const available = (sats as Record<string, unknown>).available
    if (typeof available === 'bigint' || typeof available === 'number' || typeof available === 'string') {
      return available
    }
  }
  const legacy = record.balance
  if (typeof legacy === 'bigint' || typeof legacy === 'number' || typeof legacy === 'string') return legacy
  return undefined
}

export function readTransferId(transfer: unknown): string {
  if (typeof transfer === 'string' && transfer.length > 0 && transfer.length <= 128) return transfer
  if (transfer && typeof transfer === 'object') {
    const id = (transfer as { id?: unknown }).id
    if (typeof id === 'string' && id.length > 0 && id.length <= 128) return id
  }
  throw new PotError('payment failed')
}

/* eslint-disable no-console -- Spark SDK writes to console; keep that off the MCP stdout channel. */
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
