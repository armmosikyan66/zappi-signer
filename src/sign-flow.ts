/**
 * `zappi sign <requestId>`.
 *
 * Restart recovery reads the spend journal, not the nonce ledger.
 * After the intent signature verifies:
 * - a journaled txid is never broadcast again; the receipt is posted again
 *   as `submitted` with that txid, then `markReceipted`;
 * - a spent nonce with no journaled txid is not broadcast; the receipt is
 *   `uncertain` and no txid is invented;
 * - otherwise the mnemonic is opened with `withMnemonic`, USDB is broadcast,
 *   `journal.put` records the txid, then the receipt is posted.
 *   `confirmed` is posted only when this broadcast observed confirmation.
 *   The normal receipt is `submitted`.
 * If the broadcast throws after a txid was journaled, a later `sign` posts
 * that txid and does not broadcast again.
 */
import { createInterface } from 'node:readline/promises'
import {
  SignerBackendClient,
  potSignerAuthMessage,
  type ClientSpendRequestResponse,
  type SignerAuthProvider,
  type SpendAuthorizationBody,
  type SpendAuthorizationResponse,
  type SpendReceiptBody,
  type SpendReceiptResponse,
  type SignerTrustResponse,
} from './client.js'
import { PotError } from './errors.js'
import type { FreezeState } from './guards.js'
import {
  verifyIntent,
  verifyLockAttestation,
  type IntentPayload,
  type NonceStore,
  type SparkTransferPayload,
  type SpendIntent,
} from './intent.js'
import { NonceLedger, defaultNonceLedgerPath } from './intent-store.js'
import type { KeyStore } from './keystore/types.js'
import { assertSealedPolicy } from './policy/enforce.js'
import type { PotRole, SpendingPolicy } from './policy/policy.js'
import type { SparkSigner } from './spark/signer.js'
import { FileSpendJournal, defaultSpendJournalPath, type SpendJournal } from './spend-journal.js'
import { sendUsdbFromPot, type SendUsdbFromPotInput, type SendUsdbFromPotResult } from './spark/usdb.js'
import { loadPinnedTrust, verifyPinnedTrust, type PinnedTrust } from './trust.js'
import type { MnemonicContext, SparkNetworkName } from './vault/vault.js'

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const TXID_RE = /^[0-9a-f]{64}$/
const POT_ID_ENV = 'ZAPPI_POT_ID'

export interface SpendClient {
  getSignerTrust(): Promise<SignerTrustResponse>
  getClientSpendRequest(potId: string, requestId: string): Promise<ClientSpendRequestResponse>
  createSpendAuthorization(potId: string, body: SpendAuthorizationBody): Promise<SpendAuthorizationResponse>
  postSpendReceipt(potId: string, body: SpendReceiptBody): Promise<SpendReceiptResponse>
}

export interface SignPot {
  potId: string
  policy: SpendingPolicy | null
  role: PotRole
  freeze: FreezeState
  network: SparkNetworkName
  accountIndex: number
}

export interface SignVault {
  read(potId: string): Promise<SignPot | null>
  withMnemonic<T>(potId: string, fn: (ctx: MnemonicContext) => Promise<T>): Promise<T>
}

/** `sendUsdbFromPot` is the default. `confirmed` is set only when this call observed it. */
export type UsdbBroadcastResult = SendUsdbFromPotResult & { confirmed?: boolean }

export type UsdbBroadcaster = (input: SendUsdbFromPotInput) => Promise<UsdbBroadcastResult>

export interface SignCommandOptions {
  requestId: string
  yes: boolean
  env?: NodeJS.ProcessEnv
  baseUrl?: string
  potId?: string
  stdinIsTty?: boolean
  confirm?: (view: ClientSpendRequestResponse) => boolean | Promise<boolean>
  fetchImpl?: typeof fetch
  keystore?: KeyStore
  client?: SpendClient
  vault?: SignVault
  /** Identity-key signer used by the signer-auth fallback. Production builds createSdkSparkSigner. */
  spark?: SparkSigner
  clock?: () => Date
  ledger?: NonceStore
  journal?: SpendJournal
  broadcaster?: UsdbBroadcaster
  pinnedTrust?: PinnedTrust
  trustConfigPath?: string
  vaultPath?: string
  timeoutMs?: number
}

export interface SignOutcome {
  requestId: string
  potId: string
  status: string
  intentId?: string
  txid?: string
}

export async function signCommand(options: SignCommandOptions): Promise<SignOutcome> {
  const requestId = options.requestId.trim().toLowerCase()
  const tty = options.stdinIsTty ?? Boolean(process.stdin.isTTY)
  if (!options.yes && !tty) throw new PotError('refused to spend')
  if (!UUID_RE.test(requestId)) throw new PotError('refused to spend')
  const env = options.env ?? process.env
  const potId = (options.potId ?? env[POT_ID_ENV] ?? '').trim().toLowerCase()
  if (!UUID_RE.test(potId)) throw new PotError('refused to spend')

  const client = options.client ?? (await openClient(options, env))
  const pinned =
    options.pinnedTrust ??
    loadPinnedTrust({
      env,
      ...(options.trustConfigPath !== undefined ? { configPath: options.trustConfigPath } : {}),
    })
  const trust = verifyPinnedTrust(pinned, await client.getSignerTrust())
  const view = await client.getClientSpendRequest(potId, requestId)
  if (view.requestId.trim().toLowerCase() !== requestId) throw new PotError('refused to spend')
  if (view.potId.trim().toLowerCase() !== potId) throw new PotError('refused to spend')
  if (view.status !== 'authorization_required') throw new PotError('refused to spend')
  if (!options.yes) {
    const accepted = await (options.confirm ?? confirmOnTty)(view)
    if (!accepted) throw new PotError('refused to spend')
  }

  const now = options.clock ? options.clock() : new Date()
  if (Number.isNaN(now.getTime())) throw new PotError('refused to spend')
  const vault = options.vault ?? (await openVault(options, env))
  const ledger = options.ledger ?? new NonceLedger(defaultNonceLedgerPath(env))
  const journal = options.journal ?? new FileSpendJournal(defaultSpendJournalPath(env))
  const pot = await vault.read(potId)
  const authorization = await client.createSpendAuthorization(potId, {
    approvalId: view.approvalId,
    idempotencyKey: requestId,
  })
  verifyLockAttestation({ lock: authorization.lock, trust, now, ledger })
  const verified = verifyIntent({
    intent: authorization.intent,
    trust,
    now,
    ledger,
    policy(intent) {
      if (journal.get(intent.intentId)) return
      enforceIntent(intent, view, pot, potId, now)
    },
  })

  const intentId = verified.intent.intentId
  const existing = journal.get(intentId)
  if (existing) return finishSubmitted(client, journal, potId, requestId, intentId, existing.txid)
  if (verified.replay) return finishUncertain(client, potId, requestId, intentId)

  const broadcast: UsdbBroadcaster = options.broadcaster ?? sendUsdbFromPot
  const spend = sparkSpend(verified.intent)
  let sent: { txid: string; confirmed: boolean }
  try {
    sent = await vault.withMnemonic(potId, async (ctx) => {
      const phraseBytes = Buffer.from(ctx.mnemonic)
      const phrase = phraseBytes.toString('utf8')
      try {
        const result = await broadcast({
          mnemonic: phrase,
          destination: spend.destination,
          amountCents: spend.amountCents,
          network: ctx.network,
          accountNumber: ctx.accountIndex,
          ...(spend.tokenIdentifier !== undefined ? { tokenIdentifier: spend.tokenIdentifier } : {}),
          ...(spend.tokenAmount !== undefined ? { tokenAmount: spend.tokenAmount } : {}),
        })
        const txid = canonicalTxid(result.txid)
        journal.put(intentId, txid)
        return { txid, confirmed: result.confirmed === true }
      } finally {
        phraseBytes.fill(0)
      }
    })
  } catch (error) {
    const saved = journal.get(intentId)
    if (saved) return finishSubmitted(client, journal, potId, requestId, intentId, saved.txid)
    if (isUncertain(error)) return finishUncertain(client, potId, requestId, intentId)
    throw error instanceof PotError ? error : new PotError('refused to spend')
  }

  const status = sent.confirmed ? 'confirmed' : 'submitted'
  await client.postSpendReceipt(potId, { intentId, txid: sent.txid, status })
  journal.markReceipted(intentId)
  return { requestId, potId, intentId, txid: sent.txid, status }
}

function enforceIntent(
  intent: SpendIntent,
  view: ClientSpendRequestResponse,
  pot: SignPot | null,
  potId: string,
  now: Date,
): void {
  const spend = sparkSpend(intent)
  if (intent.potId.trim().toLowerCase() !== potId) throw new PotError('refused to spend')
  if (spend.amountCents !== view.amountCents) throw new PotError('refused to spend')
  if (spend.destination !== view.receiverSparkAddress) throw new PotError('refused to spend')
  if (!pot || pot.potId.trim().toLowerCase() !== potId) {
    throw new PotError('no sealed policy', 'POLICY_REQUIRED')
  }
  assertSealedPolicy({
    policy: pot.policy,
    role: pot.role,
    freeze: pot.freeze,
    network: pot.network,
    amountCents: spend.amountCents,
    receiver: spend.destination,
    now,
  })
}

/** USDB signs only a spark transfer that carries a destination and cents. */
function sparkSpend(intent: SpendIntent): {
  destination: string
  amountCents: number
  tokenIdentifier?: string
  tokenAmount?: number
} {
  if (intent.kind !== 'spark_transfer') throw new PotError('refused to spend')
  const payload = intent.payload
  if (!isSparkTransferPayload(payload)) throw new PotError('refused to spend')
  if (payload.amountCents === undefined) throw new PotError('amount cents required', 'POLICY_AMOUNT')
  return {
    destination: payload.to,
    amountCents: payload.amountCents,
    ...(payload.tokenIdentifier !== undefined ? { tokenIdentifier: payload.tokenIdentifier } : {}),
    ...(payload.tokenAmount !== undefined ? { tokenAmount: payload.tokenAmount } : {}),
  }
}

function isSparkTransferPayload(payload: IntentPayload): payload is SparkTransferPayload {
  return 'to' in payload && typeof payload.to === 'string' && payload.to.length > 0
}

function canonicalTxid(value: string): string {
  if (typeof value !== 'string') throw new PotError('refused to spend', 'SPEND_JOURNAL')
  const txid = value.trim().toLowerCase().replace(/^0x/, '')
  if (!TXID_RE.test(txid)) throw new PotError('refused to spend', 'SPEND_JOURNAL')
  return txid
}

async function finishSubmitted(
  client: SpendClient,
  journal: SpendJournal,
  potId: string,
  requestId: string,
  intentId: string,
  txid: string,
): Promise<SignOutcome> {
  await client.postSpendReceipt(potId, { intentId, txid, status: 'submitted' })
  journal.markReceipted(intentId)
  return { requestId, potId, intentId, txid, status: 'submitted' }
}

async function finishUncertain(
  client: SpendClient,
  potId: string,
  requestId: string,
  intentId: string,
): Promise<SignOutcome> {
  await client.postSpendReceipt(potId, { intentId, status: 'uncertain' })
  return { requestId, potId, intentId, status: 'uncertain' }
}

function isUncertain(error: unknown): boolean {
  return error instanceof PotError && error.code === 'BROADCAST_UNCERTAIN'
}

async function confirmOnTty(view: ClientSpendRequestResponse): Promise<boolean> {
  const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: true })
  try {
    const answer = await rl.question(
      `Send ${view.amountCents} cents to ${view.receiverSparkAddress} on ${view.network}? [y/N] `,
    )
    const normalized = answer.trim().toLowerCase()
    return normalized === 'y' || normalized === 'yes'
  } finally {
    rl.close()
  }
}

async function openKeyStore(): Promise<KeyStore> {
  const { createOsKeyStore } = await import('./keystore/os.js')
  return createOsKeyStore()
}

async function openClient(options: SignCommandOptions, env: NodeJS.ProcessEnv): Promise<SpendClient> {
  const keystore = options.keystore ?? (await openKeyStore())
  return new SignerBackendClient({
    keystore,
    fetch: options.fetchImpl,
    baseUrl: options.baseUrl,
    env,
    ...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
    signerAuth: signerAuthProvider(options, env, keystore),
  })
}

interface SignerAuthVaultStore {
  snapshot(potId?: string): Promise<{
    potId: string
    address: string
    pubkey: string
    network: SparkNetworkName
  } | null>
  withMnemonic<T>(potId: string | undefined, fn: (ctx: MnemonicContext) => Promise<T>): Promise<T>
}

/**
 * Signer-auth fallback: sign each API call with the pot's Spark identity key.
 * Used only when the keychain has no pot client token for the pot — the MCP
 * wallet-first free-pot flow never runs an attach ceremony, so those pots
 * have no token. The vault record supplies the key material; the server
 * derives the expected public key from the pot's stored sparkAddress.
 */
export function signerAuthProvider(
  options: Pick<SignCommandOptions, 'vaultPath' | 'clock' | 'spark'>,
  env: NodeJS.ProcessEnv,
  keystore: KeyStore,
): SignerAuthProvider {
  let storePromise: Promise<SignerAuthVaultStore> | undefined
  let spark: SparkSigner | undefined
  return async ({ scope, subject, potId }) => {
    if (!storePromise) {
      storePromise = (async () => {
        const { VaultStore } = await import('./vault/vault.js')
        const { defaultVaultPath } = await import('./paths.js')
        const store: SignerAuthVaultStore = new VaultStore({
          vaultPath: options.vaultPath ?? defaultVaultPath(env),
          keystore,
        })
        return store
      })()
    }
    const store = await storePromise
    const snap = await store.snapshot(potId)
    if (!snap || snap.pubkey.length === 0) throw new PotError('refused to spend')
    const stamp = (options.clock ? options.clock() : new Date()).toISOString()
    const message = potSignerAuthMessage({ scope, potId, subject, stamp })
    const signature = await store.withMnemonic(potId, async (ctx) => {
      if (ctx.address !== snap.address || ctx.pubkey.toLowerCase() !== snap.pubkey.toLowerCase()) {
        throw new PotError('refused to spend')
      }
      const signer = options.spark ?? (spark ??= await createSdkSparkSigner())
      const signed = await signer.signRelay(ctx.mnemonic, ctx.network, message)
      if (signed.pubkey.toLowerCase() !== ctx.pubkey.toLowerCase()) {
        throw new PotError('refused to spend')
      }
      return signed.signature.trim().toLowerCase()
    })
    return { stamp, signature }
  }
}

async function createSdkSparkSigner(): Promise<SparkSigner> {
  const { createSdkSparkSigner } = await import('./spark/sdk.js')
  return createSdkSparkSigner()
}

async function openVault(options: SignCommandOptions, env: NodeJS.ProcessEnv): Promise<SignVault> {
  const { VaultStore } = await import('./vault/vault.js')
  const { defaultVaultPath } = await import('./paths.js')
  const keystore = options.keystore ?? (await openKeyStore())
  return adaptVault(
    new VaultStore({
      vaultPath: options.vaultPath ?? defaultVaultPath(env),
      keystore,
    }),
  )
}

function adaptVault(store: {
  snapshot(potId?: string): Promise<import('./vault/vault.js').PotSnapshot | null>
  withMnemonic<T>(potId: string | undefined, fn: (ctx: MnemonicContext) => Promise<T>): Promise<T>
}): SignVault {
  return {
    async read(potId) {
      try {
        const snap = await store.snapshot(potId)
        if (!snap) return null
        return {
          potId: snap.potId,
          policy: snap.policy,
          role: snap.role,
          freeze: snap.freeze,
          network: snap.network,
          accountIndex: snap.accountIndex,
        }
      } catch (error) {
        if (error instanceof PotError && error.message === 'no pot') return null
        throw error
      }
    },
    withMnemonic(potId, fn) {
      return store.withMnemonic(potId, fn)
    },
  }
}
