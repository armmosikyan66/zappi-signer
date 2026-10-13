import {
  createCipheriv,
  createDecipheriv,
  hkdfSync,
  randomBytes,
  randomInt,
  timingSafeEqual,
} from 'node:crypto'
import {
  chmodSync,
  closeSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  renameSync,
  unlinkSync,
  writeSync,
} from 'node:fs'
import { dirname, join } from 'node:path'
import { generateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
import { z } from 'zod'
import { PotError } from '../errors.js'
import { logLine } from '../log.js'
import { readNoFollow } from '../fs-safe.js'
import { freezeAfterTrip, type FreezeState } from '../guards.js'
import { tokenListSchema, type CloudTokenRecord } from './cloud-token.js'
import { PRODUCTION_SCRYPT, deriveScryptKey, type ScryptParams } from '../kdf.js'
import {
  DEVICE_TOKEN_ACCOUNT,
  HIGH_WATER_ACCOUNT,
  OAUTH_CLIENT_ACCOUNT,
  UNLOCK_ACCOUNT,
  type KeyStore,
} from '../keystore/types.js'
import { deriveChildMnemonic } from '../master.js'
import {
  BACKUP_ATTEMPT_LIMIT,
  commitSpend,
  freshPolicy,
  noteFailure as recordFailure,
  policySchema,
  rollbackSpend,
  type PotRole,
  type SpendingPolicy,
} from '../policy/policy.js'
import { assertResultHasNoMnemonic, zeroize } from '../zeroize.js'
import { withFileLock } from './lock.js'

export const VAULT_VERSION = 4
const VAULT_VERSION_V1 = 1
const VAULT_VERSION_V2 = 2
const VAULT_VERSION_V3 = 3
export const SEALED_ELSEWHERE = 'vault is sealed to another device'
const DEVICE_KEY_INFO = 'zappi-pot-device-v4'

/** Mixes the device factor into the scrypt key. v3 and older files skip this. */
export function deviceBoundKey(scryptKey: Uint8Array, factor: Uint8Array): Buffer {
  return Buffer.from(hkdfSync('sha256', scryptKey, factor, Buffer.from(DEVICE_KEY_INFO), 32))
}
export const VAULT_KIND = 'zappi-pots-mcp'
export const POT_ID_RE = /^pot_[0-9a-f]{32}$/
const GCM_NONCE_LEN = 12
const GCM_TAG_LEN = 16
const SALT_LEN = 16
const MAX_VAULT_BYTES = 1 << 20
const MAX_POTS = 16

export type SparkNetworkName = 'MAINNET' | 'REGTEST' | 'TESTNET'
export type AttachMode = 'free' | 'auth_required'
export type { PotRole, FreezeState }

export type Attachment =
  | { state: 'unattached' }
  | { state: 'attached'; mode: AttachMode; agent: string; attachedAt: string }

const attachmentSchema = z.discriminatedUnion('state', [
  z.object({ state: z.literal('unattached') }).strict(),
  z
    .object({
      state: z.literal('attached'),
      mode: z.enum(['free', 'auth_required']),
      agent: z.string().min(1).max(64),
      attachedAt: z.string().min(10).max(40),
    })
    .strict(),
])

const payloadSchema = z.object({
  v: z.literal(1),
  mnemonic: z.string().max(512),
  address: z.string().min(1).max(120),
  pubkey: z.string().regex(/^[0-9a-fA-F]{64,130}$/),
  accountIndex: z.number().int().min(0).max(2_147_483_647).default(1),
  network: z.enum(['MAINNET', 'REGTEST', 'TESTNET']),
  label: z.string().max(64).optional().default(''),
  attachment: attachmentSchema.optional().default({ state: 'unattached' }),
  policy: policySchema,
  role: z.enum(['free', 'vault', 'cloud']).optional().default('free'),
  freeze: z.enum(['active', 'frozen_guard', 'frozen_user']).optional().default('active'),
  fromMaster: z.boolean().optional().default(false),
  potIndex: z.number().int().nonnegative().optional(),
  linkedVaultId: z.string().regex(POT_ID_RE).optional(),
  lastSweepAt: z.number().int().nonnegative().optional(),
  backup: z.object({
    confirmed: z.boolean(),
    positions: z.tuple([
      z.number().int().min(0).max(11),
      z.number().int().min(0).max(11),
      z.number().int().min(0).max(11),
    ]),
    failures: z.number().int().min(0).max(100),
  }),
  bound: z.boolean(),
})

type PotSecrets = z.infer<typeof payloadSchema>

export interface PotSnapshot {
  potId: string
  createdAt: string
  label: string
  address: string
  pubkey: string
  accountIndex: number
  network: SparkNetworkName
  confirmed: boolean
  /** 1-based indexes into the 12-word phrase, in echo order. */
  confirmPositions: [number, number, number]
  bound: boolean
  attachment: Attachment
  policy: SpendingPolicy
  role: PotRole
  freeze: FreezeState
  linkedVaultId?: string
  fromMaster: boolean
  potIndex?: number
  lastSweepAt?: number
}

export interface CreateVaultInput {
  mnemonic: string
  address: string
  pubkey: string
  accountIndex: 1
  network: SparkNetworkName
  positions: [number, number, number]
  today: string
  label?: string
  role?: PotRole
  fromMaster?: boolean
  potIndex?: number
}

export interface MnemonicContext {
  mnemonic: Uint8Array
  potId: string
  address: string
  pubkey: string
  accountIndex: number
  network: SparkNetworkName
  bound: boolean
}

export interface VaultStoreOptions {
  vaultPath: string
  keystore: KeyStore
  kdf?: ScryptParams
}

interface PotEntry {
  potId: string
  createdAt: string
  secrets: PotSecrets
}

interface LoadedFile {
  pots: PotEntry[]
}

export function ambiguousPotMessage(ids: readonly string[]): string {
  return `set ZAPPI_POT_ID to one of: ${ids.join(', ')}`
}

export class VaultStore {
  private readonly vaultPath: string
  private readonly lockPath: string
  private readonly keystore: KeyStore
  private readonly kdf: ScryptParams
  private meta: VaultMeta = emptyMeta()
  private factorCache: Buffer | null = null

  constructor(options: VaultStoreOptions) {
    this.vaultPath = options.vaultPath
    this.lockPath = `${options.vaultPath}.lock`
    this.keystore = options.keystore
    this.kdf = options.kdf ?? PRODUCTION_SCRYPT
  }

  async list(): Promise<PotSnapshot[]> {
    return this.locked(async () => {
      const file = await this.loadFile()
      if (!file) return []
      try {
        return file.pots.map(toSnapshot)
      } finally {
        wipeAll(file.pots)
      }
    })
  }

  async snapshot(potId?: string): Promise<PotSnapshot | null> {
    return this.locked(async () => {
      const file = await this.loadFile()
      if (!file || file.pots.length === 0) {
        if (potId) throw new PotError('no pot')
        return null
      }
      try {
        const pot = selectPot(file.pots, potId)
        return toSnapshot(pot)
      } finally {
        wipeAll(file.pots)
      }
    })
  }

  async create(input: CreateVaultInput): Promise<{ potId: string; createdAt: string }> {
    return this.locked(async () => {
      const file = await this.loadFile()
      const pots = file?.pots ?? []
      if (pots.length >= MAX_POTS) {
        wipeAll(pots)
        throw new PotError('too many pots')
      }
      assertPositions(input.positions)
      const potId = `pot_${randomBytes(16).toString('hex')}`
      const createdAt = new Date().toISOString()
      const role = input.role ?? 'free'
      const secrets: PotSecrets = {
        v: 1,
        mnemonic: input.fromMaster ? '' : input.mnemonic,
        address: input.address,
        pubkey: input.pubkey,
        accountIndex: input.accountIndex,
        network: input.network,
        label: input.label ?? '',
        attachment: { state: 'unattached' },
        policy: freshPolicy(input.today, role),
        backup: { confirmed: false, positions: input.positions, failures: 0 },
        bound: false,
        role,
        freeze: 'active',
        fromMaster: input.fromMaster ?? false,
        ...(input.potIndex !== undefined ? { potIndex: input.potIndex } : {}),
      }
      if (role === 'free') {
        const reserve = pots.find((pot) => pot.secrets.role === 'vault')
        if (reserve) secrets.linkedVaultId = reserve.potId
      }
      pots.push({ potId, createdAt, secrets })
      if (role === 'vault') {
        for (const pot of pots) {
          if (pot.secrets.role === 'free' && !pot.secrets.linkedVaultId) pot.secrets.linkedVaultId = potId
        }
      }
      try {
        await this.commit(pots, !file)
      } finally {
        wipeAll(pots)
      }
      return { potId, createdAt }
    })
  }

  async confirm(
    words: readonly string[],
    potId?: string,
  ): Promise<{ potId: string; address: string; already: boolean }> {
    const outcome = await this.locked(async () => {
      const file = await this.requireFile()
      try {
        const pot = selectPot(file.pots, potId)
        if (pot.secrets.backup.confirmed) {
          return {
            kind: 'ok' as const,
            result: { potId: pot.potId, address: pot.secrets.address, already: true },
          }
        }
        const matched = phraseMatches(this.phraseFor(pot.secrets), pot.secrets, words)
        if (!matched) {
          pot.secrets.backup.failures += 1
          const failures = pot.secrets.backup.failures
          const id = pot.potId
          await this.commit(file.pots, false)
          return { kind: 'mismatch' as const, failures, potId: id }
        }
        pot.secrets.backup.confirmed = true
        pot.secrets.backup.failures = 0
        await this.commit(file.pots, false)
        return {
          kind: 'ok' as const,
          result: { potId: pot.potId, address: pot.secrets.address, already: false },
        }
      } finally {
        wipeAll(file.pots)
      }
    })
    if (outcome.kind === 'mismatch') {
      if (outcome.failures >= BACKUP_ATTEMPT_LIMIT) await this.removePot(outcome.potId)
      throw new PotError('backup words did not match')
    }
    return outcome.result
  }

  async abandon(potId?: string): Promise<void> {
    await this.locked(async () => {
      const file = await this.requireFile()
      let id = ''
      try {
        const pot = selectPot(file.pots, potId)
        if (pot.secrets.backup.confirmed) throw new PotError('backup already confirmed')
        id = pot.potId
      } finally {
        wipeAll(file.pots)
      }
      await this.removePotUnlocked(id)
    })
  }

  async reserve(amount: number, today: string, potId?: string): Promise<void> {
    await this.mutate(potId, (pot) => {
      if (!pot.secrets.backup.confirmed) throw new PotError('backup not confirmed')
      pot.secrets.policy = commitSpend(pot.secrets.policy, amount, today)
    })
  }

  async release(amount: number, today: string, potId?: string): Promise<void> {
    await this.locked(async () => {
      const file = await this.loadFile()
      if (!file) return
      try {
        const pot = selectPot(file.pots, potId)
        pot.secrets.policy = rollbackSpend(pot.secrets.policy, amount, today)
        await this.commit(file.pots, false)
      } finally {
        wipeAll(file.pots)
      }
    })
  }

  async markBound(potId?: string): Promise<void> {
    await this.mutate(potId, (pot) => {
      pot.secrets.bound = true
    })
  }

  async setAttachment(potId: string | undefined, attachment: Attachment): Promise<void> {
    await this.mutate(potId, (pot) => {
      pot.secrets.attachment = attachment
    })
  }

  async withMnemonic<T>(
    potId: string | undefined,
    fn: (ctx: MnemonicContext) => Promise<T>,
  ): Promise<T> {
    const loaded = await this.locked(async () => {
      const file = await this.requireFile()
      try {
        const pot = selectPot(file.pots, potId)
        return {
          phrase: this.phraseFor(pot.secrets),
          potId: pot.potId,
          address: pot.secrets.address,
          pubkey: pot.secrets.pubkey,
          accountIndex: pot.secrets.accountIndex,
          network: pot.secrets.network,
          bound: pot.secrets.bound,
        }
      } finally {
        wipeAll(file.pots)
      }
    })
    const buf = Buffer.from(loaded.phrase, 'utf8')
    const ctx: MnemonicContext = {
      mnemonic: buf,
      potId: loaded.potId,
      address: loaded.address,
      pubkey: loaded.pubkey,
      accountIndex: loaded.accountIndex,
      network: loaded.network,
      bound: loaded.bound,
    }
    try {
      const result = await fn(ctx)
      assertResultHasNoMnemonic(result, loaded.phrase)
      return result
    } finally {
      zeroize(buf)
    }
  }

  async removePot(potId: string): Promise<void> {
    await this.locked(async () => {
      await this.removePotUnlocked(potId)
    })
  }

  async allocateChild(): Promise<{ potIndex: number; childMnemonic: string }> {
    return this.locked(async () => {
      const file = await this.loadFile()
      const pots = file?.pots ?? []
      try {
        if (!this.meta.hasMaster) {
          this.meta.hasMaster = true
          this.meta.masterMnemonic = generateMnemonic(wordlist, 128)
          this.meta.nextIndex = 0
          if (!this.meta.vaultCreatedAt) this.meta.vaultCreatedAt = new Date().toISOString()
        }
        const potIndex = this.meta.nextIndex
        this.meta.nextIndex += 1
        const childMnemonic = deriveChildMnemonic(this.meta.masterMnemonic, potIndex)
        await this.commit(pots, !file)
        return { potIndex, childMnemonic }
      } finally {
        wipeAll(pots)
      }
    })
  }

  async checkBackup(words: readonly string[], potId?: string): Promise<{ passed: boolean }> {
    const outcome = await this.locked(async () => {
      const file = await this.requireFile()
      try {
        const pot = selectPot(file.pots, potId)
        if (pot.secrets.backup.confirmed) return { kind: 'pass' as const }
        if (phraseMatches(this.phraseFor(pot.secrets), pot.secrets, words)) return { kind: 'pass' as const }
        pot.secrets.backup.failures += 1
        const failures = pot.secrets.backup.failures
        const id = pot.potId
        await this.commit(file.pots, false)
        return { kind: 'fail' as const, failures, potId: id }
      } finally {
        wipeAll(file.pots)
      }
    })
    if (outcome.kind === 'fail' && outcome.failures >= BACKUP_ATTEMPT_LIMIT) await this.removePot(outcome.potId)
    return { passed: outcome.kind === 'pass' }
  }

  async confirmPresence(): Promise<void> {
    const confirm = this.keystore.confirmUserPresence
    if (!confirm) throw new PotError('keychain unavailable')
    const ok = await confirm('Authorize Zappi')
    if (!ok) throw new PotError('keychain unavailable')
  }

  async readUnlockPassphrase(): Promise<string> {
    const secret = await this.keystore.getSecret(UNLOCK_ACCOUNT)
    if (!secret) throw new PotError('vault locked')
    return secret
  }

  async replacePolicy(potId: string, policy: SpendingPolicy): Promise<void> {
    await this.mutate(potId, (pot) => {
      pot.secrets.policy = policy
    })
  }

  async setFreeze(potId: string, state: FreezeState): Promise<void> {
    await this.mutate(potId, (pot) => {
      pot.secrets.freeze = state
    })
  }

  async freezeAll(state: FreezeState): Promise<void> {
    await this.locked(async () => {
      const file = await this.requireFile()
      try {
        for (const pot of file.pots) pot.secrets.freeze = state
        await this.commit(file.pots, false)
      } finally {
        wipeAll(file.pots)
      }
    })
  }

  async noteSendFailure(potId: string, nowMs: number): Promise<FreezeState> {
    let state: FreezeState = 'active'
    await this.mutate(potId, (pot) => {
      const noted = recordFailure(pot.secrets.policy, nowMs)
      pot.secrets.policy = noted.policy
      if (noted.freeze) pot.secrets.freeze = freezeAfterTrip(pot.secrets.freeze)
      state = pot.secrets.freeze
    })
    return state
  }

  async markSwept(potId: string, nowMs: number): Promise<void> {
    await this.mutate(potId, (pot) => {
      pot.secrets.lastSweepAt = nowMs
    })
  }

  async listTokens(): Promise<CloudTokenRecord[]> {
    return this.locked(async () => {
      await this.loadFile()
      return this.meta.tokens.map((token) => ({ ...token }))
    })
  }

  async saveTokens(tokens: readonly CloudTokenRecord[]): Promise<void> {
    await this.locked(async () => {
      const file = await this.loadFile()
      const pots = file?.pots ?? []
      this.meta.tokens = tokens.map((token) => ({ ...token }))
      try {
        await this.commit(pots, !file)
      } finally {
        wipeAll(pots)
      }
    })
  }

  private async mutate(potId: string | undefined, change: (pot: PotEntry) => void): Promise<void> {
    await this.locked(async () => {
      const file = await this.requireFile()
      try {
        const pot = selectPot(file.pots, potId)
        change(pot)
        await this.commit(file.pots, false)
      } finally {
        wipeAll(file.pots)
      }
    })
  }

  private async removePotUnlocked(potId: string): Promise<void> {
    const file = await this.requireFile()
    const rest = file.pots.filter((pot) => pot.potId !== potId)
    if (rest.length === file.pots.length) {
      wipeAll(file.pots)
      throw new PotError('no pot')
    }
    try {
      if (rest.length === 0) {
        this.removeVaultFile()
        await this.forgetKeychain()
        return
      }
      await this.commit(rest, false)
    } finally {
      wipeAll(file.pots)
    }
  }

  private async locked<T>(fn: () => Promise<T>): Promise<T> {
    return withFileLock(this.lockPath, async () => {
      try {
        return await fn()
      } finally {
        this.meta.masterMnemonic = ''
      }
    })
  }

  private async passphrase(create: boolean): Promise<string> {
    let existing: string | null
    try {
      existing = await this.keystore.getSecret(UNLOCK_ACCOUNT)
    } catch {
      throw new PotError('vault locked')
    }
    if (existing) {
      if (create) {
        throw new PotError(
          'unlock secret already exists with no pot vault; refusing to reuse or replace it',
        )
      }
      return existing
    }
    if (!create) throw new PotError('vault locked')
    const created = randomBytes(32).toString('base64')
    try {
      await this.keystore.setSecret(UNLOCK_ACCOUNT, created)
    } catch {
      throw new PotError('vault locked')
    }
    return created
  }

  private async requireFile(): Promise<LoadedFile> {
    const file = await this.loadFile()
    if (!file || file.pots.length === 0) throw new PotError('no pot')
    return file
  }

  private async loadFile(): Promise<LoadedFile | null> {
    this.assertParents()
    let raw: string
    try {
      const stat = lstatSync(this.vaultPath)
      if (stat.isSymbolicLink() || !stat.isFile()) throw new PotError('vault locked')
      if (stat.size > MAX_VAULT_BYTES) throw new PotError('vault locked')
      if (process.platform !== 'win32') {
        if ((stat.mode & 0o077) !== 0) throw new PotError('vault locked')
        if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
          throw new PotError('vault locked')
        }
      }
      raw = readNoFollow(this.vaultPath, MAX_VAULT_BYTES)
    } catch (error) {
      if (error instanceof PotError) throw error
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        this.meta = emptyMeta()
        return null
      }
      throw new PotError('vault locked')
    }
    return this.decryptFile(raw)
  }

  private async decryptFile(raw: string): Promise<LoadedFile> {
    let parsed: unknown
    try {
      parsed = JSON.parse(raw)
    } catch {
      throw new PotError('vault locked')
    }
    if (isSignerVault(parsed)) {
      throw new PotError('existing signer vault found; refusing to overwrite')
    }
    const v1 = fileV1Schema.safeParse(parsed)
    if (v1.success) {
      const secrets = await this.openPayload(
        v1.data.kdf,
        v1.data.nonce,
        v1.data.tag,
        v1.data.ciphertext,
        aad(VAULT_VERSION_V1, v1.data.potId, v1.data.createdAt),
      )
      this.meta = emptyMeta()
      this.meta.vaultCreatedAt = v1.data.createdAt
      await this.guardVersion(0)
      return { pots: [{ potId: v1.data.potId, createdAt: v1.data.createdAt, secrets }] }
    }
    const sealed = fileSealedSchema.safeParse(parsed)
    if (sealed.success) return this.openSealed(sealed.data, sealed.data.version === VAULT_VERSION)
    const v2 = fileV2Schema.safeParse(parsed)
    if (!v2.success) throw new PotError('unrecognized vault; refusing to overwrite')
    const pots: PotEntry[] = []
    try {
      for (const potId of Object.keys(v2.data.pots).sort()) {
        const blob = v2.data.pots[potId]
        if (!blob) continue
        const secrets = await this.openPayload(
          v2.data.kdf,
          blob.nonce,
          blob.tag,
          blob.ciphertext,
          aad(VAULT_VERSION_V2, potId, blob.createdAt),
        )
        pots.push({ potId, createdAt: blob.createdAt, secrets })
      }
      this.meta = emptyMeta()
      const first = pots[0]
      this.meta.vaultCreatedAt = first?.createdAt ?? new Date().toISOString()
      await this.guardVersion(0)
      return { pots }
    } catch (error) {
      wipeAll(pots)
      throw error
    }
  }

  private async openPayload(
    kdf: z.infer<typeof kdfSchema>,
    nonceB64: string,
    tagB64: string,
    ciphertextB64: string,
    extra: Buffer,
  ): Promise<PotSecrets> {
    const salt = decodeB64(kdf.salt, SALT_LEN)
    const nonce = decodeB64(nonceB64, GCM_NONCE_LEN)
    const tag = decodeB64(tagB64, GCM_TAG_LEN)
    const ciphertext = decodeB64(ciphertextB64, null)
    const passphrase = Buffer.from(await this.passphrase(false), 'utf8')
    const key = deriveScryptKey(passphrase, salt, {
      N: kdf.N,
      r: kdf.r,
      p: kdf.p,
      keyLen: 32,
    })
    zeroize(passphrase)
    let plaintext: Buffer
    try {
      const decipher = createDecipheriv('aes-256-gcm', key, nonce)
      decipher.setAAD(extra)
      decipher.setAuthTag(tag)
      plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()])
    } catch {
      zeroize(key)
      throw new PotError('vault locked')
    }
    zeroize(key)
    let secrets: PotSecrets
    try {
      secrets = payloadSchema.parse(JSON.parse(plaintext.toString('utf8')))
    } catch {
      zeroize(plaintext)
      throw new PotError('vault locked')
    }
    zeroize(plaintext)
    return secrets
  }

  private async openSealed(data: z.infer<typeof fileSealedSchema>, bound: boolean): Promise<LoadedFile> {
    const pots: PotEntry[] = []
    try {
      for (const potId of Object.keys(data.pots).sort()) {
        const blob = data.pots[potId]
        if (!blob) continue
        const extra = (fieldName: string) => aadField(data.vaultVersion, potId, fieldName, blob.createdAt)
        const mnemonic = await this.openText(data.kdf, blob.fields.mnemonic, extra('mnemonic'), bound)
        const address = await this.openText(data.kdf, blob.fields.address, extra('address'), bound)
        const pubkey = await this.openText(data.kdf, blob.fields.pubkey, extra('pubkey'), bound)
        const record = await this.openText(data.kdf, blob.fields.record, extra('record'), bound)
        let secrets: PotSecrets
        try {
          secrets = payloadSchema.parse({ ...JSON.parse(record), mnemonic, address, pubkey })
        } catch {
          throw new PotError('vault locked')
        }
        pots.push({ potId, createdAt: blob.createdAt, secrets })
      }
      this.meta = emptyMeta()
      this.meta.vaultCreatedAt = data.vaultCreatedAt
      if (data.master) {
        const text = await this.openText(
          data.kdf,
          data.master,
          aadField(data.vaultVersion, 'vault', 'master', data.vaultCreatedAt),
          bound,
        )
        const master = masterSchema.parse(JSON.parse(text))
        this.meta.hasMaster = true
        this.meta.masterMnemonic = master.mnemonic
        this.meta.nextIndex = master.nextIndex
      }
      if (data.tokens) {
        const text = await this.openText(
          data.kdf,
          data.tokens,
          aadField(data.vaultVersion, 'vault', 'tokens', data.vaultCreatedAt),
          bound,
        )
        this.meta.tokens = tokenListSchema.parse(JSON.parse(text))
      }
      await this.guardVersion(data.vaultVersion)
      return { pots }
    } catch (error) {
      wipeAll(pots)
      this.meta.masterMnemonic = ''
      if (error instanceof PotError) throw error
      throw new PotError('vault locked')
    }
  }

  private async openText(
    kdf: z.infer<typeof kdfSchema>,
    blob: z.infer<typeof fieldSchema>,
    extra: Buffer,
    bound: boolean,
  ): Promise<string> {
    const plaintext = await this.openBytes(kdf, blob.nonce, blob.tag, blob.ciphertext, extra, bound)
    const text = plaintext.toString('utf8')
    zeroize(plaintext)
    return text
  }

  private async openBytes(
    kdf: z.infer<typeof kdfSchema>,
    nonceB64: string,
    tagB64: string,
    ciphertextB64: string,
    extra: Buffer,
    bound: boolean,
  ): Promise<Buffer> {
    const salt = decodeB64(kdf.salt, SALT_LEN)
    const nonce = decodeB64(nonceB64, GCM_NONCE_LEN)
    const tag = decodeB64(tagB64, GCM_TAG_LEN)
    const ciphertext = decodeB64(ciphertextB64, null)
    const passphrase = Buffer.from(await this.passphrase(false), 'utf8')
    const scryptKey = deriveScryptKey(passphrase, salt, { N: kdf.N, r: kdf.r, p: kdf.p, keyLen: 32 })
    zeroize(passphrase)
    const key = await this.mixKey(scryptKey, bound)
    try {
      const decipher = createDecipheriv('aes-256-gcm', key, nonce)
      decipher.setAAD(extra)
      decipher.setAuthTag(tag)
      return Buffer.concat([decipher.update(ciphertext), decipher.final()])
    } catch {
      throw new PotError(bound ? SEALED_ELSEWHERE : 'vault locked')
    } finally {
      zeroize(key)
    }
  }

  private async mixKey(scryptKey: Buffer, bound: boolean): Promise<Buffer> {
    if (!bound) return scryptKey
    try {
      return deviceBoundKey(scryptKey, await this.deviceFactor())
    } finally {
      zeroize(scryptKey)
    }
  }

  private async deviceFactor(): Promise<Buffer> {
    if (this.factorCache) return this.factorCache
    const factor = await this.keystore.deviceFactor()
    if (factor.length !== 32) throw new PotError('keychain unavailable')
    this.factorCache = Buffer.from(factor)
    return this.factorCache
  }

  private async commit(pots: readonly PotEntry[], create: boolean): Promise<void> {
    const mark = await this.readHighWater()
    const vaultVersion = Math.max(this.meta.vaultVersion, mark) + 1
    if (!this.meta.vaultCreatedAt) this.meta.vaultCreatedAt = new Date().toISOString()
    const passphrase = await this.passphrase(create)
    await this.writeAll(pots, passphrase, vaultVersion)
    await this.keystore.setSecret(HIGH_WATER_ACCOUNT, String(vaultVersion))
    this.meta.vaultVersion = vaultVersion
  }

  private async guardVersion(version: number): Promise<void> {
    const mark = await this.readHighWater()
    if (version < mark) throw new PotError('vault rollback refused')
    if (version > mark) await this.keystore.setSecret(HIGH_WATER_ACCOUNT, String(version))
    this.meta.vaultVersion = version
  }

  private async readHighWater(): Promise<number> {
    let raw: string | null
    try {
      raw = await this.keystore.getSecret(HIGH_WATER_ACCOUNT)
    } catch {
      throw new PotError('vault locked')
    }
    if (!raw) return 0
    if (!/^\d{1,9}$/.test(raw)) throw new PotError('vault locked')
    return Number(raw)
  }

  private phraseFor(secrets: PotSecrets): string {
    if (!secrets.fromMaster) return secrets.mnemonic
    if (!this.meta.hasMaster || secrets.potIndex === undefined) throw new PotError('vault locked')
    return deriveChildMnemonic(this.meta.masterMnemonic, secrets.potIndex)
  }

  private async writeAll(pots: readonly PotEntry[], passphrase: string, vaultVersion: number): Promise<void> {
    const salt = randomBytes(SALT_LEN)
    const passBuf = Buffer.from(passphrase, 'utf8')
    const scryptKey = deriveScryptKey(passBuf, salt, this.kdf)
    zeroize(passBuf)
    const key = await this.mixKey(scryptKey, true)
    const sealed: Record<string, { createdAt: string; fields: Record<string, FieldBlob> }> = {}
    let masterBlob: FieldBlob | undefined
    let tokenBlob: FieldBlob | undefined
    try {
      for (const pot of pots) {
        let checked: PotSecrets
        try {
          checked = payloadSchema.parse(pot.secrets)
        } catch {
          throw new PotError('vault locked')
        }
        const { mnemonic, address, pubkey, ...record } = checked
        const createdAt = pot.createdAt
        sealed[pot.potId] = {
          createdAt,
          fields: {
            mnemonic: this.sealField(key, vaultVersion, pot.potId, createdAt, 'mnemonic', Buffer.from(mnemonic, 'utf8')),
            address: this.sealField(key, vaultVersion, pot.potId, createdAt, 'address', Buffer.from(address, 'utf8')),
            pubkey: this.sealField(key, vaultVersion, pot.potId, createdAt, 'pubkey', Buffer.from(pubkey, 'utf8')),
            record: this.sealField(key, vaultVersion, pot.potId, createdAt, 'record', Buffer.from(JSON.stringify(record), 'utf8')),
          },
        }
      }
      if (this.meta.hasMaster) {
        masterBlob = this.sealField(
          key,
          vaultVersion,
          'vault',
          this.meta.vaultCreatedAt,
          'master',
          Buffer.from(JSON.stringify({ mnemonic: this.meta.masterMnemonic, nextIndex: this.meta.nextIndex }), 'utf8'),
        )
      }
      tokenBlob = this.sealField(
        key,
        vaultVersion,
        'vault',
        this.meta.vaultCreatedAt,
        'tokens',
        Buffer.from(JSON.stringify(this.meta.tokens), 'utf8'),
      )
    } finally {
      zeroize(key)
    }
    const body = `${JSON.stringify({
      version: VAULT_VERSION,
      kind: VAULT_KIND,
      vaultVersion,
      vaultCreatedAt: this.meta.vaultCreatedAt,
      kdf: {
        name: 'scrypt',
        N: this.kdf.N,
        r: this.kdf.r,
        p: this.kdf.p,
        keyLen: 32,
        salt: salt.toString('base64'),
      },
      pots: sealed,
      ...(masterBlob ? { master: masterBlob } : {}),
      tokens: tokenBlob,
    })}\n`
    if (Buffer.byteLength(body) > MAX_VAULT_BYTES) throw new PotError('vault locked')
    writeAtomic(this.vaultPath, body)
  }

  private sealField(
    key: Buffer,
    vaultVersion: number,
    potId: string,
    createdAt: string,
    fieldName: string,
    plaintext: Buffer,
  ): FieldBlob {
    const nonce = randomBytes(GCM_NONCE_LEN)
    const cipher = createCipheriv('aes-256-gcm', key, nonce)
    cipher.setAAD(aadField(vaultVersion, potId, fieldName, createdAt))
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
    const tag = cipher.getAuthTag()
    zeroize(plaintext)
    return {
      nonce: nonce.toString('base64'),
      tag: tag.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
    }
  }

  private async forgetKeychain(): Promise<void> {
    let stuck = false
    for (const account of [UNLOCK_ACCOUNT, DEVICE_TOKEN_ACCOUNT, OAUTH_CLIENT_ACCOUNT, HIGH_WATER_ACCOUNT]) {
      try {
        await this.keystore.deleteSecret(account)
      } catch {
        stuck = true
      }
    }
    if (stuck) logLine('a keychain item remains after the pot was removed')
  }

  private removeVaultFile(): void {
    try {
      const stat = lstatSync(this.vaultPath)
      if (stat.isSymbolicLink()) throw new PotError('vault locked')
      unlinkSync(this.vaultPath)
    } catch (error) {
      if (error instanceof PotError) throw error
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return
      throw new PotError('vault locked')
    }
  }

  private assertParents(): void {
    const dir = dirname(this.vaultPath)
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    if (process.platform !== 'win32') chmodSync(dir, 0o700)
    const dirStat = lstatSync(dir)
    if (dirStat.isSymbolicLink()) throw new PotError('vault locked')
  }
}

const kdfSchema = z.object({
  name: z.literal('scrypt'),
  N: z.number().int().min(1024).max(1_048_576),
  r: z.literal(8),
  p: z.literal(1),
  keyLen: z.literal(32),
  salt: z.string().min(1).max(128),
})

const potBlobSchema = z
  .object({
    createdAt: z.string().min(10).max(40),
    nonce: z.string().min(1).max(64),
    tag: z.string().min(1).max(64),
    ciphertext: z.string().min(1).max(1_000_000),
  })
  .strict()

const fileV1Schema = z
  .object({
    version: z.literal(VAULT_VERSION_V1),
    kind: z.literal(VAULT_KIND),
    potId: z.string().regex(POT_ID_RE),
    createdAt: z.string().min(10).max(40),
    kdf: kdfSchema,
    nonce: z.string().min(1).max(64),
    tag: z.string().min(1).max(64),
    ciphertext: z.string().min(1).max(1_000_000),
  })
  .strict()

const fieldSchema = z
  .object({
    nonce: z.string().min(1).max(64),
    tag: z.string().min(1).max(64),
    ciphertext: z.string().max(1_000_000),
  })
  .strict()

const masterSchema = z.object({
  mnemonic: z.string().min(1).max(512),
  nextIndex: z.number().int().nonnegative(),
})

const fileSealedSchema = z
  .object({
    version: z.union([z.literal(VAULT_VERSION_V3), z.literal(VAULT_VERSION)]),
    kind: z.literal(VAULT_KIND),
    vaultVersion: z.number().int().nonnegative(),
    vaultCreatedAt: z.string().min(10).max(40),
    kdf: kdfSchema,
    pots: z.record(
      z.string().regex(POT_ID_RE),
      z
        .object({
          createdAt: z.string().min(10).max(40),
          fields: z
            .object({
              mnemonic: fieldSchema,
              address: fieldSchema,
              pubkey: fieldSchema,
              record: fieldSchema,
            })
            .strict(),
        })
        .strict(),
    ),
    master: fieldSchema.optional(),
    tokens: fieldSchema.optional(),
  })
  .strict()

const fileV2Schema = z
  .object({
    version: z.literal(VAULT_VERSION_V2),
    kind: z.literal(VAULT_KIND),
    kdf: kdfSchema,
    pots: z.record(z.string().regex(POT_ID_RE), potBlobSchema),
  })
  .strict()

function isSignerVault(value: unknown): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const record = value as Record<string, unknown>
  return 'pots' in record && record.kind !== VAULT_KIND
}

function aad(version: number, potId: string, createdAt: string): Buffer {
  return Buffer.from(JSON.stringify({ v: version, createdAt, potId }), 'utf8')
}

function aadField(vaultVersion: number, potId: string, fieldName: string, createdAt: string): Buffer {
  return Buffer.from(JSON.stringify({ vaultVersion, potId, fieldName, createdAt }), 'utf8')
}

interface FieldBlob {
  nonce: string
  tag: string
  ciphertext: string
}

interface VaultMeta {
  vaultVersion: number
  vaultCreatedAt: string
  masterMnemonic: string
  nextIndex: number
  hasMaster: boolean
  tokens: CloudTokenRecord[]
}

function emptyMeta(): VaultMeta {
  return {
    vaultVersion: 0,
    vaultCreatedAt: '',
    masterMnemonic: '',
    nextIndex: 0,
    hasMaster: false,
    tokens: [],
  }
}

function decodeB64(value: string, expected: number | null): Buffer {
  const buf = Buffer.from(value, 'base64')
  if (expected !== null && buf.length !== expected) throw new PotError('vault locked')
  if (expected === null && value.length > 0 && buf.length === 0) throw new PotError('vault locked')
  return buf
}

function selectPot(pots: readonly PotEntry[], potId: string | undefined): PotEntry {
  if (potId) {
    const found = pots.find((pot) => pot.potId === potId)
    if (!found) throw new PotError('no pot')
    return found
  }
  if (pots.length === 1) {
    const only = pots[0]
    if (!only) throw new PotError('no pot')
    return only
  }
  throw new PotError(ambiguousPotMessage(pots.map((pot) => pot.potId)))
}

function toSnapshot(loaded: PotEntry): PotSnapshot {
  const positions = loaded.secrets.backup.positions
  const attachment = loaded.secrets.attachment
  return {
    potId: loaded.potId,
    createdAt: loaded.createdAt,
    label: loaded.secrets.label,
    address: loaded.secrets.address,
    pubkey: loaded.secrets.pubkey,
    accountIndex: loaded.secrets.accountIndex,
    network: loaded.secrets.network,
    confirmed: loaded.secrets.backup.confirmed,
    confirmPositions: [positions[0] + 1, positions[1] + 1, positions[2] + 1],
    bound: loaded.secrets.bound,
    attachment: attachment.state === 'unattached' ? { state: 'unattached' } : { ...attachment },
    policy: { ...loaded.secrets.policy },
    role: loaded.secrets.role,
    freeze: loaded.secrets.freeze,
    fromMaster: loaded.secrets.fromMaster,
    ...(loaded.secrets.linkedVaultId ? { linkedVaultId: loaded.secrets.linkedVaultId } : {}),
    ...(loaded.secrets.potIndex !== undefined ? { potIndex: loaded.secrets.potIndex } : {}),
    ...(loaded.secrets.lastSweepAt !== undefined ? { lastSweepAt: loaded.secrets.lastSweepAt } : {}),
  }
}

function wipe(secrets: PotSecrets): void {
  secrets.mnemonic = ''
  secrets.address = ''
  secrets.pubkey = ''
}

function wipeAll(pots: readonly PotEntry[]): void {
  for (const pot of pots) wipe(pot.secrets)
}

function assertPositions(positions: readonly number[]): void {
  if (positions.length !== 3) throw new PotError('could not create pot')
  const unique = new Set(positions)
  if (unique.size !== 3) throw new PotError('could not create pot')
  for (const position of positions) {
    if (!Number.isInteger(position) || position < 0 || position > 11) {
      throw new PotError('could not create pot')
    }
  }
}

function phraseMatches(phraseText: string, secrets: PotSecrets, words: readonly string[]): boolean {
  const phrase = phraseText.split(' ')
  if (phrase.length !== 12 || words.length !== 3) return false
  let matched = true
  for (let i = 0; i < 3; i += 1) {
    const index = secrets.backup.positions[i]
    const expected = index === undefined ? '' : (phrase[index] ?? '')
    const given = words[i] ?? ''
    if (!safeWordEqual(expected, given)) matched = false
  }
  return matched
}

function safeWordEqual(expected: string, given: string): boolean {
  const left = Buffer.from(expected.toLowerCase(), 'utf8')
  const right = Buffer.from(given.trim().toLowerCase(), 'utf8')
  const length = Math.max(left.length, right.length, 1)
  const a = Buffer.alloc(length)
  const b = Buffer.alloc(length)
  left.copy(a)
  right.copy(b)
  const equal = timingSafeEqual(a, b) && left.length === right.length
  zeroize(left)
  zeroize(right)
  zeroize(a)
  zeroize(b)
  return equal
}

function writeAtomic(path: string, body: string): void {
  const dir = dirname(path)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  if (process.platform !== 'win32') chmodSync(dir, 0o700)
  const tmp = join(dir, `.${randomBytes(8).toString('hex')}.tmp`)
  const fd = openSync(tmp, 'w', 0o600)
  try {
    const buf = Buffer.from(body, 'utf8')
    let offset = 0
    while (offset < buf.length) offset += writeSync(fd, buf, offset)
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }
  if (process.platform !== 'win32') chmodSync(tmp, 0o600)
  try {
    const existing = lstatSync(path)
    if (existing.isSymbolicLink()) {
      unlinkSync(tmp)
      throw new PotError('vault locked')
    }
  } catch (error) {
    if (error instanceof PotError) throw error
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      unlinkSync(tmp)
      throw new PotError('vault locked')
    }
  }
  if (process.platform === 'win32') {
    try {
      unlinkSync(path)
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        unlinkSync(tmp)
        throw new PotError('vault locked')
      }
    }
  }
  renameSync(tmp, path)
  if (process.platform !== 'win32') chmodSync(path, 0o600)
}

export function pickConfirmPositions(): [number, number, number] {
  const chosen = new Set<number>()
  while (chosen.size < 3) chosen.add(randomInt(0, 12))
  return [...chosen] as [number, number, number]
}
