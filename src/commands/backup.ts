/**
 * Seals a pot record with the user-backup helper and restores that envelope
 * into a vault. Results expose envelope fields only — never the mnemonic.
 */
import { z } from 'zod'
import { PotError } from '../errors.js'
import type { Argon2Params } from '../kdf.js'
import type { KeyStore } from '../keystore/types.js'
import { policySchema, type SpendingPolicy } from '../policy/policy.js'
import type { FreezeState } from '../guards.js'
import { openUserBackup, sealUserBackup } from '../vault/user-backup.js'
import type { CreateVaultInput, MnemonicContext, PotSnapshot } from '../vault/vault.js'
import { assertResultHasNoMnemonic, zeroize } from '../zeroize.js'

const backupBlobSchema = z
  .object({
    kdf: z.literal('argon2id'),
    t: z.number().int().positive(),
    m: z.number().int().min(8),
    p: z.number().int().positive(),
    salt: z.string().min(1),
    nonce: z.string().min(1),
    tag: z.string().min(1),
    ciphertext: z.string().min(1),
  })
  .strict()

const backupPayloadSchema = z
  .object({
    v: z.literal(1),
    mnemonic: z.string().min(1).max(512),
    address: z.string().min(1).max(120),
    pubkey: z.string().regex(/^[0-9a-fA-F]{64,130}$/),
    accountIndex: z.literal(1),
    network: z.enum(['MAINNET', 'REGTEST', 'TESTNET']),
    label: z.string().max(64),
    role: z.enum(['free', 'vault', 'cloud']),
    freeze: z.enum(['active', 'frozen_guard', 'frozen_user']),
    confirmed: z.boolean(),
    positions: z.tuple([
      z.number().int().min(0).max(11),
      z.number().int().min(0).max(11),
      z.number().int().min(0).max(11),
    ]),
    today: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
    policy: policySchema,
  })
  .superRefine((value, ctx) => {
    if (new Set(value.positions).size !== 3) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'positions' })
    }
  })

type BackupPayload = z.infer<typeof backupPayloadSchema>

export interface UserBackupBlob {
  kdf: 'argon2id'
  t: number
  m: number
  p: number
  salt: string
  nonce: string
  tag: string
  ciphertext: string
}

export type RecoveryMaterial =
  | Uint8Array
  | string
  | { passphrase: Uint8Array | string; kdf?: Argon2Params }

export interface BackupCommandVault {
  snapshot(potId?: string): Promise<PotSnapshot | null>
  withMnemonic<T>(potId: string | undefined, fn: (ctx: MnemonicContext) => Promise<T>): Promise<T>
}

export interface RestoreCommandVault {
  create(input: CreateVaultInput): Promise<{ potId: string; createdAt: string }>
  replacePolicy(potId: string, policy: SpendingPolicy): Promise<void>
  setFreeze(potId: string, state: FreezeState): Promise<void>
  confirm(
    words: readonly string[],
    potId?: string,
  ): Promise<{ potId: string; address: string; already: boolean }>
  removePot(potId: string): Promise<void>
}

export interface BackupInput {
  vault: BackupCommandVault
  potId: string
  recoveryMaterial: RecoveryMaterial
}

export interface RestoreInput {
  vault: RestoreCommandVault
  keystore: KeyStore
  backup: UserBackupBlob | string
  recoveryMaterial: RecoveryMaterial
}

export interface RestoreResult {
  potId: string
  createdAt: string
}

interface NormalizedRecovery {
  passphrase: Uint8Array
  kdf?: Argon2Params
}

export async function runBackup(input: BackupInput): Promise<UserBackupBlob> {
  const potId = requirePotId(input.potId)
  const recovery = normalizeRecovery(input.recoveryMaterial)
  const snapshot = await input.vault.snapshot(potId)
  if (!snapshot) throw new PotError('no pot')
  return input.vault.withMnemonic(potId, async (ctx) => {
    const phrase = Buffer.from(ctx.mnemonic).toString('utf8')
    const draft = backupPayloadSchema.safeParse(payloadFrom(snapshot, phrase))
    if (!draft.success) throw new PotError('backup refused')
    const plaintext = Buffer.from(JSON.stringify(draft.data), 'utf8')
    try {
      const sealed = recovery.kdf
        ? await sealUserBackup(plaintext, recovery.passphrase, recovery.kdf)
        : await sealUserBackup(plaintext, recovery.passphrase)
      return parseBackupBlob(sealed)
    } finally {
      zeroize(plaintext)
    }
  })
}

export async function runRestore(input: RestoreInput): Promise<RestoreResult> {
  await assertDeviceFactor(input.keystore)
  const recovery = normalizeRecovery(input.recoveryMaterial)
  const opened = await openUserBackup(envelopeString(input.backup), recovery.passphrase)
  try {
    const payload = parsePayload(Buffer.from(opened).toString('utf8'))
    const created = await input.vault.create(createInput(payload))
    try {
      await input.vault.replacePolicy(created.potId, payload.policy)
      await input.vault.setFreeze(created.potId, payload.freeze)
      if (payload.confirmed) {
        await input.vault.confirm(confirmWords(payload.mnemonic, payload.positions), created.potId)
      }
    } catch (error) {
      try {
        await input.vault.removePot(created.potId)
      } catch {
        // Report the restore failure, not a cleanup failure.
      }
      throw error
    }
    const result: RestoreResult = { potId: created.potId, createdAt: created.createdAt }
    assertResultHasNoMnemonic(result, payload.mnemonic)
    return result
  } finally {
    zeroize(opened)
  }
}

function payloadFrom(snapshot: PotSnapshot, mnemonic: string): unknown {
  if (snapshot.accountIndex !== 1) return null
  return {
    v: 1,
    mnemonic,
    address: snapshot.address,
    pubkey: snapshot.pubkey,
    accountIndex: 1,
    network: snapshot.network,
    label: snapshot.label,
    role: snapshot.role,
    freeze: snapshot.freeze,
    confirmed: snapshot.confirmed,
    positions: storedPositions(snapshot),
    today: snapshot.policy.spentDay,
    policy: snapshot.policy,
  }
}

function createInput(payload: BackupPayload): CreateVaultInput {
  return {
    mnemonic: payload.mnemonic,
    address: payload.address,
    pubkey: payload.pubkey,
    accountIndex: 1,
    network: payload.network,
    positions: payload.positions,
    today: payload.today,
    label: payload.label,
    role: payload.role,
  }
}

function storedPositions(snapshot: PotSnapshot): [number, number, number] {
  const indexes = snapshot.confirmPositions.map((position) => position - 1)
  const first = indexes[0]
  const second = indexes[1]
  const third = indexes[2]
  if (!validIndex(first) || !validIndex(second) || !validIndex(third)) {
    throw new PotError('backup refused')
  }
  return [first, second, third]
}

function validIndex(index: number | undefined): index is number {
  return index !== undefined && Number.isInteger(index) && index >= 0 && index <= 11
}

function confirmWords(mnemonic: string, positions: [number, number, number]): [string, string, string] {
  const words = mnemonic.split(' ')
  const picked = positions.map((index) => words[index] ?? '')
  const first = picked[0]
  const second = picked[1]
  const third = picked[2]
  if (!first || !second || !third) throw new PotError('vault locked')
  return [first, second, third]
}

function parsePayload(text: string): BackupPayload {
  let json: unknown
  try {
    json = JSON.parse(text)
  } catch {
    throw new PotError('vault locked')
  }
  const parsed = backupPayloadSchema.safeParse(json)
  if (!parsed.success) throw new PotError('vault locked')
  return parsed.data
}

function parseBackupBlob(sealed: string): UserBackupBlob {
  let json: unknown
  try {
    json = JSON.parse(sealed)
  } catch {
    throw new PotError('vault locked')
  }
  const parsed = backupBlobSchema.safeParse(json)
  if (!parsed.success) throw new PotError('vault locked')
  return {
    kdf: parsed.data.kdf,
    t: parsed.data.t,
    m: parsed.data.m,
    p: parsed.data.p,
    salt: parsed.data.salt,
    nonce: parsed.data.nonce,
    tag: parsed.data.tag,
    ciphertext: parsed.data.ciphertext,
  }
}

function envelopeString(backup: UserBackupBlob | string): string {
  if (typeof backup === 'string') return backup
  const parsed = backupBlobSchema.safeParse(backup)
  if (!parsed.success) throw new PotError('vault locked')
  return JSON.stringify(parsed.data)
}

function requirePotId(potId: string): string {
  const id = potId.trim()
  if (!id) throw new PotError('no pot')
  return id
}

function normalizeRecovery(material: RecoveryMaterial): NormalizedRecovery {
  if (typeof material === 'string') return finishRecovery(new TextEncoder().encode(material))
  if (material instanceof Uint8Array) return finishRecovery(material)
  const passphrase =
    typeof material.passphrase === 'string'
      ? new TextEncoder().encode(material.passphrase)
      : material.passphrase
  return finishRecovery(passphrase, material.kdf)
}

function finishRecovery(passphrase: Uint8Array, kdf?: Argon2Params): NormalizedRecovery {
  if (passphrase.byteLength === 0) throw new PotError('vault locked')
  if (kdf) return { passphrase, kdf }
  return { passphrase }
}

async function assertDeviceFactor(keystore: KeyStore): Promise<void> {
  const factor = await keystore.deviceFactor()
  try {
    if (factor.length !== 32) throw new PotError('keychain unavailable')
  } finally {
    zeroize(factor)
  }
}
