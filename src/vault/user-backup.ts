import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { z } from 'zod'
import { PotError } from '../errors.js'
import { deriveUserBackupKey, PRODUCTION_ARGON2, type Argon2Params } from '../kdf.js'
import { zeroize } from '../zeroize.js'

const envelopeSchema = z.object({
  kdf: z.literal('argon2id'),
  t: z.number().int().positive(),
  m: z.number().int().min(8),
  p: z.number().int().positive(),
  salt: z.string(),
  nonce: z.string(),
  tag: z.string(),
  ciphertext: z.string(),
})

/**
 * Optional envelope for a user-chosen backup passphrase.
 * Not an MCP tool: tools never accept a passphrase.
 */
export async function sealUserBackup(
  plaintext: Uint8Array,
  passphrase: Uint8Array,
  params: Argon2Params = PRODUCTION_ARGON2,
): Promise<string> {
  const salt = randomBytes(16)
  const key = Buffer.from(await deriveUserBackupKey(passphrase, salt, params))
  try {
    const nonce = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', key, nonce)
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
    const tag = cipher.getAuthTag()
    return JSON.stringify({
      kdf: 'argon2id',
      t: params.t,
      m: params.m,
      p: params.p,
      salt: salt.toString('base64'),
      nonce: nonce.toString('base64'),
      tag: tag.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
    })
  } finally {
    zeroize(key)
  }
}

export async function openUserBackup(envelope: string, passphrase: Uint8Array): Promise<Uint8Array> {
  const parsed = envelopeSchema.safeParse(JSON.parse(envelope))
  if (!parsed.success) throw new PotError('vault locked')
  const salt = Buffer.from(parsed.data.salt, 'base64')
  const key = Buffer.from(
    await deriveUserBackupKey(passphrase, salt, {
      t: parsed.data.t,
      m: parsed.data.m,
      p: parsed.data.p,
      dkLen: 32,
    }),
  )
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(parsed.data.nonce, 'base64'))
    decipher.setAuthTag(Buffer.from(parsed.data.tag, 'base64'))
    return Buffer.concat([
      decipher.update(Buffer.from(parsed.data.ciphertext, 'base64')),
      decipher.final(),
    ])
  } catch {
    throw new PotError('vault locked')
  } finally {
    zeroize(key)
  }
}
