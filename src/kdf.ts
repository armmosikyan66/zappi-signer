import { scryptSync } from 'node:crypto'
import { argon2idAsync } from '@noble/hashes/argon2'
import { zeroize } from './zeroize.js'

export interface ScryptParams {
  N: number
  r: number
  p: number
  keyLen: 32
}

/** Machine-random passphrases. High entropy, so scrypt cost stays interactive. */
export const PRODUCTION_SCRYPT: ScryptParams = {
  N: 16_384,
  r: 8,
  p: 1,
  keyLen: 32,
}

/** Fast parameters for unit tests. Production never reads these from the environment. */
export const TEST_SCRYPT: ScryptParams = {
  N: 1024,
  r: 8,
  p: 1,
  keyLen: 32,
}

export interface Argon2Params {
  t: number
  m: number
  p: number
  dkLen: 32
}

/** User-chosen backup passphrases only. Not used for the machine vault key. */
export const PRODUCTION_ARGON2: Argon2Params = {
  t: 3,
  m: 65_536,
  p: 1,
  dkLen: 32,
}

export function deriveScryptKey(passphrase: Uint8Array, salt: Uint8Array, params: ScryptParams): Buffer {
  return scryptSync(passphrase, salt, params.keyLen, {
    N: params.N,
    r: params.r,
    p: params.p,
    maxmem: 64 * 1024 * 1024,
  })
}

export async function deriveUserBackupKey(
  passphrase: Uint8Array,
  salt: Uint8Array,
  params: Argon2Params = PRODUCTION_ARGON2,
): Promise<Uint8Array> {
  const copy = new Uint8Array(passphrase)
  try {
    return await argon2idAsync(copy, salt, params)
  } finally {
    zeroize(copy)
  }
}
