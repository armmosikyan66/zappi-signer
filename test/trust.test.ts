import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { secp256k1 } from '@noble/curves/secp256k1'
import { afterEach, expect, test } from 'vitest'
import { PotError } from '../src/errors.js'
import { defaultStateDir, defaultVaultPath } from '../src/paths.js'
import {
  SIGNER_SERVER_PUBKEY_ENV,
  defaultTrustConfigPath,
  loadPinnedTrust,
  verifyPinnedTrust,
} from '../src/trust.js'

const TEST_PUBKEY = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const KEY_ID = 'backend-secp256k1-v1'
const OTHER_PUBKEY = `03${TEST_PUBKEY.slice(2)}`

const dirs: string[] = []

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'zappi-trust-'))
  dirs.push(dir)
  return dir
}

function write0600(path: string, body: string): void {
  writeFileSync(path, body, { mode: 0o600 })
  if (process.platform !== 'win32') chmodSync(path, 0o600)
}

function expectCode(run: () => unknown, code: string): void {
  try {
    run()
    expect.fail('expected a refusal')
  } catch (error) {
    expect(error).toBeInstanceOf(PotError)
    expect((error as PotError).code).toBe(code)
    expect((error as PotError).message.includes(TEST_PUBKEY)).toBe(false)
    expect((error as PotError).message.includes(OTHER_PUBKEY)).toBe(false)
  }
}

test('default trust path sits beside the vault', () => {
  expect(defaultTrustConfigPath()).toBe(join(defaultStateDir(defaultVaultPath()), 'trust.json'))
  expect(defaultTrustConfigPath({ APPDATA: 'C:\\Users\\me\\AppData\\Roaming' }, 'win32')).toBe(
    join('C:\\Users\\me\\AppData\\Roaming', 'zappi-signer', 'trust.json'),
  )
})

test('loads pins from a config file and lets the env pubkey win', () => {
  const dir = tempDir()
  const configPath = join(dir, 'trust.json')
  const uncompressed = secp256k1.Point.fromHex(TEST_PUBKEY).toHex(false)
  write0600(
    configPath,
    JSON.stringify({
      keys: { [KEY_ID]: TEST_PUBKEY.toUpperCase() },
      serverPubkey: uncompressed,
    }),
  )
  const fromFile = loadPinnedTrust({ env: {}, configPath })
  expect(fromFile.serverPubkey).toBe(uncompressed)
  expect([...fromFile.keys.entries()]).toEqual([[KEY_ID, TEST_PUBKEY]])

  const fromEnv = loadPinnedTrust({
    env: { [SIGNER_SERVER_PUBKEY_ENV]: TEST_PUBKEY },
    configPath,
  })
  expect(fromEnv.serverPubkey).toBe(TEST_PUBKEY)
  expect([...fromEnv.keys.keys()]).toEqual([KEY_ID])
})

test('a fetched trust document confirms pins and does not learn keys', () => {
  const pinned = {
    keys: new Map([[KEY_ID, TEST_PUBKEY]]),
    serverPubkey: TEST_PUBKEY,
  }
  const verified = verifyPinnedTrust(pinned, {
    keys: {
      [KEY_ID]: TEST_PUBKEY.toUpperCase(),
      'backend-secp256k1-v2': OTHER_PUBKEY,
    },
    activeKeyId: KEY_ID,
    futureField: true,
  })
  expect([...verified.entries()]).toEqual([[KEY_ID, TEST_PUBKEY]])

  expectCode(
    () =>
      verifyPinnedTrust(pinned, {
        keys: { [KEY_ID]: OTHER_PUBKEY },
        activeKeyId: KEY_ID,
      }),
    'TRUST_MISMATCH',
  )
  expectCode(
    () =>
      verifyPinnedTrust(pinned, {
        keys: { 'backend-secp256k1-v2': TEST_PUBKEY },
        activeKeyId: 'backend-secp256k1-v2',
      }),
    'TRUST_MISMATCH',
  )
  expectCode(
    () =>
      verifyPinnedTrust(
        { keys: new Map([[KEY_ID, TEST_PUBKEY]]), serverPubkey: TEST_PUBKEY },
        {
          keys: { [KEY_ID]: TEST_PUBKEY },
          activeKeyId: KEY_ID,
          addressChallengePubkey: OTHER_PUBKEY,
        },
      ),
    'TRUST_MISMATCH',
  )
  expectCode(() => verifyPinnedTrust({ keys: new Map() }, {
    keys: { [KEY_ID]: TEST_PUBKEY },
    activeKeyId: KEY_ID,
  }), 'TRUST_UNPINNED')
  expectCode(() => verifyPinnedTrust(pinned, []), 'TRUST_MALFORMED')
  expectCode(
    () => verifyPinnedTrust(pinned, { keys: { [KEY_ID]: TEST_PUBKEY }, activeKeyId: 'missing' }),
    'TRUST_MALFORMED',
  )
})

test('env-only pin binds activeKeyId when the bytes match and ignores other keys', () => {
  const dir = tempDir()
  const loaded = loadPinnedTrust({
    env: { [SIGNER_SERVER_PUBKEY_ENV]: TEST_PUBKEY },
    configPath: join(dir, 'absent.json'),
  })
  expect(loaded.keys.size).toBe(0)
  const verified = verifyPinnedTrust(loaded, {
    keys: { [KEY_ID]: TEST_PUBKEY, 'backend-secp256k1-v2': OTHER_PUBKEY },
    activeKeyId: KEY_ID,
  })
  expect([...verified.entries()]).toEqual([[KEY_ID, TEST_PUBKEY]])

  expectCode(
    () =>
      verifyPinnedTrust(loaded, {
        keys: { [KEY_ID]: OTHER_PUBKEY },
        activeKeyId: KEY_ID,
      }),
    'TRUST_MISMATCH',
  )

  const challengeOnly = verifyPinnedTrust(loaded, {
    keys: { [KEY_ID]: OTHER_PUBKEY },
    activeKeyId: KEY_ID,
    addressChallengePubkey: TEST_PUBKEY,
  })
  expect(challengeOnly.size).toBe(0)
})

test('refuses a loose, linked, or unknown-field config', () => {
  const dir = tempDir()
  const loose = join(dir, 'trust.json')
  writeFileSync(loose, JSON.stringify({ keys: { [KEY_ID]: TEST_PUBKEY } }))
  if (process.platform !== 'win32') {
    chmodSync(loose, 0o644)
    expect(() => loadPinnedTrust({ env: {}, configPath: loose })).toThrow(PotError)
    const target = join(dir, 'real.json')
    const link = join(dir, 'link.json')
    write0600(target, '{}')
    symlinkSync(target, link)
    expect(() => loadPinnedTrust({ env: {}, configPath: link })).toThrow(PotError)
  }
  const unknown = join(dir, 'unknown.json')
  write0600(unknown, JSON.stringify({ keys: { [KEY_ID]: TEST_PUBKEY }, extra: true }))
  expectCode(() => loadPinnedTrust({ env: {}, configPath: unknown }), 'TRUST_CONFIG')
})
