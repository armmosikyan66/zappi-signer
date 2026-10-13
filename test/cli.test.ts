import { secp256k1 } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha2'
import { expect, test } from 'vitest'
import type { RecoveryMaterial } from '../src/commands/backup.js'
import type { StatusClient } from '../src/commands/status.js'
import { PotError } from '../src/errors.js'
import { canonicalBindingBody, type NonceConsumeResult, type NonceStore } from '../src/intent.js'
import type { Argon2Params } from '../src/kdf.js'
import type { KeyStore } from '../src/keystore/types.js'
import { freshPolicy, type SpendingPolicy } from '../src/policy/policy.js'
import { encodeSparkAddress } from '../src/spark/address.js'
import type { SparkSigner } from '../src/spark/signer.js'
import type { CreateVaultInput, MnemonicContext, PotSnapshot } from '../src/vault/vault.js'
import { main, parseSignerArgv } from '../src/index.js'

const PHRASE =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
const SECRET = 'zappi-recovery-passphrase-do-not-echo-7f3c'
const BACKUP_PHRASE = 'local-backup-phrase'
const POT = 'pot-cli-1'
const REQUEST_ID = '11111111-2222-4333-8444-555555555555'
const APPROVAL_ID = '33333333-3333-4333-8333-333333333333'
const STATUS_POT = '22222222-2222-4222-8222-222222222222'
const SPARK = encodeSparkAddress(new Uint8Array(33).fill(2))
const PUBKEY = `02${'ab'.repeat(32)}`
const TEST_KEY = '0000000000000000000000000000000000000000000000000000000000000001'
const TEST_PUBKEY = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const OTHER_KEY = '0000000000000000000000000000000000000000000000000000000000000002'
const KEY_ID = 'backend-secp256k1-v1'
const CHALLENGE_NONCE = '11111111-1111-4111-8111-111111111111'
const FAST_ARGON2: Argon2Params = { t: 1, m: 8, p: 1, dkLen: 32 }

test('parses known commands and flags', () => {
  expect(parseSignerArgv(['--json', 'sign', 'req-1', '--yes'])).toEqual({
    json: true,
    yes: true,
    command: 'sign',
    args: ['req-1'],
  })
  expect(parseSignerArgv(['status', 'req-1'])).toEqual({
    json: false,
    yes: false,
    command: 'status',
    args: ['req-1'],
  })
  expect(parseSignerArgv(['policy', 'view', '--json'])).toEqual({
    json: true,
    yes: false,
    command: 'policy',
    args: ['view'],
  })
  expect(parseSignerArgv(['policy', 'tighten'])?.command).toBe('policy')
  for (const command of ['provision', 'prove-address', 'backup', 'restore']) {
    expect(parseSignerArgv([command, '--yes'])?.command).toBe(command)
  }
  expect(parseSignerArgv(['policy', 'view', '--pot', POT, '--json'])).toEqual({
    json: true,
    yes: false,
    command: 'policy',
    args: ['view'],
    potId: POT,
  })
  expect(parseSignerArgv(['policy', 'tighten', '--pot', POT])).toEqual({
    json: false,
    yes: false,
    command: 'policy',
    args: ['tighten'],
    potId: POT,
  })
  expect(parseSignerArgv(['backup', '--json', '--pot', POT])).toEqual({
    json: true,
    yes: false,
    command: 'backup',
    args: [],
    potId: POT,
  })
  expect(parseSignerArgv(['restore', '--pot', POT, '--json'])).toEqual({
    json: true,
    yes: false,
    command: 'restore',
    args: [],
    potId: POT,
  })
  expect(parseSignerArgv(['provision', '--label', 'desk', '--json'])).toEqual({
    json: true,
    yes: false,
    command: 'provision',
    args: [],
    label: 'desk',
  })
  expect(parseSignerArgv(['prove-address', '--pot', POT, '--json'])).toEqual({
    json: true,
    yes: false,
    command: 'prove-address',
    args: [],
    potId: POT,
  })
  expect(parseSignerArgv(['status', REQUEST_ID, '--json'])).toEqual({
    json: true,
    yes: false,
    command: 'status',
    args: [REQUEST_ID],
  })
  expect(parseSignerArgv(['sign'])).toBeNull()
  expect(parseSignerArgv(['policy', 'loosen'])).toBeNull()
  expect(parseSignerArgv(['nope'])).toBeNull()
  expect(parseSignerArgv(['--nope'])).toBeNull()
  expect(parseSignerArgv(['backup', '--pot', POT, '--passphrase', SECRET])).toBeNull()
  expect(parseSignerArgv(['backup', '--pot', POT, '--recovery', SECRET])).toBeNull()
  expect(parseSignerArgv(['sign', 'req-1', '--pot', POT])).toBeNull()
  expect(parseSignerArgv(['provision', '--pot', POT])).toBeNull()
  expect(parseSignerArgv(['policy', 'view', '--label', 'desk'])).toBeNull()
  expect(parseSignerArgv(['policy', 'tighten', '--pot'])).toBeNull()
  expect(parseSignerArgv(['provision', '--label'])).toBeNull()
})

test('sign refuses instead of reporting that it is not implemented', async () => {
  let out = ''
  const err = await captureStderr(async () => {
    const original = process.stdout.write.bind(process.stdout)
    process.stdout.write = ((chunk: string | Uint8Array) => {
      out += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8')
      return true
    }) as typeof process.stdout.write
    try {
      expect(await main(['sign', 'req-1', '--yes', '--json'])).toBe(1)
    } finally {
      process.stdout.write = original
    }
  })
  expect(err).toBe('refused to spend\n')
  expect(err).not.toContain('not implemented')
  expect(err).not.toContain('abandon')
  expect(err).not.toContain('req-1')
  expect(out).toBe('')
})

test('unknown commands are refused without echoing arguments', async () => {
  const io = await captureIo(async () => {
    expect(await main([PHRASE])).toBe(1)
    expect(await main(['sign'])).toBe(1)
    expect(await main([])).toBe(1)
    expect(await main(['policy', 'loosen'])).toBe(1)
    expect(await main(['backup', '--pot', POT, '--passphrase', SECRET])).toBe(1)
    expect(await main(['restore', '--recovery', SECRET])).toBe(1)
  })
  expect(io.err).toContain('unknown command')
  expect(io.err).not.toContain('not implemented')
  expect(io.err).not.toContain('abandon')
  expect(io.out).not.toContain('abandon')
  expectNoSecret(io)
})

test('pot commands refuse a missing pot before reading stdin', async () => {
  const io = await captureIo(async () => {
    expect(await main(['policy', 'view'])).toBe(1)
    expect(await main(['policy', 'tighten', '--json'])).toBe(1)
    expect(await main(['prove-address'])).toBe(1)
    expect(await main(['backup', '--json'])).toBe(1)
    expect(await main(['restore'])).toBe(1)
  })
  expect(io.err).toBe('no pot\n'.repeat(5))
  expect(io.out).toBe('')
  expect(io.err).not.toContain('not implemented')
})

test('help prints usage and does not echo arguments', async () => {
  let out = ''
  const original = process.stdout.write.bind(process.stdout)
  process.stdout.write = ((chunk: string | Uint8Array) => {
    out += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8')
    return true
  }) as typeof process.stdout.write
  try {
    expect(await main(['--help', PHRASE])).toBe(0)
  } finally {
    process.stdout.write = original
  }
  expect(out).toContain('zappi-signer sign <requestId>')
  expect(out).toContain('zappi-signer policy view --pot <id>')
  expect(out).toContain('zappi-signer prove-address --pot <id>')
  expect(out).not.toContain('abandon')
})

test('status prints the public spend view and does not post an authorization', async () => {
  const calls: string[] = []
  const client: StatusClient = {
    async request(method, path, body) {
      calls.push(`${method} ${path} ${body === undefined ? '' : 'body'}`)
      if (method !== 'GET' || path.includes('spend-authorizations')) throw new Error('authorization posted')
      return {
        requestId: REQUEST_ID,
        approvalId: APPROVAL_ID,
        potId: STATUS_POT,
        amountCents: 2500,
        receiverSparkAddress: SPARK,
        network: 'MAINNET',
        status: 'authorization_required',
        token: 'zpc_do_not_leak',
        backendSig: 'secret-backend-sig',
      }
    },
  }
  const json = await captureIo(async () => {
    expect(await main(['status', REQUEST_ID, '--json'], { client })).toBe(0)
  })
  expect(JSON.parse(json.out)).toEqual({
    requestId: REQUEST_ID,
    approvalId: APPROVAL_ID,
    potId: STATUS_POT,
    amountCents: 2500,
    receiverSparkAddress: SPARK,
    network: 'MAINNET',
    status: 'authorization_required',
  })
  expect(json.out).not.toContain('zpc_do_not_leak')
  expect(json.out).not.toContain('secret-backend-sig')
  expect(json.err).toBe('')
  expect(calls).toEqual([`GET /api/wallet/pots/client-spend-requests/${REQUEST_ID} `])

  const plain = await captureIo(async () => {
    expect(await main(['status', REQUEST_ID], { client })).toBe(0)
  })
  expect(plain.out).toBe('authorization_required\n')
  expect(plain.err).toBe('')
})

test('status refuses a bad request id without calling the client', async () => {
  let calls = 0
  const io = await captureIo(async () => {
    expect(
      await main(['status', 'req-1', '--json'], {
        client: {
          async request() {
            calls += 1
            return {}
          },
        },
      }),
    ).toBe(1)
  })
  expect(calls).toBe(0)
  expect(io.err).toBe('spend status is unavailable\n')
  expect(io.out).toBe('')
  expect(io.err).not.toContain('req-1')
  expect(io.err).not.toContain('not implemented')
})

test('policy view prints PolicyView for the selected pot', async () => {
  const policy = freshPolicy('2026-10-13')
  const io = await captureIo(async () => {
    expect(
      await main(['policy', 'view', '--pot', POT, '--json'], {
        vault: policyVault(policy),
      }),
    ).toBe(0)
  })
  expect(JSON.parse(io.out)).toEqual({ potId: POT, role: 'free', freeze: 'active', policy })
  expect(io.err).toBe('')
  expect(io.out).not.toContain('mnemonic')

  const plain = await captureIo(async () => {
    expect(await main(['policy', 'view', '--pot', POT], { vault: policyVault(policy) })).toBe(0)
  })
  expect(plain.out).toBe(`${POT} free active\n`)
})

test('policy tighten reads the next policy from stdin and keeps presence', async () => {
  const policy = freshPolicy('2026-10-13')
  let stored = policy
  let presence = 0
  const next = { ...policy, perTxSats: policy.perTxSats - 1 }
  const io = await captureIo(async () => {
    expect(
      await main(['policy', 'tighten', '--pot', POT, '--json'], {
        vault: {
          async snapshot() {
            return potSnapshot(stored)
          },
          async replacePolicy(_potId: string, value: SpendingPolicy) {
            stored = value
          },
        },
        keystore: keystore({
          async confirmUserPresence(reason) {
            presence += 1
            expect(reason).toBe('Authorize Zappi')
            return true
          },
        }),
        readStdin: async () => JSON.stringify(next),
      }),
    ).toBe(0)
  })
  const view = JSON.parse(io.out) as { policy: SpendingPolicy }
  expect(view.policy.perTxSats).toBe(policy.perTxSats - 1)
  expect(view.policy.spentTodaySats).toBe(policy.spentTodaySats)
  expect(presence).toBe(1)
  expect(io.err).toBe('')
  expect(stored.perTxSats).toBe(policy.perTxSats - 1)
})

test('policy tighten refuses a looser policy and missing user presence', async () => {
  const policy = freshPolicy('2026-10-13')
  let replaced = 0
  const looser = await captureIo(async () => {
    expect(
      await main(['policy', 'tighten', '--pot', POT], {
        vault: {
          async snapshot() {
            return potSnapshot(policy)
          },
          async replacePolicy() {
            replaced += 1
          },
        },
        keystore: keystore({
          async confirmUserPresence() {
            throw new Error('presence')
          },
        }),
        readStdin: async () => JSON.stringify({ ...policy, perTxSats: policy.perTxSats + 1 }),
      }),
    ).toBe(1)
  })
  expect(looser.err).toBe('POLICY_LOOSER\n')
  expect(looser.out).toBe('')
  expect(replaced).toBe(0)

  const missing = await captureIo(async () => {
    expect(
      await main(['policy', 'tighten', '--pot', POT, '--json'], {
        vault: {
          async snapshot() {
            return potSnapshot(policy)
          },
          async replacePolicy() {
            replaced += 1
          },
        },
        keystore: keystore(),
        readStdin: async () => JSON.stringify({ ...policy, perTxSats: policy.perTxSats - 1 }),
      }),
    ).toBe(1)
  })
  expect(missing.err).toBe('keychain unavailable\n')
  expect(missing.out).toBe('')
  expect(replaced).toBe(0)
})

test('backup and restore print only the envelope or pot record and never the passphrase', async () => {
  const policy = freshPolicy('2026-10-13')
  const recovery: RecoveryMaterial = { passphrase: SECRET, kdf: FAST_ARGON2 }
  const backedUp = await captureIo(async () => {
    expect(
      await main(['backup', '--pot', POT, '--json'], {
        stdinIsTty: false,
        env: {},
        recoveryMaterial: recovery,
        vault: backupVault(policy),
      }),
    ).toBe(0)
  })
  const envelope = JSON.parse(backedUp.out) as { kdf: string; ciphertext: string }
  expect(Object.keys(envelope).sort()).toEqual(
    ['ciphertext', 'kdf', 'm', 'nonce', 'p', 'salt', 't', 'tag'].sort(),
  )
  expect(envelope.kdf).toBe('argon2id')
  expect(backedUp.err).toBe('')
  expectNoSecret(backedUp)
  expect(backedUp.out).not.toContain(BACKUP_PHRASE)
  expect(backedUp.out).not.toContain('"mnemonic"')

  let restoredPhrase = ''
  const restored = await captureIo(async () => {
    expect(
      await main(['restore', '--pot', 'flag-pot', '--json'], {
        stdinIsTty: false,
        env: { ZAPPI_SIGNER_RECOVERY: SECRET },
        readStdin: async () => `${backedUp.out}`,
        keystore: keystore(),
        vault: {
          async create(input: CreateVaultInput) {
            restoredPhrase = input.mnemonic
            return { potId: 'restored-pot', createdAt: '2026-10-13T03:00:00.000Z' }
          },
          async replacePolicy() {},
          async setFreeze() {},
          async confirm() {
            throw new Error('confirm')
          },
          async removePot() {},
        },
      }),
    ).toBe(0)
  })
  expect(JSON.parse(restored.out)).toEqual({
    potId: 'restored-pot',
    createdAt: '2026-10-13T03:00:00.000Z',
  })
  expect(restored.err).toBe('')
  expect(restoredPhrase).toBe(BACKUP_PHRASE)
  expectNoSecret(restored)
  expect(restored.out).not.toContain(BACKUP_PHRASE)
  expect(restored.out).not.toContain('flag-pot')
})

test('recovery comes from the env or a tty prompt and is never printed', async () => {
  let prompted = 0
  const fromEnv = await captureIo(async () => {
    expect(
      await main(['backup', '--pot', POT], {
        stdinIsTty: true,
        env: { ZAPPI_SIGNER_RECOVERY: SECRET },
        promptRecovery: async () => {
          prompted += 1
          return 'other-secret'
        },
        vault: {
          async snapshot() {
            return null
          },
          async withMnemonic() {
            throw new Error('mnemonic')
          },
        },
      }),
    ).toBe(1)
  })
  expect(prompted).toBe(0)
  expect(fromEnv.err).toBe('no pot\n')
  expect(fromEnv.out).toBe('')
  expectNoSecret(fromEnv)

  const fromPrompt = await captureIo(async () => {
    expect(
      await main(['backup', '--pot', POT, '--json'], {
        stdinIsTty: true,
        env: {},
        promptRecovery: async () => {
          prompted += 1
          return SECRET
        },
        vault: {
          async snapshot() {
            return null
          },
          async withMnemonic() {
            throw new Error('mnemonic')
          },
        },
      }),
    ).toBe(1)
  })
  expect(prompted).toBe(1)
  expect(fromPrompt.err).toBe('no pot\n')
  expect(fromPrompt.out).toBe('')
  expectNoSecret(fromPrompt)

  const locked = await captureIo(async () => {
    expect(
      await main(['restore', '--pot', POT, '--json'], {
        stdinIsTty: false,
        env: {},
        readStdin: async () => {
          throw new Error('stdin')
        },
      }),
    ).toBe(1)
  })
  expect(locked.err).toBe('vault locked\n')
  expect(locked.out).toBe('')
  expectNoSecret(locked)
})

test('provision returns bind material and does not mark the pot bound', async () => {
  let phrase = ''
  let label = ''
  let bound = 0
  const calls: string[] = []
  const message = `zappi-pot-address-bind:v1:native:user_1:create:${SPARK}:${CHALLENGE_NONCE}`
  const io = await captureIo(async () => {
    expect(
      await main(['provision', '--label', 'desk', '--json'], {
        vault: {
          async create(input: CreateVaultInput) {
            phrase = input.mnemonic
            label = input.label ?? ''
            return { potId: 'pot-created', createdAt: '2026-10-13T00:00:00.000Z' }
          },
          async snapshot() {
            return null
          },
          async markBound() {
            bound += 1
          },
        },
        spark: sparkSigner(),
        ledger: memoryLedger(),
        pinnedTrust: { keys: new Map([[KEY_ID, TEST_PUBKEY]]), serverPubkey: TEST_PUBKEY },
        client: {
          async request(method, path, body) {
            calls.push(`${method} ${path}`)
            if (path.includes('spend-authorizations')) throw new Error('authorization posted')
            if (method === 'GET' && path === '/api/signer/trust') {
              return { keys: { [KEY_ID]: TEST_PUBKEY }, activeKeyId: KEY_ID }
            }
            if (method === 'POST' && path === '/api/wallet/pots/address-proof-challenge') {
              expect(body).toEqual({ sparkAddress: SPARK })
              return { nonce: CHALLENGE_NONCE, expiresAt: new Date(Date.now() + 60_000).toISOString(), message }
            }
            throw new Error(`unexpected ${method} ${path}`)
          },
        },
      }),
    ).toBe(0)
  })
  const result = JSON.parse(io.out) as {
    potId: string
    provisionId: string
    address: string
    pubkey: string
    signature: string
    nonce: string
  }
  expect(result.potId).toBe('pot-created')
  expect(result.provisionId).toMatch(/^prov_[0-9a-f]{16}$/)
  expect(result.address).toBe(SPARK)
  expect(result.pubkey).toBe(PUBKEY)
  expect(result.signature).toBe('cd'.repeat(64))
  expect(result.nonce).toBe(CHALLENGE_NONCE)
  expect(label).toBe('desk')
  expect(bound).toBe(0)
  expect(calls).toEqual(['GET /api/signer/trust', 'POST /api/wallet/pots/address-proof-challenge'])
  expect(io.err).toBe('')
  expect(phrase.split(' ')).toHaveLength(12)
  expect(io.out).not.toContain(phrase)
  expect(io.err).not.toContain(phrase)
})

test('prove-address reads the binding receipt from stdin and marks the pot bound', async () => {
  let bound = 0
  const receipt = bindingReceipt(POT, SPARK, TEST_KEY)
  const io = await captureIo(async () => {
    expect(
      await main(['prove-address', '--pot', POT, '--json'], {
        pinnedTrust: { keys: new Map(), serverPubkey: TEST_PUBKEY },
        readStdin: async () => JSON.stringify(receipt),
        vault: proveVault(() => {
          bound += 1
        }),
      }),
    ).toBe(0)
  })
  expect(JSON.parse(io.out)).toEqual({ potId: POT, address: SPARK, bound: true })
  expect(bound).toBe(1)
  expect(io.err).toBe('')

  bound = 0
  const forged = await captureIo(async () => {
    expect(
      await main(['prove-address', '--pot', POT], {
        pinnedTrust: { keys: new Map(), serverPubkey: TEST_PUBKEY },
        readStdin: async () => JSON.stringify(bindingReceipt(POT, SPARK, OTHER_KEY)),
        vault: proveVault(() => {
          bound += 1
        }),
      }),
    ).toBe(1)
  })
  expect(forged.err).toBe('BINDING_BAD_SIGNATURE\n')
  expect(forged.out).toBe('')
  expect(forged.err).not.toContain(OTHER_KEY)
  expect(bound).toBe(0)
})

function keystore(extra?: { confirmUserPresence?: KeyStore['confirmUserPresence'] }): KeyStore {
  const store: KeyStore = {
    async getSecret() {
      return null
    },
    async setSecret() {},
    async deleteSecret() {},
    async deviceFactor() {
      return Buffer.alloc(32, 4)
    },
  }
  if (extra?.confirmUserPresence) store.confirmUserPresence = extra.confirmUserPresence
  return store
}

function potSnapshot(policy: SpendingPolicy, potId = POT): PotSnapshot {
  return {
    potId,
    createdAt: '2026-10-13T00:00:00.000Z',
    label: 'desk',
    address: SPARK,
    pubkey: PUBKEY,
    accountIndex: 1,
    network: 'REGTEST',
    confirmed: false,
    confirmPositions: [1, 2, 3],
    bound: false,
    attachment: { state: 'unattached' },
    policy,
    role: 'free',
    freeze: 'active',
    fromMaster: false,
  }
}

function policyVault(policy: SpendingPolicy) {
  return {
    async snapshot() {
      return potSnapshot(policy)
    },
    async replacePolicy() {},
  }
}

function backupVault(policy: SpendingPolicy) {
  return {
    async snapshot() {
      return potSnapshot(policy)
    },
    async withMnemonic<T>(_potId: string | undefined, fn: (ctx: MnemonicContext) => Promise<T>) {
      const mnemonic = Buffer.from(BACKUP_PHRASE, 'utf8')
      try {
        return await fn({
          mnemonic,
          potId: POT,
          address: SPARK,
          pubkey: PUBKEY,
          accountIndex: 1,
          network: 'REGTEST',
          bound: false,
        })
      } finally {
        mnemonic.fill(0)
      }
    },
  }
}

function proveVault(onBound: () => void) {
  return {
    async create() {
      throw new Error('create')
    },
    async snapshot() {
      return potSnapshot(freshPolicy('2026-10-13'))
    },
    async markBound() {
      onBound()
    },
  }
}

function sparkSigner(): SparkSigner {
  return {
    async derive() {
      return { address: SPARK, pubkey: PUBKEY }
    },
    async signRelay() {
      return { signature: 'cd'.repeat(64), pubkey: PUBKEY }
    },
    async signNonce() {
      throw new Error('signNonce')
    },
    async balanceSats() {
      throw new Error('balance')
    },
    async transfer() {
      throw new Error('transfer')
    },
  }
}

function memoryLedger(): NonceStore {
  const rows = new Map<string, string>()
  return {
    consume(nonce, intentId, expiresAt): NonceConsumeResult {
      const existing = rows.get(nonce)
      if (existing) {
        if (existing !== intentId) throw new PotError('replay')
        return { replay: true, record: { intentId, expiresAt } }
      }
      rows.set(nonce, intentId)
      return { replay: false, record: { intentId, expiresAt } }
    },
  }
}

function bindingReceipt(potId: string, address: string, key: string) {
  const unsigned = {
    v: 1 as const,
    provisionId: 'prov_0123456789abcdef',
    potId,
    sparkAddress: address,
    nonce: 'binding-nonce-0f1e2d3c4b5a69788796a5b4c3d2e1f0',
  }
  return {
    ...unsigned,
    backendSig: secp256k1.sign(sha256(Buffer.from(canonicalBindingBody(unsigned), 'utf8')), key).toHex('compact'),
  }
}

function expectNoSecret(io: { out: string; err: string }): void {
  expect(io.out).not.toContain(SECRET)
  expect(io.err).not.toContain(SECRET)
}

async function captureIo(fn: () => Promise<void>): Promise<{ out: string; err: string }> {
  let out = ''
  let err = ''
  const writeOut = process.stdout.write.bind(process.stdout)
  const writeErr = process.stderr.write.bind(process.stderr)
  process.stdout.write = ((chunk: string | Uint8Array) => {
    out += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8')
    return true
  }) as typeof process.stdout.write
  process.stderr.write = ((chunk: string | Uint8Array) => {
    err += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8')
    return true
  }) as typeof process.stderr.write
  try {
    await fn()
  } finally {
    process.stdout.write = writeOut
    process.stderr.write = writeErr
  }
  return { out, err }
}

async function captureStderr(fn: () => Promise<void>): Promise<string> {
  let err = ''
  const original = process.stderr.write.bind(process.stderr)
  process.stderr.write = ((chunk: string | Uint8Array) => {
    err += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8')
    return true
  }) as typeof process.stderr.write
  try {
    await fn()
  } finally {
    process.stderr.write = original
  }
  return err
}
