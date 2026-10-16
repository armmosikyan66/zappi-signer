import { bech32m } from '@scure/base'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { afterEach, expect, test, vi } from 'vitest'
import { encodeSparkAddress } from '../src/spark/address.js'
import {
  broadcastUsdbFromMnemonic,
  inspectSparkAddress,
  selectCanonicalUsdbToken,
  sendUsdbFromPot,
} from '../src/spark/usdb.js'

const { initialize } = vi.hoisted(() => ({ initialize: vi.fn() }))

vi.mock('@buildonspark/spark-sdk', () => ({
  SparkWallet: { initialize },
}))

const CANONICAL = 'btkn1qqqqusdbcanonicaltoken'
const OTHER = 'btkn1qqqqothertoken'

afterEach(() => {
  initialize.mockReset()
})

function fakePhrase(): string {
  return Array.from({ length: 12 }, () => 'zappi').join(' ')
}

function digest(value: string): string {
  return createHash('sha256').update(value).digest('hex')
}

function sparkAddress(hrp: string): string {
  return bech32m.encode(hrp, bech32m.toWords(new Uint8Array(33).fill(4)))
}

function usdb(id: string, extra: Record<string, unknown> = {}) {
  return {
    tokenMetadata: {
      tokenTicker: 'USDB',
      decimals: 6,
      ...extra,
    },
    id,
  }
}

function balanceOf(entries: Array<[string, unknown]>): { tokenBalances: Map<string, unknown> } {
  return { tokenBalances: new Map(entries) }
}

function mockWallet(balance: unknown) {
  const wallet = {
    getBalance: vi.fn(async () => balance),
    transferTokens: vi.fn(async () => 'txid-usdb-1'),
    transfer: vi.fn(async () => {
      throw new Error('sats transfer')
    }),
    cleanupConnections: vi.fn(async () => undefined),
  }
  initialize.mockResolvedValue({ wallet })
  return wallet
}

function assertPhraseUsed(phrase: string): void {
  const props = initialize.mock.calls[0]?.[0] as { mnemonicOrSeed?: string } | undefined
  const used = typeof props?.mnemonicOrSeed === 'string' ? props.mnemonicOrSeed : ''
  const ok = digest(used) === digest(phrase)
  if (props) props.mnemonicOrSeed = ''
  expect(ok).toBe(true)
}

async function capture(run: () => Promise<void>): Promise<string> {
  const chunks: string[] = []
  const writeOut = process.stdout.write.bind(process.stdout)
  const writeErr = process.stderr.write.bind(process.stderr)
  const record = (chunk: string | Uint8Array) => {
    chunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'))
    return true
  }
  process.stdout.write = record as typeof process.stdout.write
  process.stderr.write = record as typeof process.stderr.write
  try {
    await run()
  } finally {
    process.stdout.write = writeOut
    process.stderr.write = writeErr
  }
  return chunks.join('')
}

test('selects the canonical btkn1 USDB token and refuses every other id', () => {
  const balances = new Map<string, unknown>([
    [OTHER, { tokenMetadata: { tokenTicker: 'OTHER', decimals: 6 } }],
    [CANONICAL, usdb(CANONICAL)],
  ])
  expect(selectCanonicalUsdbToken(balances, 'MAINNET')).toBe(CANONICAL)
  expect(() => selectCanonicalUsdbToken({ btkn1bare: { ownedBalance: '1' } }, 'MAINNET')).toThrow(
    /canonical USDB/,
  )
  expect(() => selectCanonicalUsdbToken({ btknrt1usdb: usdb('btknrt1usdb') }, 'MAINNET')).toThrow(
    /canonical USDB/,
  )
  expect(() =>
    selectCanonicalUsdbToken({ [CANONICAL]: usdb(CANONICAL, { decimals: 8 }) }, 'MAINNET'),
  ).toThrow(/decimals/)
  expect(() =>
    selectCanonicalUsdbToken({ [CANONICAL]: usdb(CANONICAL, { network: 'REGTEST' }) }, 'MAINNET'),
  ).toThrow(/metadata network/)
  expect(() =>
    selectCanonicalUsdbToken(
      {
        [CANONICAL]: usdb(CANONICAL),
        btkn1qqqqsecondusdb: usdb('btkn1qqqqsecondusdb'),
      },
      'MAINNET',
    ),
  ).toThrow(/More than one canonical USDB/)
})

test('inspects Spark address networks', () => {
  const mainnet = encodeSparkAddress(new Uint8Array(33).fill(4))
  expect(inspectSparkAddress(mainnet)).toEqual({ valid: true, network: 'MAINNET' })
  expect(inspectSparkAddress(sparkAddress('sp'))).toEqual({ valid: true, network: 'MAINNET' })
  expect(inspectSparkAddress(sparkAddress('sparkrt'))).toEqual({ valid: true, network: 'REGTEST' })
  expect(inspectSparkAddress(sparkAddress('sparkt'))).toEqual({ valid: true, network: 'FOREIGN' })
  expect(inspectSparkAddress('not-an-address')).toEqual({ valid: false, network: null })
  expect(inspectSparkAddress('   ')).toEqual({ valid: false, network: null })
})

test('sends amountCents times 10_000 USDB base units and does not transfer sats', async () => {
  const phrase = fakePhrase()
  const destination = `  ${encodeSparkAddress(new Uint8Array(33).fill(4))}  `
  const wallet = mockWallet(balanceOf([[CANONICAL, usdb(CANONICAL)]]))
  const captured = await capture(async () => {
    const sent = await sendUsdbFromPot({
      mnemonic: phrase,
      destination,
      amountCents: 25,
      network: 'MAINNET',
    })
    expect(sent).toEqual({ txid: 'txid-usdb-1' })
  })
  if (captured.includes(phrase)) throw new Error('phrase leaked to stdio')
  assertPhraseUsed(phrase)
  const props = initialize.mock.calls[0]?.[0] as {
    accountNumber: number
    options: unknown
  }
  expect(props.accountNumber).toBe(1)
  expect(props.options).toEqual({
    network: 'MAINNET',
    optimizationOptions: { auto: false, multiplicity: 0 },
    tokenOptimizationOptions: { enabled: false },
  })
  expect(wallet.transferTokens).toHaveBeenCalledWith({
    tokenIdentifier: CANONICAL,
    tokenAmount: 250_000n,
    receiverSparkAddress: destination.trim(),
  })
  expect(wallet.transfer).not.toHaveBeenCalled()
  expect(wallet.cleanupConnections).toHaveBeenCalledOnce()
  expect(initialize).toHaveBeenCalledOnce()
})

test('refuses non-positive amounts, empty destinations, and the wrong network', async () => {
  const phrase = fakePhrase()
  const destination = encodeSparkAddress(new Uint8Array(33).fill(7))
  const refusals: Array<{ input: Parameters<typeof sendUsdbFromPot>[0]; message: RegExp }> = [
    { input: { mnemonic: phrase, destination, amountCents: 0, network: 'MAINNET' }, message: /greater than zero/ },
    { input: { mnemonic: phrase, destination, amountCents: -5, network: 'MAINNET' }, message: /greater than zero/ },
    { input: { mnemonic: phrase, destination, amountCents: 1.5, network: 'MAINNET' }, message: /greater than zero/ },
    { input: { mnemonic: phrase, destination: '   ', amountCents: 1, network: 'MAINNET' }, message: /Destination is empty/ },
    { input: { mnemonic: phrase, destination, amountCents: 1, network: 'REGTEST' }, message: /Network must be MAINNET/ },
    {
      input: { mnemonic: phrase, destination: sparkAddress('sparkrt'), amountCents: 1, network: 'MAINNET' },
      message: /Recipient network must be MAINNET/,
    },
    {
      input: { mnemonic: phrase, destination: sparkAddress('sparkt'), amountCents: 1, network: 'MAINNET' },
      message: /Recipient network must be MAINNET/,
    },
  ]
  for (const refusal of refusals) {
    await expect(sendUsdbFromPot(refusal.input)).rejects.toThrow(refusal.message)
  }
  expect(initialize).not.toHaveBeenCalled()
})

test('refuses a balance that has no canonical btkn1 USDB token', async () => {
  const wallet = mockWallet(
    balanceOf([
      [OTHER, { tokenMetadata: { tokenTicker: 'OTHER', decimals: 6 } }],
      ['not-a-btkn-usdb', usdb('not-a-btkn-usdb')],
    ]),
  )
  await expect(
    sendUsdbFromPot({
      mnemonic: fakePhrase(),
      destination: encodeSparkAddress(new Uint8Array(33).fill(4)),
      amountCents: 1,
      network: 'MAINNET',
    }),
  ).rejects.toThrow(/canonical USDB/)
  expect(wallet.transferTokens).not.toHaveBeenCalled()
  expect(wallet.transfer).not.toHaveBeenCalled()
  expect(wallet.cleanupConnections).toHaveBeenCalledOnce()
})

test('broadcasts the server-created tx params after verifying them', async () => {
  const phrase = fakePhrase()
  const destination = encodeSparkAddress(new Uint8Array(33).fill(4))
  const wallet = mockWallet(balanceOf([[CANONICAL, usdb(CANONICAL)]]))
  const sent = await sendUsdbFromPot({
    mnemonic: phrase,
    destination,
    amountCents: 25,
    network: 'MAINNET',
    tokenIdentifier: CANONICAL,
    tokenAmount: '250000',
  })
  expect(sent).toEqual({ txid: 'txid-usdb-1' })
  expect(wallet.transferTokens).toHaveBeenCalledWith({
    tokenIdentifier: CANONICAL,
    tokenAmount: 250_000n,
    receiverSparkAddress: destination,
  })
})

test('refuses server tx params that do not match the pot wallet', async () => {
  const destination = encodeSparkAddress(new Uint8Array(33).fill(4))
  const wrongToken = mockWallet(balanceOf([[CANONICAL, usdb(CANONICAL)]]))
  await expect(
    sendUsdbFromPot({
      mnemonic: fakePhrase(),
      destination,
      amountCents: 25,
      network: 'MAINNET',
      tokenIdentifier: OTHER,
      tokenAmount: 250_000,
    }),
  ).rejects.toThrow(/names token .* but the pot holds/)
  expect(wrongToken.transferTokens).not.toHaveBeenCalled()

  const wrongAmount = mockWallet(balanceOf([[CANONICAL, usdb(CANONICAL)]]))
  await expect(
    sendUsdbFromPot({
      mnemonic: fakePhrase(),
      destination,
      amountCents: 25,
      network: 'MAINNET',
      tokenIdentifier: CANONICAL,
      tokenAmount: 249_999,
    }),
  ).rejects.toThrow(/does not match amountCents/)
  expect(wrongAmount.transferTokens).not.toHaveBeenCalled()

  const badAmount = mockWallet(balanceOf([[CANONICAL, usdb(CANONICAL)]]))
  await expect(
    sendUsdbFromPot({
      mnemonic: fakePhrase(),
      destination,
      amountCents: 25,
      network: 'MAINNET',
      tokenIdentifier: CANONICAL,
      tokenAmount: 'not-a-number',
    }),
  ).rejects.toThrow(/tokenAmount is not an integer/)
  expect(badAmount.transferTokens).not.toHaveBeenCalled()
})

test('a token transfer failure is an uncertain broadcast', async () => {
  const wallet = mockWallet(balanceOf([[CANONICAL, usdb(CANONICAL)]]))
  wallet.transferTokens.mockRejectedValueOnce(new Error('socket closed'))
  await expect(
    sendUsdbFromPot({
      mnemonic: fakePhrase(),
      destination: encodeSparkAddress(new Uint8Array(33).fill(4)),
      amountCents: 1,
      network: 'MAINNET',
    }),
  ).rejects.toMatchObject({ code: 'BROADCAST_UNCERTAIN' })
  expect(wallet.transfer).not.toHaveBeenCalled()
  expect(wallet.transferTokens).toHaveBeenCalledWith(
    expect.objectContaining({ tokenIdentifier: CANONICAL, tokenAmount: 10_000n }),
  )
})

test('broadcastUsdbFromMnemonic uses the pot account and does not transfer sats', async () => {
  const phrase = fakePhrase()
  const destination = encodeSparkAddress(new Uint8Array(33).fill(9))
  const wallet = mockWallet(balanceOf([[CANONICAL, usdb(CANONICAL)]]))
  const captured = await capture(async () => {
    const sent = await broadcastUsdbFromMnemonic({
      mnemonic: Buffer.from(phrase, 'utf8'),
      accountIndex: 4,
      receiverSparkAddress: destination,
      amountCents: 1,
    })
    expect(sent).toEqual({ txid: 'txid-usdb-1' })
  })
  if (captured.includes(phrase)) throw new Error('phrase leaked to stdio')
  const props = initialize.mock.calls[0]?.[0] as { accountNumber?: number; mnemonicOrSeed?: string }
  const ok = digest(props.mnemonicOrSeed ?? '') === digest(phrase)
  props.mnemonicOrSeed = ''
  expect(ok).toBe(true)
  expect(props.accountNumber).toBe(4)
  expect(wallet.transfer).not.toHaveBeenCalled()
  expect(initialize).toHaveBeenCalledOnce()
})

test('the USDB module does not call SparkSigner.transfer', () => {
  const source = readFileSync(new URL('../src/spark/usdb.ts', import.meta.url), 'utf8')
  expect(source).toMatch(/SparkSigner\.transfer/)
  expect(source).not.toMatch(/\.transfer\s*\(/)
})
