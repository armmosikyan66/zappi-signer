import { expect, test } from 'vitest'
import { SignerBackendClient, setPotClientToken, POT_CLIENT_HEADER, type SpendReceiptStatus } from '../src/client.js'
import { SIGNER_API_URL_ENV } from '../src/config.js'
import { PotError, publicMessage } from '../src/errors.js'
import { MemoryKeyStore } from '../src/keystore/memory.js'
import { potClientTokenAccount, DEVICE_TOKEN_ACCOUNT } from '../src/keystore/types.js'

const POT_ID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
const REQUEST_ID = '11111111-2222-4333-8444-555555555555'
const APPROVAL_ID = '22222222-3333-4444-8555-666666666666'
const INTENT_ID = '33333333-4444-4555-8666-777777777777'
const TOKEN = 'zpc_testtokenvalue_do_not_leak'
const DECOY = 'decoy-device-token-not-used'
const QUERY_SECRET = 'query-secret-do-not-leak'
const BODY_SECRET = 'body-secret-do-not-leak'
const TXID = 'ab'.repeat(32)
const BASE = 'https://signer.example'
const ACCOUNT = `pot-client-token-${POT_ID}`

type Call = { url: string; init: RequestInit }

function recordedFetch(
  handler: (url: string, init: RequestInit) => Response | Promise<Response>,
): { fetchImpl: typeof fetch; calls: Call[] } {
  const calls: Call[] = []
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const request = init ?? {}
    calls.push({ url, init: request })
    return handler(url, request)
  }) as typeof fetch
  return { fetchImpl, calls }
}

function clientFor(fetchImpl: typeof fetch, baseUrl = `${BASE}/`): SignerBackendClient {
  return new SignerBackendClient({
    keystore: new MemoryKeyStore(),
    fetch: fetchImpl,
    baseUrl,
    timeoutMs: 1_000,
  })
}

function headerRecord(init: RequestInit): Record<string, string> {
  const headers = init.headers
  if (!headers || headers instanceof Headers || Array.isArray(headers)) {
    throw new Error('expected a header record')
  }
  return headers
}

function spendRequestBody() {
  return {
    requestId: REQUEST_ID,
    approvalId: APPROVAL_ID,
    potId: POT_ID,
    amountCents: 1250,
    receiverSparkAddress: 'spark1pgtestaddress',
    network: 'MAINNET' as const,
    status: 'authorization_required' as const,
  }
}

function authorizationBody() {
  return {
    intent: {
      v: 1 as const,
      intentId: INTENT_ID,
      potId: POT_ID,
      kind: 'spark_transfer',
      payload: { to: 'spark1pgtestaddress', amountCents: 1250 },
      nonce: 'nonce-1',
      expiresAt: '2026-10-13T12:00:00.000Z',
      keyId: 'backend-secp256k1-v1',
      backendSig: 'sig-intent',
    },
    lock: {
      decision: 'open' as const,
      nonce: 'lock-nonce',
      expiresAt: '2026-10-13T12:00:00.000Z',
      keyId: 'backend-secp256k1-v1',
      backendSig: 'sig-lock',
    },
  }
}

function trustBody() {
  return {
    keys: { 'backend-secp256k1-v1': `02${'ab'.repeat(32)}` },
    activeKeyId: 'backend-secp256k1-v1',
    addressChallengePubkey: `03${'cd'.repeat(32)}`,
  }
}

function refusalMessage(error: unknown): string {
  expect(error).toBeInstanceOf(PotError)
  if (!(error instanceof PotError)) throw new Error('expected refusal')
  expect(error.message).toBe('refused to spend')
  expect(publicMessage(error)).toBe('refused to spend')
  return error.message
}

test('accepts an https base URL and reads a client spend request', async () => {
  const { fetchImpl, calls } = recordedFetch(() => Response.json(spendRequestBody()))
  const keystore = new MemoryKeyStore()
  await keystore.setSecret(ACCOUNT, TOKEN)
  const api = new SignerBackendClient({
    keystore,
    fetch: fetchImpl,
    baseUrl: `${BASE}/`,
    timeoutMs: 1_000,
  })
  const view = await api.getClientSpendRequest(POT_ID, REQUEST_ID)
  expect(view).toEqual(spendRequestBody())
  const call = calls[0]
  if (!call) throw new Error('missing call')
  expect(call.url).toBe(`${BASE}/api/wallet/pots/client-spend-requests/${REQUEST_ID}`)
  expect(call.url.startsWith('https://')).toBe(true)
  expect(call.init.method).toBe('GET')
})

test('reads ZAPPI_SIGNER_API_URL when baseUrl is omitted', async () => {
  const { fetchImpl, calls } = recordedFetch(() => Response.json(trustBody()))
  const api = new SignerBackendClient({
    keystore: new MemoryKeyStore(),
    fetch: fetchImpl,
    env: { [SIGNER_API_URL_ENV]: 'https://from-env.example' },
    timeoutMs: 1_000,
  })
  const trust = await api.getSignerTrust()
  expect(trust.activeKeyId).toBe('backend-secp256k1-v1')
  const call = calls[0]
  if (!call) throw new Error('missing call')
  expect(call.url).toBe('https://from-env.example/api/signer/trust')
})

test('accepts loopback http for a local Nest and still refuses public http', async () => {
  const { fetchImpl, calls } = recordedFetch(() => Response.json(trustBody()))
  const api = new SignerBackendClient({
    keystore: new MemoryKeyStore(),
    fetch: fetchImpl,
    baseUrl: 'http://127.0.0.1:3011',
    timeoutMs: 1_000,
  })
  await api.getSignerTrust()
  expect(calls[0]?.url).toBe('http://127.0.0.1:3011/api/signer/trust')

  const local = new SignerBackendClient({
    keystore: new MemoryKeyStore(),
    fetch: fetchImpl,
    env: { [SIGNER_API_URL_ENV]: 'http://localhost:3011/' },
    timeoutMs: 1_000,
  })
  await local.getSignerTrust()
  expect(calls[1]?.url).toBe('http://localhost:3011/api/signer/trust')
})

test('rejects http and any non-https URL before a request', () => {
  const calls: string[] = []
  const fetchImpl = (() => {
    calls.push('called')
    return Promise.resolve(Response.json({}))
  }) as typeof fetch
  const urls = [
    `http://signer.example/api?token=${QUERY_SECRET}`,
    'HTTP://signer.example',
    'http://127.0.0.1.evil.example',
    'http://2130706433',
    `http://127.0.0.1:3011/?token=${QUERY_SECRET}`,
    'ws://signer.example',
    'file:///tmp/signer',
    `https://user:${QUERY_SECRET}@signer.example`,
    `https://signer.example/path?token=${QUERY_SECRET}`,
    `https://signer.example/path#${QUERY_SECRET}`,
  ]
  for (const baseUrl of urls) {
    let caught: unknown
    try {
      clientFor(fetchImpl, baseUrl)
    } catch (error) {
      caught = error
    }
    const message = refusalMessage(caught)
    expect(message).not.toContain(QUERY_SECRET)
    expect(message).not.toContain('http://')
  }
  expect(calls).toEqual([])
})

test('refuses a non-2xx response without echoing the body or token', async () => {
  const { fetchImpl, calls } = recordedFetch(
    () => new Response(JSON.stringify({ token: TOKEN, detail: BODY_SECRET }), { status: 401 }),
  )
  const keystore = new MemoryKeyStore()
  await keystore.setSecret(ACCOUNT, TOKEN)
  const api = new SignerBackendClient({
    keystore,
    fetch: fetchImpl,
    baseUrl: BASE,
    timeoutMs: 1_000,
  })
  let caught: unknown
  try {
    await api.getClientSpendRequest(POT_ID, REQUEST_ID)
  } catch (error) {
    caught = error
  }
  const message = refusalMessage(caught)
  expect(message).not.toContain(TOKEN)
  expect(message).not.toContain(BODY_SECRET)
  const call = calls[0]
  if (!call) throw new Error('missing call')
  expect(call.url).not.toContain(TOKEN)
  expect(call.url).not.toContain('?')
})

test('loads x-zappi-pot-client from pot-client-token-<potId> and keeps it out of the URL', async () => {
  expect(potClientTokenAccount(POT_ID)).toBe(ACCOUNT)
  expect(potClientTokenAccount(POT_ID.toUpperCase())).toBe(ACCOUNT)
  const { fetchImpl, calls } = recordedFetch((url, init) => {
    if (url.endsWith(`/client-spend-requests/${REQUEST_ID}`)) return Response.json(spendRequestBody())
    if (url.endsWith('/spend-authorizations')) {
      expect(JSON.parse(String(init.body))).toEqual({
        approvalId: APPROVAL_ID,
        idempotencyKey: REQUEST_ID,
      })
      return Response.json(authorizationBody(), { status: 201 })
    }
    return new Response('no route', { status: 500 })
  })
  const keystore = new MemoryKeyStore()
  const api = new SignerBackendClient({
    keystore,
    fetch: fetchImpl,
    baseUrl: BASE,
    timeoutMs: 1_000,
  })
  await expect(api.getClientSpendRequest(POT_ID, REQUEST_ID)).rejects.toThrow('refused to spend')
  expect(calls).toHaveLength(0)

  await setPotClientToken(keystore, POT_ID, `  ${TOKEN}  `)
  await keystore.setSecret(DEVICE_TOKEN_ACCOUNT, DECOY)
  expect(await keystore.getSecret(ACCOUNT)).toBe(TOKEN)

  const view = await api.getClientSpendRequest(POT_ID.toUpperCase(), REQUEST_ID.toUpperCase())
  expect(view.status).toBe('authorization_required')
  const lookup = calls[0]
  if (!lookup) throw new Error('missing lookup')
  expect(lookup.url).toBe(`${BASE}/api/wallet/pots/client-spend-requests/${REQUEST_ID}`)
  expect(lookup.url).not.toContain(TOKEN)
  expect(lookup.url).not.toContain(DECOY)
  const headers = headerRecord(lookup.init)
  expect(headers[POT_CLIENT_HEADER]).toBe(TOKEN)
  expect(Object.hasOwn(headers, POT_CLIENT_HEADER)).toBe(true)
  expect(headers[POT_CLIENT_HEADER]).not.toBe(DECOY)
  expect(JSON.stringify(headers)).not.toContain(DECOY)

  const issued = await api.createSpendAuthorization(POT_ID, {
    approvalId: APPROVAL_ID,
    idempotencyKey: REQUEST_ID,
  })
  expect(issued.intent.intentId).toBe(INTENT_ID)
  expect(issued.lock.decision).toBe('open')
  const authorize = calls[1]
  if (!authorize) throw new Error('missing authorization')
  expect(authorize.url).toBe(`${BASE}/api/wallet/pots/${POT_ID}/spend-authorizations`)
  expect(authorize.init.method).toBe('POST')
  expect(authorize.url).not.toContain(TOKEN)
  expect(headerRecord(authorize.init)[POT_CLIENT_HEADER]).toBe(TOKEN)
})

test('GETs signer trust without the pot client token', async () => {
  const { fetchImpl, calls } = recordedFetch(() => Response.json(trustBody()))
  const keystore = new MemoryKeyStore()
  await keystore.setSecret(ACCOUNT, TOKEN)
  const api = new SignerBackendClient({
    keystore,
    fetch: fetchImpl,
    baseUrl: BASE,
    timeoutMs: 1_000,
  })
  const trust = await api.getSignerTrust()
  expect(trust).toEqual(trustBody())
  const call = calls[0]
  if (!call) throw new Error('missing call')
  expect(call.url).toBe(`${BASE}/api/signer/trust`)
  expect(call.init.method).toBe('GET')
  expect(call.url).not.toContain(TOKEN)
  expect(headerRecord(call.init)[POT_CLIENT_HEADER]).toBeUndefined()
  expect(new Headers(call.init.headers).has(POT_CLIENT_HEADER)).toBe(false)
})

test('posts spend receipt statuses submitted, confirmed, and uncertain', async () => {
  const seen: unknown[] = []
  const { fetchImpl, calls } = recordedFetch((_url, init) => {
    const sent = JSON.parse(String(init.body)) as { status: string; txid?: string }
    seen.push(sent)
    return Response.json({
      intentId: INTENT_ID,
      status: sent.status === 'uncertain' ? 'uncertain' : 'receipted',
      txid: sent.txid ?? null,
      receiptStatus: sent.status,
    })
  })
  const keystore = new MemoryKeyStore()
  await keystore.setSecret(ACCOUNT, TOKEN)
  const api = new SignerBackendClient({
    keystore,
    fetch: fetchImpl,
    baseUrl: BASE,
    timeoutMs: 1_000,
  })
  const statuses: SpendReceiptStatus[] = ['submitted', 'confirmed', 'uncertain']
  for (const status of statuses) {
    const receipt = await api.postSpendReceipt(POT_ID, {
      intentId: INTENT_ID,
      txid: `0x${TXID.toUpperCase()}`,
      status,
    })
    expect(receipt.intentId).toBe(INTENT_ID)
    expect(receipt.receiptStatus).toBe(status)
  }
  expect(seen).toEqual(
    statuses.map((status) => ({
      intentId: INTENT_ID,
      status,
      txid: TXID,
    })),
  )
  for (const call of calls) {
    expect(call.url).toBe(`${BASE}/api/wallet/pots/${POT_ID}/spend-receipts`)
    expect(call.init.method).toBe('POST')
    expect(call.url).not.toContain(TOKEN)
    expect(headerRecord(call.init)[POT_CLIENT_HEADER]).toBe(TOKEN)
  }

  const before = calls.length
  await expect(
    api.postSpendReceipt(POT_ID, { intentId: INTENT_ID, status: 'uncertain' }),
  ).resolves.toMatchObject({ receiptStatus: 'uncertain', txid: null })
  const omitted = seen[seen.length - 1]
  expect(omitted).toEqual({ intentId: INTENT_ID, status: 'uncertain' })
  expect(calls.length).toBe(before + 1)

  await expect(
    api.postSpendReceipt(POT_ID, { intentId: INTENT_ID, status: 'submitted' }),
  ).rejects.toThrow('refused to spend')
  await expect(
    api.postSpendReceipt(POT_ID, {
      intentId: INTENT_ID,
      txid: TXID,
      status: 'nope' as SpendReceiptStatus,
    }),
  ).rejects.toThrow('refused to spend')
  expect(calls.length).toBe(before + 1)
})

test('a timeout or network failure refuses to spend', async () => {
  const hanging = ((_url: string, init?: RequestInit) =>
    new Promise<Response>((_resolve, reject) => {
      const signal = init?.signal
      if (!signal) {
        reject(new Error('missing abort signal'))
        return
      }
      const onAbort = () => reject(new Error('aborted'))
      if (signal.aborted) onAbort()
      else signal.addEventListener('abort', onAbort, { once: true })
    })) as typeof fetch
  const slow = new SignerBackendClient({
    keystore: new MemoryKeyStore(),
    fetch: hanging,
    baseUrl: BASE,
    timeoutMs: 30,
  })
  let timedOut: unknown
  try {
    await slow.getSignerTrust()
  } catch (error) {
    timedOut = error
  }
  const timeoutMessage = refusalMessage(timedOut)
  expect(timeoutMessage).not.toContain(BASE)

  const leaked = `connect ECONNREFUSED ${TOKEN} https://signer.example/api?token=${QUERY_SECRET}`
  const failing = (() => Promise.reject(new TypeError(leaked))) as typeof fetch
  const offline = clientFor(failing, BASE)
  let failed: unknown
  try {
    await offline.getSignerTrust()
  } catch (error) {
    failed = error
  }
  const message = refusalMessage(failed)
  expect(message).not.toContain(TOKEN)
  expect(message).not.toContain(QUERY_SECRET)
})
