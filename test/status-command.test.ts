import { expect, test } from 'vitest'
import { type ClientSpendRequestResponse } from '../src/client.js'
import { runStatus, type StatusClient } from '../src/commands/status.js'

const REQUEST_ID = '11111111-2222-4333-8444-555555555555'
const APPROVAL_ID = '33333333-3333-4333-8333-333333333333'
const POT_ID = '22222222-2222-4222-8222-222222222222'
const ADDRESS = 'spark1pgssyele0qrcjdheeq2a0zmpwdwvj3r4f4stkuju0fp36g6grapv2w7l8am2cp'

test('status returns authorization_required without posting an authorization', async () => {
  const calls: Array<{ method: string; path: string; body?: unknown }> = []
  const client: StatusClient = {
    async request(method, path, body) {
      calls.push({ method, path, body })
      if (path.includes('spend-authorizations')) throw new Error('authorization posted')
      const payload: ClientSpendRequestResponse & { signCommand: string; backendSig: string; token: string } = {
        requestId: REQUEST_ID,
        approvalId: APPROVAL_ID,
        potId: POT_ID,
        amountCents: 2500,
        receiverSparkAddress: ADDRESS,
        network: 'MAINNET',
        status: 'authorization_required',
        signCommand: `zappi sign ${REQUEST_ID}`,
        backendSig: 'secret-backend-sig',
        token: 'zpc_do_not_leak',
      }
      return payload
    },
  }

  const result = await runStatus({ client, requestId: REQUEST_ID })

  expect(result).toEqual({
    requestId: REQUEST_ID,
    approvalId: APPROVAL_ID,
    potId: POT_ID,
    amountCents: 2500,
    receiverSparkAddress: ADDRESS,
    network: 'MAINNET',
    status: 'authorization_required',
  })
  expect(Object.keys(result).sort()).toEqual([
    'amountCents',
    'approvalId',
    'network',
    'potId',
    'receiverSparkAddress',
    'requestId',
    'status',
  ])
  expect(JSON.stringify(result)).not.toContain('backendSig')
  expect(JSON.stringify(result)).not.toContain('zpc_do_not_leak')
  expect(JSON.stringify(result)).not.toContain('signCommand')
  expect(calls).toEqual([
    {
      method: 'GET',
      path: `/api/wallet/pots/client-spend-requests/${REQUEST_ID}`,
      body: undefined,
    },
  ])
})
