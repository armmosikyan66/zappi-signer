import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, test } from 'vitest'
import {
  defaultApiConfigPath,
  DEFAULT_SIGNER_API_URL,
  loadPinnedApiBaseUrl,
  saveApiBaseUrl,
  signerApiBaseUrl,
} from '../src/config.js'

function tempState(): string {
  return mkdtempSync(join(tmpdir(), 'zappi-api-config-'))
}

let cleanup: string[] = []
afterEach(() => {
  for (const dir of cleanup) rmSync(dir, { recursive: true, force: true })
  cleanup = []
})

function writeConfig(dir: string, body: string): string {
  mkdirSync(dir, { recursive: true })
  const path = join(dir, 'api.json')
  writeFileSync(path, body, { mode: 0o600 })
  return path
}

describe('signerApiBaseUrl', () => {
  test('accepts https and loopback http, strips a trailing slash path', () => {
    expect(signerApiBaseUrl('https://api.zappi.money')).toBe('https://api.zappi.money')
    expect(signerApiBaseUrl('https://api.zappi.money/')).toBe('https://api.zappi.money')
    expect(signerApiBaseUrl('http://127.0.0.1:3011')).toBe('http://127.0.0.1:3011')
    expect(signerApiBaseUrl('http://localhost:3011/base')).toBe('http://localhost:3011/base')
  })

  test('refuses undefined, empty, and public http', () => {
    expect(() => signerApiBaseUrl(undefined)).toThrow('refused to spend')
    expect(() => signerApiBaseUrl('')).toThrow('refused to spend')
    expect(() => signerApiBaseUrl('   ')).toThrow('refused to spend')
    expect(() => signerApiBaseUrl('http://api.example.com')).toThrow('refused to spend')
  })
})

describe('loadPinnedApiBaseUrl', () => {
  test('missing file is undefined', () => {
    const dir = tempState()
    cleanup.push(dir)
    expect(loadPinnedApiBaseUrl({ configPath: join(dir, 'api.json') })).toBeUndefined()
  })

  test('reads a well-formed pin', () => {
    const dir = tempState()
    cleanup.push(dir)
    const path = writeConfig(dir, '{"apiBaseUrl":"https://api-dev.zappi.money"}\n')
    expect(loadPinnedApiBaseUrl({ configPath: path })).toBe('https://api-dev.zappi.money')
  })

  test('malformed, loose, or wrong-shaped files refuse', () => {
    const dir = tempState()
    cleanup.push(dir)
    expect(() => loadPinnedApiBaseUrl({ configPath: writeConfig(dir, 'not json') })).toThrow(
      'signer api config is unreadable',
    )
    expect(() => loadPinnedApiBaseUrl({ configPath: writeConfig(dir, '{"apiBaseUrl":""}') })).toThrow(
      'signer api config is unreadable',
    )
    expect(() =>
      loadPinnedApiBaseUrl({ configPath: writeConfig(dir, '{"apiBaseUrl":"https://ok.example","extra":1}') }),
    ).toThrow('signer api config is unreadable')
    expect(() => loadPinnedApiBaseUrl({ configPath: writeConfig(dir, '["https://ok.example"]') })).toThrow(
      'signer api config is unreadable',
    )
  })

  test('a loose file mode refuses', () => {
    const dir = tempState()
    cleanup.push(dir)
    const path = writeConfig(dir, '{"apiBaseUrl":"https://api-dev.zappi.money"}\n')
    chmodSync(path, 0o644)
    expect(() => loadPinnedApiBaseUrl({ configPath: path })).toThrow()
  })

  test('saveApiBaseUrl round-trips and normalizes', () => {
    const dir = tempState()
    cleanup.push(dir)
    const path = join(dir, 'nested', 'api.json')
    const saved = saveApiBaseUrl({ apiBaseUrl: 'https://api-dev.zappi.money/', configPath: path })
    expect(saved.apiBaseUrl).toBe('https://api-dev.zappi.money')
    expect(loadPinnedApiBaseUrl({ configPath: path })).toBe('https://api-dev.zappi.money')
  })

  test('saveApiBaseUrl refuses a public http origin', () => {
    const dir = tempState()
    cleanup.push(dir)
    expect(() => saveApiBaseUrl({ apiBaseUrl: 'http://api.example.com', configPath: join(dir, 'api.json') })).toThrow(
      'refused to spend',
    )
  })

  test('default path sits in the signer state dir', () => {
    expect(defaultApiConfigPath({}, 'darwin')).toContain('.zappi-signer')
    expect(defaultApiConfigPath({}, 'darwin')).toMatch(/api\.json$/)
  })

  test('the built-in default is the production origin', () => {
    expect(DEFAULT_SIGNER_API_URL).toBe('https://api.zappi.money')
  })
})
