#!/usr/bin/env node
/**
 * sign-release.mjs — sign a zappi-signer release artifact with the publisher
 * Ed25519 release key.
 *
 *   node scripts/sign-release.mjs                       # sign the target binary
 *   node scripts/sign-release.mjs dist/bin/macos-keychain
 *   node scripts/sign-release.mjs <file> --provenance   # also write provenance.json
 *
 * Inputs:
 *   ZAPPI_SIGNER_RELEASE_KEY — base64 of a 64-byte Ed25519 secret
 *   (seed(32) || public-key(32)). Only present in CI as a repo secret; never
 *   committed, never logged.
 *   ZAPPI_SIGNER_VERSION, ZAPPI_SIGNER_COMMIT_SHA — provenance fields (both
 *   fall back to package.json version / `git rev-parse HEAD`).
 *
 * Outputs next to the file:
 *   <file>.sig      — base64 raw Ed25519 signature (64 bytes), verified by the
 *                     installer with `openssl pkeyutl -verify -rawin`.
 *   <file>.sha256   — "<hex>  <basename>".
 *   <file>.provenance.json — { artifact, version, target, commitSha,
 *                     binarySha256, signedAt }. The installer parses
 *                     "version" and "binarySha256" out of this file.
 *
 * Default-deny: without ZAPPI_SIGNER_RELEASE_KEY the script exits non-zero
 * and writes nothing. An unsigned release is never produced.
 */
import crypto from 'node:crypto'
import { execSync } from 'node:child_process'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const pkgRoot = join(dirname(fileURLToPath(import.meta.url)), '..')

const TARGET_MAP = {
  'darwin-arm64': 'darwin-arm64',
  'darwin-x64': 'darwin-x64',
  'linux-x64': 'linux-x64',
  'linux-arm64': 'linux-arm64',
  'win-x64': 'win-x64',
}

function detectTarget() {
  const env = process.env.TARGET?.trim()
  if (env) {
    const t = TARGET_MAP[env.toLowerCase()]
    if (!t) throw new Error(`Unknown TARGET "${env}"`)
    return t
  }
  const key = `${process.platform === 'win32' ? 'win' : process.platform}-${process.arch}`
  const t = TARGET_MAP[key]
  if (!t) throw new Error(`Unsupported host ${key}. Set TARGET explicitly.`)
  return t
}

function defaultBinary(target) {
  const ext = target === 'win-x64' ? '.exe' : ''
  return join(pkgRoot, 'dist', 'bin', `zappi-signer-${target}${ext}`)
}

function importPrivateKey(base64Key) {
  const raw = Buffer.from(base64Key, 'base64')
  if (raw.length !== 64) {
    throw new Error('ZAPPI_SIGNER_RELEASE_KEY must be base64 of a 64-byte Ed25519 secret (seed||pub)')
  }
  return crypto.createPrivateKey({
    key: {
      kty: 'OKP',
      crv: 'Ed25519',
      d: raw.subarray(0, 32).toString('base64url'),
      x: raw.subarray(32, 64).toString('base64url'),
    },
    format: 'jwk',
  })
}

function readVersion() {
  const env = process.env.ZAPPI_SIGNER_VERSION?.trim()
  const raw = env || JSON.parse(readFileSync(join(pkgRoot, 'package.json'), 'utf8')).version
  return raw.replace(/^zappi-signer-v/, '').replace(/^v/, '')
}

function readCommitSha() {
  const env = process.env.ZAPPI_SIGNER_COMMIT_SHA?.trim()
  if (env) return env
  try {
    return execSync('git rev-parse HEAD', { cwd: pkgRoot }).toString().trim()
  } catch {
    return 'unknown'
  }
}

function fail(message) {
  console.error(`sign-release: ${message}`)
  process.exit(1)
}

const args = process.argv.slice(2)
const provenance = args.includes('--provenance')
const fileArg = args.find((a) => !a.startsWith('--'))
const target = detectTarget()
const file = fileArg ? (fileArg.includes('/') ? fileArg : join(process.cwd(), fileArg)) : defaultBinary(target)

if (!existsSync(file)) fail(`${file} not found. Run scripts/build-bin.mjs first.`)

const keyEnv = process.env.ZAPPI_SIGNER_RELEASE_KEY?.trim()
if (!keyEnv) fail('ZAPPI_SIGNER_RELEASE_KEY is not set. Refusing to produce an unsigned release.')

let privateKey
try {
  privateKey = importPrivateKey(keyEnv)
} catch (error) {
  fail(error instanceof Error ? error.message : String(error))
}

const data = readFileSync(file)
const sig = crypto.sign(null, data, privateKey).toString('base64')
const sha256 = crypto.createHash('sha256').update(data).digest('hex')

writeFileSync(`${file}.sig`, `${sig}\n`)
writeFileSync(`${file}.sha256`, `${sha256}  ${basename(file)}\n`)
console.log(`sign-release: signed ${file}`)
console.log(`sign-release: sha256 ${sha256}`)

if (provenance) {
  const record = {
    artifact: basename(file),
    version: readVersion(),
    target,
    commitSha: readCommitSha(),
    binarySha256: sha256,
    signedAt: new Date().toISOString(),
  }
  writeFileSync(`${file}.provenance.json`, `${JSON.stringify(record, null, 2)}\n`)
  console.log(`sign-release: wrote ${file}.provenance.json (version ${record.version})`)
}