#!/usr/bin/node
/**
 * smoke-bin.mjs — smoke-test a built standalone signer binary.
 *
 *   node scripts/smoke-bin.mjs dist/bin/zappi-signer-darwin-arm64 [timeoutMs]
 *
 * Runs the wallet-first `provision <potId>` path, which performs the full
 * Spark gRPC initialization (the step the Bun-compiled binary failed on;
 * see docs/agent.md) but makes no Zappi backend calls. HOME is pointed at a
 * scratch directory so the real vault is never touched. On success the
 * binary has created one keychain item (service `zappi-signer`) in the
 * running user's keychain — fine on ephemeral CI runners.
 *
 * Exits 0 when the binary returns a usable wallet, 1 otherwise. Skips with
 * exit 0 on Linux CI runners (no secret service for the keyring) and refuses
 * on any machine that already has a real vault (the keychain is shared and a
 * scratch run would corrupt its rollback guard).
 */
import { spawn } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'

const bin = process.argv[2]
const timeoutMs = Number(process.argv[3] ?? 120_000)
if (!bin || !existsSync(bin)) {
  console.error(`[smoke-bin] binary not found: ${bin ?? '(missing argument)'}`)
  process.exit(2)
}
if (process.platform === 'linux' && !process.env.ZAPPI_SMOKE_FORCE) {
  console.log('[smoke-bin] SKIP: linux CI has no secret service for the keyring')
  process.exit(0)
}
// The keychain is user-scoped, not HOME-scoped: on a machine with a real
// vault, the scratch run would reuse the real unlock secret and bump the
// shared high-water mark, bricking the real vault ("vault rollback refused").
// Only ephemeral CI runners (no existing vault/keychain item) may run this.
const { homedir } = await import('node:os')
const realVault =
  process.platform === 'win32'
    ? join(process.env.APPDATA ?? join(homedir(), 'AppData', 'Roaming'), 'zappi-signer', 'seed-vault.json')
    : join(homedir(), '.zappi-signer', 'seed-vault.json')
if (existsSync(realVault)) {
  console.error('[smoke-bin] REFUSED: a real vault exists on this machine; run this only on a clean CI runner')
  process.exit(2)
}

const home = mkdtempSync(join(tmpdir(), 'zappi-smoke-'))
const env = { ...process.env, HOME: home }
delete env.ZAPPI_SIGNER_DEBUG
if (process.platform === 'win32') {
  env.USERPROFILE = home
  env.APPDATA = join(home, 'appdata')
}

// Probe the darwin keychain helper first: the smoke run needs a working
// keychain WRITE (provision creates the unlock secret), and a locked or
// unavailable keychain otherwise masquerades as "item missing" on reads and
// only fails 60s later deep inside provision. A throwaway account name keeps
// the real zappi-signer items untouched.
if (process.platform === 'darwin') {
  const helper = env.ZAPPI_SIGNER_KEYCHAIN_HELPER
  if (!helper || !existsSync(helper)) {
    console.error(`[smoke-bin] FAIL: darwin keychain helper not found: ${helper ?? '(unset)'}`)
    process.exit(1)
  }
  const probe = (op, input) =>
    new Promise((resolve) => {
      const p = spawn(helper, [op, 'zappi-smoke-probe'], { stdio: [input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'] })
      let out = ''
      let err = ''
      if (input !== undefined) {
        p.stdin.write(input)
        p.stdin.end()
      }
      p.stdout.on('data', (c) => (out += c))
      p.stderr.on('data', (c) => (err += c))
      p.on('close', (code) => resolve({ code, out, err }))
      p.on('error', (e) => resolve({ code: -1, out, err: `${err}${e.message}` }))
    })
  const started = Date.now()
  const set = await probe('set', 'smoke-probe-secret')
  if (set.code !== 0) {
    console.error(`[smoke-bin] FAIL: keychain write probe failed (exit ${set.code}) — ${set.err.trim() || '(no stderr)'}`)
    process.exit(1)
  }
  const get = await probe('get')
  if (get.code !== 0 || get.out.toString() !== 'smoke-probe-secret') {
    console.error(`[smoke-bin] FAIL: keychain read probe failed (exit ${get.code}) — ${get.err.trim() || '(no stderr)'}`)
    process.exit(1)
  }
  await probe('delete')
  console.log(`[smoke-bin] keychain probe ok (${Date.now() - started}ms)`)
}

const potId = randomUUID()
const child = spawn(bin, ['provision', potId, '--json'], { env, stdio: ['ignore', 'pipe', 'pipe'] })
let stdout = ''
let stderr = ''
const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs)
child.stdout.on('data', (chunk) => {
  stdout += chunk
})
child.stderr.on('data', (chunk) => {
  stderr += chunk
})
child.on('error', (error) => fail(`spawn failed: ${error.message}`))
child.on('close', (code) => {
  clearTimeout(timer)
  if (code !== 0) fail(`exit ${code}`, stderr)
  let parsed
  try {
    parsed = JSON.parse(stdout)
  } catch {
    fail(`stdout is not JSON: ${stdout.slice(0, 200)}`, stderr)
  }
  const problems = []
  if (parsed.potId !== potId) problems.push('potId mismatch')
  if (!/^prov_[0-9a-f]{16}$/.test(parsed.provisionId ?? '')) problems.push('provisionId malformed')
  if (!/^spark1/.test(parsed.address ?? '')) problems.push('address missing or not mainnet spark1')
  if (!/^(02|03)[0-9a-fA-F]{64}$/.test(parsed.pubkey ?? '')) problems.push('pubkey malformed')
  if (problems.length > 0) fail(problems.join('; '), stderr)
  console.log(`[smoke-bin] PASS: provision returned a usable wallet (${parsed.address.slice(0, 12)}…)`)
  process.exit(0)
})

function fail(reason, stderr = '') {
  rmSync(home, { recursive: true, force: true })
  const cause = stderr.trim() ? ` — stderr: ${stderr.trim().slice(0, 300)}` : ''
  console.error(`[smoke-bin] FAIL: ${reason}${cause}`)
  process.exit(1)
}
