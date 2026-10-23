#!/usr/bin/env node
/**
 * release.mjs — cut a zappi-signer release in one command.
 *
 *   npm run release              # patch bump (0.1.3 -> 0.1.4)
 *   npm run release -- minor     # 0.1.3 -> 1.0.0
 *   npm run release -- 0.2.0     # explicit version
 *
 * This repo only: bump package.json, commit, tag zappi-signer-v<version>,
 * and push. The tag triggers .github/workflows/zappi-signer-release.yml,
 * which builds every target, runs the release smoke test on the real
 * artifacts, signs, and publishes the GitHub release.
 *
 * It does not read or write a shell installer in another repo, and it does
 * not download a public install script.
 */
import { spawnSync } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const pkgRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const pkgPath = join(pkgRoot, 'package.json')
const bump = process.argv[2] ?? 'patch'

function git(cwd, args) {
  const result = spawnSync('git', args, { cwd, encoding: 'utf8' })
  if (result.status !== 0) {
    console.error(`[release] git ${args.join(' ')} failed:\n${result.stderr?.trim() || result.stdout?.trim()}`)
    process.exit(result.status ?? 1)
  }
  return result.stdout.trim()
}

function die(message) {
  console.error(`[release] ${message}`)
  process.exit(1)
}

const signerStatus = git(pkgRoot, ['status', '--porcelain'])
if (signerStatus !== '') die(`signer working tree is not clean:\n${signerStatus}\nCommit or stash first — the release commit contains only the version bump.`)

const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'))
const prevVersion = pkg.version
let next = bump
if (!/^\d+\.\d+\.\d+$/.test(next)) {
  const parts = prevVersion.split('.').map(Number)
  if (bump === 'patch') next = `${parts[0]}.${parts[1]}.${parts[2] + 1}`
  else if (bump === 'minor') next = `${parts[0]}.${Number(parts[1]) + 1}.0`
  else if (bump === 'major') next = `${Number(parts[0]) + 1}.0.0`
  else die(`unknown bump "${bump}" — use patch | minor | major | <semver>`)
}
if (next === prevVersion) die(`version is already ${next}`)

const tag = `zappi-signer-v${next}`

pkg.version = next
writeFileSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`)
git(pkgRoot, ['add', 'package.json'])
git(pkgRoot, ['commit', '-m', `release: zappi-signer ${tag}`])
git(pkgRoot, ['tag', tag])
const branch = git(pkgRoot, ['rev-parse', '--abbrev-ref', 'HEAD'])
git(pkgRoot, ['push', 'origin', `HEAD:${branch}`, tag])
console.log(`[release] ${tag} pushed to ${branch} — CI builds, smoke-tests, signs, and publishes the release.`)
console.log(`[release] watch signer CI: gh run watch $(gh -R armmosikyan66/zappi-signer run list --workflow=zappi-signer-release.yml --limit 1 --json databaseId -q '.[0].databaseId')`)
