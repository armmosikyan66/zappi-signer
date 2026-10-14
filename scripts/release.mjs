#!/usr/bin/env node
/**
 * release.mjs — cut a zappi-signer release in one command.
 *
 *   npm run release              # patch bump (0.1.3 -> 0.1.4)
 *   npm run release -- minor     # 0.1.3 -> 1.0.0
 *   npm run release -- 0.2.0     # explicit version
 *
 * Spans two git repos:
 *   1. packages/zappi-signer (this repo): bump package.json, commit, tag
 *      zappi-signer-v<version>, push. The tag triggers
 *      .github/workflows/zappi-signer-release.yml, which builds every target,
 *      runs the release smoke test on the real artifacts, signs, and publishes
 *      the GitHub release the installer downloads from.
 *   2. ../web (the web/app repo, staging branch develop): re-pin the one-line
 *      installer (web/install/signer.sh: RELEASE_TAG + MIN_VERSION) so end
 *      users without npm/node get the fixed binary, commit, and push to
 *      develop — which is what deploys dev.zappi.money/signer/install.
 */
import { spawnSync } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const pkgRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const pkgPath = join(pkgRoot, 'package.json')
const webRoot = join(pkgRoot, '..', '..', 'web')
const installerRel = 'install/signer.sh'
const installerPath = join(webRoot, installerRel)
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
const webStatus = git(webRoot, ['status', '--porcelain', installerRel])
if (webStatus !== '') die(`${installerRel} has uncommitted changes in the web repo:\n${webStatus}\nCommit or stash first.`)

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
const oldTag = `zappi-signer-v${prevVersion}`

// Re-pin the one-line installer so users WITHOUT npm/node (its only runtime
// requirements are sh, curl/wget, and openssl) download the new release.
let installer = readFileSync(installerPath, 'utf8')
const before = installer
installer = installer
  .replaceAll(`RELEASE_TAG="${oldTag}"`, `RELEASE_TAG="${tag}"`)
  .replaceAll(`MIN_VERSION="${prevVersion}"`, `MIN_VERSION="${next}"`)
if (installer === before) die(`could not re-pin ${installerPath} — expected RELEASE_TAG="${oldTag}" and MIN_VERSION="${prevVersion}"`)
writeFileSync(installerPath, installer)

// 1. Signer repo: version bump commit + tag; the tag starts the release build.
pkg.version = next
writeFileSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`)
git(pkgRoot, ['add', 'package.json'])
git(pkgRoot, ['commit', '-m', `release: zappi-signer ${tag}`])
git(pkgRoot, ['tag', tag])
const branch = git(pkgRoot, ['rev-parse', '--abbrev-ref', 'HEAD'])
git(pkgRoot, ['push', 'origin', `HEAD:${branch}`, tag])
console.log(`[release] ${tag} pushed to ${branch} — CI builds, smoke-tests, signs, and publishes the release.`)

// 2. Web repo: the re-pinned installer, deployed to dev/staging by a push to develop.
const webBranch = git(webRoot, ['rev-parse', '--abbrev-ref', 'HEAD'])
git(webRoot, ['add', installerRel])
git(webRoot, ['commit', '-m', `release: pin signer installer to ${tag}`])
git(webRoot, ['push', 'origin', `HEAD:${webBranch}`])
console.log(`[release] installer re-pinned to ${tag} and pushed to web ${webBranch} — dev.zappi.money/signer/install serves the new version once that deploy lands.`)
console.log(`[release] watch signer CI: gh run watch $(gh -R armmosikyan66/zappi-signer run list --workflow=zappi-signer-release.yml --limit 1 --json databaseId -q '.[0].databaseId')`)
