#!/usr/bin/env node
/**
 * build-bin.mjs — build the standalone zappi-signer binary for one target.
 *
 *   node scripts/build-bin.mjs            # target from host
 *   TARGET=linux-x64 node scripts/build-bin.mjs
 *
 * Requires `npm run build` (tsc -> dist/index.js) to have run first.
 *
 * Steps:
 *   1. Embed the @napi-rs/keyring native bindings as base64 and generate a
 *      loader shim that dlopens them from a private temp dir at runtime
 *      (the user machine has no node_modules).
 *   2. Bundle dist/index.js into one CJS file with esbuild, aliasing
 *      @napi-rs/keyring to that shim, and define
 *      process.env.ZAPPI_SIGNER_STANDALONE = "1".
 *   3. Compile the bundle:
 *      - Bun (preferred): bun build --compile --target=bun-<triple>
 *      - Node SEA (fallback): sea-config + postject injection.
 *
 * Output: dist/bin/zappi-signer-<target>[.exe] (mode 0500).
 */
import { spawnSync } from 'node:child_process'
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'

const __dirname = dirname(fileURLToPath(import.meta.url))
const pkgRoot = join(__dirname, '..')
const require = createRequire(import.meta.url)

const TARGETS = {
  'darwin-arm64': { bun: 'bun-darwin-arm64', ext: '' },
  'darwin-x64': { bun: 'bun-darwin-x64', ext: '' },
  'linux-x64': { bun: 'bun-linux-x64', ext: '' },
  'linux-arm64': { bun: 'bun-linux-arm64', ext: '' },
  'win-x64': { bun: 'bun-windows-x64', ext: '.exe' },
}

// Platform packages that must be embedded so the binary can reach the OS
// credential store on every target. darwin uses the keychain helper instead,
// but any installed darwin binding is embedded too so the shim always works.
const REQUIRED_KEYRING_PLATFORMS = [
  'linux-x64-gnu',
  'linux-x64-musl',
  'linux-arm64-gnu',
  'linux-arm64-musl',
  'win32-x64-msvc',
]

const SEA_FUSE = 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2'

function detectTarget() {
  const env = process.env.TARGET
  if (env) {
    const t = env.trim()
    if (!TARGETS[t]) throw new Error(`Unknown TARGET "${t}". Supported: ${Object.keys(TARGETS).join(', ')}`)
    return t
  }
  const key = `${process.platform === 'win32' ? 'win' : process.platform}-${process.arch}`
  if (!TARGETS[key]) throw new Error(`Unsupported host ${key}. Set TARGET explicitly.`)
  return key
}

function run(command, args, opts = {}) {
  // Windows npm and *.cmd shims are not CreateProcess executables. spawn()
  // throws EFTYPE and leaves stdout empty unless a shell launches them.
  const spawnOpts = { stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8', ...opts }
  if (process.platform === 'win32' && !/\.exe$/i.test(command)) spawnOpts.shell = true
  let result
  try {
    result = spawnSync(command, args, spawnOpts)
  } catch (error) {
    const message = error && error.message ? error.message : String(error)
    return { ok: false, missing: error && error.code === 'ENOENT', output: message }
  }
  const output = `${result.error ? `${result.error.message}\n` : ''}${result.stdout ?? ''}${result.stderr ?? ''}`.trim()
  if (result.error && result.error.code === 'ENOENT') return { ok: false, missing: true, output }
  return { ok: result.status === 0, output }
}

/**
 * Collect every available keyring platform binding into one base64 map and
 * generate the runtime loader shim. Platform packages missing from
 * node_modules are installed with --no-save at the exact keyring version.
 */
function generateKeyringShim(outPath) {
  const keyringVersion = JSON.parse(readFileSync(require.resolve('@napi-rs/keyring/package.json'), 'utf8')).version
  const wanted = [...REQUIRED_KEYRING_PLATFORMS, 'darwin-arm64', 'darwin-x64']
  const bindings = {}
  const missing = []
  for (const platform of wanted) {
    const pkg = `@napi-rs/keyring-${platform}`
    let bindingPath = null
    try {
      bindingPath = findNativeBinding(require.resolve(`${pkg}/package.json`))
    } catch {
      missing.push(pkg)
      continue
    }
    bindings[platform] = readFileSync(bindingPath).toString('base64')
  }
  if (missing.length > 0) {
    if (process.env.ZAPPI_SKIP_KEYRING_EMBED === '1') {
      console.warn(`[build-bin] skipping missing keyring bindings: ${missing.join(', ')}`)
    } else {
      console.warn(`[build-bin] installing missing keyring bindings: ${missing.join(', ')}`)
      const install = run('npm', ['install', '--no-save', '--force', ...missing.map((p) => `${p}@${keyringVersion}`)], { cwd: pkgRoot })
      if (!install.ok) throw new Error(`could not install keyring bindings:\n${install.output}`)
      for (const pkg of missing) {
        const bindingPath = findNativeBinding(require.resolve(`${pkg}/package.json`))
        bindings[pkg.replace('@napi-rs/keyring-', '')] = readFileSync(bindingPath).toString('base64')
      }
    }
  }
  if (Object.keys(bindings).length === 0) throw new Error('no keyring bindings could be embedded')
  writeFileSync(outPath, shimSource(bindings))
  return outPath
}

function findNativeBinding(packageJsonPath) {
  const dir = dirname(packageJsonPath)
  for (const entry of readdirSync(dir)) {
    if (entry.endsWith('.node')) return join(dir, entry)
  }
  throw new Error(`no .node binding in ${dir}`)
}

function shimSource(bindings) {
  return `'use strict'
// Generated by scripts/build-bin.mjs. Native @napi-rs/keyring bindings,
// embedded as base64 and dlopened from a private temp directory at runtime.
const BINDINGS = ${JSON.stringify(bindings)}

function isMusl() {
  try {
    if (require('node:fs').readFileSync('/usr/bin/ldd', 'utf8').includes('musl')) return true
  } catch {}
  try {
    const report = process.report && process.report.getReport()
    if (report && !report.header.glibcVersionRuntime) return true
  } catch {}
  return false
}

function candidateTriples() {
  const arch = process.arch
  if (process.platform === 'linux') {
    if (arch !== 'x64' && arch !== 'arm64') return []
    const gnu = \`linux-\${arch}-gnu\`
    const musl = \`linux-\${arch}-musl\`
    return isMusl() ? [musl, gnu] : [gnu, musl]
  }
  if (process.platform === 'win32') return arch === 'x64' ? ['win32-x64-msvc'] : []
  if (process.platform === 'darwin') return arch === 'arm64' ? ['darwin-arm64'] : arch === 'x64' ? ['darwin-x64'] : []
  return []
}

function loadBinding(name) {
  const bytes = Buffer.from(BINDINGS[name], 'base64')
  const dir = require('node:fs').mkdtempSync(require('node:path').join(require('node:os').tmpdir(), 'zappi-keyring-'))
  const file = require('node:path').join(dir, 'keyring.node')
  require('node:fs').writeFileSync(file, bytes, { mode: 0o600 })
  const mod = { exports: {} }
  process.dlopen(mod, file)
  return mod.exports
}

const errors = []
for (const name of candidateTriples()) {
  if (!BINDINGS[name]) continue
  try {
    module.exports = loadBinding(name)
    break
  } catch (error) {
    errors.push(\`\${name}: \${error && error.message ? error.message : error}\`)
  }
}
if (typeof module.exports !== 'object' || module.exports === null || !module.exports.Entry) {
  throw new Error('keychain unavailable' + (errors.length ? \` (\${errors.join('; ')})\` : ''))
}
`
}

async function main() {
  const target = detectTarget()
  const { bun: bunTarget, ext } = TARGETS[target]
  const entry = join(pkgRoot, 'dist', 'index.js')
  if (!existsSync(entry)) throw new Error('dist/index.js is missing. Run `npm run build` first.')

  const buildDir = join(pkgRoot, 'dist', 'bin', '.build')
  mkdirSync(buildDir, { recursive: true })
  const shimPath = join(buildDir, 'keyring-embed.cjs')
  const bundlePath = join(buildDir, 'app.cjs')
  generateKeyringShim(shimPath)

  const esbuild = await import('esbuild').catch(() => null)
  if (!esbuild) throw new Error('esbuild is missing. Run `npm install` in packages/zappi-signer.')
  await esbuild.build({
    entryPoints: [entry],
    bundle: true,
    platform: 'node',
    format: 'cjs',
    target: 'node20',
    outfile: bundlePath,
    minify: false,
    sourcemap: false,
    alias: { '@napi-rs/keyring': shimPath },
    define: { 'process.env.ZAPPI_SIGNER_STANDALONE': '"1"' },
    logLevel: 'warning',
  })

  const outPath = join(pkgRoot, 'dist', 'bin', `zappi-signer-${target}${ext}`)
  const bun = run('bun', ['build', '--compile', `--target=${bunTarget}`, bundlePath, '--outfile', outPath])
  let bunOutputUsable = bun.ok && existsSync(outPath)
  if (bunOutputUsable && target.startsWith('darwin-')) {
    // Bun emits a malformed LC_CODE_SIGNATURE that macOS kills at exec time;
    // strip it and re-sign ad hoc so the binary actually runs.
    run('codesign', ['--remove-signature', outPath])
    const resign = run('codesign', ['--sign', '-', '--force', outPath])
    bunOutputUsable = resign.ok && codeSignatureOk(outPath, target)
  }
  if (bunOutputUsable) {
    console.log(`[build-bin] ${target}: bun --compile -> ${outPath}`)
  } else {
    if (bun.output) console.warn(`[build-bin] bun failed:\n${bun.output}`)
    if (bun.ok) console.warn('[build-bin] bun output failed the code-signature check; falling back to Node SEA')
    else console.warn('[build-bin] falling back to Node SEA')
    rmSync(outPath, { force: true })
    buildSea(bundlePath, outPath, buildDir, target)
    console.log(`[build-bin] ${target}: node SEA -> ${outPath}`)
  }

  chmodSync(outPath, 0o500)
  const { createHash } = await import('node:crypto')
  const sha = createHash('sha256').update(readFileSync(outPath)).digest('hex')
  console.log(`[build-bin] sha256: ${sha}`)
  console.log(`[build-bin] sign with: node scripts/sign-release.mjs dist/bin/zappi-signer-${target}${ext} --provenance`)
}

// On darwin an unsigned or malformed Mach-O is killed at exec time, so the
// build verifies the code signature and falls back when it is not valid.
function codeSignatureOk(path, target) {
  if (!target.startsWith('darwin-')) return true
  const check = run('codesign', ['-dv', path])
  return check.ok
}

function buildSea(bundlePath, outPath, buildDir, target) {
  const seaConfig = join(buildDir, 'sea-config.json')
  const blob = join(buildDir, 'sea-prep.blob')
  writeFileSync(
    seaConfig,
    JSON.stringify({ main: bundlePath, output: blob, disableExperimentalSEAWarning: true, useSnapshot: false, useCodeCache: false }),
  )
  const prep = run(process.execPath, ['--experimental-sea-config', seaConfig], { cwd: pkgRoot })
  if (!prep.ok || !existsSync(blob)) throw new Error(`sea-config failed:\n${prep.output}`)
  copyFileSync(process.execPath, outPath)
  const postjectBin = join(pkgRoot, 'node_modules', '.bin', process.platform === 'win32' ? 'postject.cmd' : 'postject')
  if (!existsSync(postjectBin)) throw new Error('postject is missing. Run `npm install` in packages/zappi-signer.')
  const inject = run(postjectBin, [outPath, 'NODE_SEA_BLOB', blob, '--sentinel-fuse', SEA_FUSE])
  if (!inject.ok) throw new Error(`postject injection failed:\n${inject.output}`)
  if (target.startsWith('darwin-')) {
    // The injected binary's signature is invalid; re-sign ad hoc.
    run('codesign', ['--sign', '-', '--force', outPath])
  }
}

try {
  await main()
} catch (error) {
  console.error(`[build-bin] ${error && error.message ? error.message : error}`)
  process.exit(1)
}