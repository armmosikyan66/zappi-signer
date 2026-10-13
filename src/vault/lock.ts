import { chmodSync, closeSync, mkdirSync, openSync, writeSync } from 'node:fs'
import { dirname } from 'node:path'
import lockfile from 'proper-lockfile'
import { PotError } from '../errors.js'

function ensureLockFile(lockPath: string): void {
  const dir = dirname(lockPath)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  if (process.platform !== 'win32') chmodSync(dir, 0o700)
  try {
    const fd = openSync(lockPath, 'wx', 0o600)
    try {
      writeSync(fd, '')
    } finally {
      closeSync(fd)
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
  }
  if (process.platform !== 'win32') chmodSync(lockPath, 0o600)
}

/** Exclusive lock so two MCP hosts can share one vault file. */
export async function withFileLock<T>(lockPath: string, fn: () => Promise<T>): Promise<T> {
  ensureLockFile(lockPath)
  let release: (() => Promise<void>) | undefined
  try {
    release = await lockfile.lock(lockPath, {
      realpath: false,
      stale: 60_000,
      retries: { retries: 80, factor: 1.15, minTimeout: 15, maxTimeout: 400 },
    })
  } catch {
    throw new PotError('vault locked')
  }
  try {
    return await fn()
  } finally {
    await release()
  }
}
