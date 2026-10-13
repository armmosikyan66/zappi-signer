import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeSync,
} from 'node:fs'
import { dirname } from 'node:path'
import { PotError } from './errors.js'

function noFollowFlag(flags: number): number {
  if (process.platform === 'win32') return flags
  if (typeof constants.O_NOFOLLOW !== 'number') return flags
  return flags | constants.O_NOFOLLOW
}

/** Open a real file. A symlink is refused (ELOOP / not a file). */
export function openNoFollow(path: string, flags: number, mode?: number): number {
  try {
    return mode === undefined ? openSync(path, noFollowFlag(flags)) : openSync(path, noFollowFlag(flags), mode)
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code
    if (code === 'ENOENT') throw error
    if (code === 'ELOOP') throw new PotError('vault locked')
    throw new PotError('vault locked')
  }
}

export function readNoFollow(path: string, maxBytes: number): string {
  const fd = openNoFollow(path, constants.O_RDONLY)
  try {
    const stat = fstatSync(fd)
    if (!stat.isFile()) throw new PotError('vault locked')
    if (stat.size > maxBytes) throw new PotError('vault locked')
    if (process.platform !== 'win32') {
      if ((stat.mode & 0o077) !== 0) throw new PotError('vault locked')
      if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
        throw new PotError('vault locked')
      }
    }
    return readFileSync(fd, 'utf8')
  } finally {
    closeSync(fd)
  }
}

export function appendNoFollow(path: string, line: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
  const flags = constants.O_APPEND | constants.O_CREAT | constants.O_WRONLY
  const fd = openNoFollow(path, flags, 0o600)
  try {
    const stat = fstatSync(fd)
    if (!stat.isFile()) throw new PotError('vault locked')
    const buf = Buffer.from(line, 'utf8')
    let offset = 0
    while (offset < buf.length) offset += writeSync(fd, buf, offset)
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }
}
