import { homedir } from 'node:os'
import { join } from 'node:path'

/** Same directory and file name as the existing zappi-signer vault. */
export function defaultVaultPath(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): string {
  if (platform === 'win32') {
    const base = env.APPDATA?.trim() || join(homedir(), 'AppData', 'Roaming')
    return join(base, 'zappi-signer', 'seed-vault.json')
  }
  return join(homedir(), '.zappi-signer', 'seed-vault.json')
}

export function defaultStateDir(vaultPath: string): string {
  return join(vaultPath, '..')
}
