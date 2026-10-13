export interface KeyStore {
  getSecret(account: string): Promise<string | null>
  setSecret(account: string, value: string): Promise<void>
  /** Removes the item. Resolves when it is already absent. */
  deleteSecret(account: string): Promise<void>
  /** Touch ID on macOS. Missing or false fails closed. */
  confirmUserPresence?(reason: string): Promise<boolean>
  /**
   * 32 stable bytes that only this device can produce.
   * The vault mixes them into field keys so a copied file will not open elsewhere.
   */
  deviceFactor(): Promise<Buffer>
}

/** Kept stable so this process and zappi-signer share one keychain item name. */
export const KEYCHAIN_SERVICE = 'zappi-signer'
export const UNLOCK_ACCOUNT = 'seed-vault-unlock'
export const DEVICE_FACTOR_ACCOUNT = 'device-factor'
export const HIGH_WATER_ACCOUNT = 'vault-high-water'
export const PRESENCE_ACCOUNT = 'user-presence'
export const DEVICE_TOKEN_ACCOUNT = 'device-token'
export const OAUTH_CLIENT_ACCOUNT = 'oauth-client-id'

const ACCOUNT_RE = /^[a-z0-9-]{1,64}$/

export function assertKeychainAccount(account: string): void {
  if (!ACCOUNT_RE.test(account)) {
    throw new Error('keychain account refused')
  }
}

/** One token entry per host app, so logout in Cursor does not sign Grok out. */
export function hostKeyAccounts(host: string): { device: string; client: string } {
  if (host === 'local') {
    return { device: DEVICE_TOKEN_ACCOUNT, client: OAUTH_CLIENT_ACCOUNT }
  }
  if (!/^[a-z][a-z0-9-]{0,19}$/.test(host)) {
    throw new Error('keychain account refused')
  }
  return {
    device: `device-token-${host}`,
    client: `oauth-client-${host}`,
  }
}

/**
 * OS keychain account for the pot client token (`x-zappi-pot-client`).
 * Shape is `pot-client-token-<potId>`. The pot id is lowercased so the
 * account stays inside the keychain charset `[a-z0-9-]`.
 */
export const POT_CLIENT_TOKEN_ACCOUNT_PREFIX = 'pot-client-token-'

export function potClientTokenAccount(potId: string): string {
  const pot = potId.trim().toLowerCase()
  if (pot.length === 0) throw new Error('keychain account refused')
  const account = `${POT_CLIENT_TOKEN_ACCOUNT_PREFIX}${pot}`
  assertKeychainAccount(account)
  return account
}
