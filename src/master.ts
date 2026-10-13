import { hmac } from '@noble/hashes/hmac'
import { sha512 } from '@noble/hashes/sha2'
import { entropyToMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'

const DOMAIN = new TextEncoder().encode('zappi-pot-child-v1')

/**
 * Child phrase for one pot. A leaked child does not derive its siblings:
 * the master is the HMAC key and never leaves the vault.
 */
export function deriveChildMnemonic(master: string, potIndex: number): string {
  if (!Number.isInteger(potIndex) || potIndex < 0 || potIndex > 1_000_000) {
    throw new Error('pot index refused')
  }
  const mac = hmac(sha512, DOMAIN, new TextEncoder().encode(`${potIndex}:${master}`))
  return entropyToMnemonic(mac.slice(0, 16), wordlist)
}
