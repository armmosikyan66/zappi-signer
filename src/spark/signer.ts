import type { SparkNetworkName } from '../vault/vault.js'

export interface DerivedPotKey {
  address: string
  pubkey: string
}

export interface SparkTransfer {
  destination: string
  amountSats: number
}

/**
 * Signing surface for a pot. There is no generic sign(data) method.
 * Callers pass the mnemonic only for the duration of one operation.
 */
export interface SparkSigner {
  derive(mnemonic: Uint8Array, network: SparkNetworkName): Promise<DerivedPotKey>
  signNonce(
    mnemonic: Uint8Array,
    network: SparkNetworkName,
    nonce: string,
  ): Promise<{ signature: string; pubkey: string; address: string }>
  signRelay(
    mnemonic: Uint8Array,
    network: SparkNetworkName,
    message: string,
  ): Promise<{ signature: string; pubkey: string }>
  balanceSats(mnemonic: Uint8Array, network: SparkNetworkName): Promise<number>
  transfer(
    mnemonic: Uint8Array,
    network: SparkNetworkName,
    input: SparkTransfer,
  ): Promise<{ txid: string }>
}
