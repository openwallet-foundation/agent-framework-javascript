import type { EncryptedMessage, DecryptedMessageContext, WalletConfig, WalletExportImportConfig } from '../types'
import type { Buffer } from '../utils/buffer'

export interface WalletCreateConfig extends WalletConfig {
  keepOpenAfterCreate?: boolean
}

export interface Wallet {
  publicDid: DidInfo | undefined
  isInitialized: boolean
  isProvisioned: boolean

  create(walletConfig: WalletCreateConfig): Promise<void>
  open(walletConfig: WalletConfig): Promise<void>
  close(): Promise<void>
  delete(): Promise<void>
  export(exportConfig: WalletExportImportConfig): Promise<void>
  import(walletConfig: WalletConfig, importConfig: WalletExportImportConfig): Promise<void>

  initPublicDid(didConfig: DidConfig): Promise<void>
  createDid(didConfig?: DidConfig): Promise<DidInfo>
  pack(payload: Record<string, unknown>, recipientKeys: string[], senderVerkey?: string): Promise<EncryptedMessage>
  unpack(encryptedMessage: EncryptedMessage): Promise<DecryptedMessageContext>
  sign(data: Buffer, verkey: string): Promise<Buffer>
  verify(signerVerkey: string, data: Buffer, signature: Buffer): Promise<boolean>
  generateNonce(): Promise<string>
}

export interface DidInfo {
  did: string
  verkey: string
}

export interface DidConfig {
  seed?: string
}
