import type { Key, KeyType } from '../crypto'
import type {
  EncryptedMessage,
  WalletConfig,
  WalletConfigRekey,
  PlaintextMessage,
  WalletExportImportConfig,
} from '../types'
import type { Buffer } from '../utils/buffer'

export interface Wallet {
  publicDid: DidInfo | undefined
  isInitialized: boolean
  isProvisioned: boolean

  create(walletConfig: WalletConfig): Promise<void>
  createAndOpen(walletConfig: WalletConfig): Promise<void>
  open(walletConfig: WalletConfig): Promise<void>
  rotateKey(walletConfig: WalletConfigRekey): Promise<void>
  close(): Promise<void>
  delete(): Promise<void>
  export(exportConfig: WalletExportImportConfig): Promise<void>
  import(walletConfig: WalletConfig, importConfig: WalletExportImportConfig): Promise<void>

  createKey(options: CreateKeyOptions): Promise<Key>
  sign(options: SignOptions): Promise<Buffer>
  verify(options: VerifyOptions): Promise<boolean>

  initPublicDid(didConfig: DidConfig): Promise<void>
  createDid(didConfig?: DidConfig): Promise<DidInfo>
  pack(payload: Record<string, unknown>, recipientKeys: string[], senderVerkey?: string): Promise<EncryptedMessage>
  unpack(encryptedMessage: EncryptedMessage): Promise<UnpackedMessageContext>
  generateNonce(): Promise<string>
}

export interface DidInfo {
  did: string
  verkey: string
}

export interface CreateKeyOptions {
  keyType: KeyType
  seed?: string
}

export interface SignOptions {
  data: Buffer | Buffer[]
  key: Key
}

export interface VerifyOptions {
  data: Buffer | Buffer[]
  key: Key
  signature: Buffer
}

export interface DidConfig {
  seed?: string
}

export interface UnpackedMessageContext {
  plaintextMessage: PlaintextMessage
  senderKey?: string
  recipientKey?: string
}
