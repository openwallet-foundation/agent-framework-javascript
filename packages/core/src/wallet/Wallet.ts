import type { WireMessage, UnpackedMessageContext, WalletConfig } from '../types'
import type { Buffer } from '../utils/buffer'

export interface Wallet {
  publicDid: DidInfo | undefined
  isInitialized: boolean
  isProvisioned: boolean

  initialize(walletConfig: WalletConfig): Promise<void>
  create(walletConfig: WalletConfig): Promise<void>
  open(walletConfig: WalletConfig): Promise<void>
  close(): Promise<void>
  delete(): Promise<void>

  initPublicDid(didConfig: DidConfig): Promise<void>
  createDid(didConfig?: DidConfig): Promise<DidInfo>
  pack(payload: Record<string, unknown>, recipientKeys: string[], senderVerkey?: string): Promise<WireMessage>
  unpack(messagePackage: WireMessage): Promise<UnpackedMessageContext>
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
