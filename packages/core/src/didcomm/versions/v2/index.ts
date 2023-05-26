import type { DidDocument, DidCommV2Service } from '../../../modules/dids'

export { DidCommV2Message } from './DidCommV2Message'
export { DidCommV2BaseMessage, DidComV2BaseMessageConstructor, DidCommV2MessageParams } from './DidCommV2BaseMessage'

export interface DidCommV2PackMessageParams {
  recipientDidDoc: DidDocument
  senderDidDoc?: DidDocument
  service: DidCommV2Service
}

export { isPlaintextMessageV2, isDidCommV2Message } from './helpers'
export {
  PlaintextDidCommV2Message,
  DidCommV2Types,
  DidCommV2EncryptionAlgs,
  DidCommV2KeyProtectionAlgs,
  AnoncrypDidCommV2EncryptionAlgs,
  AuthcryptDidCommV2EncryptionAlgs,
  AnoncrypDidCommV2KeyWrapAlgs,
  AuthcryptDidCommV2KeyWrapAlgs,
} from './types'
