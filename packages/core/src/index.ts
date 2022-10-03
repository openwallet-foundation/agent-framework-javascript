// reflect-metadata used for class-transformer + class-validator
import 'reflect-metadata'

export { Agent } from './agent/Agent'
export { EventEmitter } from './agent/EventEmitter'
export { Handler, HandlerInboundMessage } from './agent/Handler'
export { InboundMessageContext } from './agent/models/InboundMessageContext'
export { AgentConfig } from './agent/AgentConfig'
export { Dispatcher } from './agent/Dispatcher'
export { MessageSender } from './agent/MessageSender'
export type { AgentDependencies } from './agent/AgentDependencies'
export type { InitConfig, OutboundPackage, PlaintextMessage, ValueTransferConfig, WitnessType } from './types'
export { KeyDerivationMethod, DidCommMimeType } from './types'
export type { FileSystem } from './storage/FileSystem'
export * from './storage/BaseRecord'
export { InMemoryMessageRepository } from './storage/InMemoryMessageRepository'
export { Repository } from './storage/Repository'
export * from './storage/RepositoryEvents'
export { StorageService } from './storage/StorageService'
export { getDirFromFilePath } from './utils/path'
export { InjectionSymbols } from './constants'
export type { Wallet } from './wallet/Wallet'
export type { TransportSession } from './agent/TransportService'
export { TransportService } from './agent/TransportService'
export { DIDCommV1Message, DIDCommV2Message } from './agent/didcomm'
export { JsonEncoder } from './utils'
export { sleep } from './utils/sleep'
export { Attachment } from './decorators/attachment/Attachment'

import { parseInvitationUrl } from './utils/parseInvitation'
import { uuid } from './utils/uuid'

export * from './plugins'
export * from './transport'
export * from './modules/basic-messages'
export * from './modules/common'
export * from './modules/credentials'
export * from './modules/proofs'
export * from './modules/connections'
export * from './modules/ledger'
export * from './modules/routing'
export * from './modules/dids'
export * from './modules/value-transfer'
export * from './modules/out-of-band'
export * from './modules/gossip'
export * from './modules/question-answer'
export * from './modules/oob'
export * from './utils/JsonTransformer'
export * from './utils/string'
export * from './logger'
export * from './error'
export * from './wallet/error'
export * from './crypto'
export { parseMessageType, IsValidMessageType } from './utils/messageType'

export * from './agent/Events'

const utils = {
  uuid,
  parseInvitationUrl,
}

export { utils }
export { EncryptedMessage, SignedMessage } from './agent/didcomm'
