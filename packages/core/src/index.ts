// reflect-metadata used for class-transformer + class-validator
import 'reflect-metadata'

export { MessageReceiver } from './agent/MessageReceiver'
export { Agent } from './agent/Agent'
export { BaseAgent } from './agent/BaseAgent'
export * from './agent'
export type { ModulesMap, DefaultAgentModules, EmptyModuleMap } from './agent/AgentModules'
export { EventEmitter } from './agent/EventEmitter'
export { FeatureRegistry } from './agent/FeatureRegistry'
export { MessageHandler, MessageHandlerInboundMessage } from './agent/MessageHandler'
export { MessageHandlerRegistry } from './agent/MessageHandlerRegistry'
export * from './agent/models'
export { AgentConfig } from './agent/AgentConfig'
export { AgentMessage } from './agent/AgentMessage'
export { Dispatcher } from './agent/Dispatcher'
export { MessageSender } from './agent/MessageSender'
export type { AgentDependencies } from './agent/AgentDependencies'
export { getOutboundMessageContext } from './agent/getOutboundMessageContext'
export type {
  InitConfig,
  OutboundPackage,
  EncryptedMessage,
  WalletConfig,
  JsonArray,
  JsonObject,
  JsonValue,
  WalletConfigRekey,
  WalletExportImportConfig,
  WalletStorageConfig,
} from './types'
export { DidCommMimeType, KeyDerivationMethod } from './types'
export type { FileSystem, DownloadToFileOptions } from './storage/FileSystem'
export * from './storage/BaseRecord'
export { DidCommMessageRecord, DidCommMessageRole, DidCommMessageRepository } from './storage/didcomm'
export { Repository } from './storage/Repository'
export * from './storage/RepositoryEvents'
export { StorageService, Query, QueryOptions, SimpleQuery, BaseRecordConstructor } from './storage/StorageService'
export * from './storage/migration'
export { getDirFromFilePath, joinUriParts } from './utils/path'
export { InjectionSymbols } from './constants'
export * from './wallet'
export type { TransportSession } from './agent/TransportService'
export { TransportService } from './agent/TransportService'
export { Attachment, AttachmentData } from './decorators/attachment/Attachment'
export { ServiceDecorator, ServiceDecoratorOptions } from './decorators/service/ServiceDecorator'
export { ReturnRouteTypes } from './decorators/transport/TransportDecorator'

export * from './plugins'
export * from './transport'
export * from './modules/basic-messages'
export * from './modules/common'
export * from './modules/credentials'
export * from './modules/discover-features'
export * from './modules/message-pickup'
export * from './modules/problem-reports'
export * from './modules/proofs'
export * from './modules/connections'
export * from './modules/routing'
export * from './modules/oob'
export * from './modules/dids'
export * from './modules/vc'
export * from './modules/cache'
export * from './modules/dif-presentation-exchange'
export * from './modules/sd-jwt-vc'
export {
  JsonEncoder,
  JsonTransformer,
  isJsonObject,
  isValidJweStructure,
  TypedArrayEncoder,
  Buffer,
  deepEquality,
  isDid,
  asArray,
  equalsIgnoreOrder,
  DateTransformer,
} from './utils'
export * from './logger'
export * from './error'
export * from './wallet/error'
export { VersionString } from './utils/version'
export { parseMessageType, IsValidMessageType, replaceLegacyDidSovPrefix } from './utils/messageType'
export type { Constructor, Constructable } from './utils/mixins'
export * from './agent/Events'
export * from './crypto'

// TODO: clean up util exports
export { encodeAttachment, isLinkedAttachment } from './utils/attachment'
export type { Optional } from './utils'
export { Hasher, HashName } from './utils/Hasher'
export { MessageValidator } from './utils/MessageValidator'
export { LinkedAttachment, LinkedAttachmentOptions } from './utils/LinkedAttachment'
import { parseInvitationUrl } from './utils/parseInvitation'
import { uuid, isValidUuid } from './utils/uuid'

const utils = {
  uuid,
  isValidUuid,
  parseInvitationUrl,
}

export { utils }
