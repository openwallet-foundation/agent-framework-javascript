// reflect-metadata used for class-transformer + class-validator
import 'reflect-metadata'

export { Agent } from './agent/Agent'
export { BaseAgent } from './agent/BaseAgent'
export * from './agent'
export type { ModulesMap, DefaultAgentModules, EmptyModuleMap } from './agent/AgentModules'
export { EventEmitter } from './agent/EventEmitter'
export { AgentConfig } from './agent/AgentConfig'

export type { AgentDependencies } from './agent/AgentDependencies'

export type {
  InitConfig,
  WalletConfig,
  JsonArray,
  JsonObject,
  JsonValue,
  WalletConfigRekey,
  WalletExportImportConfig,
  WalletStorageConfig,
} from './types'
export { KeyDerivationMethod, EncryptedMessage, PlaintextMessage } from './types'
export type { FileSystem, DownloadToFileOptions } from './storage/FileSystem'
export * from './storage/BaseRecord'
export { Repository } from './storage/Repository'
export * from './storage/RepositoryEvents'
export { StorageService, Query, QueryOptions, SimpleQuery, BaseRecordConstructor } from './storage/StorageService'
export * from './storage/migration'
export { Metadata } from './storage/Metadata'
export { UpdateConfig, V0_1ToV0_2UpdateConfig } from './storage/migration/updates'

export { getDirFromFilePath, joinUriParts } from './utils/path'
export { InjectionSymbols } from './constants'
export * from './wallet'
export { VersionString } from './utils/version'

export * from './plugins'
export * from './modules/x509'
export * from './modules/dids'
export * from './modules/vc'
export * from './modules/cache'
export * from './modules/dif-presentation-exchange'
export * from './modules/sd-jwt-vc'
export * from './modules/mdoc'
export {
  JsonEncoder,
  JsonTransformer,
  isJsonObject,
  TypedArrayEncoder,
  HashlinkEncoder,
  BaseName,
  Buffer,
  deepEquality,
  isDid,
  IsUri,
  IsStringOrInstance,
  asArray,
  equalsIgnoreOrder,
  DateTransformer,
} from './utils'
export * from './logger'
export * from './error'
export * from './wallet/error'
export type { Constructor, Constructable } from './utils/mixins'
export * from './agent/Events'
export * from './crypto'

// TODO: Clean up these exports used by DIDComm module
export { getKeyFromVerificationMethod } from './modules/dids/domain/key-type'
export {
  didKeyToInstanceOfKey,
  didKeyToVerkey,
  verkeyToDidKey,
  verkeyToInstanceOfKey,
  isDidKey,
} from './modules/dids/helpers'
export { tryParseDid } from './modules/dids/domain/parse'
export { base64ToBase64URL } from './utils/base64'
export { DidRecordMetadataKeys } from './modules/dids/repository/didRecordMetadataTypes'
export { didDocumentJsonToNumAlgo1Did } from './modules/dids/methods/peer/peerDidNumAlgo1'
export { didDocumentToNumAlgo2Did } from './modules/dids/methods/peer/peerDidNumAlgo2'

export { SingleOrArray } from './utils'

// TODO: clean up util exports
export type { Optional } from './utils'
export { getDomainFromUrl } from './utils/domain'
import { uuid, isValidUuid } from './utils/uuid'
import { getProtocolScheme } from './utils/uri'
import { indyDidFromPublicKeyBase58 } from './utils/did'
import timestamp from './utils/timestamp'
export { MessageValidator } from './utils'
import { areObjectsEqual } from './utils/objectEquality'
const utils = {
  areObjectsEqual,
  uuid,
  isValidUuid,
  getProtocolScheme,
  timestamp,
  indyDidFromPublicKeyBase58,
}

export { utils }
