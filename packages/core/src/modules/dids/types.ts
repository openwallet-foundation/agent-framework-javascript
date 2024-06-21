import type { DidDocument } from './domain'
import type { DIDDocumentMetadata, DIDResolutionMetadata, DIDResolutionOptions, ParsedDID } from 'did-resolver'

export type ParsedDid = ParsedDID
export type DidDocumentMetadata = DIDDocumentMetadata

export interface DidResolutionOptions extends DIDResolutionOptions {
  /**
   * Whether to resolve the did document from the cache.
   *
   * @default true
   */
  useCache?: boolean

  /**
   * Whether to resolve the did from a local created did document in a DidRecord.
   * Cache has precendence over local records, as they're often fater. Records
   * served from DidRecords will not be added to the cache.
   *
   * The resolver must have enabled `allowsLocalDidRecord` (default false) to use this
   * feature.
   *
   * @default true
   */
  useLocalCreatedDidRecord?: boolean

  /**
   * Whether to persist the did document in the cache.
   *
   * @default true
   */
  persistInCache?: boolean

  /**
   * How many seconds to persist the resolved document
   *
   * @default 3600
   */
  cacheDurationInSeconds?: number
}

export interface DidResolutionMetadata extends DIDResolutionMetadata {
  message?: string

  /**
   * Whether the did document was served from the cache
   */
  servedFromCache?: boolean

  /**
   * Whether the did document was served from a local did record
   */
  servedFromDidRecord?: boolean
}

export interface DidResolutionResult {
  didResolutionMetadata: DidResolutionMetadata
  didDocument: DidDocument | null
  didDocumentMetadata: DidDocumentMetadata
}

// Based on https://identity.foundation/did-registration
export type DidRegistrationExtraOptions = Record<string, unknown>
export type DidRegistrationSecretOptions = Record<string, unknown>
export type DidRegistrationMetadata = Record<string, unknown>
export type DidDocumentOperation = 'setDidDocument' | 'addToDidDocument' | 'removeFromDidDocument'

export interface DidOperationStateFinished {
  state: 'finished'
  did: string
  secret?: DidRegistrationSecretOptions
  didDocument: DidDocument
}

export interface DidOperationStateFailed {
  state: 'failed'
  did?: string
  secret?: DidRegistrationSecretOptions
  didDocument?: DidDocument
  reason: string
}

export interface DidOperationStateWait {
  state: 'wait'
  did?: string
  secret?: DidRegistrationSecretOptions
  didDocument?: DidDocument
}

export interface DidOperationStateActionBase {
  state: 'action'
  action: string
  did?: string
  secret?: DidRegistrationSecretOptions
  didDocument?: DidDocument
}
export interface DidCreateOptions {
  method?: string
  did?: string
  options?: DidRegistrationExtraOptions
  secret?: DidRegistrationSecretOptions
  didDocument?: DidDocument
}

export interface DidCreateResult<
  DidOperationStateAction extends DidOperationStateActionBase = DidOperationStateActionBase
> {
  jobId?: string
  didState: DidOperationStateWait | DidOperationStateAction | DidOperationStateFinished | DidOperationStateFailed
  didRegistrationMetadata: DidRegistrationMetadata
  didDocumentMetadata: DidResolutionMetadata
}

export interface DidUpdateOptions {
  did: string
  options?: DidRegistrationExtraOptions
  secret?: DidRegistrationSecretOptions
  didDocumentOperation?: DidDocumentOperation
  didDocument: DidDocument | Partial<DidDocument>
}

export interface DidUpdateResult {
  jobId?: string
  didState: DidOperationStateWait | DidOperationStateActionBase | DidOperationStateFinished | DidOperationStateFailed
  didRegistrationMetadata: DidRegistrationMetadata
  didDocumentMetadata: DidResolutionMetadata
}

export interface DidDeactivateOptions {
  did: string
  options?: DidRegistrationExtraOptions
  secret?: DidRegistrationSecretOptions
}

export interface DidDeactivateResult {
  jobId?: string
  didState: DidOperationStateWait | DidOperationStateActionBase | DidOperationStateFinished | DidOperationStateFailed
  didRegistrationMetadata: DidRegistrationMetadata
  didDocumentMetadata: DidResolutionMetadata
}
