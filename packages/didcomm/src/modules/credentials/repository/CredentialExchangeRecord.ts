import type { TagsBase } from '@credo-ts/core'
import type { CredentialRole } from '../models'
import type { AutoAcceptCredential } from '../models/CredentialAutoAcceptType'
import type { CredentialState } from '../models/CredentialState'
import type { RevocationNotification } from '../models/RevocationNotification'

import { Type } from 'class-transformer'

import { CredoError, BaseRecord, utils } from '@credo-ts/core'
import { Attachment } from '../../../decorators/attachment/Attachment'
import { CredentialPreviewAttribute } from '../models/CredentialPreviewAttribute'

export interface CredentialExchangeRecordProps {
  id?: string
  createdAt?: Date
  state: CredentialState
  role: CredentialRole
  connectionId?: string
  threadId: string
  parentThreadId?: string
  protocolVersion: string

  tags?: CustomCredentialTags
  credentialAttributes?: CredentialPreviewAttribute[]
  autoAcceptCredential?: AutoAcceptCredential
  linkedAttachments?: Attachment[]
  revocationNotification?: RevocationNotification
  errorMessage?: string
  credentials?: CredentialRecordBinding[]
}

export type CustomCredentialTags = TagsBase
export type DefaultCredentialTags = {
  threadId: string
  parentThreadId?: string
  connectionId?: string
  state: CredentialState
  role: CredentialRole
  credentialIds: string[]
}

export interface CredentialRecordBinding {
  credentialRecordType: string
  credentialRecordId: string
}

export class CredentialExchangeRecord extends BaseRecord<DefaultCredentialTags, CustomCredentialTags> {
  public connectionId?: string
  public threadId!: string
  public parentThreadId?: string
  public state!: CredentialState
  public role!: CredentialRole
  public autoAcceptCredential?: AutoAcceptCredential
  public revocationNotification?: RevocationNotification
  public errorMessage?: string
  public protocolVersion!: string
  public credentials: CredentialRecordBinding[] = []

  @Type(() => CredentialPreviewAttribute)
  public credentialAttributes?: CredentialPreviewAttribute[]

  @Type(() => Attachment)
  public linkedAttachments?: Attachment[]

  // Type is CredentialRecord on purpose (without Exchange) as this is how the record was initially called.
  public static readonly type = 'CredentialRecord'
  public readonly type = CredentialExchangeRecord.type

  public constructor(props: CredentialExchangeRecordProps) {
    super()
    if (props) {
      this.id = props.id ?? utils.uuid()
      this.createdAt = props.createdAt ?? new Date()
      this.state = props.state
      this.role = props.role
      this.connectionId = props.connectionId
      this.threadId = props.threadId
      this.parentThreadId = props.parentThreadId
      this.protocolVersion = props.protocolVersion
      this._tags = props.tags ?? {}

      this.credentialAttributes = props.credentialAttributes
      this.autoAcceptCredential = props.autoAcceptCredential
      this.linkedAttachments = props.linkedAttachments
      this.revocationNotification = props.revocationNotification
      this.errorMessage = props.errorMessage
      this.credentials = props.credentials || []
    }
  }

  public getTags() {
    const ids = this.credentials.map((c) => c.credentialRecordId)

    return {
      ...this._tags,
      threadId: this.threadId,
      parentThreadId: this.parentThreadId,
      connectionId: this.connectionId,
      state: this.state,
      role: this.role,
      credentialIds: ids,
    }
  }

  public assertProtocolVersion(version: string) {
    if (this.protocolVersion != version) {
      throw new CredoError(
        `Credential record has invalid protocol version ${this.protocolVersion}. Expected version ${version}`
      )
    }
  }

  public assertState(expectedStates: CredentialState | CredentialState[]) {
    if (!Array.isArray(expectedStates)) {
      expectedStates = [expectedStates]
    }

    if (!expectedStates.includes(this.state)) {
      throw new CredoError(
        `Credential record is in invalid state ${this.state}. Valid states are: ${expectedStates.join(', ')}.`
      )
    }
  }

  public assertConnection(currentConnectionId: string) {
    if (!this.connectionId) {
      throw new CredoError(
        `Credential record is not associated with any connection. This is often the case with connection-less credential exchange`
      )
    } else if (this.connectionId !== currentConnectionId) {
      throw new CredoError(
        `Credential record is associated with connection '${this.connectionId}'. Current connection is '${currentConnectionId}'`
      )
    }
  }
}
