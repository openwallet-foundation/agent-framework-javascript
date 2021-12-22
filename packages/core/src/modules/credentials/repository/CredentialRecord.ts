import type { TagsBase } from '../../../storage/BaseRecord'
import type { AutoAcceptCredential } from '../CredentialAutoAcceptType'
import type { CredentialState } from '../CredentialState'
import type { CredentialMetadata } from './credentialMetadataTypes'

import { Type } from 'class-transformer'

import { Attachment } from '../../../decorators/attachment/Attachment'
import { AriesFrameworkError } from '../../../error'
import { BaseRecord } from '../../../storage/BaseRecord'
import { uuid } from '../../../utils/uuid'
import {
  CredentialPreviewAttribute,
  IssueCredentialMessage,
  OfferCredentialMessage,
  ProposeCredentialMessage,
  RequestCredentialMessage,
} from '../messages'
import { CredentialInfo } from '../models/CredentialInfo'

export interface CredentialRecordProps {
  id?: string
  createdAt?: Date
  state: CredentialState
  connectionId?: string
  threadId: string

  credentialId?: string
  tags?: CustomCredentialTags
  proposalMessage?: ProposeCredentialMessage
  offerMessage?: OfferCredentialMessage
  requestMessage?: RequestCredentialMessage
  credentialMessage?: IssueCredentialMessage
  credentialAttributes?: CredentialPreviewAttribute[]
  autoAcceptCredential?: AutoAcceptCredential
  linkedAttachments?: Attachment[]
  errorMessage?: string
}

export type CustomCredentialTags = TagsBase
export type DefaultCredentialTags = {
  threadId: string
  connectionId?: string
  state: CredentialState
  credentialId?: string
}

export class CredentialRecord extends BaseRecord<DefaultCredentialTags, CustomCredentialTags, CredentialMetadata> {
  public connectionId?: string
  public threadId!: string
  public credentialId?: string
  public state!: CredentialState
  public autoAcceptCredential?: AutoAcceptCredential
  public errorMessage?: string

  // message data
  @Type(() => ProposeCredentialMessage)
  public proposalMessage?: ProposeCredentialMessage
  @Type(() => OfferCredentialMessage)
  public offerMessage?: OfferCredentialMessage
  @Type(() => RequestCredentialMessage)
  public requestMessage?: RequestCredentialMessage
  @Type(() => IssueCredentialMessage)
  public credentialMessage?: IssueCredentialMessage

  @Type(() => CredentialPreviewAttribute)
  public credentialAttributes?: CredentialPreviewAttribute[]

  @Type(() => Attachment)
  public linkedAttachments?: Attachment[]

  public static readonly type = 'CredentialRecord'
  public readonly type = CredentialRecord.type

  public constructor(props: CredentialRecordProps) {
    super()

    if (props) {
      this.id = props.id ?? uuid()
      this.createdAt = props.createdAt ?? new Date()
      this.state = props.state
      this.connectionId = props.connectionId
      this.credentialId = props.credentialId
      this.threadId = props.threadId
      this._tags = props.tags ?? {}

      this.proposalMessage = props.proposalMessage
      this.offerMessage = props.offerMessage
      this.requestMessage = props.requestMessage
      this.credentialMessage = props.credentialMessage
      this.credentialAttributes = props.credentialAttributes
      this.autoAcceptCredential = props.autoAcceptCredential
      this.linkedAttachments = props.linkedAttachments
      this.errorMessage = props.errorMessage
    }
  }

  public getTags() {
    return {
      ...this._tags,
      threadId: this.threadId,
      connectionId: this.connectionId,
      state: this.state,
      credentialId: this.credentialId,
    }
  }

  public getCredentialInfo(): CredentialInfo | null {
    if (!this.credentialAttributes) return null

    const claims = this.credentialAttributes.reduce(
      (accumulator, current) => ({
        ...accumulator,
        [current.name]: current.value,
      }),
      {}
    )

    return new CredentialInfo({
      claims,
      attachments: this.linkedAttachments,
      metadata: this.metadata.data,
    })
  }

  public assertState(expectedStates: CredentialState | CredentialState[]) {
    if (!Array.isArray(expectedStates)) {
      expectedStates = [expectedStates]
    }

    if (!expectedStates.includes(this.state)) {
      throw new AriesFrameworkError(
        `Credential record is in invalid state ${this.state}. Valid states are: ${expectedStates.join(', ')}.`
      )
    }
  }

  public assertConnection(currentConnectionId: string) {
    if (!this.connectionId) {
      throw new AriesFrameworkError(
        `Credential record is not associated with any connection. This is often the case with connection-less credential exchange`
      )
    } else if (this.connectionId !== currentConnectionId) {
      throw new AriesFrameworkError(
        `Credential record is associated with connection '${this.connectionId}'. Current connection is '${currentConnectionId}'`
      )
    }
  }
}
