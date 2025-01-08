import type { TagsBase } from '@credo-ts/core'
import type { ProofRole, ProofState } from '../models'
import type { AutoAcceptProof } from '../models/ProofAutoAcceptType'

import { CredoError, BaseRecord, utils } from '@credo-ts/core'

export interface ProofExchangeRecordProps {
  id?: string
  createdAt?: Date
  protocolVersion: string
  isVerified?: boolean
  state: ProofState
  role: ProofRole
  connectionId?: string
  threadId: string
  parentThreadId?: string
  tags?: CustomProofTags
  autoAcceptProof?: AutoAcceptProof
  errorMessage?: string
}

export type CustomProofTags = TagsBase
export type DefaultProofTags = {
  threadId: string
  parentThreadId?: string
  connectionId?: string
  state: ProofState
  role: ProofRole
}

export class ProofExchangeRecord extends BaseRecord<DefaultProofTags, CustomProofTags> {
  public connectionId?: string
  public threadId!: string
  public protocolVersion!: string
  public parentThreadId?: string
  public isVerified?: boolean
  public state!: ProofState
  public role!: ProofRole
  public autoAcceptProof?: AutoAcceptProof
  public errorMessage?: string

  public static readonly type = 'ProofRecord'
  public readonly type = ProofExchangeRecord.type

  public constructor(props: ProofExchangeRecordProps) {
    super()

    if (props) {
      this.id = props.id ?? utils.uuid()
      this.createdAt = props.createdAt ?? new Date()
      this.protocolVersion = props.protocolVersion

      this.isVerified = props.isVerified
      this.state = props.state
      this.role = props.role
      this.connectionId = props.connectionId
      this.threadId = props.threadId
      this.parentThreadId = props.parentThreadId
      this.autoAcceptProof = props.autoAcceptProof
      this._tags = props.tags ?? {}
      this.errorMessage = props.errorMessage
    }
  }

  public getTags() {
    return {
      ...this._tags,
      threadId: this.threadId,
      parentThreadId: this.parentThreadId,
      connectionId: this.connectionId,
      state: this.state,
      role: this.role,
    }
  }

  public assertState(expectedStates: ProofState | ProofState[]) {
    if (!Array.isArray(expectedStates)) {
      expectedStates = [expectedStates]
    }

    if (!expectedStates.includes(this.state)) {
      throw new CredoError(
        `Proof record is in invalid state ${this.state}. Valid states are: ${expectedStates.join(', ')}.`
      )
    }
  }

  public assertProtocolVersion(version: string) {
    if (this.protocolVersion !== version) {
      throw new CredoError(
        `Proof record has invalid protocol version ${this.protocolVersion}. Expected version ${version}`
      )
    }
  }

  public assertConnection(currentConnectionId: string) {
    if (!this.connectionId) {
      throw new CredoError(
        `Proof record is not associated with any connection. This is often the case with connection-less presentation exchange`
      )
    } else if (this.connectionId !== currentConnectionId) {
      throw new CredoError(
        `Proof record is associated with connection '${this.connectionId}'. Current connection is '${currentConnectionId}'`
      )
    }
  }
}
