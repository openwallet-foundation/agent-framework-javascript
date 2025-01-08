import type { ConnectionMetadata } from './ConnectionMetadataTypes'
import type { TagsBase } from '../../../storage/BaseRecord'
import type { ConnectionType } from '../models/ConnectionType'

import { Transform } from 'class-transformer'

import { CredoError } from '../../../error'
import { BaseRecord } from '../../../storage/BaseRecord'
import { uuid } from '../../../utils/uuid'
import { rfc0160StateFromDidExchangeState, DidExchangeRole, DidExchangeState, HandshakeProtocol } from '../models'

export interface ConnectionRecordProps {
  id?: string
  createdAt?: Date
  did?: string
  theirDid?: string
  theirLabel?: string
  state: DidExchangeState
  role: DidExchangeRole
  alias?: string
  autoAcceptConnection?: boolean
  threadId?: string
  tags?: CustomConnectionTags
  imageUrl?: string
  mediatorId?: string
  errorMessage?: string
  protocol?: HandshakeProtocol
  outOfBandId?: string
  invitationDid?: string
  connectionTypes?: Array<ConnectionType | string>
  previousDids?: Array<string>
  previousTheirDids?: Array<string>
}

export type CustomConnectionTags = TagsBase
export type DefaultConnectionTags = {
  state: DidExchangeState
  role: DidExchangeRole
  threadId?: string
  mediatorId?: string
  did?: string
  alias?: string
  theirDid?: string
  theirLabel?: string
  outOfBandId?: string
  invitationDid?: string
  connectionTypes?: Array<ConnectionType | string>
  previousDids?: Array<string>
  previousTheirDids?: Array<string>
}

export class ConnectionRecord extends BaseRecord<DefaultConnectionTags, CustomConnectionTags, ConnectionMetadata> {
  public state!: DidExchangeState
  public role!: DidExchangeRole

  public did?: string

  public theirDid?: string
  public theirLabel?: string

  public alias?: string
  public autoAcceptConnection?: boolean
  public imageUrl?: string

  public threadId?: string
  public mediatorId?: string
  public errorMessage?: string

  // We used to store connection record using major.minor version, but we now
  // only store the major version, storing .x for the minor version. We have this
  // transformation so we don't have to migrate the data in the database.
  @Transform(
    ({ value }) => {
      if (!value || typeof value !== 'string' || value.endsWith('.x')) return value
      return value.split('.').slice(0, -1).join('.') + '.x'
    },

    { toClassOnly: true }
  )
  public protocol?: HandshakeProtocol
  public outOfBandId?: string
  public invitationDid?: string

  public connectionTypes: string[] = []
  public previousDids: string[] = []
  public previousTheirDids: string[] = []

  public static readonly type = 'ConnectionRecord'
  public readonly type = ConnectionRecord.type

  public constructor(props: ConnectionRecordProps) {
    super()

    if (props) {
      this.id = props.id ?? uuid()
      this.createdAt = props.createdAt ?? new Date()
      this.did = props.did
      this.invitationDid = props.invitationDid
      this.theirDid = props.theirDid
      this.theirLabel = props.theirLabel
      this.state = props.state
      this.role = props.role
      this.alias = props.alias
      this.autoAcceptConnection = props.autoAcceptConnection
      this._tags = props.tags ?? {}
      this.threadId = props.threadId
      this.imageUrl = props.imageUrl
      this.mediatorId = props.mediatorId
      this.errorMessage = props.errorMessage
      this.protocol = props.protocol
      this.outOfBandId = props.outOfBandId
      this.connectionTypes = props.connectionTypes ?? []
      this.previousDids = props.previousDids ?? []
      this.previousTheirDids = props.previousTheirDids ?? []
    }
  }

  public getTags(): DefaultConnectionTags & CustomConnectionTags {
    return {
      ...this._tags,
      state: this.state,
      role: this.role,
      threadId: this.threadId,
      mediatorId: this.mediatorId,
      did: this.did,
      alias: this.alias,
      theirDid: this.theirDid,
      theirLabel: this.theirLabel,
      outOfBandId: this.outOfBandId,
      invitationDid: this.invitationDid,
      connectionTypes: this.connectionTypes,
      previousDids: this.previousDids,
      previousTheirDids: this.previousTheirDids,
    }
  }

  public get isRequester() {
    return this.role === DidExchangeRole.Requester
  }

  public get rfc0160State() {
    return rfc0160StateFromDidExchangeState(this.state)
  }

  public get isReady() {
    return this.state && [DidExchangeState.Completed, DidExchangeState.ResponseSent].includes(this.state)
  }

  public assertReady() {
    if (!this.isReady) {
      throw new CredoError(
        `Connection record is not ready to be used. Expected ${DidExchangeState.ResponseSent}, ${DidExchangeState.ResponseReceived} or ${DidExchangeState.Completed}, found invalid state ${this.state}`
      )
    }
  }

  public assertState(expectedStates: DidExchangeState | DidExchangeState[]) {
    if (!Array.isArray(expectedStates)) {
      expectedStates = [expectedStates]
    }

    if (!expectedStates.includes(this.state)) {
      throw new CredoError(
        `Connection record is in invalid state ${this.state}. Valid states are: ${expectedStates.join(', ')}.`
      )
    }
  }

  public assertRole(expectedRole: DidExchangeRole) {
    if (this.role !== expectedRole) {
      throw new CredoError(`Connection record has invalid role ${this.role}. Expected role ${expectedRole}.`)
    }
  }
}
