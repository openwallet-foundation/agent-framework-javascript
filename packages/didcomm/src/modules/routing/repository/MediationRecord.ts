import type { MediationRole } from '../models/MediationRole'

import { Transform } from 'class-transformer'

import { CredoError, BaseRecord, utils } from '@credo-ts/core'

import { MediatorPickupStrategy } from '../MediatorPickupStrategy'
import { MediationState } from '../models/MediationState'

export interface MediationRecordProps {
  id?: string
  state: MediationState
  role: MediationRole
  createdAt?: Date
  connectionId: string
  threadId: string
  endpoint?: string
  recipientKeys?: string[]
  routingKeys?: string[]
  pickupStrategy?: MediatorPickupStrategy
  tags?: CustomMediationTags
}

export type CustomMediationTags = {
  default?: boolean
}

export type DefaultMediationTags = {
  role: MediationRole
  connectionId: string
  state: MediationState
  threadId: string
}

export class MediationRecord
  extends BaseRecord<DefaultMediationTags, CustomMediationTags>
  implements MediationRecordProps
{
  public state!: MediationState
  public role!: MediationRole
  public connectionId!: string
  public threadId!: string
  public endpoint?: string
  public recipientKeys!: string[]
  public routingKeys!: string[]

  @Transform(({ value }) => {
    if (value === 'Explicit') {
      return MediatorPickupStrategy.PickUpV1
    } else {
      return value
    }
  })
  public pickupStrategy?: MediatorPickupStrategy

  public static readonly type = 'MediationRecord'
  public readonly type = MediationRecord.type

  public constructor(props: MediationRecordProps) {
    super()

    if (props) {
      this.id = props.id ?? utils.uuid()
      this.createdAt = props.createdAt ?? new Date()
      this.connectionId = props.connectionId
      this.threadId = props.threadId
      this.recipientKeys = props.recipientKeys || []
      this.routingKeys = props.routingKeys || []
      this.state = props.state
      this.role = props.role
      this.endpoint = props.endpoint ?? undefined
      this.pickupStrategy = props.pickupStrategy
      this._tags = props.tags ?? {}
    }
  }

  public getTags() {
    return {
      ...this._tags,
      state: this.state,
      role: this.role,
      connectionId: this.connectionId,
      threadId: this.threadId,
      recipientKeys: this.recipientKeys,
    }
  }

  public addRecipientKey(recipientKey: string) {
    this.recipientKeys.push(recipientKey)
  }

  public removeRecipientKey(recipientKey: string): boolean {
    const index = this.recipientKeys.indexOf(recipientKey, 0)
    if (index > -1) {
      this.recipientKeys.splice(index, 1)
      return true
    }

    return false
  }

  public get isReady() {
    return this.state === MediationState.Granted
  }

  public assertReady() {
    if (!this.isReady) {
      throw new CredoError(
        `Mediation record is not ready to be used. Expected ${MediationState.Granted}, found invalid state ${this.state}`
      )
    }
  }

  public assertState(expectedStates: MediationState | MediationState[]) {
    if (!Array.isArray(expectedStates)) {
      expectedStates = [expectedStates]
    }

    if (!expectedStates.includes(this.state)) {
      throw new CredoError(
        `Mediation record is in invalid state ${this.state}. Valid states are: ${expectedStates.join(', ')}.`
      )
    }
  }

  public assertRole(expectedRole: MediationRole) {
    if (this.role !== expectedRole) {
      throw new CredoError(`Mediation record has invalid role ${this.role}. Expected role ${expectedRole}.`)
    }
  }
}
