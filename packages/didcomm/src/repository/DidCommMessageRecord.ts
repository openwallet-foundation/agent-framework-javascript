import type { DidCommMessageRole } from './DidCommMessageRole'
import type { ConstructableAgentMessage } from '../AgentMessage'
import type { PlaintextMessage } from '../types'

import { CredoError, BaseRecord, JsonTransformer, isJsonObject, utils } from '@credo-ts/core'

import { canHandleMessageType, parseMessageType } from '../util/messageType'

export type DefaultDidCommMessageTags = {
  role: DidCommMessageRole
  associatedRecordId?: string

  // Computed
  protocolName: string
  messageName: string
  protocolMajorVersion: string
  protocolMinorVersion: string
  messageType: string
  messageId: string
  threadId: string
}

export interface DidCommMessageRecordProps {
  role: DidCommMessageRole
  message: PlaintextMessage
  id?: string
  createdAt?: Date
  associatedRecordId?: string
}

export class DidCommMessageRecord extends BaseRecord<DefaultDidCommMessageTags> {
  public message!: PlaintextMessage
  public role!: DidCommMessageRole

  /**
   * The id of the record that is associated with this message record.
   *
   * E.g. if the connection record wants to store an invitation message
   * the associatedRecordId will be the id of the connection record.
   */
  public associatedRecordId?: string

  public static readonly type = 'DidCommMessageRecord'
  public readonly type = DidCommMessageRecord.type

  public constructor(props: DidCommMessageRecordProps) {
    super()

    if (props) {
      this.id = props.id ?? utils.uuid()
      this.createdAt = props.createdAt ?? new Date()
      this.associatedRecordId = props.associatedRecordId
      this.role = props.role
      this.message = props.message
    }
  }

  public getTags() {
    const messageId = this.message['@id'] as string
    const messageType = this.message['@type'] as string

    const { protocolName, protocolMajorVersion, protocolMinorVersion, messageName } = parseMessageType(messageType)

    const thread = this.message['~thread']
    let threadId = messageId

    if (isJsonObject(thread) && typeof thread.thid === 'string') {
      threadId = thread.thid
    }

    return {
      ...this._tags,
      role: this.role,
      associatedRecordId: this.associatedRecordId,

      // Computed properties based on message id and type
      threadId,
      protocolName,
      messageName,
      protocolMajorVersion: protocolMajorVersion.toString(),
      protocolMinorVersion: protocolMinorVersion.toString(),
      messageType,
      messageId,
    }
  }

  public getMessageInstance<MessageClass extends ConstructableAgentMessage = ConstructableAgentMessage>(
    messageClass: MessageClass
  ): InstanceType<MessageClass> {
    const messageType = parseMessageType(this.message['@type'] as string)

    if (!canHandleMessageType(messageClass, messageType)) {
      throw new CredoError('Provided message class type does not match type of stored message')
    }

    return JsonTransformer.fromJSON(this.message, messageClass) as InstanceType<MessageClass>
  }
}
