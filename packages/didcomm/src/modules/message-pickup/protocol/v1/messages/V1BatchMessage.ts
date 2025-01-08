import { Type, Expose } from 'class-transformer'
import { Matches, IsArray, ValidateNested, IsObject, IsInstance } from 'class-validator'

import { utils } from '@credo-ts/core'
import { AgentMessage } from '../../../../../AgentMessage'
import { MessageIdRegExp } from '../../../../../BaseMessage'
import { EncryptedMessage } from '../../../../../types'
import { IsValidMessageType, parseMessageType } from '../../../../../util/messageType'

export class BatchMessageMessage {
  public constructor(options: { id?: string; message: EncryptedMessage }) {
    if (options) {
      this.id = options.id || utils.uuid()
      this.message = options.message
    }
  }

  @Matches(MessageIdRegExp)
  public id!: string

  @IsObject()
  public message!: EncryptedMessage
}

export interface BatchMessageOptions {
  id?: string
  messages: BatchMessageMessage[]
  threadId?: string
}

/**
 * A message that contains multiple waiting messages.
 *
 * @see https://github.com/hyperledger/aries-rfcs/blob/master/features/0212-pickup/README.md#batch
 */
export class V1BatchMessage extends AgentMessage {
  public readonly allowQueueTransport = false

  public constructor(options: BatchMessageOptions) {
    super()

    if (options) {
      this.id = options.id || this.generateId()
      this.messages = options.messages

      if (options.threadId) {
        this.setThread({
          threadId: options.threadId,
        })
      }
    }
  }

  @IsValidMessageType(V1BatchMessage.type)
  public readonly type = V1BatchMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/messagepickup/1.0/batch')

  @Type(() => BatchMessageMessage)
  @IsArray()
  @ValidateNested()
  @IsInstance(BatchMessageMessage, { each: true })
  @Expose({ name: 'messages~attach' })
  public messages!: BatchMessageMessage[]
}
