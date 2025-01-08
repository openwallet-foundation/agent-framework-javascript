import { Expose } from 'class-transformer'
import { IsOptional, IsString } from 'class-validator'

import { AgentMessage } from '../../../../../AgentMessage'
import { IsValidMessageType, parseMessageType } from '../../../../../util/messageType'

export interface V2StatusRequestMessageOptions {
  id?: string
  recipientKey?: string
}

export class V2StatusRequestMessage extends AgentMessage {
  public readonly allowQueueTransport = false

  public constructor(options: V2StatusRequestMessageOptions) {
    super()

    if (options) {
      this.id = options.id || this.generateId()
      this.recipientKey = options.recipientKey
    }
  }

  @IsValidMessageType(V2StatusRequestMessage.type)
  public readonly type = V2StatusRequestMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/messagepickup/2.0/status-request')

  @IsString()
  @IsOptional()
  @Expose({ name: 'recipient_key' })
  public recipientKey?: string
}
