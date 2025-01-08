import { Expose } from 'class-transformer'
import { IsOptional, IsString } from 'class-validator'

import { AgentMessage } from '../../../../../AgentMessage'
import { AckDecorator } from '../../../../../decorators/ack/AckDecorator'
import { IsValidMessageType, parseMessageType } from '../../../../../util/messageType'

export interface RevocationNotificationMessageV1Options {
  issueThread: string
  id?: string
  comment?: string
  pleaseAck?: AckDecorator
}

export class V1RevocationNotificationMessage extends AgentMessage {
  public constructor(options: RevocationNotificationMessageV1Options) {
    super()
    if (options) {
      this.issueThread = options.issueThread
      this.id = options.id ?? this.generateId()
      this.comment = options.comment
      this.pleaseAck = options.pleaseAck
    }
  }

  @IsValidMessageType(V1RevocationNotificationMessage.type)
  public readonly type = V1RevocationNotificationMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/revocation_notification/1.0/revoke')

  @IsString()
  @IsOptional()
  public comment?: string

  @Expose({ name: 'thread_id' })
  @IsString()
  public issueThread!: string
}
