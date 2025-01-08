import { Expose, Transform } from 'class-transformer'
import { IsDate, IsString } from 'class-validator'

import { DateParser } from '../../../util/transformers'
import { AgentMessage } from '../../../AgentMessage'
import { IsValidMessageType, parseMessageType } from '../../../util/messageType'

export class BasicMessage extends AgentMessage {
  public readonly allowDidSovPrefix = true

  /**
   * Create new BasicMessage instance.
   * sentTime will be assigned to new Date if not passed, id will be assigned to uuid/v4 if not passed
   * @param options
   */
  public constructor(options: { content: string; sentTime?: Date; id?: string; locale?: string }) {
    super()

    if (options) {
      this.id = options.id || this.generateId()
      this.sentTime = options.sentTime || new Date()
      this.content = options.content
      this.addLocale(options.locale || 'en')
    }
  }

  @IsValidMessageType(BasicMessage.type)
  public readonly type = BasicMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/basicmessage/1.0/message')

  @Expose({ name: 'sent_time' })
  @Transform(({ value }) => DateParser(value))
  @IsDate()
  public sentTime!: Date

  @Expose({ name: 'content' })
  @IsString()
  public content!: string
}
