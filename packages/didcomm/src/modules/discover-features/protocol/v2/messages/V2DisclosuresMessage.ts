import { Type } from 'class-transformer'
import { IsInstance } from 'class-validator'

import { AgentMessage } from '../../../../../AgentMessage'
import { Feature } from '../../../../../models'
import { IsValidMessageType, parseMessageType } from '../../../../../util/messageType'

export interface V2DisclosuresMessageOptions {
  id?: string
  threadId?: string
  features?: Feature[]
}

export class V2DisclosuresMessage extends AgentMessage {
  public constructor(options: V2DisclosuresMessageOptions) {
    super()

    if (options) {
      this.id = options.id ?? this.generateId()
      this.disclosures = options.features ?? []
      if (options.threadId) {
        this.setThread({
          threadId: options.threadId,
        })
      }
    }
  }

  @IsValidMessageType(V2DisclosuresMessage.type)
  public readonly type = V2DisclosuresMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/discover-features/2.0/disclosures')

  @IsInstance(Feature, { each: true })
  @Type(() => Feature)
  public disclosures!: Feature[]
}
