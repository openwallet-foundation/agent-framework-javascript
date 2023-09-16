import type { V2DisclosuresMessageOptions } from './V2DisclosuresMessageOptions'

import { Type } from 'class-transformer'
import { IsInstance } from 'class-validator'

import { Feature } from '../../../../../agent/models'
import { DidCommV1Message } from '../../../../../didcomm'
import { IsValidMessageType, parseMessageType } from '../../../../../utils/messageType'

export class V2DisclosuresMessage extends DidCommV1Message {
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
