import { IsOptional, IsString } from 'class-validator'

import { AgentMessage } from '../../../../../AgentMessage'
import { IsValidMessageType, parseMessageType } from '../../../../../util/messageType'

export interface DiscoverFeaturesQueryMessageOptions {
  id?: string
  query: string
  comment?: string
}

export class V1QueryMessage extends AgentMessage {
  public constructor(options: DiscoverFeaturesQueryMessageOptions) {
    super()

    if (options) {
      this.id = options.id ?? this.generateId()
      this.query = options.query
      this.comment = options.comment
    }
  }

  @IsValidMessageType(V1QueryMessage.type)
  public readonly type = V1QueryMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/discover-features/1.0/query')

  @IsString()
  public query!: string

  @IsString()
  @IsOptional()
  public comment?: string
}
