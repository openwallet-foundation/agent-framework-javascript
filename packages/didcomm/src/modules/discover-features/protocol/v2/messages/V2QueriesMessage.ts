import type { FeatureQueryOptions } from '../../../../../models'

import { Type } from 'class-transformer'
import { ArrayNotEmpty, IsInstance } from 'class-validator'

import { AgentMessage } from '../../../../../AgentMessage'
import { FeatureQuery } from '../../../../../models'
import { IsValidMessageType, parseMessageType } from '../../../../../util/messageType'

export interface V2DiscoverFeaturesQueriesMessageOptions {
  id?: string
  queries: FeatureQueryOptions[]
  comment?: string
}

export class V2QueriesMessage extends AgentMessage {
  public constructor(options: V2DiscoverFeaturesQueriesMessageOptions) {
    super()

    if (options) {
      this.id = options.id ?? this.generateId()
      this.queries = options.queries.map((q) => new FeatureQuery(q))
    }
  }

  @IsValidMessageType(V2QueriesMessage.type)
  public readonly type = V2QueriesMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/discover-features/2.0/queries')

  @IsInstance(FeatureQuery, { each: true })
  @Type(() => FeatureQuery)
  @ArrayNotEmpty()
  public queries!: FeatureQuery[]
}
