import { Expose } from 'class-transformer'
import { IsArray, IsNotEmpty, IsString } from 'class-validator'

import { AgentMessage } from '../../../AgentMessage'
import { IsValidMessageType, parseMessageType } from '../../../util/messageType'

export interface MediationGrantMessageOptions {
  id?: string
  endpoint: string
  routingKeys: string[]
  threadId: string
}

/**
 * A route grant message is a signal from the mediator to the recipient that permission is given to distribute the
 * included information as an inbound route.
 *
 * @see https://github.com/hyperledger/aries-rfcs/blob/master/features/0211-route-coordination/README.md#mediation-grant
 */
export class MediationGrantMessage extends AgentMessage {
  public constructor(options: MediationGrantMessageOptions) {
    super()

    if (options) {
      this.id = options.id ?? this.generateId()
      this.endpoint = options.endpoint
      this.routingKeys = options.routingKeys
      this.setThread({
        threadId: options.threadId,
      })
    }
  }

  @IsValidMessageType(MediationGrantMessage.type)
  public readonly type = MediationGrantMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/coordinate-mediation/1.0/mediate-grant')

  @IsNotEmpty()
  @IsArray()
  @Expose({ name: 'routing_keys' })
  public routingKeys!: string[]

  @IsNotEmpty()
  @IsString()
  public endpoint!: string
}
