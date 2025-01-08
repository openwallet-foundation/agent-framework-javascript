import { Expose } from 'class-transformer'
import { IsBoolean } from 'class-validator'

import { AgentMessage } from '../../../../../AgentMessage'
import { ReturnRouteTypes } from '../../../../../decorators/transport/TransportDecorator'
import { IsValidMessageType, parseMessageType } from '../../../../../util/messageType'

export interface V2LiveDeliveryChangeMessageOptions {
  id?: string
  liveDelivery: boolean
}

export class V2LiveDeliveryChangeMessage extends AgentMessage {
  public readonly allowQueueTransport = false

  public constructor(options: V2LiveDeliveryChangeMessageOptions) {
    super()

    if (options) {
      this.id = options.id || this.generateId()
      this.liveDelivery = options.liveDelivery
    }
    this.setReturnRouting(ReturnRouteTypes.all)
  }

  @IsValidMessageType(V2LiveDeliveryChangeMessage.type)
  public readonly type = V2LiveDeliveryChangeMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/messagepickup/2.0/live-delivery-change')

  @IsBoolean()
  @Expose({ name: 'live_delivery' })
  public liveDelivery!: boolean
}
