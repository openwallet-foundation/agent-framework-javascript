import { Expose } from 'class-transformer'
import { IsInt } from 'class-validator'

import { AgentMessage } from '../../../../../AgentMessage'
import { IsValidMessageType, parseMessageType } from '../../../../../util/messageType'

export interface BatchPickupMessageOptions {
  id?: string
  batchSize: number
}

/**
 * A message to request to have multiple waiting messages sent inside a `batch` message.
 *
 * @see https://github.com/hyperledger/aries-rfcs/blob/master/features/0212-pickup/README.md#batch-pickup
 */
export class V1BatchPickupMessage extends AgentMessage {
  public readonly allowQueueTransport = false

  /**
   * Create new BatchPickupMessage instance.
   *
   * @param options
   */
  public constructor(options: BatchPickupMessageOptions) {
    super()

    if (options) {
      this.id = options.id || this.generateId()
      this.batchSize = options.batchSize
    }
  }

  @IsValidMessageType(V1BatchPickupMessage.type)
  public readonly type = V1BatchPickupMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/messagepickup/1.0/batch-pickup')

  @IsInt()
  @Expose({ name: 'batch_size' })
  public batchSize!: number
}
