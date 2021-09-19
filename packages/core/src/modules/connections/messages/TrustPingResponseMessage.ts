import type { TimingDecorator } from '../../../decorators/timing/TimingDecorator'

import { Equals, IsOptional, IsString } from 'class-validator'

import { AgentMessage } from '../../../agent/AgentMessage'

export interface TrustPingResponseMessageOptions {
  comment?: string
  id?: string
  threadId: string
  timing?: Pick<TimingDecorator, 'inTime' | 'outTime'>
}

/**
 * Message to respond to a trust ping message
 *
 * @see https://github.com/hyperledger/aries-rfcs/blob/master/features/0048-trust-ping/README.md#messages
 */
export class TrustPingResponseMessage extends AgentMessage {
  /**
   * Create new TrustPingResponseMessage instance.
   * responseRequested will be true if not passed
   * @param options
   */
  public constructor(options: TrustPingResponseMessageOptions) {
    super()

    if (options) {
      this.id = options.id || this.generateId()
      this.comment = options.comment

      this.setThread({
        threadId: options.threadId,
      })

      if (options.timing) {
        this.setTiming({
          inTime: options.timing.inTime,
          outTime: options.timing.outTime,
        })
      }
    }
  }

  @Equals(TrustPingResponseMessage.type)
  public readonly type = TrustPingResponseMessage.type
  public static readonly type = 'https://didcomm.org/trust_ping/1.0/ping_response'

  @IsString()
  @IsOptional()
  public comment?: string
}
