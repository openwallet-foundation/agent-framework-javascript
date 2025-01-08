import { Type, Expose } from 'class-transformer'
import { IsOptional, IsString, ValidateNested } from 'class-validator'

import { AgentMessage } from '../../../AgentMessage'
import { Attachment } from '../../../decorators/attachment/Attachment'
import { IsValidMessageType, parseMessageType } from '../../../util/messageType'

export interface DidExchangeResponseMessageOptions {
  id?: string
  threadId: string
  did: string
}

/**
 * Message part of connection protocol used to complete the connection
 *
 * @see https://github.com/hyperledger/aries-rfcs/blob/main/features/0023-did-exchange/README.md#2-exchange-response
 */
export class DidExchangeResponseMessage extends AgentMessage {
  /**
   * Create new DidExchangeResponseMessage instance.
   * @param options
   */
  public constructor(options: DidExchangeResponseMessageOptions) {
    super()

    if (options) {
      this.id = options.id || this.generateId()
      this.did = options.did

      this.setThread({
        threadId: options.threadId,
      })
    }
  }

  @IsValidMessageType(DidExchangeResponseMessage.type)
  public readonly type = DidExchangeResponseMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/didexchange/1.1/response')

  @IsString()
  public readonly did!: string

  @Expose({ name: 'did_doc~attach' })
  @IsOptional()
  @Type(() => Attachment)
  @ValidateNested()
  public didDoc?: Attachment

  @Expose({ name: 'did_rotate~attach' })
  @IsOptional()
  @Type(() => Attachment)
  @ValidateNested()
  public didRotate?: Attachment
}
