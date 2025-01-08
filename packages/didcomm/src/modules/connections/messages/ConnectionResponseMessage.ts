import { Type, Expose } from 'class-transformer'
import { IsInstance, ValidateNested } from 'class-validator'

import { AgentMessage } from '../../../AgentMessage'
import { SignatureDecorator } from '../../../decorators/signature/SignatureDecorator'
import { IsValidMessageType, parseMessageType } from '../../../util/messageType'

export interface ConnectionResponseMessageOptions {
  id?: string
  threadId: string
  connectionSig: SignatureDecorator
}

/**
 * Message part of connection protocol used to complete the connection
 *
 * @see https://github.com/hyperledger/aries-rfcs/blob/master/features/0160-connection-protocol/README.md#2-connection-response
 */
export class ConnectionResponseMessage extends AgentMessage {
  public readonly allowDidSovPrefix = true

  /**
   * Create new ConnectionResponseMessage instance.
   * @param options
   */
  public constructor(options: ConnectionResponseMessageOptions) {
    super()

    if (options) {
      this.id = options.id || this.generateId()
      this.connectionSig = options.connectionSig

      this.setThread({ threadId: options.threadId })
    }
  }

  @IsValidMessageType(ConnectionResponseMessage.type)
  public readonly type = ConnectionResponseMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/connections/1.0/response')

  @Type(() => SignatureDecorator)
  @ValidateNested()
  @IsInstance(SignatureDecorator)
  @Expose({ name: 'connection~sig' })
  public connectionSig!: SignatureDecorator
}
