import type { AckMessageOptions } from '@credo-ts/didcomm'

import { AckMessage, IsValidMessageType, parseMessageType } from '@credo-ts/didcomm'

export type V1CredentialAckMessageOptions = AckMessageOptions

/**
 * @see https://github.com/hyperledger/aries-rfcs/blob/master/features/0015-acks/README.md#explicit-acks
 */
export class V1CredentialAckMessage extends AckMessage {
  public readonly allowDidSovPrefix = true

  /**
   * Create new CredentialAckMessage instance.
   * @param options
   */
  public constructor(options: V1CredentialAckMessageOptions) {
    super(options)
  }

  @IsValidMessageType(V1CredentialAckMessage.type)
  public readonly type = V1CredentialAckMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/issue-credential/1.0/ack')
}
