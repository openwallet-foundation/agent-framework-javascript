import type { OutboundMessageContext } from '../models'

import { CredoError } from '@credo-ts/core'

export class MessageSendingError extends CredoError {
  public outboundMessageContext: OutboundMessageContext
  public constructor(
    message: string,
    { outboundMessageContext, cause }: { outboundMessageContext: OutboundMessageContext; cause?: Error }
  ) {
    super(message, { cause })
    this.outboundMessageContext = outboundMessageContext
  }
}
