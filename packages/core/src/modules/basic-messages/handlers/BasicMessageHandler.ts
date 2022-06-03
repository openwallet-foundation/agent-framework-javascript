import type { Handler, HandlerInboundMessage } from '../../../agent/Handler'
import type { DIDCommV1Message } from '../../../agent/didcomm'
import type { BasicMessageService } from '../services/BasicMessageService'

import { AriesFrameworkError } from '../../../error'
import { BasicMessage } from '../messages'

export class BasicMessageHandler implements Handler<typeof DIDCommV1Message> {
  private basicMessageService: BasicMessageService
  public supportedMessages = [BasicMessage]

  public constructor(basicMessageService: BasicMessageService) {
    this.basicMessageService = basicMessageService
  }

  public async handle(messageContext: HandlerInboundMessage<BasicMessageHandler>) {
    const connection = messageContext.connection

    if (!connection) {
      throw new AriesFrameworkError(`Connection for verkey ${messageContext.recipient} not found!`)
    }

    if (!connection.theirKey) {
      throw new AriesFrameworkError(`Connection with verkey ${connection.verkey} has no recipient keys.`)
    }

    await this.basicMessageService.save(messageContext, connection)
  }
}
