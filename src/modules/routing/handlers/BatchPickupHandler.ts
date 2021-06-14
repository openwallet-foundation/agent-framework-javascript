import { Handler, HandlerInboundMessage } from '../../../agent/Handler'
import { MessagePickupService } from '../services'
import { BatchPickupMessage } from '../messages'
import { AriesFrameworkError } from '../../../error'

export class BatchPickupHandler implements Handler {
  private messagePickupService: MessagePickupService
  public supportedMessages = [BatchPickupMessage]

  public constructor(messagePickupService: MessagePickupService) {
    this.messagePickupService = messagePickupService
  }

  public async handle(messageContext: HandlerInboundMessage<BatchPickupHandler>) {
    console.log("batchPickup message handler.")
    if (!messageContext.connection) {
      throw new AriesFrameworkError(`Connection for verkey ${messageContext.recipientVerkey} not found!`)
    }
    return this.messagePickupService.batch(messageContext.connection)
  }
}
