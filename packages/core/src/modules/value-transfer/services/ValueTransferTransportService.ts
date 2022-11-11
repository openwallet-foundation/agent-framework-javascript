/* eslint-disable @typescript-eslint/no-explicit-any */
import type { Logger } from '../../../logger'
import type { VtpTransportInterface } from '@sicpa-dlab/value-transfer-protocol-ts'

import { AgentConfig } from '../../../agent/AgentConfig'
import { MessageSender } from '../../../agent/MessageSender'
import { SendingMessageType } from '../../../agent/didcomm/types'
import { DIDCommV2Message } from '../../../agent/didcomm/v2/DIDCommV2Message'
import { injectable } from '../../../plugins'
import { JsonEncoder } from '../../../utils'
import { DidResolverService } from '../../dids/services/DidResolverService'

@injectable()
export class ValueTransferTransportService implements VtpTransportInterface {
  private readonly logger: Logger
  private didResolverService: DidResolverService
  private messageSender: MessageSender

  public constructor(config: AgentConfig, messageSender: MessageSender, didResolverService: DidResolverService) {
    this.logger = config.logger.createContextLogger('VTP-TransportService')
    this.messageSender = messageSender
    this.didResolverService = didResolverService
  }

  public async send(message: any, args?: any): Promise<void> {
    this.logger.info(`Sending VTP message with type '${message.type}' to DID ${message?.to}`)
    this.logger.debug(` Message: ${JsonEncoder.toString(message)}`)
    const didComMessage = new DIDCommV2Message({ ...message })
    const sendingMessageType = didComMessage.to ? SendingMessageType.Encrypted : SendingMessageType.Signed
    await this.messageSender.sendDIDCommV2Message(didComMessage, sendingMessageType, undefined, args?.mayProxyVia)
    this.logger.info('message sent!')
  }
}
