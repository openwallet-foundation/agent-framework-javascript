import type { WalletQuery } from 'indy-sdk'

import { Lifecycle, scoped } from 'tsyringe'

import { EventEmitter } from '../../../agent/EventEmitter'
import { createOutboundMessage } from '../../../agent/helpers'
import { InboundMessageContext } from '../../../agent/models/InboundMessageContext'
import { OutboundMessage } from '../../../types'
import { ConnectionRecord } from '../../connections/repository/ConnectionRecord'
import { BasicMessageEventTypes, BasicMessageReceivedEvent } from '../BasicMessageEvents'
import { BasicMessage } from '../messages'
import { BasicMessageRepository } from '../repository'
import { BasicMessageRecord } from '../repository/BasicMessageRecord'

@scoped(Lifecycle.ContainerScoped)
export class BasicMessageService {
  private basicMessageRepository: BasicMessageRepository
  private eventEmitter: EventEmitter

  public constructor(basicMessageRepository: BasicMessageRepository, eventEmitter: EventEmitter) {
    this.basicMessageRepository = basicMessageRepository
    this.eventEmitter = eventEmitter
  }

  public async send(message: string, connection: ConnectionRecord): Promise<OutboundMessage<BasicMessage>> {
    const basicMessage = new BasicMessage({
      content: message,
    })

    const basicMessageRecord = new BasicMessageRecord({
      id: basicMessage.id,
      sentTime: basicMessage.sentTime.toISOString(),
      content: basicMessage.content,
      tags: { from: connection.did || '', to: connection.theirDid || '' },
    })

    await this.basicMessageRepository.save(basicMessageRecord)
    return createOutboundMessage(connection, basicMessage)
  }

  /**
   * @todo use connection from message context
   */
  public async save({ message }: InboundMessageContext<BasicMessage>, connection: ConnectionRecord) {
    const basicMessageRecord = new BasicMessageRecord({
      id: message.id,
      sentTime: message.sentTime.toISOString(),
      content: message.content,
      tags: { from: connection.theirDid || '', to: connection.did || '' },
    })

    await this.basicMessageRepository.save(basicMessageRecord)
    this.eventEmitter.emit<BasicMessageReceivedEvent>({
      type: BasicMessageEventTypes.BasicMessageReceived,
      payload: { message, verkey: connection.verkey },
    })
  }

  public async findAllByQuery(query: WalletQuery) {
    return this.basicMessageRepository.findByQuery(query)
  }
}
