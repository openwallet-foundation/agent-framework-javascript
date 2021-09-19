import type { InboundMessageContext } from '../../../agent/models/InboundMessageContext'
import type { OutboundMessage } from '../../../types'
import type { ConnectionRecord } from '../../connections/repository/ConnectionRecord'
import type { BasicMessageReceivedEvent } from '../BasicMessageEvents'
import type { BasicMessageTags } from '../repository'

import { Lifecycle, scoped } from 'tsyringe'

import { EventEmitter } from '../../../agent/EventEmitter'
import { createOutboundMessage } from '../../../agent/helpers'
import { BasicMessageEventTypes } from '../BasicMessageEvents'
import { BasicMessageRole } from '../BasicMessageRole'
import { BasicMessage } from '../messages'
import { BasicMessageRecord, BasicMessageRepository } from '../repository'

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
      connectionId: connection.id,
      role: BasicMessageRole.Sender,
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
      connectionId: connection.id,
      role: BasicMessageRole.Receiver,
    })

    await this.basicMessageRepository.save(basicMessageRecord)
    this.eventEmitter.emit<BasicMessageReceivedEvent>({
      type: BasicMessageEventTypes.BasicMessageReceived,
      payload: { message, basicMessageRecord },
    })
  }

  public async findAllByQuery(query: Partial<BasicMessageTags>) {
    return this.basicMessageRepository.findByQuery(query)
  }
}
