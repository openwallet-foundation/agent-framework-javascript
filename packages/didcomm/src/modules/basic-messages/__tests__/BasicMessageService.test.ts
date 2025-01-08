import { EventEmitter } from '@credo-ts/core'

import { getAgentContext, getMockConnection } from '../../../../../core/tests/helpers'
import { InboundMessageContext } from '../../../models'
import { BasicMessageRole } from '../BasicMessageRole'
import { BasicMessage } from '../messages'
import { BasicMessageRecord } from '../repository/BasicMessageRecord'
import { BasicMessageRepository } from '../repository/BasicMessageRepository'
import { BasicMessageService } from '../services'

jest.mock('../repository/BasicMessageRepository')
const BasicMessageRepositoryMock = BasicMessageRepository as jest.Mock<BasicMessageRepository>
const basicMessageRepository = new BasicMessageRepositoryMock()

jest.mock('../../../../../agent/EventEmitter')
const EventEmitterMock = EventEmitter as jest.Mock<EventEmitter>
const eventEmitter = new EventEmitterMock()

const agentContext = getAgentContext()

describe('BasicMessageService', () => {
  let basicMessageService: BasicMessageService
  const mockConnectionRecord = getMockConnection({
    id: 'd3849ac3-c981-455b-a1aa-a10bea6cead8',
    did: 'did:sov:C2SsBf5QUQpqSAQfhu3sd2',
  })

  beforeEach(() => {
    basicMessageService = new BasicMessageService(basicMessageRepository, eventEmitter)
  })

  describe('createMessage', () => {
    it(`creates message and record, and emits message and basic message record`, async () => {
      const { message } = await basicMessageService.createMessage(agentContext, 'hello', mockConnectionRecord)

      expect(message.content).toBe('hello')

      expect(basicMessageRepository.save).toHaveBeenCalledWith(agentContext, expect.any(BasicMessageRecord))
      expect(eventEmitter.emit).toHaveBeenCalledWith(agentContext, {
        type: 'BasicMessageStateChanged',
        payload: {
          basicMessageRecord: expect.objectContaining({
            connectionId: mockConnectionRecord.id,
            id: expect.any(String),
            sentTime: expect.any(String),
            content: 'hello',
            role: BasicMessageRole.Sender,
          }),
          message,
        },
      })
    })
  })

  describe('save', () => {
    it(`stores record and emits message and basic message record`, async () => {
      const basicMessage = new BasicMessage({
        id: '123',
        content: 'message',
      })

      const messageContext = new InboundMessageContext(basicMessage, { agentContext })

      await basicMessageService.save(messageContext, mockConnectionRecord)

      expect(basicMessageRepository.save).toHaveBeenCalledWith(agentContext, expect.any(BasicMessageRecord))
      expect(eventEmitter.emit).toHaveBeenCalledWith(agentContext, {
        type: 'BasicMessageStateChanged',
        payload: {
          basicMessageRecord: expect.objectContaining({
            connectionId: mockConnectionRecord.id,
            id: expect.any(String),
            sentTime: basicMessage.sentTime.toISOString(),
            content: basicMessage.content,
            role: BasicMessageRole.Receiver,
          }),
          message: messageContext.message,
        },
      })
    })
  })
})
