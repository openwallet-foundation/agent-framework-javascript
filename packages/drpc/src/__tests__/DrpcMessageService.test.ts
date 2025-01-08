import type { DrpcRequestObject } from '../messages'

import { DidExchangeState, InboundMessageContext } from '@credo-ts/didcomm'

import { EventEmitter } from '../../../core/src/agent/EventEmitter'
import { getAgentContext, getMockConnection } from '../../../core/tests/helpers'
import { DrpcRequestMessage } from '../messages'
import { DrpcRole } from '../models/DrpcRole'
import { DrpcRecord } from '../repository/DrpcRecord'
import { DrpcRepository } from '../repository/DrpcRepository'
import { DrpcService } from '../services'

jest.mock('../repository/DrpcRepository')
const DrpcRepositoryMock = DrpcRepository as jest.Mock<DrpcRepository>
const drpcMessageRepository = new DrpcRepositoryMock()

jest.mock('../../../core/src/agent/EventEmitter')
const EventEmitterMock = EventEmitter as jest.Mock<EventEmitter>
const eventEmitter = new EventEmitterMock()

const agentContext = getAgentContext()

describe('DrpcService', () => {
  let drpcMessageService: DrpcService
  const mockConnectionRecord = getMockConnection({
    id: 'd3849ac3-c981-455b-a1aa-a10bea6cead8',
    did: 'did:sov:C2SsBf5QUQpqSAQfhu3sd2',
    state: DidExchangeState.Completed,
  })

  beforeEach(() => {
    drpcMessageService = new DrpcService(drpcMessageRepository, eventEmitter)
  })

  describe('createMessage', () => {
    it(`creates message and record, and emits message and basic message record`, async () => {
      const messageRequest: DrpcRequestObject = {
        jsonrpc: '2.0',
        method: 'hello',
        id: 1,
      }
      const { requestMessage } = await drpcMessageService.createRequestMessage(
        agentContext,
        messageRequest,
        mockConnectionRecord.id
      )

      expect(requestMessage).toBeInstanceOf(DrpcRequestMessage)
      expect((requestMessage.request as DrpcRequestObject).method).toBe('hello')

      expect(drpcMessageRepository.save).toHaveBeenCalledWith(agentContext, expect.any(DrpcRecord))
      expect(eventEmitter.emit).toHaveBeenCalledWith(agentContext, {
        type: 'DrpcRequestStateChanged',
        payload: {
          drpcMessageRecord: expect.objectContaining({
            connectionId: mockConnectionRecord.id,
            request: {
              id: 1,
              jsonrpc: '2.0',
              method: 'hello',
            },
            role: DrpcRole.Client,
          }),
        },
      })
    })
  })

  describe('recieve request', () => {
    it(`stores record and emits message and basic message record`, async () => {
      const drpcMessage = new DrpcRequestMessage({ request: { jsonrpc: '2.0', method: 'hello', id: 1 } })

      const messageContext = new InboundMessageContext(drpcMessage, { agentContext, connection: mockConnectionRecord })

      await drpcMessageService.receiveRequest(messageContext)

      expect(drpcMessageRepository.save).toHaveBeenCalledWith(agentContext, expect.any(DrpcRecord))
      expect(eventEmitter.emit).toHaveBeenCalledWith(agentContext, {
        type: 'DrpcRequestStateChanged',
        payload: {
          drpcMessageRecord: expect.objectContaining({
            connectionId: mockConnectionRecord.id,
            request: {
              id: 1,
              jsonrpc: '2.0',
              method: 'hello',
            },
            role: DrpcRole.Server,
          }),
        },
      })
    })
  })
})
