import type { EncryptedMessage } from '../../../../../types'

import { getAgentContext, getMockConnection, mockFunction } from '@credo-ts/core/tests/helpers'
import { EventEmitter } from '@credo-ts/core/src/agent/EventEmitter'
import { InjectionSymbols } from '@credo-ts/core/src/constants'
import { CredoError } from '@credo-ts/core/src/error'
import { verkeyToDidKey } from '@credo-ts/core/src/modules/dids/helpers'
import { uuid } from '@credo-ts/core/src/utils/uuid'
import { AgentEventTypes } from '../../../../../Events'
import { MessageSender } from '../../../../../MessageSender'
import { Attachment } from '../../../../../decorators/attachment/Attachment'
import { TrustPingMessage } from '../../../../../messages'
import { DidExchangeState, InboundMessageContext } from '../../../../../models'
import { ConnectionService } from '../../../../../services'
import { MessagePickupModuleConfig } from '../../../MessagePickupModuleConfig'
import { InMemoryMessagePickupRepository } from '../../../storage/InMemoryMessagePickupRepository'
import { V1MessagePickupProtocol } from '../../v1'
import { V2MessagePickupProtocol } from '../V2MessagePickupProtocol'
import {
  V2DeliveryRequestMessage,
  V2MessageDeliveryMessage,
  V2MessagesReceivedMessage,
  V2StatusMessage,
  V2StatusRequestMessage,
} from '../messages'

const mockConnection = getMockConnection({
  state: DidExchangeState.Completed,
})

// Mock classes
jest.mock('../../../storage/InMemoryMessagePickupRepository')
jest.mock('../../../../../agent/EventEmitter')
jest.mock('../../../../../agent/MessageSender')
jest.mock('../../../../connections/services/ConnectionService')

// Mock typed object
const InMessageRepositoryMock = InMemoryMessagePickupRepository as jest.Mock<InMemoryMessagePickupRepository>
const EventEmitterMock = EventEmitter as jest.Mock<EventEmitter>
const MessageSenderMock = MessageSender as jest.Mock<MessageSender>
const ConnectionServiceMock = ConnectionService as jest.Mock<ConnectionService>

const messagePickupModuleConfig = new MessagePickupModuleConfig({
  maximumBatchSize: 10,
  protocols: [new V1MessagePickupProtocol(), new V2MessagePickupProtocol()],
})
const messageSender = new MessageSenderMock()
const eventEmitter = new EventEmitterMock()
const connectionService = new ConnectionServiceMock()
const messagePickupRepository = new InMessageRepositoryMock()

const agentContext = getAgentContext({
  registerInstances: [
    [InjectionSymbols.MessagePickupRepository, messagePickupRepository],
    [EventEmitter, eventEmitter],
    [MessageSender, messageSender],
    [ConnectionService, connectionService],
    [MessagePickupModuleConfig, messagePickupModuleConfig],
  ],
})

const encryptedMessage: EncryptedMessage = {
  protected: 'base64url',
  iv: 'base64url',
  ciphertext: 'base64url',
  tag: 'base64url',
}
const queuedMessages = [
  { id: '1', encryptedMessage },
  { id: '2', encryptedMessage },
  { id: '3', encryptedMessage },
]

describe('V2MessagePickupProtocol', () => {
  let pickupProtocol: V2MessagePickupProtocol

  beforeEach(async () => {
    pickupProtocol = new V2MessagePickupProtocol()
  })

  describe('processStatusRequest', () => {
    test('no available messages in queue', async () => {
      mockFunction(messagePickupRepository.getAvailableMessageCount).mockResolvedValue(0)

      const statusRequest = new V2StatusRequestMessage({})

      const messageContext = new InboundMessageContext(statusRequest, { connection: mockConnection, agentContext })

      const { connection, message } = await pickupProtocol.processStatusRequest(messageContext)

      expect(connection).toEqual(mockConnection)
      expect(message).toEqual(
        new V2StatusMessage({
          id: message.id,
          threadId: statusRequest.threadId,
          messageCount: 0,
        })
      )
      expect(messagePickupRepository.getAvailableMessageCount).toHaveBeenCalledWith({ connectionId: mockConnection.id })
    })

    test('multiple messages in queue', async () => {
      mockFunction(messagePickupRepository.getAvailableMessageCount).mockResolvedValue(5)
      const statusRequest = new V2StatusRequestMessage({})

      const messageContext = new InboundMessageContext(statusRequest, { connection: mockConnection, agentContext })

      const { connection, message } = await pickupProtocol.processStatusRequest(messageContext)

      expect(connection).toEqual(mockConnection)
      expect(message).toEqual(
        new V2StatusMessage({
          id: message.id,
          threadId: statusRequest.threadId,
          messageCount: 5,
        })
      )
      expect(messagePickupRepository.getAvailableMessageCount).toHaveBeenCalledWith({ connectionId: mockConnection.id })
    })

    test('status request specifying recipient key', async () => {
      mockFunction(messagePickupRepository.getAvailableMessageCount).mockResolvedValue(10)

      const statusRequest = new V2StatusRequestMessage({
        recipientKey: '79CXkde3j8TNuMXxPdV7nLUrT2g7JAEjH5TreyVY7GEZ',
      })

      const messageContext = new InboundMessageContext(statusRequest, { connection: mockConnection, agentContext })

      await pickupProtocol.processStatusRequest(messageContext)
      expect(messagePickupRepository.getAvailableMessageCount).toHaveBeenCalledWith({ connectionId: mockConnection.id })
    })
  })

  describe('processDeliveryRequest', () => {
    test('no available messages in queue', async () => {
      mockFunction(messagePickupRepository.takeFromQueue).mockReturnValue([])

      const deliveryRequest = new V2DeliveryRequestMessage({ limit: 10 })

      const messageContext = new InboundMessageContext(deliveryRequest, { connection: mockConnection, agentContext })

      const { connection, message } = await pickupProtocol.processDeliveryRequest(messageContext)

      expect(connection).toEqual(mockConnection)
      expect(message).toEqual(
        new V2StatusMessage({
          id: message.id,
          threadId: deliveryRequest.threadId,
          messageCount: 0,
        })
      )
      expect(messagePickupRepository.takeFromQueue).toHaveBeenCalledWith({
        connectionId: mockConnection.id,
        limit: 10,
      })
    })

    test('less messages in queue than limit', async () => {
      mockFunction(messagePickupRepository.takeFromQueue).mockReturnValue(queuedMessages)

      const deliveryRequest = new V2DeliveryRequestMessage({ limit: 10 })

      const messageContext = new InboundMessageContext(deliveryRequest, { connection: mockConnection, agentContext })

      const { connection, message } = await pickupProtocol.processDeliveryRequest(messageContext)

      expect(connection).toEqual(mockConnection)
      expect(message).toBeInstanceOf(V2MessageDeliveryMessage)
      expect(message.threadId).toEqual(deliveryRequest.threadId)
      expect(message.appendedAttachments?.length).toEqual(3)
      expect(message.appendedAttachments).toEqual(
        expect.arrayContaining(
          queuedMessages.map((msg) =>
            expect.objectContaining({
              id: msg.id,
              data: {
                json: msg.encryptedMessage,
              },
            })
          )
        )
      )
      expect(messagePickupRepository.takeFromQueue).toHaveBeenCalledWith({
        connectionId: mockConnection.id,
        limit: 10,
      })
    })

    test('more messages in queue than limit', async () => {
      mockFunction(messagePickupRepository.takeFromQueue).mockReturnValue(queuedMessages.slice(0, 2))

      const deliveryRequest = new V2DeliveryRequestMessage({ limit: 2 })

      const messageContext = new InboundMessageContext(deliveryRequest, { connection: mockConnection, agentContext })

      const { connection, message } = await pickupProtocol.processDeliveryRequest(messageContext)

      expect(connection).toEqual(mockConnection)
      expect(message).toBeInstanceOf(V2MessageDeliveryMessage)
      expect(message.threadId).toEqual(deliveryRequest.threadId)
      expect(message.appendedAttachments?.length).toEqual(2)
      expect(message.appendedAttachments).toEqual(
        expect.arrayContaining(
          queuedMessages.slice(0, 2).map((msg) =>
            expect.objectContaining({
              id: msg.id,
              data: {
                json: msg.encryptedMessage,
              },
            })
          )
        )
      )
      expect(messagePickupRepository.takeFromQueue).toHaveBeenCalledWith({
        connectionId: mockConnection.id,
        limit: 2,
      })
    })

    test('delivery request specifying recipient key', async () => {
      mockFunction(messagePickupRepository.takeFromQueue).mockReturnValue(queuedMessages)

      const deliveryRequest = new V2DeliveryRequestMessage({
        limit: 10,
        recipientKey: 'recipientKey',
      })

      const messageContext = new InboundMessageContext(deliveryRequest, { connection: mockConnection, agentContext })

      await pickupProtocol.processDeliveryRequest(messageContext)

      expect(messagePickupRepository.takeFromQueue).toHaveBeenCalledWith({
        connectionId: mockConnection.id,
        limit: 10,
        recipientDid: verkeyToDidKey('recipientKey'),
      })
    })
  })

  describe('processMessagesReceived', () => {
    test('messages received partially', async () => {
      mockFunction(messagePickupRepository.takeFromQueue).mockReturnValue(queuedMessages)
      mockFunction(messagePickupRepository.getAvailableMessageCount).mockResolvedValue(4)

      const messagesReceived = new V2MessagesReceivedMessage({
        messageIdList: ['1', '2'],
      })

      const messageContext = new InboundMessageContext(messagesReceived, { connection: mockConnection, agentContext })

      const { connection, message } = await pickupProtocol.processMessagesReceived(messageContext)

      expect(connection).toEqual(mockConnection)
      expect(message).toEqual(
        new V2StatusMessage({
          id: message.id,
          threadId: messagesReceived.threadId,
          messageCount: 4,
        })
      )
      expect(messagePickupRepository.getAvailableMessageCount).toHaveBeenCalledWith({ connectionId: mockConnection.id })
      expect(messagePickupRepository.removeMessages).toHaveBeenCalledWith({
        connectionId: mockConnection.id,
        messageIds: ['1', '2'],
      })
    })

    test('all messages have been received', async () => {
      mockFunction(messagePickupRepository.takeFromQueue).mockReturnValue(queuedMessages)
      mockFunction(messagePickupRepository.getAvailableMessageCount).mockResolvedValue(0)

      const messagesReceived = new V2MessagesReceivedMessage({
        messageIdList: ['1', '2'],
      })

      const messageContext = new InboundMessageContext(messagesReceived, { connection: mockConnection, agentContext })

      const { connection, message } = await pickupProtocol.processMessagesReceived(messageContext)

      expect(connection).toEqual(mockConnection)
      expect(message).toEqual(
        new V2StatusMessage({
          id: message.id,
          threadId: messagesReceived.threadId,
          messageCount: 0,
        })
      )

      expect(messagePickupRepository.getAvailableMessageCount).toHaveBeenCalledWith({ connectionId: mockConnection.id })
      expect(messagePickupRepository.removeMessages).toHaveBeenCalledWith({
        connectionId: mockConnection.id,
        messageIds: ['1', '2'],
      })
    })
  })

  describe('createPickupMessage', () => {
    it('creates a status request message', async () => {
      const { message: statusRequestMessage } = await pickupProtocol.createPickupMessage(agentContext, {
        connectionRecord: mockConnection,
        recipientDid: 'a-key',
      })

      expect(statusRequestMessage).toMatchObject({
        id: expect.any(String),
        recipientKey: 'a-key',
      })
    })
  })

  describe('processStatus', () => {
    it('if status request has a message count of zero returns nothing', async () => {
      const status = new V2StatusMessage({
        threadId: uuid(),
        messageCount: 0,
      })

      mockFunction(connectionService.createTrustPing).mockResolvedValueOnce({
        message: new TrustPingMessage({}),
        connectionRecord: mockConnection,
      })

      const messageContext = new InboundMessageContext(status, { connection: mockConnection, agentContext })
      const deliveryRequestMessage = await pickupProtocol.processStatus(messageContext)
      expect(deliveryRequestMessage).toBeNull()
    })

    it('if it has a message count greater than zero return a valid delivery request', async () => {
      const status = new V2StatusMessage({
        threadId: uuid(),
        messageCount: 1,
      })
      const messageContext = new InboundMessageContext(status, { connection: mockConnection, agentContext })

      const deliveryRequestMessage = await pickupProtocol.processStatus(messageContext)
      expect(deliveryRequestMessage)
      expect(deliveryRequestMessage).toEqual(new V2DeliveryRequestMessage({ id: deliveryRequestMessage?.id, limit: 1 }))
    })
  })

  describe('processDelivery', () => {
    it('if the delivery has no attachments expect an error', async () => {
      const messageContext = new InboundMessageContext({} as V2MessageDeliveryMessage, {
        connection: mockConnection,
        agentContext,
      })

      await expect(pickupProtocol.processDelivery(messageContext)).rejects.toThrowError(
        new CredoError('Error processing attachments')
      )
    })

    it('should return a message received with an message id list in it', async () => {
      const messageDeliveryMessage = new V2MessageDeliveryMessage({
        threadId: uuid(),
        attachments: [
          new Attachment({
            id: '1',
            data: {
              json: {
                a: 'value',
              },
            },
          }),
        ],
      })
      const messageContext = new InboundMessageContext(messageDeliveryMessage, {
        connection: mockConnection,
        agentContext,
      })

      const messagesReceivedMessage = await pickupProtocol.processDelivery(messageContext)

      expect(messagesReceivedMessage).toEqual(
        new V2MessagesReceivedMessage({
          id: messagesReceivedMessage.id,
          messageIdList: ['1'],
        })
      )
    })

    it('calls the event emitter for each message', async () => {
      // This is to not take into account events previously emitted
      jest.clearAllMocks()

      const messageDeliveryMessage = new V2MessageDeliveryMessage({
        threadId: uuid(),
        attachments: [
          new Attachment({
            id: '1',
            data: {
              json: {
                first: 'value',
              },
            },
          }),
          new Attachment({
            id: '2',
            data: {
              json: {
                second: 'value',
              },
            },
          }),
        ],
      })
      const messageContext = new InboundMessageContext(messageDeliveryMessage, {
        connection: mockConnection,
        agentContext,
      })

      await pickupProtocol.processDelivery(messageContext)

      expect(eventEmitter.emit).toHaveBeenCalledTimes(2)
      expect(eventEmitter.emit).toHaveBeenNthCalledWith(1, agentContext, {
        type: AgentEventTypes.AgentMessageReceived,
        payload: {
          message: { first: 'value' },
          contextCorrelationId: agentContext.contextCorrelationId,
        },
      })
      expect(eventEmitter.emit).toHaveBeenNthCalledWith(2, agentContext, {
        type: AgentEventTypes.AgentMessageReceived,
        payload: {
          message: { second: 'value' },
          contextCorrelationId: agentContext.contextCorrelationId,
        },
      })
    })
  })
})
