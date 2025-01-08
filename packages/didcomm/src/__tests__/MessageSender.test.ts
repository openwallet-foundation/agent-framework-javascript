/* eslint-disable @typescript-eslint/ban-ts-comment */

import type { DidDocumentService, IndyAgentService } from '../../../core/src/modules/dids'
import type { AgentMessageSentEvent } from '../Events'
import type { ConnectionRecord } from '../modules'
import type { MessagePickupRepository } from '../modules/message-pickup/storage'
import type { OutboundTransport } from '../transport'
import type { EncryptedMessage, ResolvedDidCommService } from '../types'

import { Subject } from 'rxjs'

import { EventEmitter } from '../../../core/src/agent/EventEmitter'
import { Key, KeyType } from '../../../core/src/crypto'
import { DidDocument, VerificationMethod } from '../../../core/src/modules/dids'
import { DidCommV1Service } from '../../../core/src/modules/dids/domain/service/DidCommV1Service'
import { verkeyToInstanceOfKey } from '../../../core/src/modules/dids/helpers'
import { DidResolverService } from '../../../core/src/modules/dids/services/DidResolverService'
import { TestMessage } from '../../../core/tests/TestMessage'
import {
  agentDependencies,
  getAgentConfig,
  getAgentContext,
  getMockConnection,
  mockFunction,
} from '../../../core/tests/helpers'
import testLogger from '../../../core/tests/logger'
import { EnvelopeService as EnvelopeServiceImpl } from '../EnvelopeService'
import { AgentEventTypes } from '../Events'
import { MessageSender } from '../MessageSender'
import { TransportService } from '../TransportService'
import { ReturnRouteTypes } from '../decorators/transport/TransportDecorator'
import { OutboundMessageContext, OutboundMessageSendStatus } from '../models'
import { InMemoryMessagePickupRepository } from '../modules/message-pickup/storage'
import { DidCommDocumentService } from '../services/DidCommDocumentService'

import { DummyTransportSession } from './stubs'

jest.mock('../TransportService')
jest.mock('../EnvelopeService')
jest.mock('../../../core/src/modules/dids/services/DidResolverService')
jest.mock('../services/DidCommDocumentService')

const logger = testLogger

const TransportServiceMock = TransportService as jest.MockedClass<typeof TransportService>
const DidResolverServiceMock = DidResolverService as jest.Mock<DidResolverService>
const DidCommDocumentServiceMock = DidCommDocumentService as jest.Mock<DidCommDocumentService>

class DummyHttpOutboundTransport implements OutboundTransport {
  public start(): Promise<void> {
    throw new Error('Method not implemented.')
  }

  public stop(): Promise<void> {
    throw new Error('Method not implemented.')
  }

  public supportedSchemes: string[] = ['https']

  public sendMessage() {
    return Promise.resolve()
  }
}

class DummyWsOutboundTransport implements OutboundTransport {
  public start(): Promise<void> {
    throw new Error('Method not implemented.')
  }

  public stop(): Promise<void> {
    throw new Error('Method not implemented.')
  }

  public supportedSchemes: string[] = ['wss']

  public sendMessage() {
    return Promise.resolve()
  }
}

describe('MessageSender', () => {
  const EnvelopeService = <jest.Mock<EnvelopeServiceImpl>>(<unknown>EnvelopeServiceImpl)

  const encryptedMessage: EncryptedMessage = {
    protected: 'base64url',
    iv: 'base64url',
    ciphertext: 'base64url',
    tag: 'base64url',
  }

  const enveloperService = new EnvelopeService()
  const envelopeServicePackMessageMock = mockFunction(enveloperService.packMessage)

  const didResolverService = new DidResolverServiceMock()
  const didCommDocumentService = new DidCommDocumentServiceMock()
  const eventEmitter = new EventEmitter(agentDependencies, new Subject())
  const didResolverServiceResolveMock = mockFunction(didResolverService.resolveDidDocument)
  const didResolverServiceResolveDidServicesMock = mockFunction(didCommDocumentService.resolveServicesFromDid)

  const inboundMessage = new TestMessage()
  inboundMessage.setReturnRouting(ReturnRouteTypes.all)

  const recipientKey = Key.fromPublicKeyBase58('8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K', KeyType.Ed25519)
  const senderKey = Key.fromPublicKeyBase58('79CXkde3j8TNuMXxPdV7nLUrT2g7JAEjH5TreyVY7GEZ', KeyType.Ed25519)
  const session = new DummyTransportSession('session-123')
  session.keys = {
    recipientKeys: [recipientKey],
    routingKeys: [],
    senderKey: senderKey,
  }
  session.inboundMessage = inboundMessage
  session.send = jest.fn()

  const sessionWithoutKeys = new DummyTransportSession('sessionWithoutKeys-123')
  sessionWithoutKeys.inboundMessage = inboundMessage
  sessionWithoutKeys.send = jest.fn()

  const transportService = new TransportService(getAgentContext(), eventEmitter)
  const transportServiceFindSessionMock = mockFunction(transportService.findSessionByConnectionId)
  const transportServiceFindSessionByIdMock = mockFunction(transportService.findSessionById)
  const transportServiceHasInboundEndpoint = mockFunction(transportService.hasInboundEndpoint)

  const firstDidCommService = new DidCommV1Service({
    id: `<did>;indy`,
    serviceEndpoint: 'https://www.first-endpoint.com',
    recipientKeys: ['#authentication-1'],
  })
  const secondDidCommService = new DidCommV1Service({
    id: `<did>;indy`,
    serviceEndpoint: 'https://www.second-endpoint.com',
    recipientKeys: ['#authentication-1'],
  })

  let messageSender: MessageSender
  let outboundTransport: OutboundTransport
  let messagePickupRepository: MessagePickupRepository
  let connection: ConnectionRecord
  let outboundMessageContext: OutboundMessageContext
  const agentConfig = getAgentConfig('MessageSender')
  const agentContext = getAgentContext()
  const eventListenerMock = jest.fn()

  describe('sendMessage', () => {
    beforeEach(() => {
      TransportServiceMock.mockClear()
      DidResolverServiceMock.mockClear()

      eventEmitter.on<AgentMessageSentEvent>(AgentEventTypes.AgentMessageSent, eventListenerMock)

      outboundTransport = new DummyHttpOutboundTransport()
      messagePickupRepository = new InMemoryMessagePickupRepository(agentConfig.logger)
      messageSender = new MessageSender(
        enveloperService,
        transportService,
        messagePickupRepository,
        logger,
        didResolverService,
        didCommDocumentService,
        eventEmitter
      )
      connection = getMockConnection({
        id: 'test-123',
        did: 'did:peer:1mydid',
        theirDid: 'did:peer:1theirdid',
        theirLabel: 'Test 123',
      })
      outboundMessageContext = new OutboundMessageContext(new TestMessage(), { agentContext, connection })

      envelopeServicePackMessageMock.mockReturnValue(Promise.resolve(encryptedMessage))
      transportServiceHasInboundEndpoint.mockReturnValue(true)

      const didDocumentInstance = getMockDidDocument({
        service: [firstDidCommService, secondDidCommService],
      })
      didResolverServiceResolveMock.mockResolvedValue(didDocumentInstance)
      didResolverServiceResolveDidServicesMock.mockResolvedValue([
        getMockResolvedDidService(firstDidCommService),
        getMockResolvedDidService(secondDidCommService),
      ])
    })

    afterEach(() => {
      eventEmitter.off<AgentMessageSentEvent>(AgentEventTypes.AgentMessageSent, eventListenerMock)

      jest.resetAllMocks()
    })

    test('throw error when there is no outbound transport', async () => {
      await expect(messageSender.sendMessage(outboundMessageContext)).rejects.toThrow(
        /Message is undeliverable to connection/
      )
      expect(eventListenerMock).toHaveBeenCalledWith({
        type: AgentEventTypes.AgentMessageSent,
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          message: outboundMessageContext,
          status: OutboundMessageSendStatus.Undeliverable,
        },
      })
    })

    test('throw error when there is no service or queue', async () => {
      messageSender.registerOutboundTransport(outboundTransport)

      didResolverServiceResolveMock.mockResolvedValue(getMockDidDocument({ service: [] }))
      didResolverServiceResolveDidServicesMock.mockResolvedValue([])

      await expect(messageSender.sendMessage(outboundMessageContext)).rejects.toThrow(
        `Message is undeliverable to connection test-123 (Test 123)`
      )
      expect(eventListenerMock).toHaveBeenCalledWith({
        type: AgentEventTypes.AgentMessageSent,
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          message: outboundMessageContext,
          status: OutboundMessageSendStatus.Undeliverable,
        },
      })
    })

    test('call send message when session send method fails', async () => {
      messageSender.registerOutboundTransport(outboundTransport)
      transportServiceFindSessionMock.mockReturnValue(session)
      session.send = jest.fn().mockRejectedValue(new Error('some error'))

      messageSender.registerOutboundTransport(outboundTransport)
      const sendMessageSpy = jest.spyOn(outboundTransport, 'sendMessage')

      await messageSender.sendMessage(outboundMessageContext)

      expect(eventListenerMock).toHaveBeenCalledWith({
        type: AgentEventTypes.AgentMessageSent,
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          message: outboundMessageContext,
          status: OutboundMessageSendStatus.SentToTransport,
        },
      })

      expect(sendMessageSpy).toHaveBeenCalledWith({
        connectionId: 'test-123',
        payload: encryptedMessage,
        endpoint: firstDidCommService.serviceEndpoint,
        responseRequested: false,
      })
      expect(sendMessageSpy).toHaveBeenCalledTimes(1)
    })

    test("resolves the did service using the did resolver if connection.theirDid starts with 'did:'", async () => {
      messageSender.registerOutboundTransport(outboundTransport)

      const sendMessageSpy = jest.spyOn(outboundTransport, 'sendMessage')

      await messageSender.sendMessage(outboundMessageContext)

      expect(eventListenerMock).toHaveBeenCalledWith({
        type: AgentEventTypes.AgentMessageSent,
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          message: outboundMessageContext,
          status: OutboundMessageSendStatus.SentToTransport,
        },
      })

      expect(didResolverServiceResolveDidServicesMock).toHaveBeenCalledWith(agentContext, connection.theirDid)
      expect(sendMessageSpy).toHaveBeenCalledWith({
        connectionId: 'test-123',
        payload: encryptedMessage,
        endpoint: firstDidCommService.serviceEndpoint,
        responseRequested: false,
      })
      expect(sendMessageSpy).toHaveBeenCalledTimes(1)
    })

    test("throws an error if connection.theirDid starts with 'did:' but the resolver can't resolve the did document", async () => {
      messageSender.registerOutboundTransport(outboundTransport)

      didResolverServiceResolveMock.mockRejectedValue(
        new Error(`Unable to resolve did document for did '${connection.theirDid}': notFound`)
      )

      await expect(messageSender.sendMessage(outboundMessageContext)).rejects.toThrowError(
        `Unable to resolve DID Document for '${connection.did}`
      )

      expect(eventListenerMock).toHaveBeenCalledWith({
        type: AgentEventTypes.AgentMessageSent,
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          message: outboundMessageContext,
          status: OutboundMessageSendStatus.Undeliverable,
        },
      })
    })

    test('call send message when session send method fails with missing keys', async () => {
      messageSender.registerOutboundTransport(outboundTransport)
      transportServiceFindSessionMock.mockReturnValue(sessionWithoutKeys)

      messageSender.registerOutboundTransport(outboundTransport)
      const sendMessageSpy = jest.spyOn(outboundTransport, 'sendMessage')

      await messageSender.sendMessage(outboundMessageContext)

      expect(eventListenerMock).toHaveBeenCalledWith({
        type: AgentEventTypes.AgentMessageSent,
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          message: outboundMessageContext,
          status: OutboundMessageSendStatus.SentToTransport,
        },
      })

      expect(sendMessageSpy).toHaveBeenCalledWith({
        connectionId: 'test-123',
        payload: encryptedMessage,
        endpoint: firstDidCommService.serviceEndpoint,
        responseRequested: false,
      })
      expect(sendMessageSpy).toHaveBeenCalledTimes(1)
    })

    test('call send message on session when outbound message has sessionId attached', async () => {
      transportServiceFindSessionByIdMock.mockReturnValue(session)
      messageSender.registerOutboundTransport(outboundTransport)
      const sendMessageSpy = jest.spyOn(outboundTransport, 'sendMessage')
      // @ts-ignore
      const sendMessageToServiceSpy = jest.spyOn(messageSender, 'sendMessageToService')

      const contextWithSessionId = new OutboundMessageContext(outboundMessageContext.message, {
        agentContext: outboundMessageContext.agentContext,
        connection: outboundMessageContext.connection,
        sessionId: 'session-123',
      })

      await messageSender.sendMessage(contextWithSessionId)

      expect(eventListenerMock).toHaveBeenCalledWith({
        type: AgentEventTypes.AgentMessageSent,
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          message: contextWithSessionId,
          status: OutboundMessageSendStatus.SentToSession,
        },
      })

      expect(session.send).toHaveBeenCalledTimes(1)
      expect(session.send).toHaveBeenNthCalledWith(1, agentContext, encryptedMessage)
      expect(sendMessageSpy).toHaveBeenCalledTimes(0)
      expect(sendMessageToServiceSpy).toHaveBeenCalledTimes(0)
      expect(transportServiceFindSessionByIdMock).toHaveBeenCalledWith('session-123')
    })

    test('call send message on session when there is a session for a given connection', async () => {
      messageSender.registerOutboundTransport(outboundTransport)
      const sendMessageSpy = jest.spyOn(outboundTransport, 'sendMessage')
      //@ts-ignore
      const sendToServiceSpy = jest.spyOn(messageSender, 'sendToService')

      await messageSender.sendMessage(outboundMessageContext)

      //@ts-ignore
      const [[sendMessage]] = sendToServiceSpy.mock.calls

      expect(eventListenerMock).toHaveBeenCalledWith({
        type: AgentEventTypes.AgentMessageSent,
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          message: outboundMessageContext,
          status: OutboundMessageSendStatus.SentToTransport,
        },
      })
      expect(sendMessage).toMatchObject({
        connection: {
          id: 'test-123',
        },
        message: outboundMessageContext.message,
        serviceParams: {
          returnRoute: false,
          service: {
            serviceEndpoint: firstDidCommService.serviceEndpoint,
          },
        },
      })

      //@ts-ignore
      expect(sendMessage.serviceParams.senderKey.publicKeyBase58).toEqual(
        'EoGusetSxDJktp493VCyh981nUnzMamTRjvBaHZAy68d'
      )

      //@ts-ignore
      expect(sendMessage.serviceParams.service.recipientKeys.map((key) => key.publicKeyBase58)).toEqual([
        'EoGusetSxDJktp493VCyh981nUnzMamTRjvBaHZAy68d',
      ])

      expect(sendToServiceSpy).toHaveBeenCalledTimes(1)
      expect(sendMessageSpy).toHaveBeenCalledTimes(1)
    })

    test('calls sendToService with payload and endpoint from second DidComm service when the first fails', async () => {
      messageSender.registerOutboundTransport(outboundTransport)
      const sendMessageSpy = jest.spyOn(outboundTransport, 'sendMessage')
      //@ts-ignore
      const sendToServiceSpy = jest.spyOn(messageSender, 'sendToService')

      // Simulate the case when the first call fails
      sendMessageSpy.mockRejectedValueOnce(new Error())

      await messageSender.sendMessage(outboundMessageContext)

      expect(eventListenerMock).toHaveBeenCalledWith({
        type: AgentEventTypes.AgentMessageSent,
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          message: outboundMessageContext,
          status: OutboundMessageSendStatus.SentToTransport,
        },
      })

      //@ts-ignore
      const [, [sendMessage]] = sendToServiceSpy.mock.calls

      expect(sendMessage).toMatchObject({
        agentContext,
        connection: {
          id: 'test-123',
        },
        message: outboundMessageContext.message,
        serviceParams: {
          returnRoute: false,
          service: {
            serviceEndpoint: secondDidCommService.serviceEndpoint,
          },
        },
      })

      //@ts-ignore
      expect(sendMessage.serviceParams.senderKey.publicKeyBase58).toEqual(
        'EoGusetSxDJktp493VCyh981nUnzMamTRjvBaHZAy68d'
      )
      //@ts-ignore
      expect(sendMessage.serviceParams.service.recipientKeys.map((key) => key.publicKeyBase58)).toEqual([
        'EoGusetSxDJktp493VCyh981nUnzMamTRjvBaHZAy68d',
      ])

      expect(sendToServiceSpy).toHaveBeenCalledTimes(2)
      expect(sendMessageSpy).toHaveBeenCalledTimes(2)
    })

    test('throw error when message endpoint is not supported by outbound transport schemes', async () => {
      messageSender.registerOutboundTransport(new DummyWsOutboundTransport())
      await expect(messageSender.sendMessage(outboundMessageContext)).rejects.toThrow(
        /Message is undeliverable to connection/
      )

      expect(eventListenerMock).toHaveBeenCalledWith({
        type: AgentEventTypes.AgentMessageSent,
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          message: outboundMessageContext,
          status: OutboundMessageSendStatus.Undeliverable,
        },
      })
    })
  })

  describe('sendMessageToService', () => {
    const service: ResolvedDidCommService = {
      id: 'out-of-band',
      recipientKeys: [Key.fromFingerprint('z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL')],
      routingKeys: [],
      serviceEndpoint: 'https://example.com',
    }
    const senderKey = Key.fromFingerprint('z6MkmjY8GnV5i9YTDtPETC2uUAW6ejw3nk5mXF5yci5ab7th')

    beforeEach(() => {
      outboundTransport = new DummyHttpOutboundTransport()
      messageSender = new MessageSender(
        enveloperService,
        transportService,
        new InMemoryMessagePickupRepository(agentConfig.logger),
        logger,
        didResolverService,
        didCommDocumentService,
        eventEmitter
      )

      eventEmitter.on<AgentMessageSentEvent>(AgentEventTypes.AgentMessageSent, eventListenerMock)

      envelopeServicePackMessageMock.mockReturnValue(Promise.resolve(encryptedMessage))
    })

    afterEach(() => {
      jest.resetAllMocks()
      eventEmitter.off<AgentMessageSentEvent>(AgentEventTypes.AgentMessageSent, eventListenerMock)
    })

    test('throws error when there is no outbound transport', async () => {
      outboundMessageContext = new OutboundMessageContext(new TestMessage(), {
        agentContext,
        serviceParams: {
          senderKey,
          service,
        },
      })
      await expect(messageSender.sendMessage(outboundMessageContext)).rejects.toThrow(
        `Agent has no outbound transport!`
      )

      expect(eventListenerMock).toHaveBeenCalledWith({
        type: AgentEventTypes.AgentMessageSent,
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          message: outboundMessageContext,
          status: OutboundMessageSendStatus.Undeliverable,
        },
      })
    })

    test('calls send message with payload and endpoint from DIDComm service', async () => {
      messageSender.registerOutboundTransport(outboundTransport)
      const sendMessageSpy = jest.spyOn(outboundTransport, 'sendMessage')

      outboundMessageContext = new OutboundMessageContext(new TestMessage(), {
        agentContext,
        serviceParams: {
          senderKey,
          service,
        },
      })

      await messageSender.sendMessage(outboundMessageContext)

      expect(eventListenerMock).toHaveBeenCalledWith({
        type: AgentEventTypes.AgentMessageSent,
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          message: outboundMessageContext,
          status: OutboundMessageSendStatus.SentToTransport,
        },
      })

      expect(sendMessageSpy).toHaveBeenCalledWith({
        payload: encryptedMessage,
        endpoint: service.serviceEndpoint,
        responseRequested: false,
      })
      expect(sendMessageSpy).toHaveBeenCalledTimes(1)
    })

    test('call send message with responseRequested when message has return route', async () => {
      messageSender.registerOutboundTransport(outboundTransport)
      const sendMessageSpy = jest.spyOn(outboundTransport, 'sendMessage')

      const message = new TestMessage()
      message.setReturnRouting(ReturnRouteTypes.all)

      outboundMessageContext = new OutboundMessageContext(message, {
        agentContext,
        serviceParams: {
          senderKey,
          service,
        },
      })

      await messageSender.sendMessage(outboundMessageContext)

      expect(eventListenerMock).toHaveBeenCalledWith({
        type: AgentEventTypes.AgentMessageSent,
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          message: outboundMessageContext,
          status: OutboundMessageSendStatus.SentToTransport,
        },
      })

      expect(sendMessageSpy).toHaveBeenCalledWith({
        payload: encryptedMessage,
        endpoint: service.serviceEndpoint,
        responseRequested: true,
      })
      expect(sendMessageSpy).toHaveBeenCalledTimes(1)
    })

    test('throw error when message endpoint is not supported by outbound transport schemes', async () => {
      messageSender.registerOutboundTransport(new DummyWsOutboundTransport())
      outboundMessageContext = new OutboundMessageContext(new TestMessage(), {
        agentContext,
        serviceParams: {
          senderKey,
          service,
        },
      })

      await expect(messageSender.sendMessage(outboundMessageContext)).rejects.toThrow(
        /Unable to send message to service/
      )
      expect(eventListenerMock).toHaveBeenCalledWith({
        type: AgentEventTypes.AgentMessageSent,
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          message: outboundMessageContext,
          status: OutboundMessageSendStatus.Undeliverable,
        },
      })
    })
  })

  describe('packMessage', () => {
    beforeEach(() => {
      outboundTransport = new DummyHttpOutboundTransport()
      messagePickupRepository = new InMemoryMessagePickupRepository(agentConfig.logger)
      messageSender = new MessageSender(
        enveloperService,
        transportService,
        messagePickupRepository,
        logger,
        didResolverService,
        didCommDocumentService,
        eventEmitter
      )
      connection = getMockConnection()

      envelopeServicePackMessageMock.mockReturnValue(Promise.resolve(encryptedMessage))
    })

    afterEach(() => {
      jest.resetAllMocks()
    })

    test('return outbound message context with connection, payload and endpoint', async () => {
      const message = new TestMessage()
      const endpoint = 'https://example.com'

      const keys = {
        recipientKeys: [recipientKey],
        routingKeys: [],
        senderKey: senderKey,
      }
      const result = await messageSender.packMessage(agentContext, { message, keys, endpoint })

      expect(result).toEqual({
        payload: encryptedMessage,
        responseRequested: message.hasAnyReturnRoute(),
        endpoint,
      })
    })
  })
})

function getMockDidDocument({ service }: { service: DidDocumentService[] }) {
  return new DidDocument({
    id: 'did:sov:SKJVx2kn373FNgvff1SbJo',
    alsoKnownAs: ['did:sov:SKJVx2kn373FNgvff1SbJo'],
    controller: ['did:sov:SKJVx2kn373FNgvff1SbJo'],
    verificationMethod: [],
    service,
    authentication: [
      new VerificationMethod({
        id: 'did:sov:SKJVx2kn373FNgvff1SbJo#authentication-1',
        type: 'Ed25519VerificationKey2018',
        controller: 'did:sov:LjgpST2rjsoxYegQDRm7EL',
        publicKeyBase58: 'EoGusetSxDJktp493VCyh981nUnzMamTRjvBaHZAy68d',
      }),
    ],
  })
}

function getMockResolvedDidService(service: DidCommV1Service | IndyAgentService): ResolvedDidCommService {
  return {
    id: service.id,
    serviceEndpoint: service.serviceEndpoint,
    recipientKeys: [verkeyToInstanceOfKey('EoGusetSxDJktp493VCyh981nUnzMamTRjvBaHZAy68d')],
    routingKeys: [],
  }
}
