import type {
  DiscoverFeaturesDisclosureReceivedEvent,
  DiscoverFeaturesQueryReceivedEvent,
} from '../../../DiscoverFeaturesEvents'
import type { DiscoverFeaturesProtocolMsgReturnType } from '../../../DiscoverFeaturesServiceOptions'

import { Subject } from 'rxjs'

import { agentDependencies, getAgentContext, getMockConnection } from '../../../../../../../tests/helpers'
import { EventEmitter } from '../../../../../../agent/EventEmitter'
import { ConsoleLogger } from '../../../../../../logger'
import { FeatureRegistry } from '../../../../FeatureRegistry'
import { MessageHandlerRegistry } from '../../../../MessageHandlerRegistry'
import { Protocol, DidExchangeState, InboundMessageContext } from '../../../../models'
import { DiscoverFeaturesEventTypes } from '../../../DiscoverFeaturesEvents'
import { DiscoverFeaturesModuleConfig } from '../../../DiscoverFeaturesModuleConfig'
import { V1DiscoverFeaturesService } from '../V1DiscoverFeaturesService'
import { V1DiscloseMessage, V1QueryMessage } from '../messages'

jest.mock('../../../../MessageHandlerRegistry')
const MessageHandlerRegistryMock = MessageHandlerRegistry as jest.Mock<MessageHandlerRegistry>
const eventEmitter = new EventEmitter(agentDependencies, new Subject())
const featureRegistry = new FeatureRegistry()
featureRegistry.register(new Protocol({ id: 'https://didcomm.org/connections/1.0' }))
featureRegistry.register(new Protocol({ id: 'https://didcomm.org/notification/1.0', roles: ['role-1', 'role-2'] }))
featureRegistry.register(new Protocol({ id: 'https://didcomm.org/issue-credential/1.0' }))

jest.mock('../../../../../logger/Logger')
const LoggerMock = ConsoleLogger as jest.Mock<ConsoleLogger>

describe('V1DiscoverFeaturesService - auto accept queries', () => {
  const discoverFeaturesModuleConfig = new DiscoverFeaturesModuleConfig({ autoAcceptQueries: true })

  const discoverFeaturesService = new V1DiscoverFeaturesService(
    featureRegistry,
    eventEmitter,
    new MessageHandlerRegistryMock(),
    new LoggerMock(),
    discoverFeaturesModuleConfig
  )
  describe('createDisclosure', () => {
    it('should return all protocols when query is *', async () => {
      const queryMessage = new V1QueryMessage({
        query: '*',
      })

      const { message } = await discoverFeaturesService.createDisclosure({
        disclosureQueries: [{ featureType: 'protocol', match: queryMessage.query }],
        threadId: queryMessage.threadId,
      })

      expect(message.protocols.map((p) => p.protocolId)).toStrictEqual([
        'https://didcomm.org/connections/1.0',
        'https://didcomm.org/notification/1.0',
        'https://didcomm.org/issue-credential/1.0',
      ])
    })

    it('should return only one protocol if the query specifies a specific protocol', async () => {
      const queryMessage = new V1QueryMessage({
        query: 'https://didcomm.org/connections/1.0',
      })

      const { message } = await discoverFeaturesService.createDisclosure({
        disclosureQueries: [{ featureType: 'protocol', match: queryMessage.query }],
        threadId: queryMessage.threadId,
      })

      expect(message.protocols.map((p) => p.protocolId)).toStrictEqual(['https://didcomm.org/connections/1.0'])
    })

    it('should respect a wild card at the end of the query', async () => {
      const queryMessage = new V1QueryMessage({
        query: 'https://didcomm.org/connections/*',
      })

      const { message } = await discoverFeaturesService.createDisclosure({
        disclosureQueries: [{ featureType: 'protocol', match: queryMessage.query }],
        threadId: queryMessage.threadId,
      })

      expect(message.protocols.map((p) => p.protocolId)).toStrictEqual(['https://didcomm.org/connections/1.0'])
    })

    it('should send an empty array if no feature matches query', async () => {
      const queryMessage = new V1QueryMessage({
        query: 'not-supported',
      })

      const { message } = await discoverFeaturesService.createDisclosure({
        disclosureQueries: [{ featureType: 'protocol', match: queryMessage.query }],
        threadId: queryMessage.threadId,
      })

      expect(message.protocols.map((p) => p.protocolId)).toStrictEqual([])
    })

    it('should throw error if features other than protocols are disclosed', async () => {
      expect(
        discoverFeaturesService.createDisclosure({
          disclosureQueries: [
            { featureType: 'protocol', match: '1' },
            { featureType: 'goal-code', match: '2' },
          ],
          threadId: '1234',
        })
      ).rejects.toThrow('Discover Features V1 only supports protocols')
    })

    it('should throw error if no thread id is provided', async () => {
      expect(
        discoverFeaturesService.createDisclosure({
          disclosureQueries: [{ featureType: 'protocol', match: '1' }],
        })
      ).rejects.toThrow('Thread Id is required for Discover Features V1 disclosure')
    })
  })

  describe('createQuery', () => {
    it('should return a query message with the query and comment', async () => {
      const { message } = await discoverFeaturesService.createQuery({
        queries: [{ featureType: 'protocol', match: '*' }],
        comment: 'Hello',
      })

      expect(message.query).toBe('*')
      expect(message.comment).toBe('Hello')
    })

    it('should throw error if multiple features are queried', async () => {
      expect(
        discoverFeaturesService.createQuery({
          queries: [
            { featureType: 'protocol', match: '1' },
            { featureType: 'protocol', match: '2' },
          ],
        })
      ).rejects.toThrow('Discover Features V1 only supports a single query')
    })

    it('should throw error if a feature other than protocol is queried', async () => {
      expect(
        discoverFeaturesService.createQuery({
          queries: [{ featureType: 'goal-code', match: '1' }],
        })
      ).rejects.toThrow('Discover Features V1 only supports querying for protocol support')
    })
  })

  describe('processQuery', () => {
    it('should emit event and create disclosure message', async () => {
      const eventListenerMock = jest.fn()
      eventEmitter.on<DiscoverFeaturesQueryReceivedEvent>(DiscoverFeaturesEventTypes.QueryReceived, eventListenerMock)

      const queryMessage = new V1QueryMessage({ query: '*' })

      const connection = getMockConnection({ state: DidExchangeState.Completed })
      const messageContext = new InboundMessageContext(queryMessage, {
        agentContext: getAgentContext(),
        connection,
      })
      const outboundMessage = await discoverFeaturesService.processQuery(messageContext)

      eventEmitter.off<DiscoverFeaturesQueryReceivedEvent>(DiscoverFeaturesEventTypes.QueryReceived, eventListenerMock)

      expect(eventListenerMock).toHaveBeenCalledWith(
        expect.objectContaining({
          type: DiscoverFeaturesEventTypes.QueryReceived,
          payload: expect.objectContaining({
            connection,
            protocolVersion: 'v1',
            queries: [{ featureType: 'protocol', match: queryMessage.query }],
            threadId: queryMessage.threadId,
          }),
        })
      )
      expect(outboundMessage).toBeDefined()
      expect(
        (outboundMessage as DiscoverFeaturesProtocolMsgReturnType<V1DiscloseMessage>).message.protocols.map(
          (p) => p.protocolId
        )
      ).toStrictEqual([
        'https://didcomm.org/connections/1.0',
        'https://didcomm.org/notification/1.0',
        'https://didcomm.org/issue-credential/1.0',
      ])
    })
  })

  describe('processDisclosure', () => {
    it('should emit event', async () => {
      const eventListenerMock = jest.fn()
      eventEmitter.on<DiscoverFeaturesDisclosureReceivedEvent>(
        DiscoverFeaturesEventTypes.DisclosureReceived,
        eventListenerMock
      )

      const discloseMessage = new V1DiscloseMessage({
        protocols: [{ protocolId: 'prot1', roles: ['role1', 'role2'] }, { protocolId: 'prot2' }],
        threadId: '1234',
      })

      const connection = getMockConnection({ state: DidExchangeState.Completed })
      const messageContext = new InboundMessageContext(discloseMessage, {
        agentContext: getAgentContext(),
        connection,
      })
      await discoverFeaturesService.processDisclosure(messageContext)

      eventEmitter.off<DiscoverFeaturesDisclosureReceivedEvent>(
        DiscoverFeaturesEventTypes.DisclosureReceived,
        eventListenerMock
      )

      expect(eventListenerMock).toHaveBeenCalledWith(
        expect.objectContaining({
          type: DiscoverFeaturesEventTypes.DisclosureReceived,
          payload: expect.objectContaining({
            connection,
            protocolVersion: 'v1',
            disclosures: [
              { type: 'protocol', id: 'prot1', roles: ['role1', 'role2'] },
              { type: 'protocol', id: 'prot2' },
            ],

            threadId: discloseMessage.threadId,
          }),
        })
      )
    })
  })
})

describe('V1DiscoverFeaturesService - auto accept disabled', () => {
  const discoverFeaturesModuleConfig = new DiscoverFeaturesModuleConfig({ autoAcceptQueries: false })

  const discoverFeaturesService = new V1DiscoverFeaturesService(
    featureRegistry,
    eventEmitter,
    new MessageHandlerRegistry(),
    new LoggerMock(),
    discoverFeaturesModuleConfig
  )

  describe('processQuery', () => {
    it('should emit event and not send any message', async () => {
      const eventListenerMock = jest.fn()
      eventEmitter.on<DiscoverFeaturesQueryReceivedEvent>(DiscoverFeaturesEventTypes.QueryReceived, eventListenerMock)

      const queryMessage = new V1QueryMessage({ query: '*' })

      const connection = getMockConnection({ state: DidExchangeState.Completed })
      const messageContext = new InboundMessageContext(queryMessage, {
        agentContext: getAgentContext(),
        connection,
      })
      const outboundMessage = await discoverFeaturesService.processQuery(messageContext)

      eventEmitter.off<DiscoverFeaturesQueryReceivedEvent>(DiscoverFeaturesEventTypes.QueryReceived, eventListenerMock)

      expect(eventListenerMock).toHaveBeenCalledWith(
        expect.objectContaining({
          type: DiscoverFeaturesEventTypes.QueryReceived,
          payload: expect.objectContaining({
            connection,
            protocolVersion: 'v1',
            queries: [{ featureType: 'protocol', match: queryMessage.query }],
            threadId: queryMessage.threadId,
          }),
        })
      )
      expect(outboundMessage).toBeUndefined()
    })
  })
})
