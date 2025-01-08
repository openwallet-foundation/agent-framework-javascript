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
import { Protocol, GoalCode, DidExchangeState, InboundMessageContext } from '../../../../models'
import { DiscoverFeaturesEventTypes } from '../../../DiscoverFeaturesEvents'
import { DiscoverFeaturesModuleConfig } from '../../../DiscoverFeaturesModuleConfig'
import { V2DiscoverFeaturesService } from '../V2DiscoverFeaturesService'
import { V2DisclosuresMessage, V2QueriesMessage } from '../messages'

jest.mock('../../../../MessageHandlerRegistry')
const MessageHandlerRegistryMock = MessageHandlerRegistry as jest.Mock<MessageHandlerRegistry>
const eventEmitter = new EventEmitter(agentDependencies, new Subject())
const featureRegistry = new FeatureRegistry()
featureRegistry.register(new Protocol({ id: 'https://didcomm.org/connections/1.0' }))
featureRegistry.register(new Protocol({ id: 'https://didcomm.org/notification/1.0', roles: ['role-1', 'role-2'] }))
featureRegistry.register(new Protocol({ id: 'https://didcomm.org/issue-credential/1.0' }))
featureRegistry.register(new GoalCode({ id: 'aries.vc.1' }))
featureRegistry.register(new GoalCode({ id: 'aries.vc.2' }))
featureRegistry.register(new GoalCode({ id: 'caries.vc.3' }))

jest.mock('../../../../../logger/Logger')
const LoggerMock = ConsoleLogger as jest.Mock<ConsoleLogger>

describe('V2DiscoverFeaturesService - auto accept queries', () => {
  const discoverFeaturesModuleConfig = new DiscoverFeaturesModuleConfig({ autoAcceptQueries: true })

  const discoverFeaturesService = new V2DiscoverFeaturesService(
    featureRegistry,
    eventEmitter,
    new MessageHandlerRegistryMock(),
    new LoggerMock(),
    discoverFeaturesModuleConfig
  )
  describe('createDisclosure', () => {
    it('should return all items when query is *', async () => {
      const queryMessage = new V2QueriesMessage({
        queries: [
          { featureType: Protocol.type, match: '*' },
          { featureType: GoalCode.type, match: '*' },
        ],
      })

      const { message } = await discoverFeaturesService.createDisclosure({
        disclosureQueries: queryMessage.queries,
        threadId: queryMessage.threadId,
      })

      expect(message.disclosures.map((p) => p.id)).toStrictEqual([
        'https://didcomm.org/connections/1.0',
        'https://didcomm.org/notification/1.0',
        'https://didcomm.org/issue-credential/1.0',
        'aries.vc.1',
        'aries.vc.2',
        'caries.vc.3',
      ])
    })

    it('should return only one protocol if the query specifies a specific protocol', async () => {
      const queryMessage = new V2QueriesMessage({
        queries: [{ featureType: 'protocol', match: 'https://didcomm.org/connections/1.0' }],
      })

      const { message } = await discoverFeaturesService.createDisclosure({
        disclosureQueries: queryMessage.queries,
        threadId: queryMessage.threadId,
      })

      expect(message.disclosures).toEqual([{ type: 'protocol', id: 'https://didcomm.org/connections/1.0' }])
    })

    it('should respect a wild card at the end of the query', async () => {
      const queryMessage = new V2QueriesMessage({
        queries: [
          { featureType: 'protocol', match: 'https://didcomm.org/connections/*' },
          { featureType: 'goal-code', match: 'aries*' },
        ],
      })

      const { message } = await discoverFeaturesService.createDisclosure({
        disclosureQueries: queryMessage.queries,
        threadId: queryMessage.threadId,
      })

      expect(message.disclosures.map((p) => p.id)).toStrictEqual([
        'https://didcomm.org/connections/1.0',
        'aries.vc.1',
        'aries.vc.2',
      ])
    })

    it('should send an empty array if no feature matches query', async () => {
      const queryMessage = new V2QueriesMessage({
        queries: [{ featureType: 'anything', match: 'not-supported' }],
      })

      const { message } = await discoverFeaturesService.createDisclosure({
        disclosureQueries: queryMessage.queries,
        threadId: queryMessage.threadId,
      })

      expect(message.disclosures).toStrictEqual([])
    })

    it('should accept an empty queries object', async () => {
      const { message } = await discoverFeaturesService.createDisclosure({
        disclosureQueries: [],
        threadId: '1234',
      })

      expect(message.disclosures).toStrictEqual([])
    })

    it('should accept no thread Id', async () => {
      const { message } = await discoverFeaturesService.createDisclosure({
        disclosureQueries: [{ featureType: 'goal-code', match: 'caries*' }],
      })

      expect(message.disclosures).toEqual([
        {
          type: 'goal-code',
          id: 'caries.vc.3',
        },
      ])
      expect(message.threadId).toEqual(message.id)
    })
  })

  describe('createQuery', () => {
    it('should return a queries message with the query and comment', async () => {
      const { message } = await discoverFeaturesService.createQuery({
        queries: [{ featureType: 'protocol', match: '*' }],
      })

      expect(message.queries).toEqual([{ featureType: 'protocol', match: '*' }])
    })

    it('should accept multiple features', async () => {
      const { message } = await discoverFeaturesService.createQuery({
        queries: [
          { featureType: 'protocol', match: '1' },
          { featureType: 'anything', match: '2' },
        ],
      })

      expect(message.queries).toEqual([
        { featureType: 'protocol', match: '1' },
        { featureType: 'anything', match: '2' },
      ])
    })
  })

  describe('processQuery', () => {
    it('should emit event and create disclosure message', async () => {
      const eventListenerMock = jest.fn()
      eventEmitter.on<DiscoverFeaturesQueryReceivedEvent>(DiscoverFeaturesEventTypes.QueryReceived, eventListenerMock)

      const queryMessage = new V2QueriesMessage({ queries: [{ featureType: 'protocol', match: '*' }] })

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
            protocolVersion: 'v2',
            queries: queryMessage.queries,
            threadId: queryMessage.threadId,
          }),
        })
      )
      expect(outboundMessage).toBeDefined()
      expect(
        (outboundMessage as DiscoverFeaturesProtocolMsgReturnType<V2DisclosuresMessage>).message.disclosures.map(
          (p) => p.id
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

      const discloseMessage = new V2DisclosuresMessage({
        features: [new Protocol({ id: 'prot1', roles: ['role1', 'role2'] }), new Protocol({ id: 'prot2' })],
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
            protocolVersion: 'v2',
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

describe('V2DiscoverFeaturesService - auto accept disabled', () => {
  const discoverFeaturesModuleConfig = new DiscoverFeaturesModuleConfig({ autoAcceptQueries: false })

  const discoverFeaturesService = new V2DiscoverFeaturesService(
    featureRegistry,
    eventEmitter,
    new MessageHandlerRegistryMock(),
    new LoggerMock(),
    discoverFeaturesModuleConfig
  )

  describe('processQuery', () => {
    it('should emit event and not send any message', async () => {
      const eventListenerMock = jest.fn()
      eventEmitter.on<DiscoverFeaturesQueryReceivedEvent>(DiscoverFeaturesEventTypes.QueryReceived, eventListenerMock)

      const queryMessage = new V2QueriesMessage({ queries: [{ featureType: 'protocol', match: '*' }] })

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
            protocolVersion: 'v2',
            queries: queryMessage.queries,
            threadId: queryMessage.threadId,
          }),
        })
      )
      expect(outboundMessage).toBeUndefined()
    })
  })
})
