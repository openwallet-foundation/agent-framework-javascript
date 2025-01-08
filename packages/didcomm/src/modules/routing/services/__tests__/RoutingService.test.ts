import type { Wallet } from '@credo-ts/core/src/wallet'

import { Subject } from 'rxjs'

import { getAgentConfig, getAgentContext, mockFunction } from '@credo-ts/core/tests/helpers'
import { EventEmitter } from '@credo-ts/core/src/agent/EventEmitter'
import { Key } from '@credo-ts/core/src/crypto'
import { RoutingEventTypes } from '../../RoutingEvents'
import { MediationRecipientService } from '../MediationRecipientService'
import { RoutingService } from '../RoutingService'

jest.mock('../MediationRecipientService')
const MediationRecipientServiceMock = MediationRecipientService as jest.Mock<MediationRecipientService>

const recipientKey = Key.fromFingerprint('z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL')
const agentConfig = getAgentConfig('RoutingService', {
  endpoints: ['http://endpoint.com'],
})
const eventEmitter = new EventEmitter(agentConfig.agentDependencies, new Subject())
const wallet = {
  createKey: jest.fn().mockResolvedValue(recipientKey),
  // with satisfies Partial<Wallet> we still get type errors when the interface changes
} satisfies Partial<Wallet>
const agentContext = getAgentContext({
  wallet: wallet as unknown as Wallet,
  agentConfig,
})
const mediationRecipientService = new MediationRecipientServiceMock()
const routingService = new RoutingService(mediationRecipientService, eventEmitter)

const routing = {
  endpoints: ['http://endpoint.com'],
  recipientKey,
  routingKeys: [],
}
mockFunction(mediationRecipientService.addMediationRouting).mockResolvedValue(routing)

describe('RoutingService', () => {
  afterEach(() => {
    jest.clearAllMocks()
  })

  describe('getRouting', () => {
    test('calls mediation recipient service', async () => {
      const routing = await routingService.getRouting(agentContext, {
        mediatorId: 'mediator-id',
        useDefaultMediator: true,
      })

      expect(mediationRecipientService.addMediationRouting).toHaveBeenCalledWith(agentContext, routing, {
        mediatorId: 'mediator-id',
        useDefaultMediator: true,
      })
    })

    test('emits RoutingCreatedEvent', async () => {
      const routingListener = jest.fn()
      eventEmitter.on(RoutingEventTypes.RoutingCreatedEvent, routingListener)

      const routing = await routingService.getRouting(agentContext)

      expect(routing).toEqual(routing)
      expect(routingListener).toHaveBeenCalledWith({
        type: RoutingEventTypes.RoutingCreatedEvent,
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          routing,
        },
      })
    })
  })
})
