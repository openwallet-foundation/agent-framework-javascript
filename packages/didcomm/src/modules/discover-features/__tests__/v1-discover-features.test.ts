import type { ConnectionRecord } from '../../repository'
import type {
  DiscoverFeaturesDisclosureReceivedEvent,
  DiscoverFeaturesQueryReceivedEvent,
} from '../DiscoverFeaturesEvents'

import { ReplaySubject } from 'rxjs'

import { setupSubjectTransports } from '../../../../../tests'
import { getInMemoryAgentOptions, makeConnection } from '../../../../../tests/helpers'
import { Agent } from '../../../../agent/Agent'
import { DiscoverFeaturesEventTypes } from '../DiscoverFeaturesEvents'

import { waitForDisclosureSubject, waitForQuerySubject } from './helpers'

const faberAgentOptions = getInMemoryAgentOptions('Faber Discover Features V1 E2E', {
  endpoints: ['rxjs:faber'],
})

const aliceAgentOptions = getInMemoryAgentOptions('Alice Discover Features V1 E2E', {
  endpoints: ['rxjs:alice'],
})

describe('v1 discover features', () => {
  let faberAgent: Agent
  let aliceAgent: Agent
  let faberConnection: ConnectionRecord

  beforeAll(async () => {
    faberAgent = new Agent(faberAgentOptions)
    aliceAgent = new Agent(aliceAgentOptions)

    setupSubjectTransports([faberAgent, aliceAgent])

    await faberAgent.initialize()
    await aliceAgent.initialize()
    ;[faberConnection] = await makeConnection(faberAgent, aliceAgent)
  })

  afterAll(async () => {
    await faberAgent.shutdown()
    await faberAgent.wallet.delete()
    await aliceAgent.shutdown()
    await aliceAgent.wallet.delete()
  })

  test('Faber asks Alice for revocation notification protocol support', async () => {
    const faberReplay = new ReplaySubject<DiscoverFeaturesDisclosureReceivedEvent>()
    const aliceReplay = new ReplaySubject<DiscoverFeaturesQueryReceivedEvent>()

    faberAgent.events
      .observable<DiscoverFeaturesDisclosureReceivedEvent>(DiscoverFeaturesEventTypes.DisclosureReceived)
      .subscribe(faberReplay)
    aliceAgent.events
      .observable<DiscoverFeaturesQueryReceivedEvent>(DiscoverFeaturesEventTypes.QueryReceived)
      .subscribe(aliceReplay)

    await faberAgent.discovery.queryFeatures({
      connectionId: faberConnection.id,
      protocolVersion: 'v1',
      queries: [{ featureType: 'protocol', match: 'https://didcomm.org/revocation_notification/*' }],
    })

    const query = await waitForQuerySubject(aliceReplay, { timeoutMs: 10000 })

    expect(query).toMatchObject({
      protocolVersion: 'v1',
      queries: [{ featureType: 'protocol', match: 'https://didcomm.org/revocation_notification/*' }],
    })

    const disclosure = await waitForDisclosureSubject(faberReplay, { timeoutMs: 10000 })

    expect(disclosure).toMatchObject({
      protocolVersion: 'v1',
      disclosures: [
        { type: 'protocol', id: 'https://didcomm.org/revocation_notification/1.0', roles: ['holder'] },
        { type: 'protocol', id: 'https://didcomm.org/revocation_notification/2.0', roles: ['holder'] },
      ],
    })
  })

  test('Faber asks Alice for revocation notification protocol support synchronously', async () => {
    const matchingFeatures = await faberAgent.discovery.queryFeatures({
      connectionId: faberConnection.id,
      protocolVersion: 'v1',
      queries: [{ featureType: 'protocol', match: 'https://didcomm.org/revocation_notification/*' }],
      awaitDisclosures: true,
    })

    expect(matchingFeatures).toMatchObject({
      features: [
        { type: 'protocol', id: 'https://didcomm.org/revocation_notification/1.0', roles: ['holder'] },
        { type: 'protocol', id: 'https://didcomm.org/revocation_notification/2.0', roles: ['holder'] },
      ],
    })
  })
})
