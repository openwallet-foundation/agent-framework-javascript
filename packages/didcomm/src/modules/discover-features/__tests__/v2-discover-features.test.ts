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

const faberAgentOptions = getInMemoryAgentOptions('Faber Discover Features V2 E2E', {
  endpoints: ['rxjs:faber'],
})

const aliceAgentOptions = getInMemoryAgentOptions('Alice Discover Features V2 E2E', {
  endpoints: ['rxjs:alice'],
})

describe('v2 discover features', () => {
  let faberAgent: Agent
  let aliceAgent: Agent
  let aliceConnection: ConnectionRecord
  let faberConnection: ConnectionRecord

  beforeAll(async () => {
    faberAgent = new Agent(faberAgentOptions)
    aliceAgent = new Agent(aliceAgentOptions)
    setupSubjectTransports([faberAgent, aliceAgent])

    await faberAgent.initialize()
    await aliceAgent.initialize()
    ;[faberConnection, aliceConnection] = await makeConnection(faberAgent, aliceAgent)
  })

  afterAll(async () => {
    await faberAgent.shutdown()
    await faberAgent.wallet.delete()
    await aliceAgent.shutdown()
    await aliceAgent.wallet.delete()
  })

  test('Faber asks Alice for issue credential protocol support', async () => {
    const faberReplay = new ReplaySubject<DiscoverFeaturesDisclosureReceivedEvent>()
    const aliceReplay = new ReplaySubject<DiscoverFeaturesQueryReceivedEvent>()

    faberAgent.discovery.config.autoAcceptQueries
    faberAgent.events
      .observable<DiscoverFeaturesDisclosureReceivedEvent>(DiscoverFeaturesEventTypes.DisclosureReceived)
      .subscribe(faberReplay)
    aliceAgent.events
      .observable<DiscoverFeaturesQueryReceivedEvent>(DiscoverFeaturesEventTypes.QueryReceived)
      .subscribe(aliceReplay)

    await faberAgent.discovery.queryFeatures({
      connectionId: faberConnection.id,
      protocolVersion: 'v2',
      queries: [{ featureType: 'protocol', match: 'https://didcomm.org/revocation_notification/*' }],
    })

    const query = await waitForQuerySubject(aliceReplay, { timeoutMs: 10000 })

    expect(query).toMatchObject({
      protocolVersion: 'v2',
      queries: [{ featureType: 'protocol', match: 'https://didcomm.org/revocation_notification/*' }],
    })

    const disclosure = await waitForDisclosureSubject(faberReplay, { timeoutMs: 10000 })

    expect(disclosure).toMatchObject({
      protocolVersion: 'v2',
      disclosures: [
        { type: 'protocol', id: 'https://didcomm.org/revocation_notification/1.0', roles: ['holder'] },
        { type: 'protocol', id: 'https://didcomm.org/revocation_notification/2.0', roles: ['holder'] },
      ],
    })
  })

  test('Faber defines a supported goal code and Alice queries', async () => {
    const faberReplay = new ReplaySubject<DiscoverFeaturesQueryReceivedEvent>()
    const aliceReplay = new ReplaySubject<DiscoverFeaturesDisclosureReceivedEvent>()

    aliceAgent.events
      .observable<DiscoverFeaturesDisclosureReceivedEvent>(DiscoverFeaturesEventTypes.DisclosureReceived)
      .subscribe(aliceReplay)
    faberAgent.events
      .observable<DiscoverFeaturesQueryReceivedEvent>(DiscoverFeaturesEventTypes.QueryReceived)
      .subscribe(faberReplay)

    // Register some goal codes
    faberAgent.features.register(new GoalCode({ id: 'faber.vc.issuance' }), new GoalCode({ id: 'faber.vc.query' }))

    await aliceAgent.discovery.queryFeatures({
      connectionId: aliceConnection.id,
      protocolVersion: 'v2',
      queries: [{ featureType: 'goal-code', match: '*' }],
    })

    const query = await waitForQuerySubject(faberReplay, { timeoutMs: 10000 })

    expect(query).toMatchObject({
      protocolVersion: 'v2',
      queries: [{ featureType: 'goal-code', match: '*' }],
    })

    const disclosure = await waitForDisclosureSubject(aliceReplay, { timeoutMs: 10000 })

    expect(disclosure).toMatchObject({
      protocolVersion: 'v2',
      disclosures: [
        { type: 'goal-code', id: 'faber.vc.issuance' },
        { type: 'goal-code', id: 'faber.vc.query' },
      ],
    })
  })

  test('Faber defines a custom feature and Alice queries', async () => {
    const faberReplay = new ReplaySubject<DiscoverFeaturesQueryReceivedEvent>()
    const aliceReplay = new ReplaySubject<DiscoverFeaturesDisclosureReceivedEvent>()

    aliceAgent.events
      .observable<DiscoverFeaturesDisclosureReceivedEvent>(DiscoverFeaturesEventTypes.DisclosureReceived)
      .subscribe(aliceReplay)
    faberAgent.events
      .observable<DiscoverFeaturesQueryReceivedEvent>(DiscoverFeaturesEventTypes.QueryReceived)
      .subscribe(faberReplay)

    // Define a custom feature type
    class GenericFeature extends Feature {
      public 'generic-field'!: string

      public constructor(options: { id: string; genericField: string }) {
        super({ id: options.id, type: 'generic' })
        this['generic-field'] = options.genericField
      }
    }

    // Register a custom feature
    faberAgent.features.register(new GenericFeature({ id: 'custom-feature', genericField: 'custom-field' }))

    await aliceAgent.discovery.queryFeatures({
      connectionId: aliceConnection.id,
      protocolVersion: 'v2',
      queries: [{ featureType: 'generic', match: 'custom-feature' }],
    })

    const query = await waitForQuerySubject(faberReplay, { timeoutMs: 10000 })

    expect(query).toMatchObject({
      protocolVersion: 'v2',
      queries: [{ featureType: 'generic', match: 'custom-feature' }],
    })

    const disclosure = await waitForDisclosureSubject(aliceReplay, { timeoutMs: 10000 })

    expect(disclosure).toMatchObject({
      protocolVersion: 'v2',
      disclosures: [
        {
          type: 'generic',
          id: 'custom-feature',
          'generic-field': 'custom-field',
        },
      ],
    })
  })

  test('Faber proactively sends a set of features to Alice', async () => {
    const faberReplay = new ReplaySubject<DiscoverFeaturesQueryReceivedEvent>()
    const aliceReplay = new ReplaySubject<DiscoverFeaturesDisclosureReceivedEvent>()

    aliceAgent.events
      .observable<DiscoverFeaturesDisclosureReceivedEvent>(DiscoverFeaturesEventTypes.DisclosureReceived)
      .subscribe(aliceReplay)
    faberAgent.events
      .observable<DiscoverFeaturesQueryReceivedEvent>(DiscoverFeaturesEventTypes.QueryReceived)
      .subscribe(faberReplay)

    // Register a custom feature
    faberAgent.features.register(
      new Feature({ id: 'AIP2.0', type: 'aip' }),
      new Feature({ id: 'AIP2.0/INDYCRED', type: 'aip' }),
      new Feature({ id: 'AIP2.0/MEDIATE', type: 'aip' })
    )

    await faberAgent.discovery.discloseFeatures({
      connectionId: faberConnection.id,
      protocolVersion: 'v2',
      disclosureQueries: [{ featureType: 'aip', match: '*' }],
    })

    const disclosure = await waitForDisclosureSubject(aliceReplay, { timeoutMs: 10000 })

    expect(disclosure).toMatchObject({
      protocolVersion: 'v2',
      disclosures: [
        { type: 'aip', id: 'AIP2.0' },
        { type: 'aip', id: 'AIP2.0/INDYCRED' },
        { type: 'aip', id: 'AIP2.0/MEDIATE' },
      ],
    })
  })

  test('Faber asks Alice for issue credential protocol support synchronously', async () => {
    const matchingFeatures = await faberAgent.discovery.queryFeatures({
      connectionId: faberConnection.id,
      protocolVersion: 'v2',
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
