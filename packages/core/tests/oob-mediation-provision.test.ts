/* eslint-disable @typescript-eslint/no-non-null-assertion */
import type { OutOfBandInvitation } from '../../didcomm/src/modules/oob/messages'

import { DidExchangeState, HandshakeProtocol } from '../../didcomm/src/modules/connections'
import {
  MediationState,
  MediatorModule,
  MediatorPickupStrategy,
  MediationRecipientModule,
} from '../../didcomm/src/modules/routing'
import { Agent } from '../src/agent/Agent'

import { getInMemoryAgentOptions, waitForBasicMessage } from './helpers'
import { setupSubjectTransports } from './transport'

const faberAgentOptions = getInMemoryAgentOptions('OOB mediation provision - Faber Agent', {
  endpoints: ['rxjs:faber'],
})
const aliceAgentOptions = getInMemoryAgentOptions(
  'OOB mediation provision - Alice Recipient Agent',
  {
    endpoints: ['rxjs:alice'],
  },
  {},
  {
    mediationRecipient: new MediationRecipientModule({
      mediatorPickupStrategy: MediatorPickupStrategy.PickUpV1,
    }),
  }
)
const mediatorAgentOptions = getInMemoryAgentOptions(
  'OOB mediation provision - Mediator Agent',
  {
    endpoints: ['rxjs:mediator'],
  },
  {},
  { mediator: new MediatorModule({ autoAcceptMediationRequests: true }) }
)

describe('out of band with mediation set up with provision method', () => {
  const makeConnectionConfig = {
    goal: 'To make a connection',
    goalCode: 'p2p-messaging',
    label: 'Faber College',
    handshake: true,
    multiUseInvitation: false,
  }

  let faberAgent: Agent
  let aliceAgent: Agent
  let mediatorAgent: Agent

  let mediatorOutOfBandInvitation: OutOfBandInvitation

  beforeAll(async () => {
    mediatorAgent = new Agent(mediatorAgentOptions)
    aliceAgent = new Agent(aliceAgentOptions)
    faberAgent = new Agent(faberAgentOptions)

    setupSubjectTransports([mediatorAgent, aliceAgent, faberAgent])

    await mediatorAgent.initialize()
    await aliceAgent.initialize()
    await faberAgent.initialize()

    const mediationOutOfBandRecord = await mediatorAgent.modules.oob.createInvitation(makeConnectionConfig)
    mediatorOutOfBandInvitation = mediationOutOfBandRecord.outOfBandInvitation

    let { connectionRecord } = await aliceAgent.modules.oob.receiveInvitation(mediatorOutOfBandInvitation)
    connectionRecord = await aliceAgent.modules.connections.returnWhenIsConnected(connectionRecord!.id)
    await aliceAgent.modules.mediationRecipient.provision(connectionRecord!)
    await aliceAgent.modules.mediationRecipient.initialize()
  })

  afterAll(async () => {
    await faberAgent.shutdown()
    await faberAgent.wallet.delete()
    await aliceAgent.shutdown()
    await aliceAgent.wallet.delete()
    await mediatorAgent.shutdown()
    await mediatorAgent.wallet.delete()
  })

  test(`make a connection with ${HandshakeProtocol.DidExchange} on OOB invitation encoded in URL`, async () => {
    // Check if mediation between Alice and Mediator has been set
    const defaultMediator = await aliceAgent.modules.mediationRecipient.findDefaultMediator()
    expect(defaultMediator).not.toBeNull()
    expect(defaultMediator?.state).toBe(MediationState.Granted)

    // Make a connection between Alice and Faber
    const outOfBandRecord = await faberAgent.modules.oob.createInvitation(makeConnectionConfig)
    const { outOfBandInvitation } = outOfBandRecord
    const urlMessage = outOfBandInvitation.toUrl({ domain: 'http://example.com' })

    let { connectionRecord: aliceFaberConnection } = await aliceAgent.modules.oob.receiveInvitationFromUrl(urlMessage)

    aliceFaberConnection = await aliceAgent.modules.connections.returnWhenIsConnected(aliceFaberConnection!.id)
    expect(aliceFaberConnection.state).toBe(DidExchangeState.Completed)

    let [faberAliceConnection] = await faberAgent.modules.connections.findAllByOutOfBandId(outOfBandRecord.id)
    faberAliceConnection = await faberAgent.modules.connections.returnWhenIsConnected(faberAliceConnection!.id)
    expect(faberAliceConnection.state).toBe(DidExchangeState.Completed)

    expect(aliceFaberConnection).toBeConnectedWith(faberAliceConnection)
    expect(faberAliceConnection).toBeConnectedWith(aliceFaberConnection)

    await aliceAgent.modules.basicMessages.sendMessage(aliceFaberConnection.id, 'hello')
    const basicMessage = await waitForBasicMessage(faberAgent, {})

    expect(basicMessage.content).toBe('hello')

    // Test if we can call provision for the same out-of-band record, respectively connection
    const reusedOutOfBandRecord = await aliceAgent.modules.oob.findByReceivedInvitationId(
      mediatorOutOfBandInvitation.id
    )
    const [reusedAliceMediatorConnection] = reusedOutOfBandRecord
      ? await aliceAgent.modules.connections.findAllByOutOfBandId(reusedOutOfBandRecord.id)
      : []
    await aliceAgent.modules.mediationRecipient.provision(reusedAliceMediatorConnection!)
    const mediators = await aliceAgent.modules.mediationRecipient.getMediators()
    expect(mediators).toHaveLength(1)
  })
})
