/* eslint-disable @typescript-eslint/no-non-null-assertion */
import type { SubjectMessage } from '../../../tests/transport/SubjectInboundTransport'
import type { AgentMessageProcessedEvent } from '../../didcomm/src'
import type { OutOfBandDidCommService } from '../../didcomm/src/modules/oob'

import { filter, firstValueFrom, map, Subject, timeout } from 'rxjs'

import { SubjectInboundTransport } from '../../../tests/transport/SubjectInboundTransport'
import { SubjectOutboundTransport } from '../../../tests/transport/SubjectOutboundTransport'
import { AgentEventTypes } from '../../didcomm/src'
import { ConnectionType, DidExchangeState, HandshakeProtocol } from '../../didcomm/src/modules/connections'
import {
  KeylistUpdateAction,
  KeylistUpdateMessage,
  MediationRecipientModule,
  MediationState,
  MediatorModule,
  MediatorPickupStrategy,
} from '../../didcomm/src/modules/routing'
import { Agent } from '../src/agent/Agent'
import { didKeyToVerkey } from '../src/modules/dids/helpers'

import { getInMemoryAgentOptions, waitForBasicMessage } from './helpers'

const faberAgentOptions = getInMemoryAgentOptions('OOB mediation - Faber Agent', {
  endpoints: ['rxjs:faber'],
})
const aliceAgentOptions = getInMemoryAgentOptions(
  'OOB mediation - Alice Recipient Agent',
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
  'OOB mediation - Mediator Agent',
  {
    endpoints: ['rxjs:mediator'],
  },
  {},
  { mediator: new MediatorModule({ autoAcceptMediationRequests: true }) }
)

describe('out of band with mediation', () => {
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

  beforeAll(async () => {
    const faberMessages = new Subject<SubjectMessage>()
    const aliceMessages = new Subject<SubjectMessage>()
    const mediatorMessages = new Subject<SubjectMessage>()
    const subjectMap = {
      'rxjs:faber': faberMessages,
      'rxjs:alice': aliceMessages,
      'rxjs:mediator': mediatorMessages,
    }

    faberAgent = new Agent(faberAgentOptions)
    faberAgent.modules.didcomm.registerInboundTransport(new SubjectInboundTransport(faberMessages))
    faberAgent.modules.didcomm.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    await faberAgent.initialize()

    aliceAgent = new Agent(aliceAgentOptions)
    aliceAgent.modules.didcomm.registerInboundTransport(new SubjectInboundTransport(aliceMessages))
    aliceAgent.modules.didcomm.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    await aliceAgent.initialize()

    mediatorAgent = new Agent(mediatorAgentOptions)
    mediatorAgent.modules.didcomm.registerInboundTransport(new SubjectInboundTransport(mediatorMessages))
    mediatorAgent.modules.didcomm.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    await mediatorAgent.initialize()

    // ========== Make a connection between Alice and Mediator agents ==========
    const mediationOutOfBandRecord = await mediatorAgent.modules.oob.createInvitation(makeConnectionConfig)
    const { outOfBandInvitation: mediatorOutOfBandInvitation } = mediationOutOfBandRecord
    const mediatorUrlMessage = mediatorOutOfBandInvitation.toUrl({ domain: 'http://example.com' })

    let { connectionRecord: aliceMediatorConnection } = await aliceAgent.modules.oob.receiveInvitationFromUrl(
      mediatorUrlMessage
    )

    aliceMediatorConnection = await aliceAgent.modules.connections.returnWhenIsConnected(aliceMediatorConnection!.id)
    expect(aliceMediatorConnection.state).toBe(DidExchangeState.Completed)

    // Tag the connection with an initial type
    aliceMediatorConnection = await aliceAgent.modules.connections.addConnectionType(
      aliceMediatorConnection.id,
      'initial-type'
    )

    let [mediatorAliceConnection] = await mediatorAgent.modules.connections.findAllByOutOfBandId(
      mediationOutOfBandRecord.id
    )
    mediatorAliceConnection = await mediatorAgent.modules.connections.returnWhenIsConnected(mediatorAliceConnection!.id)
    expect(mediatorAliceConnection.state).toBe(DidExchangeState.Completed)

    // ========== Set mediation between Alice and Mediator agents ==========
    let connectionTypes = await aliceAgent.modules.connections.getConnectionTypes(aliceMediatorConnection.id)
    expect(connectionTypes).toMatchObject(['initial-type'])

    const mediationRecord = await aliceAgent.modules.mediationRecipient.requestAndAwaitGrant(aliceMediatorConnection)
    connectionTypes = await aliceAgent.modules.connections.getConnectionTypes(mediationRecord.connectionId)
    expect(connectionTypes.sort()).toMatchObject(['initial-type', ConnectionType.Mediator].sort())
    await aliceAgent.modules.connections.removeConnectionType(mediationRecord.connectionId, 'initial-type')
    connectionTypes = await aliceAgent.modules.connections.getConnectionTypes(mediationRecord.connectionId)
    expect(connectionTypes).toMatchObject([ConnectionType.Mediator])
    expect(mediationRecord.state).toBe(MediationState.Granted)

    await aliceAgent.modules.mediationRecipient.setDefaultMediator(mediationRecord)
    await aliceAgent.modules.mediationRecipient.initiateMessagePickup(mediationRecord)
    const defaultMediator = await aliceAgent.modules.mediationRecipient.findDefaultMediator()
    expect(defaultMediator?.id).toBe(mediationRecord.id)
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
    // ========== Make a connection between Alice and Faber ==========
    const outOfBandRecord = await faberAgent.modules.oob.createInvitation({ multiUseInvitation: false })

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
  })

  test(`create and delete OOB invitation when using mediation`, async () => {
    // Alice creates an invitation: the key is notified to her mediator

    const keyAddMessagePromise = firstValueFrom(
      mediatorAgent.events.observable<AgentMessageProcessedEvent>(AgentEventTypes.AgentMessageProcessed).pipe(
        filter((event) => event.payload.message.type === KeylistUpdateMessage.type.messageTypeUri),
        map((event) => event.payload.message as KeylistUpdateMessage),
        timeout(5000)
      )
    )

    const outOfBandRecord = await aliceAgent.modules.oob.createInvitation({})
    const { outOfBandInvitation } = outOfBandRecord

    const keyAddMessage = await keyAddMessagePromise

    expect(keyAddMessage.updates.length).toEqual(1)
    expect(
      keyAddMessage.updates.map((update) => ({
        action: update.action,
        recipientKey: didKeyToVerkey(update.recipientKey),
      }))[0]
    ).toEqual({
      action: KeylistUpdateAction.add,
      recipientKey: didKeyToVerkey((outOfBandInvitation.getServices()[0] as OutOfBandDidCommService).recipientKeys[0]),
    })

    const keyRemoveMessagePromise = firstValueFrom(
      mediatorAgent.events.observable<AgentMessageProcessedEvent>(AgentEventTypes.AgentMessageProcessed).pipe(
        filter((event) => event.payload.message.type === KeylistUpdateMessage.type.messageTypeUri),
        map((event) => event.payload.message as KeylistUpdateMessage),
        timeout(5000)
      )
    )

    await aliceAgent.modules.oob.deleteById(outOfBandRecord.id)

    const keyRemoveMessage = await keyRemoveMessagePromise
    expect(keyRemoveMessage.updates.length).toEqual(1)
    expect(
      keyRemoveMessage.updates.map((update) => ({
        action: update.action,
        recipientKey: didKeyToVerkey(update.recipientKey),
      }))[0]
    ).toEqual({
      action: KeylistUpdateAction.remove,
      recipientKey: didKeyToVerkey((outOfBandInvitation.getServices()[0] as OutOfBandDidCommService).recipientKeys[0]),
    })
  })
})
