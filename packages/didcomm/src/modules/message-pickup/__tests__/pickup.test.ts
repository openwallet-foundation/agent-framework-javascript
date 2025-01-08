/* eslint-disable @typescript-eslint/no-non-null-assertion */
import type { SubjectMessage } from '../../../../../../tests/transport/SubjectInboundTransport'

import { Subject } from 'rxjs'

import { SubjectInboundTransport } from '../../../../../../tests/transport/SubjectInboundTransport'
import { SubjectOutboundTransport } from '../../../../../../tests/transport/SubjectOutboundTransport'
import {
  getInMemoryAgentOptions,
  waitForAgentMessageProcessedEvent,
  waitForBasicMessage,
} from '@credo-ts/core/tests/helpers'
import { Agent } from '@credo-ts/core/src/agent/Agent'
import { MediatorModule } from '../../routing'
import { MessageForwardingStrategy } from '../../routing/MessageForwardingStrategy'
import { V2MessagesReceivedMessage, V2StatusMessage } from '../protocol'
import { HandshakeProtocol } from '../../../models'

const recipientOptions = getInMemoryAgentOptions('Mediation Pickup Loop Recipient')
const mediatorOptions = getInMemoryAgentOptions(
  'Mediation Pickup Loop Mediator',
  {
    endpoints: ['wss://mediator'],
  },
  {
    mediator: new MediatorModule({
      autoAcceptMediationRequests: true,
      messageForwardingStrategy: MessageForwardingStrategy.QueueAndLiveModeDelivery,
    }),
  }
)

describe('E2E Pick Up protocol', () => {
  let recipientAgent: Agent
  let mediatorAgent: Agent

  afterEach(async () => {
    await recipientAgent.mediationRecipient.stopMessagePickup()

    await recipientAgent.shutdown()
    await recipientAgent.wallet.delete()
    await mediatorAgent.shutdown()
    await mediatorAgent.wallet.delete()
  })

  test('E2E manual Pick Up V1 loop', async () => {
    const mediatorMessages = new Subject<SubjectMessage>()

    const subjectMap = {
      'wss://mediator': mediatorMessages,
    }

    // Initialize mediatorReceived message
    mediatorAgent = new Agent(mediatorOptions)
    mediatorAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    mediatorAgent.registerInboundTransport(new SubjectInboundTransport(mediatorMessages))
    await mediatorAgent.initialize()

    // Create connection to use for recipient
    const mediatorOutOfBandRecord = await mediatorAgent.oob.createInvitation({
      label: 'mediator invitation',
      handshake: true,
      handshakeProtocols: [HandshakeProtocol.DidExchange],
    })

    // Initialize recipient
    recipientAgent = new Agent(recipientOptions)
    recipientAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    await recipientAgent.initialize()

    // Connect
    const mediatorInvitation = mediatorOutOfBandRecord.outOfBandInvitation

    let { connectionRecord: recipientMediatorConnection } = await recipientAgent.oob.receiveInvitationFromUrl(
      mediatorInvitation.toUrl({ domain: 'https://example.com/ssi' })
    )

    recipientMediatorConnection = await recipientAgent.connections.returnWhenIsConnected(
      recipientMediatorConnection!.id
    )

    let [mediatorRecipientConnection] = await mediatorAgent.connections.findAllByOutOfBandId(mediatorOutOfBandRecord.id)

    mediatorRecipientConnection = await mediatorAgent.connections.returnWhenIsConnected(mediatorRecipientConnection!.id)

    // Now they are connected, reinitialize recipient agent in order to lose the session (as with SubjectTransport it remains open)
    await recipientAgent.shutdown()
    await recipientAgent.initialize()

    const message = 'hello pickup V1'
    await mediatorAgent.basicMessages.sendMessage(mediatorRecipientConnection.id, message)

    await recipientAgent.messagePickup.pickupMessages({
      connectionId: recipientMediatorConnection.id,
      protocolVersion: 'v1',
    })

    const basicMessage = await waitForBasicMessage(recipientAgent, {
      content: message,
    })

    expect(basicMessage.content).toBe(message)
  })

  test('E2E manual Pick Up V1 loop - waiting for completion', async () => {
    const mediatorMessages = new Subject<SubjectMessage>()

    const subjectMap = {
      'wss://mediator': mediatorMessages,
    }

    // Initialize mediatorReceived message
    mediatorAgent = new Agent(mediatorOptions)
    mediatorAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    mediatorAgent.registerInboundTransport(new SubjectInboundTransport(mediatorMessages))
    await mediatorAgent.initialize()

    // Create connection to use for recipient
    const mediatorOutOfBandRecord = await mediatorAgent.oob.createInvitation({
      label: 'mediator invitation',
      handshake: true,
      handshakeProtocols: [HandshakeProtocol.DidExchange],
    })

    // Initialize recipient
    recipientAgent = new Agent(recipientOptions)
    recipientAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    await recipientAgent.initialize()

    // Connect
    const mediatorInvitation = mediatorOutOfBandRecord.outOfBandInvitation

    let { connectionRecord: recipientMediatorConnection } = await recipientAgent.oob.receiveInvitationFromUrl(
      mediatorInvitation.toUrl({ domain: 'https://example.com/ssi' })
    )

    recipientMediatorConnection = await recipientAgent.connections.returnWhenIsConnected(
      recipientMediatorConnection!.id
    )

    let [mediatorRecipientConnection] = await mediatorAgent.connections.findAllByOutOfBandId(mediatorOutOfBandRecord.id)

    mediatorRecipientConnection = await mediatorAgent.connections.returnWhenIsConnected(mediatorRecipientConnection!.id)

    // Now they are connected, reinitialize recipient agent in order to lose the session (as with SubjectTransport it remains open)
    await recipientAgent.shutdown()
    await recipientAgent.initialize()

    const message = 'hello pickup V1'
    await mediatorAgent.basicMessages.sendMessage(mediatorRecipientConnection.id, message)

    const basicMessagePromise = waitForBasicMessage(recipientAgent, {
      content: message,
    })
    await recipientAgent.messagePickup.pickupMessages({
      connectionId: recipientMediatorConnection.id,
      protocolVersion: 'v1',
      awaitCompletion: true,
    })

    const basicMessage = await basicMessagePromise
    expect(basicMessage.content).toBe(message)
  })

  test('E2E manual Pick Up V2 loop', async () => {
    const mediatorMessages = new Subject<SubjectMessage>()

    // FIXME: we harcoded that pickup of messages MUST be using ws(s) scheme when doing implicit pickup
    // For liver delivery we need a duplex transport. however that means we can't test it with the subject transport. Using wss here to 'hack' this. We should
    // extend the API to allow custom schemes (or maybe add a `supportsDuplex` transport / `supportMultiReturnMessages`)
    // For pickup v2 pickup message (which we're testing here) we could just as well use `http` as it is just request/response.
    const subjectMap = {
      'wss://mediator': mediatorMessages,
    }

    // Initialize mediatorReceived message
    mediatorAgent = new Agent(mediatorOptions)
    mediatorAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    mediatorAgent.registerInboundTransport(new SubjectInboundTransport(mediatorMessages))
    await mediatorAgent.initialize()

    // Create connection to use for recipient
    const mediatorOutOfBandRecord = await mediatorAgent.oob.createInvitation({
      label: 'mediator invitation',
      handshake: true,
      handshakeProtocols: [HandshakeProtocol.DidExchange],
    })

    // Initialize recipient
    recipientAgent = new Agent(recipientOptions)
    recipientAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    await recipientAgent.initialize()

    // Connect
    const mediatorInvitation = mediatorOutOfBandRecord.outOfBandInvitation

    let { connectionRecord: recipientMediatorConnection } = await recipientAgent.oob.receiveInvitationFromUrl(
      mediatorInvitation.toUrl({ domain: 'https://example.com/ssi' })
    )

    recipientMediatorConnection = await recipientAgent.connections.returnWhenIsConnected(
      recipientMediatorConnection!.id
    )

    let [mediatorRecipientConnection] = await mediatorAgent.connections.findAllByOutOfBandId(mediatorOutOfBandRecord.id)

    mediatorRecipientConnection = await mediatorAgent.connections.returnWhenIsConnected(mediatorRecipientConnection!.id)

    // Now they are connected, reinitialize recipient agent in order to lose the session (as with SubjectTransport it remains open)
    await recipientAgent.shutdown()
    await recipientAgent.initialize()

    const message = 'hello pickup V2'

    await mediatorAgent.basicMessages.sendMessage(mediatorRecipientConnection.id, message)

    const basicMessagePromise = waitForBasicMessage(recipientAgent, {
      content: message,
    })
    await recipientAgent.messagePickup.pickupMessages({
      connectionId: recipientMediatorConnection.id,
      protocolVersion: 'v2',
    })
    const firstStatusMessage = await waitForAgentMessageProcessedEvent(recipientAgent, {
      messageType: V2StatusMessage.type.messageTypeUri,
    })

    expect((firstStatusMessage as V2StatusMessage).messageCount).toBe(1)

    const basicMessage = await basicMessagePromise
    expect(basicMessage.content).toBe(message)

    const messagesReceived = await waitForAgentMessageProcessedEvent(mediatorAgent, {
      messageType: V2MessagesReceivedMessage.type.messageTypeUri,
    })

    expect((messagesReceived as V2MessagesReceivedMessage).messageIdList.length).toBe(1)

    const secondStatusMessage = await waitForAgentMessageProcessedEvent(recipientAgent, {
      messageType: V2StatusMessage.type.messageTypeUri,
    })

    expect((secondStatusMessage as V2StatusMessage).messageCount).toBe(0)
  })

  test('E2E manual Pick Up V2 loop - waiting for completion', async () => {
    const mediatorMessages = new Subject<SubjectMessage>()

    // FIXME: we harcoded that pickup of messages MUST be using ws(s) scheme when doing implicit pickup
    // For liver delivery we need a duplex transport. however that means we can't test it with the subject transport. Using wss here to 'hack' this. We should
    // extend the API to allow custom schemes (or maybe add a `supportsDuplex` transport / `supportMultiReturnMessages`)
    // For pickup v2 pickup message (which we're testing here) we could just as well use `http` as it is just request/response.
    const subjectMap = {
      'wss://mediator': mediatorMessages,
    }

    // Initialize mediatorReceived message
    mediatorAgent = new Agent(mediatorOptions)
    mediatorAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    mediatorAgent.registerInboundTransport(new SubjectInboundTransport(mediatorMessages))
    await mediatorAgent.initialize()

    // Create connection to use for recipient
    const mediatorOutOfBandRecord = await mediatorAgent.oob.createInvitation({
      label: 'mediator invitation',
      handshake: true,
      handshakeProtocols: [HandshakeProtocol.DidExchange],
    })

    // Initialize recipient
    recipientAgent = new Agent(recipientOptions)
    recipientAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    await recipientAgent.initialize()

    // Connect
    const mediatorInvitation = mediatorOutOfBandRecord.outOfBandInvitation

    let { connectionRecord: recipientMediatorConnection } = await recipientAgent.oob.receiveInvitationFromUrl(
      mediatorInvitation.toUrl({ domain: 'https://example.com/ssi' })
    )

    recipientMediatorConnection = await recipientAgent.connections.returnWhenIsConnected(
      recipientMediatorConnection!.id
    )

    let [mediatorRecipientConnection] = await mediatorAgent.connections.findAllByOutOfBandId(mediatorOutOfBandRecord.id)

    mediatorRecipientConnection = await mediatorAgent.connections.returnWhenIsConnected(mediatorRecipientConnection!.id)

    // Now they are connected, reinitialize recipient agent in order to lose the session (as with SubjectTransport it remains open)
    await recipientAgent.shutdown()
    await recipientAgent.initialize()

    const message = 'hello pickup V2'

    await mediatorAgent.basicMessages.sendMessage(mediatorRecipientConnection.id, message)

    const basicMessagePromise = waitForBasicMessage(recipientAgent, {
      content: message,
    })
    await recipientAgent.messagePickup.pickupMessages({
      connectionId: recipientMediatorConnection.id,
      protocolVersion: 'v2',
      awaitCompletion: true,
    })

    const basicMessage = await basicMessagePromise
    expect(basicMessage.content).toBe(message)
  })
})
