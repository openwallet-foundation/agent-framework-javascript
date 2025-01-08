/* eslint-disable @typescript-eslint/no-non-null-assertion */
import type { SubjectMessage } from '../../../../../../tests/transport/SubjectInboundTransport'
import type { AgentDependencies } from '@credo-ts/core/src/agent/AgentDependencies'
import type { AgentModulesInput } from '@credo-ts/core/src/agent/AgentModules'
import type { InitConfig } from '@credo-ts/core/src/types'

import { Subject } from 'rxjs'

import { SubjectInboundTransport } from '../../../../../../tests/transport/SubjectInboundTransport'
import { SubjectOutboundTransport } from '../../../../../../tests/transport/SubjectOutboundTransport'
import { getInMemoryAgentOptions, waitForBasicMessage } from '@credo-ts/core/tests/helpers'
import { Agent } from '@credo-ts/core/src/agent/Agent'
import { sleep } from '@credo-ts/core/src/utils/sleep'
import { ConnectionRecord, HandshakeProtocol } from '../../connections'
import { MediationRecipientModule } from '../MediationRecipientModule'
import { MediatorModule } from '../MediatorModule'
import { MediatorPickupStrategy } from '../MediatorPickupStrategy'
import { MediationState } from '../models/MediationState'

const recipientAgentOptions = getInMemoryAgentOptions('Mediation: Recipient')
const mediatorAgentOptions = getInMemoryAgentOptions(
  'Mediation: Mediator',
  {
    endpoints: ['rxjs:mediator'],
  },
  {
    mediator: new MediatorModule({
      autoAcceptMediationRequests: true,
    }),
  }
)

const senderAgentOptions = getInMemoryAgentOptions('Mediation: Sender', {
  endpoints: ['rxjs:sender'],
})

describe('mediator establishment', () => {
  let recipientAgent: Agent
  let mediatorAgent: Agent
  let senderAgent: Agent

  afterEach(async () => {
    await recipientAgent?.shutdown()
    await recipientAgent?.wallet.delete()
    await mediatorAgent?.shutdown()
    await mediatorAgent?.wallet.delete()
    await senderAgent?.shutdown()
    await senderAgent?.wallet.delete()
  })

  const e2eMediationTest = async (
    mediatorAgentOptions: {
      readonly config: InitConfig
      readonly dependencies: AgentDependencies
      modules: AgentModulesInput
    },
    recipientAgentOptions: {
      config: InitConfig
      dependencies: AgentDependencies
      modules: AgentModulesInput
    }
  ) => {
    const mediatorMessages = new Subject<SubjectMessage>()
    const recipientMessages = new Subject<SubjectMessage>()
    const senderMessages = new Subject<SubjectMessage>()

    const subjectMap = {
      'rxjs:mediator': mediatorMessages,
      'rxjs:sender': senderMessages,
    }

    // Initialize mediatorReceived message
    mediatorAgent = new Agent(mediatorAgentOptions)
    mediatorAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    mediatorAgent.registerInboundTransport(new SubjectInboundTransport(mediatorMessages))
    await mediatorAgent.initialize()

    // Create connection to use for recipient
    const mediatorOutOfBandRecord = await mediatorAgent.oob.createInvitation({
      label: 'mediator invitation',
      handshake: true,
      handshakeProtocols: [HandshakeProtocol.Connections],
    })

    // Initialize recipient with mediation connections invitation
    recipientAgent = new Agent({
      ...recipientAgentOptions,
      modules: {
        ...recipientAgentOptions.modules,
        mediationRecipient: new MediationRecipientModule({
          mediatorPickupStrategy: MediatorPickupStrategy.PickUpV1,
          mediatorInvitationUrl: mediatorOutOfBandRecord.outOfBandInvitation.toUrl({
            domain: 'https://example.com/ssi',
          }),
        }),
      },
    })
    recipientAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    recipientAgent.registerInboundTransport(new SubjectInboundTransport(recipientMessages))
    await recipientAgent.initialize()

    const recipientMediator = await recipientAgent.mediationRecipient.findDefaultMediator()
    // eslint-disable-next-line @typescript-eslint/no-non-null-asserted-optional-chain, @typescript-eslint/no-non-null-assertion
    const recipientMediatorConnection = await recipientAgent.connections.getById(recipientMediator!.connectionId)

    expect(recipientMediatorConnection).toBeInstanceOf(ConnectionRecord)
    expect(recipientMediatorConnection?.isReady).toBe(true)

    const [mediatorRecipientConnection] = await mediatorAgent.connections.findAllByOutOfBandId(
      mediatorOutOfBandRecord.id
    )
    expect(mediatorRecipientConnection!.isReady).toBe(true)

    expect(mediatorRecipientConnection).toBeConnectedWith(recipientMediatorConnection)
    expect(recipientMediatorConnection).toBeConnectedWith(mediatorRecipientConnection!)

    expect(recipientMediator?.state).toBe(MediationState.Granted)

    // Initialize sender agent
    senderAgent = new Agent(senderAgentOptions)
    senderAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    senderAgent.registerInboundTransport(new SubjectInboundTransport(senderMessages))
    await senderAgent.initialize()

    const recipientOutOfBandRecord = await recipientAgent.oob.createInvitation({
      label: 'mediator invitation',
      handshake: true,
      handshakeProtocols: [HandshakeProtocol.Connections],
    })
    const recipientInvitation = recipientOutOfBandRecord.outOfBandInvitation

    let { connectionRecord: senderRecipientConnection } = await senderAgent.oob.receiveInvitationFromUrl(
      recipientInvitation.toUrl({ domain: 'https://example.com/ssi' })
    )

    senderRecipientConnection = await senderAgent.connections.returnWhenIsConnected(senderRecipientConnection!.id)

    let [recipientSenderConnection] = await recipientAgent.connections.findAllByOutOfBandId(recipientOutOfBandRecord.id)
    expect(recipientSenderConnection).toBeConnectedWith(senderRecipientConnection)
    expect(senderRecipientConnection).toBeConnectedWith(recipientSenderConnection!)
    expect(recipientSenderConnection!.isReady).toBe(true)
    expect(senderRecipientConnection.isReady).toBe(true)

    recipientSenderConnection = await recipientAgent.connections.returnWhenIsConnected(recipientSenderConnection!.id)

    const message = 'hello, world'
    await senderAgent.basicMessages.sendMessage(senderRecipientConnection.id, message)

    const basicMessage = await waitForBasicMessage(recipientAgent, {
      content: message,
    })

    // polling interval is 100ms, so 500ms should be enough to make sure no messages are sent
    await recipientAgent.mediationRecipient.stopMessagePickup()
    await sleep(500)

    expect(basicMessage.content).toBe(message)
  }

  test(`Mediation end-to-end flow
        1. Start mediator agent and create invitation
        2. Start recipient agent with mediatorConnectionsInvite from mediator
        3. Assert mediator and recipient are connected and mediation state is Granted
        4. Start sender agent and create connection with recipient
        5. Assert endpoint in recipient invitation for sender is mediator endpoint
        6. Send basic message from sender to recipient and assert it is received on the recipient side
`, async () => {
    await e2eMediationTest(mediatorAgentOptions, recipientAgentOptions)
  })

  test('Mediation end-to-end flow (not using did:key)', async () => {
    await e2eMediationTest(
      {
        ...mediatorAgentOptions,
        config: { ...mediatorAgentOptions.config, useDidKeyInProtocols: false },
      },
      {
        ...recipientAgentOptions,
        config: {
          ...recipientAgentOptions.config,
          useDidKeyInProtocols: false,
        },
      }
    )
  })

  test('restart recipient agent and create connection through mediator after recipient agent is restarted', async () => {
    const mediatorMessages = new Subject<SubjectMessage>()
    const recipientMessages = new Subject<SubjectMessage>()
    const senderMessages = new Subject<SubjectMessage>()

    const subjectMap = {
      'rxjs:mediator': mediatorMessages,
      'rxjs:sender': senderMessages,
    }

    // Initialize mediator
    mediatorAgent = new Agent(mediatorAgentOptions)
    mediatorAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    mediatorAgent.registerInboundTransport(new SubjectInboundTransport(mediatorMessages))
    await mediatorAgent.initialize()

    // Create connection to use for recipient
    const mediatorOutOfBandRecord = await mediatorAgent.oob.createInvitation({
      label: 'mediator invitation',
      handshake: true,
      handshakeProtocols: [HandshakeProtocol.Connections],
    })

    // Initialize recipient with mediation connections invitation
    recipientAgent = new Agent({
      ...recipientAgentOptions,
      modules: {
        ...recipientAgentOptions.modules,
        mediationRecipient: new MediationRecipientModule({
          mediatorInvitationUrl: mediatorOutOfBandRecord.outOfBandInvitation.toUrl({
            domain: 'https://example.com/ssi',
          }),
          mediatorPickupStrategy: MediatorPickupStrategy.PickUpV1,
        }),
      },
    })
    recipientAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    recipientAgent.registerInboundTransport(new SubjectInboundTransport(recipientMessages))
    await recipientAgent.initialize()

    const recipientMediator = await recipientAgent.mediationRecipient.findDefaultMediator()
    const recipientMediatorConnection = await recipientAgent.connections.getById(recipientMediator!.connectionId)
    expect(recipientMediatorConnection?.isReady).toBe(true)

    const [mediatorRecipientConnection] = await mediatorAgent.connections.findAllByOutOfBandId(
      mediatorOutOfBandRecord.id
    )
    expect(mediatorRecipientConnection!.isReady).toBe(true)

    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    expect(mediatorRecipientConnection).toBeConnectedWith(recipientMediatorConnection!)
    expect(recipientMediatorConnection).toBeConnectedWith(mediatorRecipientConnection!)

    expect(recipientMediator?.state).toBe(MediationState.Granted)

    await recipientAgent.mediationRecipient.stopMessagePickup()

    // Restart recipient agent
    await recipientAgent.shutdown()
    await recipientAgent.initialize()

    // Initialize sender agent
    senderAgent = new Agent(senderAgentOptions)
    senderAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    senderAgent.registerInboundTransport(new SubjectInboundTransport(senderMessages))
    await senderAgent.initialize()

    const recipientOutOfBandRecord = await recipientAgent.oob.createInvitation({
      label: 'mediator invitation',
      handshake: true,
      handshakeProtocols: [HandshakeProtocol.Connections],
    })
    const recipientInvitation = recipientOutOfBandRecord.outOfBandInvitation

    let { connectionRecord: senderRecipientConnection } = await senderAgent.oob.receiveInvitationFromUrl(
      recipientInvitation.toUrl({ domain: 'https://example.com/ssi' })
    )

    senderRecipientConnection = await senderAgent.connections.returnWhenIsConnected(senderRecipientConnection!.id)
    const [recipientSenderConnection] = await recipientAgent.connections.findAllByOutOfBandId(
      recipientOutOfBandRecord.id
    )
    expect(recipientSenderConnection).toBeConnectedWith(senderRecipientConnection)
    expect(senderRecipientConnection).toBeConnectedWith(recipientSenderConnection!)

    expect(recipientSenderConnection!.isReady).toBe(true)
    expect(senderRecipientConnection.isReady).toBe(true)

    const message = 'hello, world'
    await senderAgent.basicMessages.sendMessage(senderRecipientConnection.id, message)

    const basicMessage = await waitForBasicMessage(recipientAgent, {
      content: message,
    })

    expect(basicMessage.content).toBe(message)

    await recipientAgent.mediationRecipient.stopMessagePickup()
  })
})
