import type { AnonCredsTestsAgent } from '../packages/anoncreds/tests/legacyAnonCredsSetup'

import { getAnonCredsIndyModules } from '../packages/anoncreds/tests/legacyAnonCredsSetup'
import { askarModule } from '../packages/askar/tests/helpers'
import { MessageForwardingStrategy } from '../packages/core/src/modules/routing/MessageForwardingStrategy'
import { getAgentOptions } from '../packages/core/tests/helpers'

import { e2eTest } from './e2e-test'

import {
  Agent,
  WsOutboundTransport,
  AutoAcceptCredential,
  MediatorPickupStrategy,
  MediationRecipientModule,
  MediatorModule,
} from '@credo-ts/core'
import { WsInboundTransport } from '@credo-ts/node'

// FIXME: somehow if we use the in memory wallet and storage service in the WS test it will fail,
// but it succeeds with Askar. We should look into this at some point

// FIXME: port numbers should not depend on availability from other test suites that use web sockets
const mediatorPort = 4100
const mediatorOptions = getAgentOptions(
  'E2E WS Pickup V2 Mediator',
  {
    endpoints: [`ws://localhost:${mediatorPort}`],
  },
  {
    ...getAnonCredsIndyModules({
      autoAcceptCredentials: AutoAcceptCredential.ContentApproved,
    }),
    mediator: new MediatorModule({
      autoAcceptMediationRequests: true,
      messageForwardingStrategy: MessageForwardingStrategy.QueueAndLiveModeDelivery,
    }),
    askar: askarModule,
  }
)

const senderPort = 4101
const senderOptions = getAgentOptions(
  'E2E WS Pickup V2 Sender',
  {
    endpoints: [`ws://localhost:${senderPort}`],
  },
  {
    ...getAnonCredsIndyModules({
      autoAcceptCredentials: AutoAcceptCredential.ContentApproved,
    }),
    mediationRecipient: new MediationRecipientModule({
      mediatorPollingInterval: 1000,
      mediatorPickupStrategy: MediatorPickupStrategy.PickUpV1,
    }),
    askar: askarModule,
  }
)

describe('E2E WS Pickup V2 tests', () => {
  let recipientAgent: AnonCredsTestsAgent
  let mediatorAgent: AnonCredsTestsAgent
  let senderAgent: AnonCredsTestsAgent

  beforeEach(async () => {
    mediatorAgent = new Agent(mediatorOptions) as unknown as AnonCredsTestsAgent
    senderAgent = new Agent(senderOptions) as unknown as AnonCredsTestsAgent
  })

  afterEach(async () => {
    await recipientAgent.shutdown()
    await recipientAgent.wallet.delete()
    await mediatorAgent.shutdown()
    await mediatorAgent.wallet.delete()
    await senderAgent.shutdown()
    await senderAgent.wallet.delete()
  })

  test('Full WS flow (connect, request mediation, issue, verify) using Message Pickup V2 polling mode', async () => {
    const recipientOptions = getAgentOptions(
      'E2E WS Pickup V2 Recipient polling mode',
      {},
      {
        ...getAnonCredsIndyModules({
          autoAcceptCredentials: AutoAcceptCredential.ContentApproved,
        }),
        mediationRecipient: new MediationRecipientModule({
          mediatorPickupStrategy: MediatorPickupStrategy.PickUpV2,
          mediatorPollingInterval: 1000,
        }),
        askar: askarModule,
      }
    )

    recipientAgent = new Agent(recipientOptions) as unknown as AnonCredsTestsAgent

    // Recipient Setup
    recipientAgent.registerOutboundTransport(new WsOutboundTransport())
    await recipientAgent.initialize()

    // Mediator Setup
    mediatorAgent.registerInboundTransport(new WsInboundTransport({ port: mediatorPort }))
    mediatorAgent.registerOutboundTransport(new WsOutboundTransport())
    await mediatorAgent.initialize()

    // Sender Setup
    senderAgent.registerInboundTransport(new WsInboundTransport({ port: senderPort }))
    senderAgent.registerOutboundTransport(new WsOutboundTransport())
    await senderAgent.initialize()

    await e2eTest({
      mediatorAgent,
      senderAgent,
      recipientAgent,
    })
  })

  test('Full WS flow (connect, request mediation, issue, verify) using Message Pickup V2 live mode', async () => {
    const recipientOptions = getAgentOptions(
      'E2E WS Pickup V2 Recipient live mode',
      {},
      {
        ...getAnonCredsIndyModules({
          autoAcceptCredentials: AutoAcceptCredential.ContentApproved,
        }),
        mediationRecipient: new MediationRecipientModule({
          mediatorPickupStrategy: MediatorPickupStrategy.PickUpV2LiveMode,
        }),
        askar: askarModule,
      }
    )

    recipientAgent = new Agent(recipientOptions) as unknown as AnonCredsTestsAgent

    // Recipient Setup
    recipientAgent.registerOutboundTransport(new WsOutboundTransport())
    await recipientAgent.initialize()

    // Mediator Setup
    mediatorAgent.registerInboundTransport(new WsInboundTransport({ port: mediatorPort }))
    mediatorAgent.registerOutboundTransport(new WsOutboundTransport())
    await mediatorAgent.initialize()

    // Sender Setup
    senderAgent.registerInboundTransport(new WsInboundTransport({ port: senderPort }))
    senderAgent.registerOutboundTransport(new WsOutboundTransport())
    await senderAgent.initialize()

    await e2eTest({
      mediatorAgent,
      senderAgent,
      recipientAgent,
    })
  })
})
