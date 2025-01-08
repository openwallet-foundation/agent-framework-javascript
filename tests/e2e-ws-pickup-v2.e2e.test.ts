import type { AnonCredsTestsAgent } from '../packages/anoncreds/tests/anoncredsSetup'

import { getAnonCredsModules } from '../packages/anoncreds/tests/anoncredsSetup'
import { askarModule } from '../packages/askar/tests/helpers'
import { getAgentOptions } from '../packages/core/tests/helpers'
import {
  MessageForwardingStrategy,
  WsOutboundTransport,
  AutoAcceptCredential,
  MediatorPickupStrategy,
  MediationRecipientModule,
  MediatorModule,
} from '../packages/didcomm/src'

import { e2eTest } from './e2e-test'

import { Agent } from '@credo-ts/core'
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
  {},
  {
    ...getAnonCredsModules({
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
  {},
  {
    ...getAnonCredsModules({
      autoAcceptCredentials: AutoAcceptCredential.ContentApproved,
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
    // NOTE: the order is important here, as the recipient sends pickup messages to the mediator
    // so we first want the recipient to fully be finished with the sending of messages
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
      {},
      {
        ...getAnonCredsModules({
          autoAcceptCredentials: AutoAcceptCredential.ContentApproved,
        }),
        mediationRecipient: new MediationRecipientModule({
          mediatorPickupStrategy: MediatorPickupStrategy.PickUpV2,
          mediatorPollingInterval: 500,
        }),
        askar: askarModule,
      }
    )

    recipientAgent = new Agent(recipientOptions) as unknown as AnonCredsTestsAgent

    // Recipient Setup
    recipientAgent.modules.didcomm.registerOutboundTransport(new WsOutboundTransport())
    await recipientAgent.initialize()

    // Mediator Setup
    mediatorAgent.modules.didcomm.registerInboundTransport(new WsInboundTransport({ port: mediatorPort }))
    mediatorAgent.modules.didcomm.registerOutboundTransport(new WsOutboundTransport())
    await mediatorAgent.initialize()

    // Sender Setup
    senderAgent.modules.didcomm.registerInboundTransport(new WsInboundTransport({ port: senderPort }))
    senderAgent.modules.didcomm.registerOutboundTransport(new WsOutboundTransport())
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
      {},
      {
        ...getAnonCredsModules({
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
    recipientAgent.modules.didcomm.registerOutboundTransport(new WsOutboundTransport())
    await recipientAgent.initialize()

    // Mediator Setup
    mediatorAgent.modules.didcomm.registerInboundTransport(new WsInboundTransport({ port: mediatorPort }))
    mediatorAgent.modules.didcomm.registerOutboundTransport(new WsOutboundTransport())
    await mediatorAgent.initialize()

    // Sender Setup
    senderAgent.modules.didcomm.registerInboundTransport(new WsInboundTransport({ port: senderPort }))
    senderAgent.modules.didcomm.registerOutboundTransport(new WsOutboundTransport())
    await senderAgent.initialize()

    await e2eTest({
      mediatorAgent,
      senderAgent,
      recipientAgent,
    })
  })
})
