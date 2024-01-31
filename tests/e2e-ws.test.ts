import type { AnonCredsTestsAgent } from '../packages/anoncreds/tests/legacyAnonCredsSetup'

import { getAnonCredsIndyModules } from '../packages/anoncreds/tests/legacyAnonCredsSetup'
import { askarModule } from '../packages/askar/tests/helpers'
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
const recipientAgentOptions = getAgentOptions(
  'E2E WS Recipient ',
  {},
  {
    ...getAnonCredsIndyModules({
      autoAcceptCredentials: AutoAcceptCredential.ContentApproved,
    }),
    mediationRecipient: new MediationRecipientModule({
      mediatorPickupStrategy: MediatorPickupStrategy.PickUpV1,
    }),
    askar: askarModule,
  }
)

const mediatorPort = 4000
const mediatorAgentOptions = getAgentOptions(
  'E2E WS Mediator',
  {
    endpoints: [`ws://localhost:${mediatorPort}`],
  },
  {
    ...getAnonCredsIndyModules({
      autoAcceptCredentials: AutoAcceptCredential.ContentApproved,
    }),
    mediator: new MediatorModule({ autoAcceptMediationRequests: true }),
    askar: askarModule,
  }
)

const senderPort = 4001
const senderAgentOptions = getAgentOptions(
  'E2E WS Sender',
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

describe('E2E WS tests', () => {
  let recipientAgent: AnonCredsTestsAgent
  let mediatorAgent: AnonCredsTestsAgent
  let senderAgent: AnonCredsTestsAgent

  beforeEach(async () => {
    recipientAgent = new Agent(recipientAgentOptions) as unknown as AnonCredsTestsAgent
    mediatorAgent = new Agent(mediatorAgentOptions) as unknown as AnonCredsTestsAgent
    senderAgent = new Agent(senderAgentOptions) as unknown as AnonCredsTestsAgent
  })

  afterEach(async () => {
    await recipientAgent.shutdown()
    await recipientAgent.wallet.delete()
    await mediatorAgent.shutdown()
    await mediatorAgent.wallet.delete()
    await senderAgent.shutdown()
    await senderAgent.wallet.delete()
  })

  test('Full WS flow (connect, request mediation, issue, verify)', async () => {
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
