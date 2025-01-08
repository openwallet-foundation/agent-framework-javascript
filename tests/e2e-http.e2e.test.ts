import type { AnonCredsTestsAgent } from '../packages/anoncreds/tests/anoncredsSetup'

import { getAnonCredsModules } from '../packages/anoncreds/tests/anoncredsSetup'
import { getInMemoryAgentOptions } from '../packages/core/tests/helpers'

import { e2eTest } from './e2e-test'

import { Agent } from '@credo-ts/core'
import {
  HttpOutboundTransport,
  AutoAcceptCredential,
  MediatorPickupStrategy,
  MediationRecipientModule,
  MediatorModule,
} from '@credo-ts/didcomm'
import { HttpInboundTransport } from '@credo-ts/node'

const recipientAgentOptions = getInMemoryAgentOptions(
  'E2E HTTP Recipient',
  {},
  {},
  {
    ...getAnonCredsModules({
      autoAcceptCredentials: AutoAcceptCredential.ContentApproved,
    }),
    mediationRecipient: new MediationRecipientModule({
      mediatorPollingInterval: 500,
      mediatorPickupStrategy: MediatorPickupStrategy.PickUpV1,
    }),
  }
)

const mediatorPort = 3000
const mediatorAgentOptions = getInMemoryAgentOptions(
  'E2E HTTP Mediator',
  {
    endpoints: [`http://localhost:${mediatorPort}`],
  },
  {},
  {
    ...getAnonCredsModules({
      autoAcceptCredentials: AutoAcceptCredential.ContentApproved,
    }),
    mediator: new MediatorModule({
      autoAcceptMediationRequests: true,
    }),
  }
)

const senderPort = 3001
const senderAgentOptions = getInMemoryAgentOptions(
  'E2E HTTP Sender',
  {
    endpoints: [`http://localhost:${senderPort}`],
  },
  {},
  getAnonCredsModules({
    autoAcceptCredentials: AutoAcceptCredential.ContentApproved,
  })
)

describe('E2E HTTP tests', () => {
  let recipientAgent: AnonCredsTestsAgent
  let mediatorAgent: AnonCredsTestsAgent
  let senderAgent: AnonCredsTestsAgent

  beforeEach(async () => {
    recipientAgent = new Agent(recipientAgentOptions) as AnonCredsTestsAgent
    mediatorAgent = new Agent(mediatorAgentOptions) as AnonCredsTestsAgent
    senderAgent = new Agent(senderAgentOptions) as AnonCredsTestsAgent
  })

  afterEach(async () => {
    await recipientAgent.shutdown()
    await recipientAgent.wallet.delete()
    await mediatorAgent.shutdown()
    await mediatorAgent.wallet.delete()
    await senderAgent.shutdown()
    await senderAgent.wallet.delete()
  })

  test('Full HTTP flow (connect, request mediation, issue, verify)', async () => {
    // Recipient Setup
    recipientAgent.modules.didcomm.registerOutboundTransport(new HttpOutboundTransport())
    await recipientAgent.initialize()

    // Mediator Setup
    mediatorAgent.modules.didcomm.registerInboundTransport(new HttpInboundTransport({ port: mediatorPort }))
    mediatorAgent.modules.didcomm.registerOutboundTransport(new HttpOutboundTransport())
    await mediatorAgent.initialize()

    // Sender Setup
    senderAgent.modules.didcomm.registerInboundTransport(new HttpInboundTransport({ port: senderPort }))
    senderAgent.modules.didcomm.registerOutboundTransport(new HttpOutboundTransport())
    await senderAgent.initialize()

    await e2eTest({
      mediatorAgent,
      senderAgent,
      recipientAgent,
    })
  })
})
