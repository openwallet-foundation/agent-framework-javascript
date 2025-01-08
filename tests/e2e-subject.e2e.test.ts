import type { SubjectMessage } from './transport/SubjectInboundTransport'
import type { AnonCredsTestsAgent } from '../packages/anoncreds/tests/anoncredsSetup'

import { Subject } from 'rxjs'

import { getAnonCredsModules } from '../packages/anoncreds/tests/anoncredsSetup'
import { getInMemoryAgentOptions } from '../packages/core/tests/helpers'

import { e2eTest } from './e2e-test'
import { SubjectInboundTransport } from './transport/SubjectInboundTransport'
import { SubjectOutboundTransport } from './transport/SubjectOutboundTransport'

import { Agent } from '@credo-ts/core'
import {
  AutoAcceptCredential,
  MediatorModule,
  MediatorPickupStrategy,
  MediationRecipientModule,
} from '@credo-ts/didcomm'

const recipientAgentOptions = getInMemoryAgentOptions(
  'E2E Subject Recipient',
  {},
  {},
  {
    ...getAnonCredsModules({
      autoAcceptCredentials: AutoAcceptCredential.ContentApproved,
    }),
    mediationRecipient: new MediationRecipientModule({
      mediatorPickupStrategy: MediatorPickupStrategy.PickUpV1,
    }),
  }
)
const mediatorAgentOptions = getInMemoryAgentOptions(
  'E2E Subject Mediator',
  {
    endpoints: ['rxjs:mediator'],
  },
  {},
  {
    ...getAnonCredsModules({
      autoAcceptCredentials: AutoAcceptCredential.ContentApproved,
    }),
    mediator: new MediatorModule({ autoAcceptMediationRequests: true }),
  }
)
const senderAgentOptions = getInMemoryAgentOptions(
  'E2E Subject Sender',
  {
    endpoints: ['rxjs:sender'],
  },
  {},
  {
    ...getAnonCredsModules({
      autoAcceptCredentials: AutoAcceptCredential.ContentApproved,
    }),
    mediationRecipient: new MediationRecipientModule({
      mediatorPollingInterval: 1000,
      mediatorPickupStrategy: MediatorPickupStrategy.PickUpV1,
    }),
  }
)

describe('E2E Subject tests', () => {
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

  test('Full Subject flow (connect, request mediation, issue, verify)', async () => {
    const mediatorMessages = new Subject<SubjectMessage>()
    const senderMessages = new Subject<SubjectMessage>()

    const subjectMap = {
      'rxjs:mediator': mediatorMessages,
      'rxjs:sender': senderMessages,
    }

    // Recipient Setup
    recipientAgent.modules.didcomm.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    await recipientAgent.initialize()

    // Mediator Setup
    mediatorAgent.modules.didcomm.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    mediatorAgent.modules.didcomm.registerInboundTransport(new SubjectInboundTransport(mediatorMessages))
    await mediatorAgent.initialize()

    // Sender Setup
    senderAgent.modules.didcomm.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    senderAgent.modules.didcomm.registerInboundTransport(new SubjectInboundTransport(senderMessages))
    await senderAgent.initialize()

    await e2eTest({
      mediatorAgent,
      senderAgent,
      recipientAgent,
    })
  })
})
