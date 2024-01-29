/* eslint-disable @typescript-eslint/no-non-null-assertion */
import type { SubjectMessage } from '../../../tests/transport/SubjectInboundTransport'

import { Agent } from '@aries-framework/core'
import { Subject } from 'rxjs'

import { SubjectInboundTransport } from '../../../tests/transport/SubjectInboundTransport'
import { SubjectOutboundTransport } from '../../../tests/transport/SubjectOutboundTransport'

import { e2eTest, getSqliteAgentOptions } from './helpers'

const aliceInMemoryAgentOptions = getSqliteAgentOptions(
  'AgentsAlice',
  {
    endpoints: ['rxjs:alice'],
  },
  true
)
const bobInMemoryAgentOptions = getSqliteAgentOptions(
  'AgentsBob',
  {
    endpoints: ['rxjs:bob'],
  },
  true
)

describe('Askar In Memory agents', () => {
  let aliceAgent: Agent
  let bobAgent: Agent

  afterAll(async () => {
    if (bobAgent) {
      await bobAgent.shutdown()
      await bobAgent.wallet.delete()
    }

    if (aliceAgent) {
      await aliceAgent.shutdown()
      await aliceAgent.wallet.delete()
    }
  })

  test('In memory Askar wallets E2E test', async () => {
    const aliceMessages = new Subject<SubjectMessage>()
    const bobMessages = new Subject<SubjectMessage>()

    const subjectMap = {
      'rxjs:alice': aliceMessages,
      'rxjs:bob': bobMessages,
    }

    aliceAgent = new Agent(aliceInMemoryAgentOptions)
    aliceAgent.registerInboundTransport(new SubjectInboundTransport(aliceMessages))
    aliceAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    await aliceAgent.initialize()

    bobAgent = new Agent(bobInMemoryAgentOptions)
    bobAgent.registerInboundTransport(new SubjectInboundTransport(bobMessages))
    bobAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    await bobAgent.initialize()

    await e2eTest(aliceAgent, bobAgent)
  })
})
