/* eslint-disable @typescript-eslint/no-non-null-assertion */
import type { SubjectMessage } from '../../../tests/transport/SubjectInboundTransport'

import { Agent } from '@credo-ts/core'
import { Subject } from 'rxjs'

import { SubjectInboundTransport } from '../../../tests/transport/SubjectInboundTransport'
import { SubjectOutboundTransport } from '../../../tests/transport/SubjectOutboundTransport'

import { askarPostgresStorageConfig, e2eTest, getAskarPostgresAgentOptions } from './helpers'

const alicePostgresAgentOptions = getAskarPostgresAgentOptions(
  'AgentsAlice',
  { endpoints: ['rxjs:alice'] },
  askarPostgresStorageConfig
)
const bobPostgresAgentOptions = getAskarPostgresAgentOptions(
  'AgentsBob',
  {
    endpoints: ['rxjs:bob'],
  },
  askarPostgresStorageConfig
)

describe('Askar Postgres agents', () => {
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

  test('Postgres Askar wallets E2E test', async () => {
    const aliceMessages = new Subject<SubjectMessage>()
    const bobMessages = new Subject<SubjectMessage>()

    const subjectMap = {
      'rxjs:alice': aliceMessages,
      'rxjs:bob': bobMessages,
    }

    aliceAgent = new Agent(alicePostgresAgentOptions)
    aliceAgent.modules.didcomm.registerInboundTransport(new SubjectInboundTransport(aliceMessages))
    aliceAgent.modules.didcomm.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    await aliceAgent.initialize()

    bobAgent = new Agent(bobPostgresAgentOptions)
    bobAgent.modules.didcomm.registerInboundTransport(new SubjectInboundTransport(bobMessages))
    bobAgent.modules.didcomm.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    await bobAgent.initialize()

    await e2eTest(aliceAgent, bobAgent)
  })
})
