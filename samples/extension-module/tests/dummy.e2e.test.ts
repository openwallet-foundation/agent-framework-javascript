import type { SubjectMessage } from '../../../tests/transport/SubjectInboundTransport'
import type { ConnectionRecord } from '@credo-ts/core'

import { Agent } from '@credo-ts/core'
import { Subject } from 'rxjs'

import { indySdk } from '../../../packages/core/tests'
import { getAgentOptions, makeConnection } from '../../../packages/core/tests/helpers'
import testLogger from '../../../packages/core/tests/logger'
import { IndySdkModule } from '../../../packages/indy-sdk/src'
import { SubjectInboundTransport } from '../../../tests/transport/SubjectInboundTransport'
import { SubjectOutboundTransport } from '../../../tests/transport/SubjectOutboundTransport'
import { DummyModule } from '../dummy/DummyModule'
import { DummyState } from '../dummy/repository'

import { waitForDummyRecord } from './helpers'

const modules = {
  dummy: new DummyModule(),
  indySdk: new IndySdkModule({ indySdk }),
}

const bobAgentOptions = getAgentOptions(
  'Bob Dummy',
  {
    endpoints: ['rxjs:bob'],
  },
  modules
)

const aliceAgentOptions = getAgentOptions(
  'Alice Dummy',
  {
    endpoints: ['rxjs:alice'],
  },
  modules
)

describe('Dummy extension module test', () => {
  let bobAgent: Agent<typeof modules>
  let aliceAgent: Agent<typeof modules>
  let aliceConnection: ConnectionRecord

  beforeEach(async () => {
    const bobMessages = new Subject<SubjectMessage>()
    const aliceMessages = new Subject<SubjectMessage>()
    const subjectMap = {
      'rxjs:bob': bobMessages,
      'rxjs:alice': aliceMessages,
    }

    bobAgent = new Agent(bobAgentOptions)
    bobAgent.registerInboundTransport(new SubjectInboundTransport(bobMessages))
    bobAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    await bobAgent.initialize()

    aliceAgent = new Agent(aliceAgentOptions)

    aliceAgent.registerInboundTransport(new SubjectInboundTransport(aliceMessages))
    aliceAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    await aliceAgent.initialize()
    ;[aliceConnection] = await makeConnection(aliceAgent, bobAgent)
  })

  afterEach(async () => {
    await bobAgent.shutdown()
    await bobAgent.wallet.delete()
    await aliceAgent.shutdown()
    await aliceAgent.wallet.delete()
  })

  test('Alice sends a request and Bob answers', async () => {
    testLogger.test('Alice sends request to Bob')
    let aliceDummyRecord = await aliceAgent.modules.dummy.request(aliceConnection.id)

    testLogger.test('Bob waits for request from Alice')
    const bobDummyRecord = await waitForDummyRecord(bobAgent, {
      threadId: aliceDummyRecord.threadId,
      state: DummyState.RequestReceived,
    })

    testLogger.test('Bob sends response to Alice')
    await bobAgent.modules.dummy.respond(bobDummyRecord.id)

    testLogger.test('Alice waits until Bob responds')
    aliceDummyRecord = await waitForDummyRecord(aliceAgent, {
      threadId: aliceDummyRecord.threadId,
      state: DummyState.ResponseReceived,
    })

    const retrievedRecord = (await aliceAgent.modules.dummy.getAll()).find((item) => item.id === aliceDummyRecord.id)
    expect(retrievedRecord).toMatchObject(
      expect.objectContaining({
        id: aliceDummyRecord.id,
        threadId: aliceDummyRecord.threadId,
        state: DummyState.ResponseReceived,
      })
    )
  })
})
