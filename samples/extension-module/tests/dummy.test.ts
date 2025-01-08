import type { SubjectMessage } from '../../../tests/transport/SubjectInboundTransport'
import type { ConnectionRecord } from '@credo-ts/didcomm'

import { AskarModule } from '@credo-ts/askar'
import { Agent } from '@credo-ts/core'
import { ariesAskar } from '@hyperledger/aries-askar-nodejs'
import { Subject } from 'rxjs'

import { getAgentOptions, makeConnection } from '../../../packages/core/tests/helpers'
import testLogger from '../../../packages/core/tests/logger'
import { getDefaultDidcommModules } from '../../../packages/didcomm/src/util/modules'
import { SubjectInboundTransport } from '../../../tests/transport/SubjectInboundTransport'
import { SubjectOutboundTransport } from '../../../tests/transport/SubjectOutboundTransport'
import { DummyModule } from '../dummy/DummyModule'
import { DummyState } from '../dummy/repository'

import { waitForDummyRecord } from './helpers'

const modules = {
  ...getDefaultDidcommModules(),
  dummy: new DummyModule(),
  askar: new AskarModule({
    ariesAskar,
  }),
}

const bobAgentOptions = getAgentOptions(
  'Bob Dummy',
  {
    endpoints: ['rxjs:bob'],
  },
  {},
  modules
)

const aliceAgentOptions = getAgentOptions(
  'Alice Dummy',
  {
    endpoints: ['rxjs:alice'],
  },
  {},
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
    bobAgent.modules.didcomm.registerInboundTransport(new SubjectInboundTransport(bobMessages))
    bobAgent.modules.didcomm.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    await bobAgent.initialize()

    aliceAgent = new Agent(aliceAgentOptions)

    aliceAgent.modules.didcomm.registerInboundTransport(new SubjectInboundTransport(aliceMessages))
    aliceAgent.modules.didcomm.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
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
