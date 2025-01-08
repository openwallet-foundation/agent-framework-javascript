import type { DrpcRequest, DrpcRequestObject, DrpcResponseObject } from '../src/messages'
import type { ConnectionRecord } from '@credo-ts/didcomm'

import { Agent } from '../../core/src/agent/Agent'
import { setupSubjectTransports } from '../../core/tests'
import { getInMemoryAgentOptions, makeConnection } from '../../core/tests/helpers'
import testLogger from '../../core/tests/logger'
import { DrpcModule } from '../src/DrpcModule'
import { DrpcErrorCode } from '../src/models'

const modules = {
  drpc: new DrpcModule(),
}

const faberConfig = getInMemoryAgentOptions(
  'Faber Drpc Messages',
  {
    endpoints: ['rxjs:faber'],
  },
  {},
  modules
)

const aliceConfig = getInMemoryAgentOptions(
  'Alice Drpc Messages',
  {
    endpoints: ['rxjs:alice'],
  },
  {},
  modules
)

const handleMessageOrError = async (
  handlers: Map<string, (message: DrpcRequestObject) => Promise<DrpcResponseObject | Record<string, never>>>,
  message: DrpcRequestObject
) => {
  const handler = handlers.get(message.method)
  if (handler) {
    return handler(message)
  }
  return {
    jsonrpc: '2.0',
    id: message.id,
    error: { code: DrpcErrorCode.METHOD_NOT_FOUND, message: 'Method not found' },
  }
}

const sendAndRecieve = async (
  sender: Agent,
  receiver: Agent,
  connectionRecord: ConnectionRecord,
  message: DrpcRequestObject,
  messageHandlers: Map<string, (message: DrpcRequestObject) => Promise<DrpcResponseObject | Record<string, never>>>
) => {
  const responseListener = await sender.modules.drpc.sendRequest(connectionRecord.id, message)
  const { request, sendResponse } = await receiver.modules.drpc.recvRequest()
  const result = await handleMessageOrError(messageHandlers, request as DrpcRequestObject)
  await sendResponse(result as DrpcResponseObject)

  const helloRecord = await responseListener()
  return helloRecord as DrpcResponseObject
}

const sendAndRecieveBatch = async (
  sender: Agent,
  receiver: Agent,
  connectionRecord: ConnectionRecord,
  message: DrpcRequestObject[],
  messageHandlers: Map<string, (message: DrpcRequestObject) => Promise<DrpcResponseObject | Record<string, never>>>
) => {
  const responseListener = await sender.modules.drpc.sendRequest(connectionRecord.id, message)
  const { request: batchRequest, sendResponse: sendBatchResponse } = await receiver.modules.drpc.recvRequest()
  const batchRequests = batchRequest as DrpcRequestObject[]
  const batchResults: (DrpcResponseObject | Record<string, never>)[] = []
  for (const request of batchRequests) {
    batchResults.push(await handleMessageOrError(messageHandlers, request))
  }
  await sendBatchResponse(batchResults)
  const batchRecord = await responseListener()
  return batchRecord as DrpcResponseObject[]
}

describe('Drpc Messages E2E', () => {
  let faberAgent: Agent
  let aliceAgent: Agent
  let aliceConnection: ConnectionRecord
  let messageHandlers: Map<string, (message: DrpcRequestObject) => Promise<DrpcResponseObject | Record<string, never>>>

  beforeEach(async () => {
    faberAgent = new Agent(faberConfig)
    aliceAgent = new Agent(aliceConfig)

    setupSubjectTransports([faberAgent, aliceAgent])

    await faberAgent.initialize()
    await aliceAgent.initialize()
    ;[aliceConnection] = await makeConnection(aliceAgent, faberAgent)

    messageHandlers = new Map()
    messageHandlers.set('hello', async (message: DrpcRequestObject) => {
      return { jsonrpc: '2.0', result: 'Hello', id: message.id }
    })
    messageHandlers.set('add', async (message) => {
      const operands = message.params as number[]
      const result = operands.reduce((a, b) => a + b, 0)
      return { jsonrpc: '2.0', result, id: message.id }
    })
    messageHandlers.set('parseFoo', async (message) => {
      const params = message.params as { foo: string }
      return { jsonrpc: '2.0', result: params.foo, id: message.id }
    })
  })

  afterEach(async () => {
    await faberAgent.shutdown()
    await faberAgent.wallet.delete()
    await aliceAgent.shutdown()
    await aliceAgent.wallet.delete()
  })

  test('Alice and Faber exchange messages', async () => {
    testLogger.test('Alice sends message to Faber')
    const helloRecord = await sendAndRecieve(
      aliceAgent,
      faberAgent,
      aliceConnection,
      {
        jsonrpc: '2.0',
        method: 'hello',
        id: 1,
      },
      messageHandlers
    )
    expect((helloRecord as DrpcResponseObject).result).toBe('Hello')

    testLogger.test('Alice sends message with positional parameters to Faber')

    const addRecord = await sendAndRecieve(
      aliceAgent,
      faberAgent,
      aliceConnection,
      {
        jsonrpc: '2.0',
        method: 'add',
        params: [2, 3, 7],
        id: 2,
      },
      messageHandlers
    )

    expect((addRecord as DrpcResponseObject).result).toBe(12)

    testLogger.test('Alice sends message with keyed parameters to Faber')

    const parseFooRecord = await sendAndRecieve(
      aliceAgent,
      faberAgent,
      aliceConnection,
      {
        jsonrpc: '2.0',
        method: 'parseFoo',
        params: { foo: 'bar' },
        id: 3,
      },
      messageHandlers
    )
    expect((parseFooRecord as DrpcResponseObject).result).toBe('bar')

    testLogger.test('Alice sends message with invalid method to Faber')

    const errorRecord = await sendAndRecieve(
      aliceAgent,
      faberAgent,
      aliceConnection,
      {
        jsonrpc: '2.0',
        method: 'error',
        id: 4,
      },
      messageHandlers
    )
    expect((errorRecord as DrpcResponseObject).error).toBeDefined()
    expect((errorRecord as DrpcResponseObject).error?.code).toBe(DrpcErrorCode.METHOD_NOT_FOUND)
  })

  test('Alice sends Faber Drpc batch message', async () => {
    testLogger.test('Alice sends batch message to Faber')

    const batchRecord = await sendAndRecieveBatch(
      aliceAgent,
      faberAgent,
      aliceConnection,
      [
        { jsonrpc: '2.0', method: 'hello', id: 1 },
        { jsonrpc: '2.0', method: 'add', params: [2, 3, 7], id: 2 },
        { jsonrpc: '2.0', method: 'parseFoo', params: { foo: 'bar' }, id: 3 },
        { jsonrpc: '2.0', method: 'error', id: 4 },
      ],
      messageHandlers
    )
    expect(batchRecord as DrpcResponseObject[]).toHaveLength(4)
    expect((batchRecord as DrpcResponseObject[]).find((item) => item.id === 1)?.result).toBe('Hello')
    expect((batchRecord as DrpcResponseObject[]).find((item) => item.id === 2)?.result).toBe(12)
    expect((batchRecord as DrpcResponseObject[]).find((item) => item.id === 3)?.result).toBe('bar')
    expect((batchRecord as DrpcResponseObject[]).find((item) => item.id === 4)?.error).toBeDefined()
    expect((batchRecord as DrpcResponseObject[]).find((item) => item.id === 4)?.error?.code).toBe(
      DrpcErrorCode.METHOD_NOT_FOUND
    )
  })

  test('Alice sends Faber Drpc notification', async () => {
    testLogger.test('Alice sends notification to Faber')
    let notified = false
    messageHandlers.set('notify', async () => {
      notified = true
      return {}
    })
    const notifyRecord = await sendAndRecieve(
      aliceAgent,
      faberAgent,
      aliceConnection,
      {
        jsonrpc: '2.0',
        method: 'notify',
        id: null,
      },
      messageHandlers
    )
    expect(notifyRecord).toMatchObject({})
    expect(notified).toBe(true)

    testLogger.test('Alice sends batch notification to Faber')
    notified = false

    const notifyBatchRecord = await sendAndRecieveBatch(
      aliceAgent,
      faberAgent,
      aliceConnection,
      [
        { jsonrpc: '2.0', method: 'hello', id: 1 },
        { jsonrpc: '2.0', method: 'notify', id: null },
      ],
      messageHandlers
    )
    expect(
      (notifyBatchRecord as (DrpcResponseObject | Record<string, never>)[]).find(
        (item) => (item as DrpcResponseObject)?.id === 1
      )
    ).toMatchObject({ jsonrpc: '2.0', result: 'Hello', id: 1 })
    expect(
      (notifyBatchRecord as (DrpcResponseObject | Record<string, never>)[]).find(
        (item) => !(item as DrpcResponseObject)?.id
      )
    ).toMatchObject({})
    expect(notified).toBe(true)
  })

  test('Alice sends Faber invalid Drpc message | Faber responds with invalid Drpc message', async () => {
    messageHandlers.set('hello', async () => {
      return [] as unknown as DrpcResponseObject
    })
    let error = false
    try {
      await aliceAgent.modules.drpc.sendRequest(aliceConnection.id, 'test' as unknown as DrpcRequest)
    } catch {
      error = true
    }
    expect(error).toBe(true)
    await aliceAgent.modules.drpc.sendRequest(aliceConnection.id, {
      jsonrpc: '2.0',
      method: 'hello',
      id: 1,
    })
    const { request, sendResponse } = await faberAgent.modules.drpc.recvRequest()
    const result = await handleMessageOrError(messageHandlers, request as DrpcRequestObject)
    let responseError = false
    try {
      await sendResponse(result as DrpcResponseObject)
    } catch {
      responseError = true
    }
    expect(responseError).toBe(true)
  })

  test('Request times out', async () => {
    // recvRequest timeout
    setTimeout(async () => {
      await aliceAgent.modules.drpc.sendRequest(aliceConnection.id, { jsonrpc: '2.0', method: 'hello', id: 1 })
    }, 500)
    const req = await faberAgent.modules.drpc.recvRequest(100)
    expect(req).toBe(undefined)

    // response listener timeout
    const responseListener = await aliceAgent.modules.drpc.sendRequest(aliceConnection.id, {
      jsonrpc: '2.0',
      method: 'hello',
      id: 1,
    })
    const { request, sendResponse } = await faberAgent.modules.drpc.recvRequest()
    setTimeout(async () => {
      const result = await handleMessageOrError(messageHandlers, request)
      sendResponse(result as DrpcResponseObject)
    }, 500)

    const helloRecord = await responseListener(100)
    expect(helloRecord).toBe(undefined)

    await new Promise((r) => setTimeout(r, 1500))
  })
})
