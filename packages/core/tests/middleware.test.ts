import type { SubjectMessage } from '../../../tests/transport/SubjectInboundTransport'
import type { ConnectionRecord, InboundMessageContext } from '../src'

import { Subject } from 'rxjs'

import { SubjectInboundTransport } from '../../../tests/transport/SubjectInboundTransport'
import { SubjectOutboundTransport } from '../../../tests/transport/SubjectOutboundTransport'
import {
  TrustPingResponseMessage,
  BasicMessage,
  getOutboundMessageContext,
  MessageSender,
  AgentMessage,
  JsonTransformer,
  Agent,
} from '../src'

import {
  getInMemoryAgentOptions,
  makeConnection,
  waitForAgentMessageProcessedEvent,
  waitForBasicMessage,
} from './helpers'

const faberConfig = getInMemoryAgentOptions('Faber Message Handler Middleware', {
  endpoints: ['rxjs:faber'],
})

const aliceConfig = getInMemoryAgentOptions('Alice Message Handler Middleware', {
  endpoints: ['rxjs:alice'],
})

describe('Message Handler Middleware E2E', () => {
  let faberAgent: Agent
  let aliceAgent: Agent
  let faberConnection: ConnectionRecord
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  let aliceConnection: ConnectionRecord

  beforeEach(async () => {
    const faberMessages = new Subject<SubjectMessage>()
    const aliceMessages = new Subject<SubjectMessage>()
    const subjectMap = {
      'rxjs:faber': faberMessages,
      'rxjs:alice': aliceMessages,
    }

    faberAgent = new Agent(faberConfig)
    faberAgent.registerInboundTransport(new SubjectInboundTransport(faberMessages))
    faberAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    await faberAgent.initialize()

    aliceAgent = new Agent(aliceConfig)
    aliceAgent.registerInboundTransport(new SubjectInboundTransport(aliceMessages))
    aliceAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    await aliceAgent.initialize()
    ;[aliceConnection, faberConnection] = await makeConnection(aliceAgent, faberAgent)
  })

  afterEach(async () => {
    await faberAgent.shutdown()
    await faberAgent.wallet.delete()
    await aliceAgent.shutdown()
    await aliceAgent.wallet.delete()
  })

  test('Correctly calls the fallback message handler if no message handler is defined', async () => {
    // Fallback message handler
    aliceAgent.dependencyManager.setFallbackMessageHandler((messageContext) => {
      return getOutboundMessageContext(messageContext.agentContext, {
        connectionRecord: messageContext.connection,
        message: new BasicMessage({
          content: "Hey there, I'm not sure I understand the message you sent to me",
        }),
      })
    })

    const message = JsonTransformer.fromJSON(
      {
        '@type': 'https://credo.js.org/custom-messaging/1.0/say-hello',
        '@id': 'b630b69a-2b82-4764-87ba-56aa2febfb97',
      },
      AgentMessage
    )

    // Send a custom message
    const messageSender = faberAgent.dependencyManager.resolve(MessageSender)
    const outboundMessageContext = await getOutboundMessageContext(faberAgent.context, {
      connectionRecord: faberConnection,
      message,
    })
    await messageSender.sendMessage(outboundMessageContext)

    // Expect the basic message sent by the fallback message handler
    await waitForBasicMessage(faberAgent, {
      content: "Hey there, I'm not sure I understand the message you sent to me",
    })
  })

  test('Correctly calls the registered message handler middleware', async () => {
    aliceAgent.dependencyManager.registerMessageHandlerMiddleware(
      async (inboundMessageContext: InboundMessageContext, next) => {
        await next()

        if (inboundMessageContext.responseMessage) {
          inboundMessageContext.responseMessage.message.setTiming({
            outTime: new Date('2021-01-01'),
          })
        }
      }
    )

    await faberAgent.connections.sendPing(faberConnection.id, {})
    const receiveMessage = await waitForAgentMessageProcessedEvent(faberAgent, {
      messageType: TrustPingResponseMessage.type.messageTypeUri,
    })

    // Should have sent the message with the timing added in the middleware
    expect(receiveMessage.timing?.outTime).toEqual(new Date('2021-01-01'))
  })
})
