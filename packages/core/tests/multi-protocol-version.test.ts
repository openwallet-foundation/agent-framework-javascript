import type { AgentMessageProcessedEvent } from '../../didcomm/src'

import { filter, firstValueFrom, timeout } from 'rxjs'

import {
  AgentEventTypes,
  OutboundMessageContext,
  parseMessageType,
  MessageSender,
  AgentMessage,
  IsValidMessageType,
} from '../../didcomm/src'
import { Agent } from '../src/agent/Agent'

import { getInMemoryAgentOptions } from './helpers'
import { setupSubjectTransports } from './transport'

const aliceAgentOptions = getInMemoryAgentOptions('Multi Protocol Versions - Alice', {
  endpoints: ['rxjs:alice'],
})
const bobAgentOptions = getInMemoryAgentOptions('Multi Protocol Versions - Bob', {
  endpoints: ['rxjs:bob'],
})

describe('multi version protocols', () => {
  let aliceAgent: Agent
  let bobAgent: Agent

  afterAll(async () => {
    await bobAgent.shutdown()
    await bobAgent.wallet.delete()
    await aliceAgent.shutdown()
    await aliceAgent.wallet.delete()
  })

  test('should successfully handle a message with a lower minor version than the currently supported version', async () => {
    bobAgent = new Agent(bobAgentOptions)
    aliceAgent = new Agent(aliceAgentOptions)
    setupSubjectTransports([aliceAgent, bobAgent])

    // Register the test handler with the v1.3 version of the message
    const mockHandle = jest.fn()
    aliceAgent.modules.didcomm.registerMessageHandlers([{ supportedMessages: [TestMessageV13], handle: mockHandle }])

    await aliceAgent.initialize()
    await bobAgent.initialize()

    const { outOfBandInvitation, id } = await aliceAgent.modules.oob.createInvitation()
    let { connectionRecord: bobConnection } = await bobAgent.modules.oob.receiveInvitation(outOfBandInvitation, {
      autoAcceptConnection: true,
      autoAcceptInvitation: true,
    })

    if (!bobConnection) {
      throw new Error('No connection for bob')
    }

    bobConnection = await bobAgent.modules.connections.returnWhenIsConnected(bobConnection.id)

    let [aliceConnection] = await aliceAgent.modules.connections.findAllByOutOfBandId(id)
    aliceConnection = await aliceAgent.modules.connections.returnWhenIsConnected(aliceConnection.id)

    expect(aliceConnection).toBeConnectedWith(bobConnection)
    expect(bobConnection).toBeConnectedWith(aliceConnection)

    const bobMessageSender = bobAgent.dependencyManager.resolve(MessageSender)

    // Start event listener for message processed
    const agentMessageV11ProcessedPromise = firstValueFrom(
      aliceAgent.events.observable<AgentMessageProcessedEvent>(AgentEventTypes.AgentMessageProcessed).pipe(
        filter((event) => event.payload.message.type === TestMessageV11.type.messageTypeUri),
        timeout(8000)
      )
    )

    await bobMessageSender.sendMessage(
      new OutboundMessageContext(new TestMessageV11(), { agentContext: bobAgent.context, connection: bobConnection })
    )

    // Wait for the agent message processed event to be called
    await agentMessageV11ProcessedPromise

    expect(mockHandle).toHaveBeenCalledTimes(1)

    // Start event listener for message processed
    const agentMessageV15ProcessedPromise = firstValueFrom(
      aliceAgent.events.observable<AgentMessageProcessedEvent>(AgentEventTypes.AgentMessageProcessed).pipe(
        filter((event) => event.payload.message.type === TestMessageV15.type.messageTypeUri),
        timeout(8000)
      )
    )

    await bobMessageSender.sendMessage(
      new OutboundMessageContext(new TestMessageV15(), { agentContext: bobAgent.context, connection: bobConnection })
    )
    await agentMessageV15ProcessedPromise

    expect(mockHandle).toHaveBeenCalledTimes(2)
  })
})

class TestMessageV11 extends AgentMessage {
  public constructor() {
    super()
    this.id = this.generateId()
  }

  @IsValidMessageType(TestMessageV11.type)
  public readonly type = TestMessageV11.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/custom-protocol/1.1/test-message')
}

class TestMessageV13 extends AgentMessage {
  public constructor() {
    super()
    this.id = this.generateId()
  }

  @IsValidMessageType(TestMessageV13.type)
  public readonly type = TestMessageV13.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/custom-protocol/1.3/test-message')
}

class TestMessageV15 extends AgentMessage {
  public constructor() {
    super()
    this.id = this.generateId()
  }

  @IsValidMessageType(TestMessageV15.type)
  public readonly type = TestMessageV15.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/custom-protocol/1.5/test-message')
}
