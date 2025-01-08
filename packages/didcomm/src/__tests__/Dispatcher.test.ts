import { Subject } from 'rxjs'

import { EventEmitter } from '../../../core/src/agent/EventEmitter'
import { getAgentConfig, getAgentContext } from '../../../core/tests/helpers'
import { AgentMessage } from '../AgentMessage'
import { Dispatcher } from '../Dispatcher'
import { MessageHandlerRegistry } from '../MessageHandlerRegistry'
import { MessageSender } from '../MessageSender'
import { getOutboundMessageContext } from '../getOutboundMessageContext'
import { InboundMessageContext } from '../models'
import { type ConnectionRecord } from '../modules/connections'
import { parseMessageType } from '../util/messageType'

jest.mock('../MessageSender')

class CustomProtocolMessage extends AgentMessage {
  public readonly type = CustomProtocolMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/fake-protocol/1.5/message')

  public constructor(options: { id?: string }) {
    super()

    if (options) {
      this.id = options.id ?? this.generateId()
    }
  }
}

describe('Dispatcher', () => {
  const agentConfig = getAgentConfig('DispatcherTest')
  const agentContext = getAgentContext()
  const MessageSenderMock = MessageSender as jest.Mock<MessageSender>
  const eventEmitter = new EventEmitter(agentConfig.agentDependencies, new Subject())

  describe('dispatch()', () => {
    it('calls the handle method of the handler', async () => {
      const messageHandlerRegistry = new MessageHandlerRegistry()
      const dispatcher = new Dispatcher(
        new MessageSenderMock(),
        eventEmitter,
        messageHandlerRegistry,
        agentConfig.logger
      )
      const customProtocolMessage = new CustomProtocolMessage({})
      const inboundMessageContext = new InboundMessageContext(customProtocolMessage, { agentContext })

      const mockHandle = jest.fn()
      messageHandlerRegistry.registerMessageHandler({ supportedMessages: [CustomProtocolMessage], handle: mockHandle })

      await dispatcher.dispatch(inboundMessageContext)

      expect(mockHandle).toHaveBeenNthCalledWith(1, inboundMessageContext)
    })

    it('throws an error if no handler for the message could be found', async () => {
      const messageHandlerRegistry = new MessageHandlerRegistry()
      const dispatcher = new Dispatcher(
        new MessageSenderMock(),
        eventEmitter,
        new MessageHandlerRegistry(),
        agentConfig.logger
      )
      const customProtocolMessage = new CustomProtocolMessage({
        id: '55170d10-b91f-4df2-9dcd-6deb4e806c1b',
      })
      const inboundMessageContext = new InboundMessageContext(customProtocolMessage, { agentContext })

      const mockHandle = jest.fn()
      messageHandlerRegistry.registerMessageHandler({ supportedMessages: [], handle: mockHandle })

      await expect(dispatcher.dispatch(inboundMessageContext)).rejects.toThrow(
        'Error handling message 55170d10-b91f-4df2-9dcd-6deb4e806c1b with type https://didcomm.org/fake-protocol/1.5/message. The message type is not supported'
      )
    })

    it('calls the middleware in the order they are registered', async () => {
      const agentContext = getAgentContext()

      // Replace the MessageHandlerRegistry instance with a empty one
      agentContext.dependencyManager.registerInstance(MessageHandlerRegistry, new MessageHandlerRegistry())

      const dispatcher = new Dispatcher(
        new MessageSenderMock(),
        eventEmitter,
        agentContext.dependencyManager.resolve(MessageHandlerRegistry),
        agentConfig.logger
      )

      const customProtocolMessage = new CustomProtocolMessage({
        id: '55170d10-b91f-4df2-9dcd-6deb4e806c1b',
      })
      const inboundMessageContext = new InboundMessageContext(customProtocolMessage, { agentContext })

      const firstMiddleware = jest.fn().mockImplementation(async (_, next) => next())
      const secondMiddleware = jest.fn()
      agentContext.dependencyManager.resolve(MessageHandlerRegistry).registerMessageHandlerMiddleware(firstMiddleware)
      agentContext.dependencyManager.resolve(MessageHandlerRegistry).registerMessageHandlerMiddleware(secondMiddleware)

      await dispatcher.dispatch(inboundMessageContext)

      expect(firstMiddleware).toHaveBeenCalled()
      expect(secondMiddleware).toHaveBeenCalled()

      // Verify the order of calls
      const firstMiddlewareCallOrder = firstMiddleware.mock.invocationCallOrder[0]
      const secondMiddlewareCallOrder = secondMiddleware.mock.invocationCallOrder[0]
      expect(firstMiddlewareCallOrder).toBeLessThan(secondMiddlewareCallOrder)
    })

    it('calls the middleware in the order they are registered', async () => {
      const agentContext = getAgentContext()

      // Replace the MessageHandlerRegistry instance with a empty one
      agentContext.dependencyManager.registerInstance(MessageHandlerRegistry, new MessageHandlerRegistry())

      const dispatcher = new Dispatcher(
        new MessageSenderMock(),
        eventEmitter,
        agentContext.dependencyManager.resolve(MessageHandlerRegistry),
        agentConfig.logger
      )

      const customProtocolMessage = new CustomProtocolMessage({
        id: '55170d10-b91f-4df2-9dcd-6deb4e806c1b',
      })
      const inboundMessageContext = new InboundMessageContext(customProtocolMessage, { agentContext })

      const firstMiddleware = jest.fn().mockImplementation(async (_, next) => next())
      const secondMiddleware = jest.fn()
      agentContext.dependencyManager.resolve(MessageHandlerRegistry).registerMessageHandlerMiddleware(firstMiddleware)
      agentContext.dependencyManager.resolve(MessageHandlerRegistry).registerMessageHandlerMiddleware(secondMiddleware)

      await dispatcher.dispatch(inboundMessageContext)

      expect(firstMiddleware).toHaveBeenCalled()
      expect(secondMiddleware).toHaveBeenCalled()

      // Verify the order of calls
      const firstMiddlewareCallOrder = firstMiddleware.mock.invocationCallOrder[0]
      const secondMiddlewareCallOrder = secondMiddleware.mock.invocationCallOrder[0]
      expect(firstMiddlewareCallOrder).toBeLessThan(secondMiddlewareCallOrder)
    })

    it('correctly calls the fallback message handler if no message handler is registered for the message type', async () => {
      const agentContext = getAgentContext()

      // Replace the MessageHandlerRegistry instance with a empty one
      agentContext.dependencyManager.registerInstance(MessageHandlerRegistry, new MessageHandlerRegistry())

      const dispatcher = new Dispatcher(
        new MessageSenderMock(),
        eventEmitter,
        agentContext.dependencyManager.resolve(MessageHandlerRegistry),
        agentConfig.logger
      )

      const customProtocolMessage = new CustomProtocolMessage({
        id: '55170d10-b91f-4df2-9dcd-6deb4e806c1b',
      })
      const inboundMessageContext = new InboundMessageContext(customProtocolMessage, { agentContext })

      const fallbackMessageHandler = jest.fn()
      agentContext.dependencyManager.resolve(MessageHandlerRegistry).setFallbackMessageHandler(fallbackMessageHandler)

      await dispatcher.dispatch(inboundMessageContext)

      expect(fallbackMessageHandler).toHaveBeenCalled()
    })

    it('will not call the message handler if the middleware does not call next (intercept incoming message handling)', async () => {
      const agentContext = getAgentContext()

      // Replace the MessageHandlerRegistry instance with a empty one
      agentContext.dependencyManager.registerInstance(MessageHandlerRegistry, new MessageHandlerRegistry())

      const dispatcher = new Dispatcher(
        new MessageSenderMock(),
        eventEmitter,
        agentContext.dependencyManager.resolve(MessageHandlerRegistry),
        agentConfig.logger
      )

      const customProtocolMessage = new CustomProtocolMessage({
        id: '55170d10-b91f-4df2-9dcd-6deb4e806c1b',
      })
      const inboundMessageContext = new InboundMessageContext(customProtocolMessage, { agentContext })

      const mockHandle = jest.fn()
      agentContext.dependencyManager.resolve(MessageHandlerRegistry).registerMessageHandlers([
        {
          supportedMessages: [CustomProtocolMessage],
          handle: mockHandle,
        },
      ])

      const middleware = jest.fn()
      agentContext.dependencyManager.resolve(MessageHandlerRegistry).registerMessageHandlerMiddleware(middleware)
      await dispatcher.dispatch(inboundMessageContext)
      expect(mockHandle).not.toHaveBeenCalled()

      // Not it should call it, as the middleware calls next
      middleware.mockImplementationOnce((_, next) => next())
      await dispatcher.dispatch(inboundMessageContext)
      expect(mockHandle).toHaveBeenCalled()
    })

    it('calls the message handler set by the middleware', async () => {
      const agentContext = getAgentContext()

      // Replace the MessageHandlerRegistry instance with a empty one
      agentContext.dependencyManager.registerInstance(MessageHandlerRegistry, new MessageHandlerRegistry())

      const dispatcher = new Dispatcher(
        new MessageSenderMock(),
        eventEmitter,
        agentContext.dependencyManager.resolve(MessageHandlerRegistry),
        agentConfig.logger
      )

      const customProtocolMessage = new CustomProtocolMessage({
        id: '55170d10-b91f-4df2-9dcd-6deb4e806c1b',
      })
      const inboundMessageContext = new InboundMessageContext(customProtocolMessage, { agentContext })

      const handle = jest.fn()
      const middleware = jest
        .fn()
        .mockImplementationOnce(async (inboundMessageContext: InboundMessageContext, next) => {
          inboundMessageContext.messageHandler = {
            supportedMessages: [],
            handle: handle,
          }

          await next()
        })

      agentContext.dependencyManager.resolve(MessageHandlerRegistry).registerMessageHandlerMiddleware(middleware)
      await dispatcher.dispatch(inboundMessageContext)
      expect(middleware).toHaveBeenCalled()
      expect(handle).toHaveBeenCalled()
    })

    it('sends the response message set by the middleware', async () => {
      const agentContext = getAgentContext({
        agentConfig,
      })
      const messageSenderMock = new MessageSenderMock()

      // Replace the MessageHandlerRegistry instance with a empty one
      agentContext.dependencyManager.registerInstance(MessageHandlerRegistry, new MessageHandlerRegistry())

      const dispatcher = new Dispatcher(
        messageSenderMock,
        eventEmitter,
        agentContext.dependencyManager.resolve(MessageHandlerRegistry),
        agentConfig.logger
      )

      const connectionMock = jest.fn() as unknown as ConnectionRecord

      const customProtocolMessage = new CustomProtocolMessage({
        id: '55170d10-b91f-4df2-9dcd-6deb4e806c1b',
      })
      const inboundMessageContext = new InboundMessageContext(customProtocolMessage, {
        agentContext,
        connection: connectionMock,
      })

      const middleware = jest.fn().mockImplementationOnce(async (inboundMessageContext: InboundMessageContext) => {
        // We do not call next
        inboundMessageContext.responseMessage = await getOutboundMessageContext(inboundMessageContext.agentContext, {
          message: new CustomProtocolMessage({
            id: 'static-id',
          }),
          connectionRecord: inboundMessageContext.connection,
        })
      })

      agentContext.dependencyManager.resolve(MessageHandlerRegistry).registerMessageHandlerMiddleware(middleware)
      await dispatcher.dispatch(inboundMessageContext)
      expect(middleware).toHaveBeenCalled()
      expect(messageSenderMock.sendMessage).toHaveBeenCalledWith({
        inboundMessageContext,
        agentContext,
        associatedRecord: undefined,
        connection: connectionMock,
        message: new CustomProtocolMessage({
          id: 'static-id',
        }),
        outOfBand: undefined,
        serviceParams: undefined,
        sessionId: undefined,
      })
    })
  })
})
