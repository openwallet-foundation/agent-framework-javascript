import type { AgentMessage } from './AgentMessage'
import type { AgentMessageProcessedEvent } from './Events'
import type { MessageHandlerMiddleware } from './MessageHandlerMiddleware'
import type { InboundMessageContext } from './models/InboundMessageContext'

import { InjectionSymbols } from '../constants'
import { CredoError } from '../error'
import { Logger } from '../logger'
import { ProblemReportError, ProblemReportReason } from '../modules/problem-reports'
import { injectable, inject } from '../plugins'
import { canHandleMessageType, parseMessageType } from '../utils/messageType'

import { ProblemReportMessage } from './../modules/problem-reports/messages/ProblemReportMessage'
import { EventEmitter } from './EventEmitter'
import { AgentEventTypes } from './Events'
import { MessageHandlerMiddlewareRunner } from './MessageHandlerMiddleware'
import { MessageHandlerRegistry } from './MessageHandlerRegistry'
import { MessageSender } from './MessageSender'
import { OutboundMessageContext } from './models'

@injectable()
class Dispatcher {
  private messageHandlerRegistry: MessageHandlerRegistry
  private messageSender: MessageSender
  private eventEmitter: EventEmitter
  private logger: Logger

  public constructor(
    messageSender: MessageSender,
    eventEmitter: EventEmitter,
    messageHandlerRegistry: MessageHandlerRegistry,
    @inject(InjectionSymbols.Logger) logger: Logger
  ) {
    this.messageSender = messageSender
    this.eventEmitter = eventEmitter
    this.messageHandlerRegistry = messageHandlerRegistry
    this.logger = logger
  }

  private defaultHandlerMiddleware: MessageHandlerMiddleware = async (inboundMessageContext, next) => {
    let messageHandler = inboundMessageContext.messageHandler

    if (!messageHandler && inboundMessageContext.agentContext.dependencyManager.fallbackMessageHandler) {
      messageHandler = {
        supportedMessages: [],
        handle: inboundMessageContext.agentContext.dependencyManager.fallbackMessageHandler,
      }
    }

    if (!messageHandler) {
      throw new ProblemReportError(
        `Error handling message ${inboundMessageContext.message.id} with type ${inboundMessageContext.message.type}. The message type is not supported`,
        {
          problemCode: ProblemReportReason.MessageParseFailure,
        }
      )
    }

    const outboundMessage = await messageHandler.handle(inboundMessageContext)
    if (outboundMessage) {
      inboundMessageContext.setResponseMessage(outboundMessage)
    }

    await next()
  }

  public async dispatch(messageContext: InboundMessageContext): Promise<void> {
    const { agentContext, connection, senderKey, recipientKey, message } = messageContext

    // Set default handler if available, middleware can still override the message handler
    const messageHandler = this.messageHandlerRegistry.getHandlerForMessageType(message.type)
    if (messageHandler) {
      messageContext.setMessageHandler(messageHandler)
    }

    let outboundMessage: OutboundMessageContext<AgentMessage> | undefined

    try {
      const middlewares = [...agentContext.dependencyManager.messageHandlerMiddlewares, this.defaultHandlerMiddleware]
      await MessageHandlerMiddlewareRunner.run(middlewares, messageContext)

      outboundMessage = messageContext.responseMessage
    } catch (error) {
      const problemReportMessage = error.problemReport

      if (problemReportMessage instanceof ProblemReportMessage && messageContext.connection) {
        const messageType = parseMessageType(messageContext.message.type)
        if (canHandleMessageType(ProblemReportMessage, messageType)) {
          throw new CredoError(`Not sending problem report in response to problem report: ${message}`)
        }

        const { protocolUri: problemReportProtocolUri } = parseMessageType(problemReportMessage.type)
        const { protocolUri: inboundProtocolUri } = parseMessageType(messageContext.message.type)

        // If the inbound protocol uri is the same as the problem report protocol uri, we can see the interaction as the same thread
        // However if it is no the same we should see it as a new thread, where the inbound message `@id` is the parentThreadId
        if (inboundProtocolUri === problemReportProtocolUri) {
          problemReportMessage.setThread({
            threadId: message.threadId,
          })
        } else {
          problemReportMessage.setThread({
            parentThreadId: message.id,
          })
        }

        outboundMessage = new OutboundMessageContext(problemReportMessage, {
          agentContext,
          connection: messageContext.connection,
          inboundMessageContext: messageContext,
        })
      } else {
        this.logger.error(`Error handling message with type ${message.type}`, {
          message: message.toJSON(),
          error,
          senderKey: senderKey?.fingerprint,
          recipientKey: recipientKey?.fingerprint,
          connectionId: connection?.id,
        })

        throw error
      }
    }

    if (outboundMessage) {
      // set the inbound message context, if not already defined
      if (!outboundMessage.inboundMessageContext) {
        outboundMessage.inboundMessageContext = messageContext
      }

      await this.messageSender.sendMessage(outboundMessage)
    }

    // Emit event that allows to hook into received messages
    this.eventEmitter.emit<AgentMessageProcessedEvent>(agentContext, {
      type: AgentEventTypes.AgentMessageProcessed,
      payload: {
        message,
        connection,
        receivedAt: messageContext.receivedAt,
      },
    })
  }
}

export { Dispatcher }
