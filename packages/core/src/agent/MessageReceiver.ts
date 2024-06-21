import type { DecryptedMessageContext } from './EnvelopeService'
import type { TransportSession } from './TransportService'
import type { AgentContext } from './context'
import type { ConnectionRecord } from '../modules/connections'
import type { InboundTransport } from '../transport'
import type { EncryptedMessage, PlaintextMessage } from '../types'

import { InjectionSymbols } from '../constants'
import { CredoError } from '../error'
import { Logger } from '../logger'
import { ConnectionService } from '../modules/connections'
import { ProblemReportError, ProblemReportMessage, ProblemReportReason } from '../modules/problem-reports'
import { inject, injectable } from '../plugins'
import { isValidJweStructure } from '../utils/JWE'
import { JsonTransformer } from '../utils/JsonTransformer'
import { canHandleMessageType, parseMessageType, replaceLegacyDidSovPrefixOnMessage } from '../utils/messageType'

import { AgentMessage } from './AgentMessage'
import { Dispatcher } from './Dispatcher'
import { EnvelopeService } from './EnvelopeService'
import { MessageHandlerRegistry } from './MessageHandlerRegistry'
import { MessageSender } from './MessageSender'
import { TransportService } from './TransportService'
import { AgentContextProvider } from './context'
import { InboundMessageContext, OutboundMessageContext } from './models'

@injectable()
export class MessageReceiver {
  private envelopeService: EnvelopeService
  private transportService: TransportService
  private messageSender: MessageSender
  private dispatcher: Dispatcher
  private logger: Logger
  private connectionService: ConnectionService
  private messageHandlerRegistry: MessageHandlerRegistry
  private agentContextProvider: AgentContextProvider
  private _inboundTransports: InboundTransport[] = []

  public constructor(
    envelopeService: EnvelopeService,
    transportService: TransportService,
    messageSender: MessageSender,
    connectionService: ConnectionService,
    dispatcher: Dispatcher,
    messageHandlerRegistry: MessageHandlerRegistry,
    @inject(InjectionSymbols.AgentContextProvider) agentContextProvider: AgentContextProvider,
    @inject(InjectionSymbols.Logger) logger: Logger
  ) {
    this.envelopeService = envelopeService
    this.transportService = transportService
    this.messageSender = messageSender
    this.connectionService = connectionService
    this.dispatcher = dispatcher
    this.messageHandlerRegistry = messageHandlerRegistry
    this.agentContextProvider = agentContextProvider
    this.logger = logger
    this._inboundTransports = []
  }

  public get inboundTransports() {
    return this._inboundTransports
  }

  public registerInboundTransport(inboundTransport: InboundTransport) {
    this._inboundTransports.push(inboundTransport)
  }

  public async unregisterInboundTransport(inboundTransport: InboundTransport) {
    this._inboundTransports = this._inboundTransports.filter((transport) => transport !== inboundTransport)
    await inboundTransport.stop()
  }

  /**
   * Receive and handle an inbound DIDComm message. It will determine the agent context, decrypt the message, transform it
   * to it's corresponding message class and finally dispatch it to the dispatcher.
   *
   * @param inboundMessage the message to receive and handle
   */
  public async receiveMessage(
    inboundMessage: unknown,
    {
      session,
      connection,
      contextCorrelationId,
      receivedAt,
    }: {
      session?: TransportSession
      connection?: ConnectionRecord
      contextCorrelationId?: string
      receivedAt?: Date
    } = {}
  ) {
    this.logger.debug(`Agent received message`)

    // Find agent context for the inbound message
    const agentContext = await this.agentContextProvider.getContextForInboundMessage(inboundMessage, {
      contextCorrelationId,
    })

    try {
      if (this.isEncryptedMessage(inboundMessage)) {
        await this.receiveEncryptedMessage(agentContext, inboundMessage as EncryptedMessage, session, receivedAt)
      } else if (this.isPlaintextMessage(inboundMessage)) {
        await this.receivePlaintextMessage(agentContext, inboundMessage, connection, receivedAt)
      } else {
        throw new CredoError('Unable to parse incoming message: unrecognized format')
      }
    } finally {
      // Always end the session for the agent context after handling the message.
      await agentContext.endSession()
    }
  }

  private async receivePlaintextMessage(
    agentContext: AgentContext,
    plaintextMessage: PlaintextMessage,
    connection?: ConnectionRecord,
    receivedAt?: Date
  ) {
    const message = await this.transformAndValidate(agentContext, plaintextMessage)
    const messageContext = new InboundMessageContext(message, { connection, agentContext, receivedAt })
    await this.dispatcher.dispatch(messageContext)
  }

  private async receiveEncryptedMessage(
    agentContext: AgentContext,
    encryptedMessage: EncryptedMessage,
    session?: TransportSession,
    receivedAt?: Date
  ) {
    const decryptedMessage = await this.decryptMessage(agentContext, encryptedMessage)
    const { plaintextMessage, senderKey, recipientKey } = decryptedMessage

    this.logger.info(
      `Received message with type '${plaintextMessage['@type']}', recipient key ${recipientKey?.fingerprint} and sender key ${senderKey?.fingerprint}`,
      plaintextMessage
    )

    const connection = await this.findConnectionByMessageKeys(agentContext, decryptedMessage)

    const message = await this.transformAndValidate(agentContext, plaintextMessage, connection)

    const messageContext = new InboundMessageContext(message, {
      // Only make the connection available in message context if the connection is ready
      // To prevent unwanted usage of unready connections. Connections can still be retrieved from
      // Storage if the specific protocol allows an unready connection to be used.
      connection: connection?.isReady ? connection : undefined,
      senderKey,
      recipientKey,
      agentContext,
      receivedAt,
    })

    // We want to save a session if there is a chance of returning outbound message via inbound transport.
    // That can happen when inbound message has `return_route` set to `all` or `thread`.
    // If `return_route` defines just `thread`, we decide later whether to use session according to outbound message `threadId`.
    if (senderKey && recipientKey && message.hasAnyReturnRoute() && session) {
      this.logger.debug(`Storing session for inbound message '${message.id}'`)
      const keys = {
        recipientKeys: [senderKey],
        routingKeys: [],
        senderKey: recipientKey,
      }
      session.keys = keys
      session.inboundMessage = message
      // We allow unready connections to be attached to the session as we want to be able to
      // use return routing to make connections. This is especially useful for creating connections
      // with mediators when you don't have a public endpoint yet.
      session.connectionId = connection?.id
      messageContext.sessionId = session.id
      this.transportService.saveSession(session)
    } else if (session) {
      // No need to wait for session to stay open if we're not actually going to respond to the message.
      await session.close()
    }

    await this.dispatcher.dispatch(messageContext)
  }

  /**
   * Decrypt a message using the envelope service.
   *
   * @param message the received inbound message to decrypt
   */
  private async decryptMessage(
    agentContext: AgentContext,
    message: EncryptedMessage
  ): Promise<DecryptedMessageContext> {
    try {
      return await this.envelopeService.unpackMessage(agentContext, message)
    } catch (error) {
      this.logger.error('Error while decrypting message', {
        error,
        encryptedMessage: message,
        errorMessage: error instanceof Error ? error.message : error,
      })
      throw error
    }
  }

  private isPlaintextMessage(message: unknown): message is PlaintextMessage {
    if (typeof message !== 'object' || message == null) {
      return false
    }
    // If the message has a @type field we assume the message is in plaintext and it is not encrypted.
    return '@type' in message
  }

  private isEncryptedMessage(message: unknown): message is EncryptedMessage {
    // If the message does has valid JWE structure, we can assume the message is encrypted.
    return isValidJweStructure(message)
  }

  private async transformAndValidate(
    agentContext: AgentContext,
    plaintextMessage: PlaintextMessage,
    connection?: ConnectionRecord | null
  ): Promise<AgentMessage> {
    let message: AgentMessage
    try {
      message = await this.transformMessage(plaintextMessage)
    } catch (error) {
      if (connection) await this.sendProblemReportMessage(agentContext, error.message, connection, plaintextMessage)
      throw error
    }
    return message
  }

  private async findConnectionByMessageKeys(
    agentContext: AgentContext,
    { recipientKey, senderKey }: DecryptedMessageContext
  ): Promise<ConnectionRecord | null> {
    // We only fetch connections that are sent in AuthCrypt mode
    if (!recipientKey || !senderKey) return null

    // Try to find the did records that holds the sender and recipient keys
    return this.connectionService.findByKeys(agentContext, {
      senderKey,
      recipientKey,
    })
  }

  /**
   * Transform an plaintext DIDComm message into it's corresponding message class. Will look at all message types in the registered handlers.
   *
   * @param message the plaintext message for which to transform the message in to a class instance
   */
  private async transformMessage(message: PlaintextMessage): Promise<AgentMessage> {
    // replace did:sov:BzCbsNYhMrjHiqZDTUASHg;spec prefix for message type with https://didcomm.org
    replaceLegacyDidSovPrefixOnMessage(message)

    const messageType = message['@type']
    const MessageClass = this.messageHandlerRegistry.getMessageClassForMessageType(messageType) ?? AgentMessage

    // Cast the plain JSON object to specific instance of Message extended from AgentMessage
    let messageTransformed: AgentMessage
    try {
      messageTransformed = JsonTransformer.fromJSON(message, MessageClass)
    } catch (error) {
      this.logger.error(`Error validating message ${message.type}`, {
        errors: error,
        message: JSON.stringify(message),
      })
      throw new ProblemReportError(`Error validating message ${message.type}`, {
        problemCode: ProblemReportReason.MessageParseFailure,
      })
    }
    return messageTransformed
  }

  /**
   * Send the problem report message (https://didcomm.org/notification/1.0/problem-report) to the recipient.
   * @param message error message to send
   * @param connection connection to send the message to
   * @param plaintextMessage received inbound message
   */
  private async sendProblemReportMessage(
    agentContext: AgentContext,
    message: string,
    connection: ConnectionRecord,
    plaintextMessage: PlaintextMessage
  ) {
    const messageType = parseMessageType(plaintextMessage['@type'])
    if (canHandleMessageType(ProblemReportMessage, messageType)) {
      throw new CredoError(`Not sending problem report in response to problem report: ${message}`)
    }
    const problemReportMessage = new ProblemReportMessage({
      description: {
        en: message,
        code: ProblemReportReason.MessageParseFailure,
      },
    })
    problemReportMessage.setThread({
      parentThreadId: plaintextMessage['@id'],
    })
    const outboundMessageContext = new OutboundMessageContext(problemReportMessage, { agentContext, connection })
    if (outboundMessageContext) {
      await this.messageSender.sendMessage(outboundMessageContext)
    }
  }
}
