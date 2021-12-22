import type { Logger } from '../logger'
import type { ConnectionRecord } from '../modules/connections'
import type { InboundTransport } from '../transport'
import type { DecryptedMessageContext, PlaintextMessage, EncryptedMessage } from '../types'
import type { AgentMessage } from './AgentMessage'
import type { TransportSession } from './TransportService'

import { Lifecycle, scoped } from 'tsyringe'

import { AriesFrameworkError } from '../error'
import { ConnectionService } from '../modules/connections/services/ConnectionService'
import { ProblemReportError, ProblemReportMessage, ProblemReportReason } from '../modules/problem-reports'
import { JsonTransformer } from '../utils/JsonTransformer'
import { MessageValidator } from '../utils/MessageValidator'
import { replaceLegacyDidSovPrefixOnMessage } from '../utils/messageType'

import { AgentConfig } from './AgentConfig'
import { Dispatcher } from './Dispatcher'
import { EnvelopeService } from './EnvelopeService'
import { MessageSender } from './MessageSender'
import { TransportService } from './TransportService'
import { createOutboundMessage } from './helpers'
import { InboundMessageContext } from './models/InboundMessageContext'

@scoped(Lifecycle.ContainerScoped)
export class MessageReceiver {
  private config: AgentConfig
  private envelopeService: EnvelopeService
  private transportService: TransportService
  private messageSender: MessageSender
  private connectionService: ConnectionService
  private dispatcher: Dispatcher
  private logger: Logger
  public readonly inboundTransports: InboundTransport[] = []

  public constructor(
    config: AgentConfig,
    envelopeService: EnvelopeService,
    transportService: TransportService,
    messageSender: MessageSender,
    connectionService: ConnectionService,
    dispatcher: Dispatcher
  ) {
    this.config = config
    this.envelopeService = envelopeService
    this.transportService = transportService
    this.messageSender = messageSender
    this.connectionService = connectionService
    this.dispatcher = dispatcher
    this.logger = this.config.logger
  }

  public registerInboundTransport(inboundTransport: InboundTransport) {
    this.inboundTransports.push(inboundTransport)
  }

  /**
   * Receive and handle an inbound DIDComm message. It will decrypt the message, transform it
   * to it's corresponding message class and finally dispatch it to the dispatcher.
   *
   * @param inboundMessage the message to receive and handle
   */
  public async receiveMessage(inboundMessage: unknown, session?: TransportSession) {
    this.logger.debug(`Agent ${this.config.label} received message`)

    if (this.isPlaintextMessage(inboundMessage)) {
      await this.receivePlaintextMessage(inboundMessage)
    } else {
      await this.receiveEncryptedMessage(inboundMessage as EncryptedMessage, session)
    }
  }

  private async receivePlaintextMessage(plaintextMessage: PlaintextMessage) {
    const message = await this.transformAndValidate(plaintextMessage)
    const messageContext = new InboundMessageContext(message, {})
    await this.dispatcher.dispatch(messageContext)
  }

  private async receiveEncryptedMessage(encryptedMessage: EncryptedMessage, session?: TransportSession) {
    const { plaintextMessage, senderKey, recipientKey } = await this.decryptMessage(encryptedMessage)

    let connection: ConnectionRecord | null = null

    // Only fetch connection if recipientKey and senderKey are present (AuthCrypt)
    if (senderKey && recipientKey) {
      connection = await this.connectionService.findByVerkey(recipientKey)

      // Throw error if the recipient key (ourKey) does not match the key of the connection record
      if (connection && connection.theirKey !== null && connection.theirKey !== senderKey) {
        throw new AriesFrameworkError(
          `Inbound message senderKey '${senderKey}' is different from connection.theirKey '${connection.theirKey}'`
        )
      }
    }

    this.logger.info(
      `Received message with type '${plaintextMessage['@type']}' from connection ${connection?.id} (${connection?.theirLabel})`,
      plaintextMessage
    )

    const message = await this.transformAndValidate(plaintextMessage, connection)

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
      session.connection = connection ?? undefined
      this.transportService.saveSession(session)
    }

    const messageContext = new InboundMessageContext(message, {
      // Only make the connection available in message context if the connection is ready
      // To prevent unwanted usage of unready connections. Connections can still be retrieved from
      // Storage if the specific protocol allows an unready connection to be used.
      connection: connection?.isReady ? connection : undefined,
      senderVerkey: senderKey,
      recipientVerkey: recipientKey,
    })
    await this.dispatcher.dispatch(messageContext)
  }

  /**
   * Decrypt a message using the envelope service.
   *
   * @param message the received inbound message to decrypt
   */
  private async decryptMessage(message: EncryptedMessage): Promise<DecryptedMessageContext> {
    try {
      return await this.envelopeService.unpackMessage(message)
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
      throw new AriesFrameworkError('Invalid message received. Message should be object')
    }
    // If the message does have an @type field we assume the message is in plaintext and it is not encrypted.
    return '@type' in message
  }

  private async transformAndValidate(
    plaintextMessage: PlaintextMessage,
    connection?: ConnectionRecord | null
  ): Promise<AgentMessage> {
    let message: AgentMessage
    try {
      message = await this.transformMessage(plaintextMessage)
      await this.validateMessage(message)
    } catch (error) {
      if (connection) await this.sendProblemReportMessage(error.message, connection, plaintextMessage)
      throw error
    }
    return message
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
    const MessageClass = this.dispatcher.getMessageClassForType(messageType)

    if (!MessageClass) {
      throw new ProblemReportError(`No message class found for message type "${messageType}"`, {
        problemCode: ProblemReportReason.MessageParseFailure,
      })
    }

    // Cast the plain JSON object to specific instance of Message extended from AgentMessage
    return JsonTransformer.fromJSON(message, MessageClass)
  }

  /**
   * Validate an AgentMessage instance.
   * @param message agent message to validate
   */
  private async validateMessage(message: AgentMessage) {
    try {
      await MessageValidator.validate(message)
    } catch (error) {
      this.logger.error(`Error validating message ${message.type}`, {
        errors: error,
        message: message.toJSON(),
      })
      throw new ProblemReportError(`Error validating message ${message.type}`, {
        problemCode: ProblemReportReason.MessageParseFailure,
      })
    }
  }

  /**
   * Send the problem report message (https://didcomm.org/notification/1.0/problem-report) to the recipient.
   * @param message error message to send
   * @param connection connection to send the message to
   * @param plaintextMessage received inbound message
   */
  private async sendProblemReportMessage(
    message: string,
    connection: ConnectionRecord,
    plaintextMessage: PlaintextMessage
  ) {
    if (plaintextMessage['@type'] === ProblemReportMessage.type) {
      throw new AriesFrameworkError(message)
    }
    const problemReportMessage = new ProblemReportMessage({
      description: {
        en: message,
        code: ProblemReportReason.MessageParseFailure,
      },
    })
    problemReportMessage.setThread({
      threadId: plaintextMessage['@id'],
    })
    const outboundMessage = createOutboundMessage(connection, problemReportMessage)
    if (outboundMessage) {
      await this.messageSender.sendMessage(outboundMessage)
    }
  }
}
