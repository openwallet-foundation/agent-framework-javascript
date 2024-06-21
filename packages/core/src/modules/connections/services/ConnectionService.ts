import type { AgentContext } from '../../../agent'
import type { AgentMessage } from '../../../agent/AgentMessage'
import type { InboundMessageContext } from '../../../agent/models/InboundMessageContext'
import type { Query, QueryOptions } from '../../../storage/StorageService'
import type { AckMessage } from '../../common'
import type { OutOfBandDidCommService } from '../../oob/domain/OutOfBandDidCommService'
import type { OutOfBandRecord } from '../../oob/repository'
import type { ConnectionStateChangedEvent } from '../ConnectionEvents'
import type { ConnectionProblemReportMessage } from '../messages'
import type { ConnectionType } from '../models'
import type { ConnectionRecordProps } from '../repository/ConnectionRecord'

import { firstValueFrom, ReplaySubject } from 'rxjs'
import { first, map, timeout } from 'rxjs/operators'

import { EventEmitter } from '../../../agent/EventEmitter'
import { filterContextCorrelationId } from '../../../agent/Events'
import { InjectionSymbols } from '../../../constants'
import { Key } from '../../../crypto'
import { signData, unpackAndVerifySignatureDecorator } from '../../../decorators/signature/SignatureDecoratorUtils'
import { CredoError } from '../../../error'
import { Logger } from '../../../logger'
import { inject, injectable } from '../../../plugins'
import { JsonTransformer } from '../../../utils/JsonTransformer'
import { indyDidFromPublicKeyBase58 } from '../../../utils/did'
import { DidKey, IndyAgentService } from '../../dids'
import { DidDocumentRole } from '../../dids/domain/DidDocumentRole'
import { didKeyToVerkey } from '../../dids/helpers'
import { didDocumentJsonToNumAlgo1Did } from '../../dids/methods/peer/peerDidNumAlgo1'
import { DidRecord, DidRepository } from '../../dids/repository'
import { DidRecordMetadataKeys } from '../../dids/repository/didRecordMetadataTypes'
import { OutOfBandService } from '../../oob/OutOfBandService'
import { OutOfBandRole } from '../../oob/domain/OutOfBandRole'
import { OutOfBandState } from '../../oob/domain/OutOfBandState'
import { InvitationType } from '../../oob/messages'
import { OutOfBandRepository } from '../../oob/repository'
import { OutOfBandRecordMetadataKeys } from '../../oob/repository/outOfBandRecordMetadataTypes'
import { ConnectionEventTypes } from '../ConnectionEvents'
import { ConnectionProblemReportError, ConnectionProblemReportReason } from '../errors'
import { ConnectionRequestMessage, ConnectionResponseMessage, TrustPingMessage } from '../messages'
import {
  authenticationTypes,
  Connection,
  DidDoc,
  DidExchangeRole,
  DidExchangeState,
  Ed25119Sig2018,
  HandshakeProtocol,
  ReferencedAuthentication,
} from '../models'
import { ConnectionRecord } from '../repository/ConnectionRecord'
import { ConnectionRepository } from '../repository/ConnectionRepository'

import { assertNoCreatedDidExistsForKeys, convertToNewDidDocument } from './helpers'

export interface ConnectionRequestParams {
  label?: string
  imageUrl?: string
  alias?: string
  routing: Routing
  autoAcceptConnection?: boolean
}

@injectable()
export class ConnectionService {
  private connectionRepository: ConnectionRepository
  private didRepository: DidRepository
  private eventEmitter: EventEmitter
  private logger: Logger

  public constructor(
    @inject(InjectionSymbols.Logger) logger: Logger,
    connectionRepository: ConnectionRepository,
    didRepository: DidRepository,
    eventEmitter: EventEmitter
  ) {
    this.connectionRepository = connectionRepository
    this.didRepository = didRepository
    this.eventEmitter = eventEmitter
    this.logger = logger
  }

  /**
   * Create a connection request message for a given out-of-band.
   *
   * @param outOfBandRecord out-of-band record for which to create a connection request
   * @param config config for creation of connection request
   * @returns outbound message containing connection request
   */
  public async createRequest(
    agentContext: AgentContext,
    outOfBandRecord: OutOfBandRecord,
    config: ConnectionRequestParams
  ): Promise<ConnectionProtocolMsgReturnType<ConnectionRequestMessage>> {
    this.logger.debug(`Create message ${ConnectionRequestMessage.type.messageTypeUri} start`, outOfBandRecord)
    outOfBandRecord.assertRole(OutOfBandRole.Receiver)
    outOfBandRecord.assertState(OutOfBandState.PrepareResponse)

    // TODO check there is no connection record for particular oob record

    const { outOfBandInvitation } = outOfBandRecord

    const { mediatorId } = config.routing
    const didDoc = this.createDidDoc(config.routing)

    // TODO: We should store only one did that we'll use to send the request message with success.
    // We take just the first one for now.
    const [invitationDid] = outOfBandInvitation.invitationDids

    const { did: peerDid } = await this.createDid(agentContext, {
      role: DidDocumentRole.Created,
      didDoc,
    })

    const { label, imageUrl } = config
    const connectionRequest = new ConnectionRequestMessage({
      label: label ?? agentContext.config.label,
      did: didDoc.id,
      didDoc,
      imageUrl: imageUrl ?? agentContext.config.connectionImageUrl,
    })

    connectionRequest.setThread({
      threadId: connectionRequest.threadId,
      parentThreadId: outOfBandRecord.outOfBandInvitation.id,
    })

    const connectionRecord = await this.createConnection(agentContext, {
      protocol: HandshakeProtocol.Connections,
      role: DidExchangeRole.Requester,
      state: DidExchangeState.InvitationReceived,
      theirLabel: outOfBandInvitation.label,
      alias: config?.alias,
      did: peerDid,
      mediatorId,
      autoAcceptConnection: config?.autoAcceptConnection,
      outOfBandId: outOfBandRecord.id,
      invitationDid,
      imageUrl: outOfBandInvitation.imageUrl,
      threadId: connectionRequest.threadId,
    })

    await this.updateState(agentContext, connectionRecord, DidExchangeState.RequestSent)

    return {
      connectionRecord,
      message: connectionRequest,
    }
  }

  public async processRequest(
    messageContext: InboundMessageContext<ConnectionRequestMessage>,
    outOfBandRecord: OutOfBandRecord
  ): Promise<ConnectionRecord> {
    this.logger.debug(`Process message ${ConnectionRequestMessage.type.messageTypeUri} start`, {
      message: messageContext.message,
    })
    outOfBandRecord.assertRole(OutOfBandRole.Sender)
    outOfBandRecord.assertState(OutOfBandState.AwaitResponse)

    // TODO check there is no connection record for particular oob record

    const { message } = messageContext
    if (!message.connection.didDoc) {
      throw new ConnectionProblemReportError('Public DIDs are not supported yet', {
        problemCode: ConnectionProblemReportReason.RequestNotAccepted,
      })
    }

    const { did: peerDid } = await this.createDid(messageContext.agentContext, {
      role: DidDocumentRole.Received,
      didDoc: message.connection.didDoc,
    })

    const connectionRecord = await this.createConnection(messageContext.agentContext, {
      protocol: HandshakeProtocol.Connections,
      role: DidExchangeRole.Responder,
      state: DidExchangeState.RequestReceived,
      alias: outOfBandRecord.alias,
      theirLabel: message.label,
      imageUrl: message.imageUrl,
      outOfBandId: outOfBandRecord.id,
      theirDid: peerDid,
      threadId: message.threadId,
      mediatorId: outOfBandRecord.mediatorId,
      autoAcceptConnection: outOfBandRecord.autoAcceptConnection,
    })

    await this.connectionRepository.update(messageContext.agentContext, connectionRecord)
    this.emitStateChangedEvent(messageContext.agentContext, connectionRecord, null)

    this.logger.debug(`Process message ${ConnectionRequestMessage.type.messageTypeUri} end`, connectionRecord)
    return connectionRecord
  }

  /**
   * Create a connection response message for the connection with the specified connection id.
   *
   * @param connectionRecord the connection for which to create a connection response
   * @returns outbound message containing connection response
   */
  public async createResponse(
    agentContext: AgentContext,
    connectionRecord: ConnectionRecord,
    outOfBandRecord: OutOfBandRecord,
    routing?: Routing
  ): Promise<ConnectionProtocolMsgReturnType<ConnectionResponseMessage>> {
    this.logger.debug(`Create message ${ConnectionResponseMessage.type.messageTypeUri} start`, connectionRecord)
    connectionRecord.assertState(DidExchangeState.RequestReceived)
    connectionRecord.assertRole(DidExchangeRole.Responder)

    let didDoc: DidDoc
    if (routing) {
      didDoc = this.createDidDoc(routing)
    } else if (outOfBandRecord.outOfBandInvitation.getInlineServices().length > 0) {
      didDoc = this.createDidDocFromOutOfBandDidCommServices(outOfBandRecord.outOfBandInvitation.getInlineServices())
    } else {
      // We don't support using a did from the OOB invitation services currently, in this case we always pass routing to this method
      throw new CredoError(
        'No routing provided, and no inline services found in out of band invitation. When using did services in out of band invitation, make sure to provide routing information for rotation.'
      )
    }

    const { did: peerDid } = await this.createDid(agentContext, {
      role: DidDocumentRole.Created,
      didDoc,
    })

    const connection = new Connection({
      did: didDoc.id,
      didDoc,
    })

    const connectionJson = JsonTransformer.toJSON(connection)

    if (!connectionRecord.threadId) {
      throw new CredoError(`Connection record with id ${connectionRecord.id} does not have a thread id`)
    }

    const signingKey = Key.fromFingerprint(outOfBandRecord.getTags().recipientKeyFingerprints[0]).publicKeyBase58

    const connectionResponse = new ConnectionResponseMessage({
      threadId: connectionRecord.threadId,
      connectionSig: await signData(connectionJson, agentContext.wallet, signingKey),
    })

    connectionRecord.did = peerDid
    await this.updateState(agentContext, connectionRecord, DidExchangeState.ResponseSent)

    this.logger.debug(`Create message ${ConnectionResponseMessage.type.messageTypeUri} end`, {
      connectionRecord,
      message: connectionResponse,
    })
    return {
      connectionRecord,
      message: connectionResponse,
    }
  }

  /**
   * Process a received connection response message. This will not accept the connection request
   * or send a connection acknowledgement message. It will only update the existing connection record
   * with all the new information from the connection response message. Use {@link ConnectionService.createTrustPing}
   * after calling this function to create a trust ping message.
   *
   * @param messageContext the message context containing a connection response message
   * @returns updated connection record
   */
  public async processResponse(
    messageContext: InboundMessageContext<ConnectionResponseMessage>,
    outOfBandRecord: OutOfBandRecord
  ): Promise<ConnectionRecord> {
    this.logger.debug(`Process message ${ConnectionResponseMessage.type.messageTypeUri} start`, {
      message: messageContext.message,
    })
    const { connection: connectionRecord, message, recipientKey, senderKey } = messageContext

    if (!recipientKey || !senderKey) {
      throw new CredoError('Unable to process connection request without senderKey or recipientKey')
    }

    if (!connectionRecord) {
      throw new CredoError('No connection record in message context.')
    }

    connectionRecord.assertState(DidExchangeState.RequestSent)
    connectionRecord.assertRole(DidExchangeRole.Requester)

    let connectionJson = null
    try {
      connectionJson = await unpackAndVerifySignatureDecorator(
        message.connectionSig,
        messageContext.agentContext.wallet
      )
    } catch (error) {
      if (error instanceof CredoError) {
        throw new ConnectionProblemReportError(error.message, {
          problemCode: ConnectionProblemReportReason.ResponseProcessingError,
        })
      }
      throw error
    }

    const connection = JsonTransformer.fromJSON(connectionJson, Connection)

    // Per the Connection RFC we must check if the key used to sign the connection~sig is the same key
    // as the recipient key(s) in the connection invitation message
    const signerVerkey = message.connectionSig.signer

    const invitationKey = Key.fromFingerprint(outOfBandRecord.getTags().recipientKeyFingerprints[0]).publicKeyBase58

    if (signerVerkey !== invitationKey) {
      throw new ConnectionProblemReportError(
        `Connection object in connection response message is not signed with same key as recipient key in invitation expected='${invitationKey}' received='${signerVerkey}'`,
        { problemCode: ConnectionProblemReportReason.ResponseNotAccepted }
      )
    }

    if (!connection.didDoc) {
      throw new CredoError('DID Document is missing.')
    }

    const { did: peerDid } = await this.createDid(messageContext.agentContext, {
      role: DidDocumentRole.Received,
      didDoc: connection.didDoc,
    })

    connectionRecord.theirDid = peerDid
    connectionRecord.threadId = message.threadId

    await this.updateState(messageContext.agentContext, connectionRecord, DidExchangeState.ResponseReceived)
    return connectionRecord
  }

  /**
   * Create a trust ping message for the connection with the specified connection id.
   *
   * By default a trust ping message should elicit a response. If this is not desired the
   * `config.responseRequested` property can be set to `false`.
   *
   * @param connectionRecord the connection for which to create a trust ping message
   * @param config the config for the trust ping message
   * @returns outbound message containing trust ping message
   */
  public async createTrustPing(
    agentContext: AgentContext,
    connectionRecord: ConnectionRecord,
    config: { responseRequested?: boolean; comment?: string } = {}
  ): Promise<ConnectionProtocolMsgReturnType<TrustPingMessage>> {
    connectionRecord.assertState([DidExchangeState.ResponseReceived, DidExchangeState.Completed])

    // TODO:
    //  - create ack message
    //  - maybe this shouldn't be in the connection service?
    const trustPing = new TrustPingMessage(config)

    // Only update connection record and emit an event if the state is not already 'Complete'
    if (connectionRecord.state !== DidExchangeState.Completed) {
      await this.updateState(agentContext, connectionRecord, DidExchangeState.Completed)
    }

    return {
      connectionRecord,
      message: trustPing,
    }
  }

  /**
   * Process a received ack message. This will update the state of the connection
   * to Completed if this is not already the case.
   *
   * @param messageContext the message context containing an ack message
   * @returns updated connection record
   */
  public async processAck(messageContext: InboundMessageContext<AckMessage>): Promise<ConnectionRecord> {
    const { connection, recipientKey } = messageContext

    if (!connection) {
      throw new CredoError(
        `Unable to process connection ack: connection for recipient key ${recipientKey?.fingerprint} not found`
      )
    }

    // TODO: This is better addressed in a middleware of some kind because
    // any message can transition the state to complete, not just an ack or trust ping
    if (connection.state === DidExchangeState.ResponseSent && connection.role === DidExchangeRole.Responder) {
      await this.updateState(messageContext.agentContext, connection, DidExchangeState.Completed)
    }

    return connection
  }

  /**
   * Process a received {@link ProblemReportMessage}.
   *
   * @param messageContext The message context containing a connection problem report message
   * @returns connection record associated with the connection problem report message
   *
   */
  public async processProblemReport(
    messageContext: InboundMessageContext<ConnectionProblemReportMessage>
  ): Promise<ConnectionRecord> {
    const { message: connectionProblemReportMessage, recipientKey, senderKey } = messageContext

    this.logger.debug(`Processing connection problem report for verkey ${recipientKey?.fingerprint}`)

    if (!recipientKey) {
      throw new CredoError('Unable to process connection problem report without recipientKey')
    }

    const ourDidRecord = await this.didRepository.findCreatedDidByRecipientKey(
      messageContext.agentContext,
      recipientKey
    )
    if (!ourDidRecord) {
      throw new CredoError(
        `Unable to process connection problem report: created did record for recipient key ${recipientKey.fingerprint} not found`
      )
    }

    const connectionRecord = await this.findByOurDid(messageContext.agentContext, ourDidRecord.did)
    if (!connectionRecord) {
      throw new CredoError(
        `Unable to process connection problem report: connection for recipient key ${recipientKey.fingerprint} not found`
      )
    }

    const theirDidRecord =
      connectionRecord.theirDid &&
      (await this.didRepository.findReceivedDid(messageContext.agentContext, connectionRecord.theirDid))
    if (!theirDidRecord) {
      throw new CredoError(`Received did record for did ${connectionRecord.theirDid} not found.`)
    }

    if (senderKey) {
      if (!theirDidRecord?.getTags().recipientKeyFingerprints?.includes(senderKey.fingerprint)) {
        throw new CredoError("Sender key doesn't match key of connection record")
      }
    }

    connectionRecord.errorMessage = `${connectionProblemReportMessage.description.code} : ${connectionProblemReportMessage.description.en}`
    await this.update(messageContext.agentContext, connectionRecord)

    // Marking connection as abandoned in case of problem report from issuer agent
    // TODO: Can be conditionally abandoned - Like if another user is scanning already used connection invite where issuer will send invite-already-used problem code.
    await this.updateState(messageContext.agentContext, connectionRecord, DidExchangeState.Abandoned)

    return connectionRecord
  }

  /**
   * Assert that an inbound message either has a connection associated with it,
   * or has everything correctly set up for connection-less exchange (optionally with out of band)
   *
   * @param messageContext - the inbound message context
   */
  public async assertConnectionOrOutOfBandExchange(
    messageContext: InboundMessageContext,
    {
      lastSentMessage,
      lastReceivedMessage,
      expectedConnectionId,
    }: {
      lastSentMessage?: AgentMessage | null
      lastReceivedMessage?: AgentMessage | null
      expectedConnectionId?: string
    } = {}
  ) {
    const { connection, message } = messageContext

    if (expectedConnectionId && !connection) {
      throw new CredoError(
        `Expected incoming message to be from connection ${expectedConnectionId} but no connection found.`
      )
    }
    if (expectedConnectionId && connection?.id !== expectedConnectionId) {
      throw new CredoError(
        `Expected incoming message to be from connection ${expectedConnectionId} but connection is ${connection?.id}.`
      )
    }

    // Check if we have a ready connection. Verification is already done somewhere else. Return
    if (connection) {
      connection.assertReady()
      this.logger.debug(`Processing message with id ${message.id} and connection id ${connection.id}`, {
        type: message.type,
      })
    } else {
      this.logger.debug(`Processing connection-less message with id ${message.id}`, {
        type: message.type,
      })

      const recipientKey = messageContext.recipientKey && messageContext.recipientKey.publicKeyBase58
      const senderKey = messageContext.senderKey && messageContext.senderKey.publicKeyBase58

      // set theirService to the value of lastReceivedMessage.service
      let theirService =
        messageContext.message?.service?.resolvedDidCommService ?? lastReceivedMessage?.service?.resolvedDidCommService
      let ourService = lastSentMessage?.service?.resolvedDidCommService

      // 1. check if there's an oob record associated.
      const outOfBandRepository = messageContext.agentContext.dependencyManager.resolve(OutOfBandRepository)
      const outOfBandService = messageContext.agentContext.dependencyManager.resolve(OutOfBandService)
      const outOfBandRecord = await outOfBandRepository.findSingleByQuery(messageContext.agentContext, {
        invitationRequestsThreadIds: [message.threadId],
      })

      // If we have an out of band record, we can extract the service for our/the other party from the oob record
      if (outOfBandRecord?.role === OutOfBandRole.Sender) {
        ourService = await outOfBandService.getResolvedServiceForOutOfBandServices(
          messageContext.agentContext,
          outOfBandRecord.outOfBandInvitation.getServices()
        )
      } else if (outOfBandRecord?.role === OutOfBandRole.Receiver) {
        theirService = await outOfBandService.getResolvedServiceForOutOfBandServices(
          messageContext.agentContext,
          outOfBandRecord.outOfBandInvitation.getServices()
        )
      }

      // theirService can be null when we receive an oob invitation and process the message.
      // In this case there MUST be an oob record, otherwise there is no way for us to reply
      // to the message
      if (!theirService && !outOfBandRecord) {
        throw new CredoError(
          'No service for incoming connection-less message and no associated out of band record found.'
        )
      }

      // ourService can be null when we receive an oob invitation or legacy connectionless message and process the message.
      // In this case lastSentMessage and lastReceivedMessage MUST be null, because there shouldn't be any previous exchange
      if (!ourService && (lastReceivedMessage || lastSentMessage)) {
        throw new CredoError(
          'No keys on our side to use for encrypting messages, and previous messages found (in which case our keys MUST also be present).'
        )
      }

      // If the message is unpacked or AuthCrypt, there cannot be any previous exchange (this must be the first message).
      // All exchange after the first unpacked oob exchange MUST be encrypted.
      if ((!senderKey || !recipientKey) && (lastSentMessage || lastReceivedMessage)) {
        throw new CredoError(
          'Incoming message must have recipientKey and senderKey (so cannot be AuthCrypt or unpacked) if there are lastSentMessage or lastReceivedMessage.'
        )
      }

      // Check if recipientKey is in ourService
      if (recipientKey && ourService) {
        const recipientKeyFound = ourService.recipientKeys.some((key) => key.publicKeyBase58 === recipientKey)
        if (!recipientKeyFound) {
          throw new CredoError(`Recipient key ${recipientKey} not found in our service`)
        }
      }

      // Check if senderKey is in theirService
      if (senderKey && theirService) {
        const senderKeyFound = theirService.recipientKeys.some((key) => key.publicKeyBase58 === senderKey)
        if (!senderKeyFound) {
          throw new CredoError(`Sender key ${senderKey} not found in their service.`)
        }
      }
    }
  }

  /**
   * If knownConnectionId is passed, it will compare the incoming connection id with the knownConnectionId, and skip the other validation.
   *
   * If no known connection id is passed, it asserts that the incoming message is in response to an attached request message to an out of band invitation.
   * If is the case, and the state of the out of band record is still await response, the state will be updated to done
   *
   */
  public async matchIncomingMessageToRequestMessageInOutOfBandExchange(
    messageContext: InboundMessageContext,
    { expectedConnectionId }: { expectedConnectionId?: string }
  ) {
    if (expectedConnectionId && messageContext.connection?.id !== expectedConnectionId) {
      throw new CredoError(
        `Expecting incoming message to have connection ${expectedConnectionId}, but incoming connection is ${
          messageContext.connection?.id ?? 'undefined'
        }`
      )
    }

    const outOfBandRepository = messageContext.agentContext.dependencyManager.resolve(OutOfBandRepository)
    const outOfBandInvitationId = messageContext.message.thread?.parentThreadId

    // Find the out of band record that is associated with this request
    const outOfBandRecord = await outOfBandRepository.findSingleByQuery(messageContext.agentContext, {
      invitationId: outOfBandInvitationId,
      role: OutOfBandRole.Sender,
      invitationRequestsThreadIds: [messageContext.message.threadId],
    })

    // There is no out of band record
    if (!outOfBandRecord) {
      throw new CredoError(
        `No out of band record found for credential request message with thread ${messageContext.message.threadId}, out of band invitation id ${outOfBandInvitationId} and role ${OutOfBandRole.Sender}`
      )
    }

    const legacyInvitationMetadata = outOfBandRecord.metadata.get(OutOfBandRecordMetadataKeys.LegacyInvitation)

    // If the original invitation was a legacy connectionless invitation, it's okay if the message does not have a pthid.
    if (
      legacyInvitationMetadata?.legacyInvitationType !== InvitationType.Connectionless &&
      outOfBandRecord.outOfBandInvitation.id !== outOfBandInvitationId
    ) {
      throw new CredoError(
        'Response messages to out of band invitation requests MUST have a parent thread id that matches the out of band invitation id.'
      )
    }

    // This should not happen, as it is not allowed to create reusable out of band invitations with attached messages
    // But should that implementation change, we at least cover it here.
    if (outOfBandRecord.reusable) {
      throw new CredoError('Receiving messages in response to reusable out of band invitations is not supported.')
    }

    if (outOfBandRecord.state === OutOfBandState.Done) {
      if (!messageContext.connection) {
        throw new CredoError(
          "Can't find connection associated with incoming message, while out of band state is done. State must be await response if no connection has been created"
        )
      }
      if (messageContext.connection.outOfBandId !== outOfBandRecord.id) {
        throw new CredoError(
          'Connection associated with incoming message is not associated with the out of band invitation containing the attached message.'
        )
      }

      // We're good to go. Connection was created and points to the correct out of band record. And the message is in response to an attached request message from the oob invitation.
    } else if (outOfBandRecord.state === OutOfBandState.AwaitResponse) {
      // We're good to go. Waiting for a response. And the message is in response to an attached request message from the oob invitation.

      // Now that we have received the first response message to our out of band invitation, we mark the out of band record as done
      outOfBandRecord.state = OutOfBandState.Done
      await outOfBandRepository.update(messageContext.agentContext, outOfBandRecord)
    } else {
      throw new CredoError(`Out of band record is in incorrect state ${outOfBandRecord.state}`)
    }
  }

  public async updateState(agentContext: AgentContext, connectionRecord: ConnectionRecord, newState: DidExchangeState) {
    const previousState = connectionRecord.state
    connectionRecord.state = newState
    await this.connectionRepository.update(agentContext, connectionRecord)

    this.emitStateChangedEvent(agentContext, connectionRecord, previousState)
  }

  private emitStateChangedEvent(
    agentContext: AgentContext,
    connectionRecord: ConnectionRecord,
    previousState: DidExchangeState | null
  ) {
    this.eventEmitter.emit<ConnectionStateChangedEvent>(agentContext, {
      type: ConnectionEventTypes.ConnectionStateChanged,
      payload: {
        // Connection record in event should be static
        connectionRecord: connectionRecord.clone(),
        previousState,
      },
    })
  }

  public update(agentContext: AgentContext, connectionRecord: ConnectionRecord) {
    return this.connectionRepository.update(agentContext, connectionRecord)
  }

  /**
   * Retrieve all connections records
   *
   * @returns List containing all connection records
   */
  public getAll(agentContext: AgentContext) {
    return this.connectionRepository.getAll(agentContext)
  }

  /**
   * Retrieve a connection record by id
   *
   * @param connectionId The connection record id
   * @throws {RecordNotFoundError} If no record is found
   * @return The connection record
   *
   */
  public getById(agentContext: AgentContext, connectionId: string): Promise<ConnectionRecord> {
    return this.connectionRepository.getById(agentContext, connectionId)
  }

  /**
   * Find a connection record by id
   *
   * @param connectionId the connection record id
   * @returns The connection record or null if not found
   */
  public findById(agentContext: AgentContext, connectionId: string): Promise<ConnectionRecord | null> {
    return this.connectionRepository.findById(agentContext, connectionId)
  }

  /**
   * Delete a connection record by id
   *
   * @param connectionId the connection record id
   */
  public async deleteById(agentContext: AgentContext, connectionId: string) {
    const connectionRecord = await this.getById(agentContext, connectionId)
    return this.connectionRepository.delete(agentContext, connectionRecord)
  }

  public async findByDids(agentContext: AgentContext, query: { ourDid: string; theirDid: string }) {
    return this.connectionRepository.findByDids(agentContext, query)
  }

  /**
   * Retrieve a connection record by thread id
   *
   * @param threadId The thread id
   * @throws {RecordNotFoundError} If no record is found
   * @throws {RecordDuplicateError} If multiple records are found
   * @returns The connection record
   */
  public async getByThreadId(agentContext: AgentContext, threadId: string): Promise<ConnectionRecord> {
    return this.connectionRepository.getByThreadId(agentContext, threadId)
  }

  public async getByRoleAndThreadId(agentContext: AgentContext, role: DidExchangeRole, threadId: string) {
    return this.connectionRepository.getByRoleAndThreadId(agentContext, role, threadId)
  }

  public async findByTheirDid(agentContext: AgentContext, theirDid: string): Promise<ConnectionRecord | null> {
    return this.connectionRepository.findSingleByQuery(agentContext, { theirDid })
  }

  public async findByOurDid(agentContext: AgentContext, ourDid: string): Promise<ConnectionRecord | null> {
    return this.connectionRepository.findSingleByQuery(agentContext, { did: ourDid })
  }

  public async findAllByOutOfBandId(agentContext: AgentContext, outOfBandId: string) {
    return this.connectionRepository.findByQuery(agentContext, { outOfBandId })
  }

  public async findAllByConnectionTypes(agentContext: AgentContext, connectionTypes: Array<ConnectionType | string>) {
    return this.connectionRepository.findByQuery(agentContext, { connectionTypes })
  }

  public async findByInvitationDid(agentContext: AgentContext, invitationDid: string) {
    return this.connectionRepository.findByQuery(agentContext, { invitationDid })
  }

  public async findByKeys(
    agentContext: AgentContext,
    { senderKey, recipientKey }: { senderKey: Key; recipientKey: Key }
  ) {
    const theirDidRecord = await this.didRepository.findReceivedDidByRecipientKey(agentContext, senderKey)
    if (theirDidRecord) {
      const ourDidRecord = await this.didRepository.findCreatedDidByRecipientKey(agentContext, recipientKey)
      if (ourDidRecord) {
        const connectionRecord = await this.findByDids(agentContext, {
          ourDid: ourDidRecord.did,
          theirDid: theirDidRecord.did,
        })
        if (connectionRecord && connectionRecord.isReady) return connectionRecord
      }
    }

    this.logger.debug(
      `No connection record found for encrypted message with recipient key ${recipientKey.fingerprint} and sender key ${senderKey.fingerprint}`
    )

    return null
  }

  public async findAllByQuery(
    agentContext: AgentContext,
    query: Query<ConnectionRecord>,
    queryOptions?: QueryOptions
  ): Promise<ConnectionRecord[]> {
    return this.connectionRepository.findByQuery(agentContext, query, queryOptions)
  }

  public async createConnection(agentContext: AgentContext, options: ConnectionRecordProps): Promise<ConnectionRecord> {
    const connectionRecord = new ConnectionRecord(options)
    await this.connectionRepository.save(agentContext, connectionRecord)
    return connectionRecord
  }

  public async addConnectionType(agentContext: AgentContext, connectionRecord: ConnectionRecord, type: string) {
    const connectionTypes = connectionRecord.connectionTypes || []
    connectionRecord.connectionTypes = [type, ...connectionTypes]
    await this.update(agentContext, connectionRecord)
  }

  public async removeConnectionType(agentContext: AgentContext, connectionRecord: ConnectionRecord, type: string) {
    connectionRecord.connectionTypes = connectionRecord.connectionTypes.filter((value) => value !== type)
    await this.update(agentContext, connectionRecord)
  }

  public async getConnectionTypes(connectionRecord: ConnectionRecord) {
    return connectionRecord.connectionTypes || []
  }

  private async createDid(agentContext: AgentContext, { role, didDoc }: { role: DidDocumentRole; didDoc: DidDoc }) {
    // Convert the legacy did doc to a new did document
    const didDocument = convertToNewDidDocument(didDoc)

    // Assert that the keys we are going to use for creating a did document haven't already been used in another did document
    if (role === DidDocumentRole.Created) {
      await assertNoCreatedDidExistsForKeys(agentContext, didDocument.recipientKeys)
    }

    const peerDid = didDocumentJsonToNumAlgo1Did(didDocument.toJSON())
    didDocument.id = peerDid
    const didRecord = new DidRecord({
      did: peerDid,
      role,
      didDocument,
    })

    // Store the unqualified did with the legacy did document in the metadata
    // Can be removed at a later stage if we know for sure we don't need it anymore
    didRecord.metadata.set(DidRecordMetadataKeys.LegacyDid, {
      unqualifiedDid: didDoc.id,
      didDocumentString: JsonTransformer.serialize(didDoc),
    })

    this.logger.debug('Saving DID record', {
      id: didRecord.id,
      did: didRecord.did,
      role: didRecord.role,
      tags: didRecord.getTags(),
      didDocument: 'omitted...',
    })

    await this.didRepository.save(agentContext, didRecord)
    this.logger.debug('Did record created.', didRecord)
    return { did: peerDid, didDocument }
  }

  private createDidDoc(routing: Routing) {
    const indyDid = indyDidFromPublicKeyBase58(routing.recipientKey.publicKeyBase58)

    const publicKey = new Ed25119Sig2018({
      id: `${indyDid}#1`,
      controller: indyDid,
      publicKeyBase58: routing.recipientKey.publicKeyBase58,
    })

    const auth = new ReferencedAuthentication(publicKey, authenticationTypes.Ed25519VerificationKey2018)

    // IndyAgentService is old service type
    const services = routing.endpoints.map(
      (endpoint, index) =>
        new IndyAgentService({
          id: `${indyDid}#IndyAgentService-${index + 1}`,
          serviceEndpoint: endpoint,
          recipientKeys: [routing.recipientKey.publicKeyBase58],
          routingKeys: routing.routingKeys.map((key) => key.publicKeyBase58),
          // Order of endpoint determines priority
          priority: index,
        })
    )

    return new DidDoc({
      id: indyDid,
      authentication: [auth],
      service: services,
      publicKey: [publicKey],
    })
  }

  private createDidDocFromOutOfBandDidCommServices(services: OutOfBandDidCommService[]) {
    const [recipientDidKey] = services[0].recipientKeys

    const recipientKey = DidKey.fromDid(recipientDidKey).key
    const did = indyDidFromPublicKeyBase58(recipientKey.publicKeyBase58)

    const publicKey = new Ed25119Sig2018({
      id: `${did}#1`,
      controller: did,
      publicKeyBase58: recipientKey.publicKeyBase58,
    })

    const auth = new ReferencedAuthentication(publicKey, authenticationTypes.Ed25519VerificationKey2018)

    // IndyAgentService is old service type
    const service = services.map(
      (service, index) =>
        new IndyAgentService({
          id: `${did}#IndyAgentService-${index + 1}`,
          serviceEndpoint: service.serviceEndpoint,
          recipientKeys: [recipientKey.publicKeyBase58],
          routingKeys: service.routingKeys?.map(didKeyToVerkey),
          priority: index,
        })
    )

    return new DidDoc({
      id: did,
      authentication: [auth],
      service,
      publicKey: [publicKey],
    })
  }

  public async returnWhenIsConnected(
    agentContext: AgentContext,
    connectionId: string,
    timeoutMs = 20000
  ): Promise<ConnectionRecord> {
    const isConnected = (connection: ConnectionRecord) => {
      return connection.id === connectionId && connection.state === DidExchangeState.Completed
    }

    const observable = this.eventEmitter.observable<ConnectionStateChangedEvent>(
      ConnectionEventTypes.ConnectionStateChanged
    )
    const subject = new ReplaySubject<ConnectionRecord>(1)

    observable
      .pipe(
        filterContextCorrelationId(agentContext.contextCorrelationId),
        map((e) => e.payload.connectionRecord),
        first(isConnected), // Do not wait for longer than specified timeout
        timeout({
          first: timeoutMs,
          meta: 'ConnectionService.returnWhenIsConnected',
        })
      )
      .subscribe(subject)

    const connection = await this.getById(agentContext, connectionId)
    if (isConnected(connection)) {
      subject.next(connection)
    }

    return firstValueFrom(subject)
  }
}

export interface Routing {
  endpoints: string[]
  recipientKey: Key
  routingKeys: Key[]
  mediatorId?: string
}

export interface ConnectionProtocolMsgReturnType<MessageType extends AgentMessage> {
  message: MessageType
  connectionRecord: ConnectionRecord
}
