import type { ConnectionType } from './models'
import type { ConnectionRecord } from './repository/ConnectionRecord'
import type { Routing } from './services'
import type { Query, QueryOptions } from '../../storage/StorageService'
import type { OutOfBandRecord } from '../oob/repository'

import { AgentContext } from '../../agent'
import { MessageHandlerRegistry } from '../../agent/MessageHandlerRegistry'
import { MessageSender } from '../../agent/MessageSender'
import { OutboundMessageContext } from '../../agent/models'
import { ReturnRouteTypes } from '../../decorators/transport/TransportDecorator'
import { CredoError } from '../../error'
import { injectable } from '../../plugins'
import { DidResolverService } from '../dids'
import { DidRepository } from '../dids/repository'
import { OutOfBandService } from '../oob/OutOfBandService'
import { RoutingService } from '../routing/services/RoutingService'
import { getMediationRecordForDidDocument } from '../routing/services/helpers'

import { ConnectionsModuleConfig } from './ConnectionsModuleConfig'
import { DidExchangeProtocol } from './DidExchangeProtocol'
import {
  AckMessageHandler,
  ConnectionRequestHandler,
  ConnectionResponseHandler,
  DidExchangeCompleteHandler,
  DidExchangeRequestHandler,
  DidExchangeResponseHandler,
  TrustPingMessageHandler,
  TrustPingResponseMessageHandler,
  ConnectionProblemReportHandler,
  DidRotateHandler,
  DidRotateAckHandler,
  DidRotateProblemReportHandler,
  HangupHandler,
} from './handlers'
import { HandshakeProtocol } from './models'
import { DidRotateService } from './services'
import { ConnectionService } from './services/ConnectionService'
import { TrustPingService } from './services/TrustPingService'

export interface SendPingOptions {
  responseRequested?: boolean
  withReturnRouting?: boolean
}

@injectable()
export class ConnectionsApi {
  /**
   * Configuration for the connections module
   */
  public readonly config: ConnectionsModuleConfig

  private didExchangeProtocol: DidExchangeProtocol
  private connectionService: ConnectionService
  private didRotateService: DidRotateService
  private outOfBandService: OutOfBandService
  private messageSender: MessageSender
  private trustPingService: TrustPingService
  private routingService: RoutingService
  private didRepository: DidRepository
  private didResolverService: DidResolverService
  private agentContext: AgentContext

  public constructor(
    messageHandlerRegistry: MessageHandlerRegistry,
    didExchangeProtocol: DidExchangeProtocol,
    connectionService: ConnectionService,
    didRotateService: DidRotateService,
    outOfBandService: OutOfBandService,
    trustPingService: TrustPingService,
    routingService: RoutingService,
    didRepository: DidRepository,
    didResolverService: DidResolverService,
    messageSender: MessageSender,
    agentContext: AgentContext,
    connectionsModuleConfig: ConnectionsModuleConfig
  ) {
    this.didExchangeProtocol = didExchangeProtocol
    this.connectionService = connectionService
    this.didRotateService = didRotateService
    this.outOfBandService = outOfBandService
    this.trustPingService = trustPingService
    this.routingService = routingService
    this.didRepository = didRepository
    this.messageSender = messageSender
    this.didResolverService = didResolverService
    this.agentContext = agentContext
    this.config = connectionsModuleConfig

    this.registerMessageHandlers(messageHandlerRegistry)
  }

  public async acceptOutOfBandInvitation(
    outOfBandRecord: OutOfBandRecord,
    config: {
      autoAcceptConnection?: boolean
      label?: string
      alias?: string
      imageUrl?: string
      protocol: HandshakeProtocol
      routing?: Routing
      ourDid?: string
    }
  ) {
    const { protocol, label, alias, imageUrl, autoAcceptConnection, ourDid } = config

    if (ourDid && config.routing) {
      throw new CredoError(`'routing' is disallowed when defining 'ourDid'`)
    }

    // Only generate routing if ourDid hasn't been provided
    let routing = config.routing
    if (!routing && !ourDid) {
      routing = await this.routingService.getRouting(this.agentContext, { mediatorId: outOfBandRecord.mediatorId })
    }

    let result
    if (protocol === HandshakeProtocol.DidExchange) {
      result = await this.didExchangeProtocol.createRequest(this.agentContext, outOfBandRecord, {
        label,
        alias,
        routing,
        autoAcceptConnection,
        ourDid,
      })
    } else if (protocol === HandshakeProtocol.Connections) {
      if (ourDid) {
        throw new CredoError('Using an externally defined did for connections protocol is unsupported')
      }
      // This is just to make TS happy, as we always generate routing if ourDid is not provided
      // and ourDid is not supported for connection (see check above)
      if (!routing) {
        throw new CredoError('Routing is required for connections protocol')
      }

      result = await this.connectionService.createRequest(this.agentContext, outOfBandRecord, {
        label,
        alias,
        imageUrl,
        routing,
        autoAcceptConnection,
      })
    } else {
      throw new CredoError(`Unsupported handshake protocol ${protocol}.`)
    }

    const { message, connectionRecord } = result
    const outboundMessageContext = new OutboundMessageContext(message, {
      agentContext: this.agentContext,
      connection: connectionRecord,
      outOfBand: outOfBandRecord,
    })
    await this.messageSender.sendMessage(outboundMessageContext)
    return connectionRecord
  }

  /**
   * Accept a connection request as inviter (by sending a connection response message) for the connection with the specified connection id.
   * This is not needed when auto accepting of connection is enabled.
   *
   * @param connectionId the id of the connection for which to accept the request
   * @returns connection record
   */
  public async acceptRequest(connectionId: string): Promise<ConnectionRecord> {
    const connectionRecord = await this.connectionService.findById(this.agentContext, connectionId)
    if (!connectionRecord) {
      throw new CredoError(`Connection record ${connectionId} not found.`)
    }
    if (!connectionRecord.outOfBandId) {
      throw new CredoError(`Connection record ${connectionId} does not have out-of-band record.`)
    }

    const outOfBandRecord = await this.outOfBandService.findById(this.agentContext, connectionRecord.outOfBandId)
    if (!outOfBandRecord) {
      throw new CredoError(`Out-of-band record ${connectionRecord.outOfBandId} not found.`)
    }

    // We generate routing in two scenarios:
    // 1. When the out-of-band invitation is reusable, as otherwise all connections use the same keys
    // 2. When the out-of-band invitation has no inline services, as we don't want to generate a legacy did doc from a service did
    const routing =
      outOfBandRecord.reusable || outOfBandRecord.outOfBandInvitation.getInlineServices().length === 0
        ? await this.routingService.getRouting(this.agentContext)
        : undefined

    let outboundMessageContext
    if (connectionRecord.protocol === HandshakeProtocol.DidExchange) {
      const message = await this.didExchangeProtocol.createResponse(
        this.agentContext,
        connectionRecord,
        outOfBandRecord,
        routing
      )
      outboundMessageContext = new OutboundMessageContext(message, {
        agentContext: this.agentContext,
        connection: connectionRecord,
      })
    } else {
      // We generate routing in two scenarios:
      // 1. When the out-of-band invitation is reusable, as otherwise all connections use the same keys
      // 2. When the out-of-band invitation has no inline services, as we don't want to generate a legacy did doc from a service did
      const routing =
        outOfBandRecord.reusable || outOfBandRecord.outOfBandInvitation.getInlineServices().length === 0
          ? await this.routingService.getRouting(this.agentContext)
          : undefined

      const { message } = await this.connectionService.createResponse(
        this.agentContext,
        connectionRecord,
        outOfBandRecord,
        routing
      )
      outboundMessageContext = new OutboundMessageContext(message, {
        agentContext: this.agentContext,
        connection: connectionRecord,
      })
    }

    await this.messageSender.sendMessage(outboundMessageContext)
    return connectionRecord
  }

  /**
   * Accept a connection response as invitee (by sending a trust ping message) for the connection with the specified connection id.
   * This is not needed when auto accepting of connection is enabled.
   *
   * @param connectionId the id of the connection for which to accept the response
   * @returns connection record
   */
  public async acceptResponse(connectionId: string): Promise<ConnectionRecord> {
    const connectionRecord = await this.connectionService.getById(this.agentContext, connectionId)

    let outboundMessageContext
    if (connectionRecord.protocol === HandshakeProtocol.DidExchange) {
      if (!connectionRecord.outOfBandId) {
        throw new CredoError(`Connection ${connectionRecord.id} does not have outOfBandId!`)
      }
      const outOfBandRecord = await this.outOfBandService.findById(this.agentContext, connectionRecord.outOfBandId)
      if (!outOfBandRecord) {
        throw new CredoError(
          `OutOfBand record for connection ${connectionRecord.id} with outOfBandId ${connectionRecord.outOfBandId} not found!`
        )
      }
      const message = await this.didExchangeProtocol.createComplete(
        this.agentContext,
        connectionRecord,
        outOfBandRecord
      )
      // Disable return routing as we don't want to receive a response for this message over the same channel
      // This has led to long timeouts as not all clients actually close an http socket if there is no response message
      message.setReturnRouting(ReturnRouteTypes.none)
      outboundMessageContext = new OutboundMessageContext(message, {
        agentContext: this.agentContext,
        connection: connectionRecord,
      })
    } else {
      const { message } = await this.connectionService.createTrustPing(this.agentContext, connectionRecord, {
        responseRequested: false,
      })
      // Disable return routing as we don't want to receive a response for this message over the same channel
      // This has led to long timeouts as not all clients actually close an http socket if there is no response message
      message.setReturnRouting(ReturnRouteTypes.none)
      outboundMessageContext = new OutboundMessageContext(message, {
        agentContext: this.agentContext,
        connection: connectionRecord,
      })
    }

    await this.messageSender.sendMessage(outboundMessageContext)
    return connectionRecord
  }

  /**
   * Send a trust ping to an established connection
   *
   * @param connectionId the id of the connection for which to accept the response
   * @param responseRequested do we want a response to our ping
   * @param withReturnRouting do we want a response at the time of posting
   * @returns TrustPingMessage
   */
  public async sendPing(
    connectionId: string,
    { responseRequested = true, withReturnRouting = undefined }: SendPingOptions = {}
  ) {
    const connection = await this.getById(connectionId)

    const { message } = await this.connectionService.createTrustPing(this.agentContext, connection, {
      responseRequested: responseRequested,
    })

    if (withReturnRouting === true) {
      message.setReturnRouting(ReturnRouteTypes.all)
    }

    // Disable return routing as we don't want to receive a response for this message over the same channel
    // This has led to long timeouts as not all clients actually close an http socket if there is no response message
    if (withReturnRouting === false) {
      message.setReturnRouting(ReturnRouteTypes.none)
    }

    await this.messageSender.sendMessage(
      new OutboundMessageContext(message, { agentContext: this.agentContext, connection })
    )

    return message
  }

  /**
   * Rotate the DID used for a given connection, notifying the other party immediately.
   *
   *  If `toDid` is not specified, a new peer did will be created. Optionally, routing
   * configuration can be set.
   *
   * Note: any did created or imported in agent wallet can be used as `toDid`, as long as
   * there are valid DIDComm services in its DID Document.
   *
   * @param options connectionId and optional target did and routing configuration
   * @returns object containing the new did
   */
  public async rotate(options: { connectionId: string; toDid?: string; routing?: Routing }) {
    const { connectionId, toDid } = options
    const connection = await this.connectionService.getById(this.agentContext, connectionId)

    if (toDid && options.routing) {
      throw new CredoError(`'routing' is disallowed when defining 'toDid'`)
    }

    let routing = options.routing
    if (!toDid && !routing) {
      routing = await this.routingService.getRouting(this.agentContext, {})
    }

    const message = await this.didRotateService.createRotate(this.agentContext, {
      connection,
      toDid,
      routing,
    })

    const outboundMessageContext = new OutboundMessageContext(message, {
      agentContext: this.agentContext,
      connection,
    })

    await this.messageSender.sendMessage(outboundMessageContext)

    return { newDid: message.toDid }
  }

  /**
   * Terminate a connection by sending a hang-up message to the other party. The connection record itself and any
   * keys used for mediation will only be deleted if `deleteAfterHangup` flag is set.
   *
   * @param options connectionId
   */
  public async hangup(options: { connectionId: string; deleteAfterHangup?: boolean }) {
    const connection = await this.connectionService.getById(this.agentContext, options.connectionId)

    const connectionBeforeHangup = connection.clone()

    // Create Hangup message and update did in connection record
    const message = await this.didRotateService.createHangup(this.agentContext, { connection })

    const outboundMessageContext = new OutboundMessageContext(message, {
      agentContext: this.agentContext,
      connection: connectionBeforeHangup,
    })

    await this.messageSender.sendMessage(outboundMessageContext)

    // After hang-up message submission, delete connection if required
    if (options.deleteAfterHangup) {
      // First remove any recipient keys related to it
      await this.removeRouting(connectionBeforeHangup)

      await this.deleteById(connection.id)
    }
  }

  public async returnWhenIsConnected(connectionId: string, options?: { timeoutMs: number }): Promise<ConnectionRecord> {
    return this.connectionService.returnWhenIsConnected(this.agentContext, connectionId, options?.timeoutMs)
  }

  /**
   * Retrieve all connections records
   *
   * @returns List containing all connection records
   */
  public getAll() {
    return this.connectionService.getAll(this.agentContext)
  }

  /**
   * Retrieve all connections records by specified query params
   *
   * @returns List containing all connection records matching specified query paramaters
   */
  public findAllByQuery(query: Query<ConnectionRecord>, queryOptions?: QueryOptions) {
    return this.connectionService.findAllByQuery(this.agentContext, query, queryOptions)
  }

  /**
   * Allows for the addition of connectionType to the record.
   *  Either updates or creates an array of string connection types
   * @param connectionId
   * @param type
   * @throws {RecordNotFoundError} If no record is found
   */
  public async addConnectionType(connectionId: string, type: ConnectionType | string) {
    const record = await this.getById(connectionId)

    await this.connectionService.addConnectionType(this.agentContext, record, type)

    return record
  }

  /**
   * Removes the given tag from the given record found by connectionId, if the tag exists otherwise does nothing
   * @param connectionId
   * @param type
   * @throws {RecordNotFoundError} If no record is found
   */
  public async removeConnectionType(connectionId: string, type: ConnectionType | string) {
    const record = await this.getById(connectionId)

    await this.connectionService.removeConnectionType(this.agentContext, record, type)

    return record
  }

  /**
   * Gets the known connection types for the record matching the given connectionId
   * @param connectionId
   * @returns An array of known connection types or null if none exist
   * @throws {RecordNotFoundError} If no record is found
   */
  public async getConnectionTypes(connectionId: string) {
    const record = await this.getById(connectionId)

    return this.connectionService.getConnectionTypes(record)
  }

  /**
   *
   * @param connectionTypes An array of connection types to query for a match for
   * @returns a promise of ab array of connection records
   */
  public async findAllByConnectionTypes(connectionTypes: Array<ConnectionType | string>) {
    return this.connectionService.findAllByConnectionTypes(this.agentContext, connectionTypes)
  }

  /**
   * Retrieve a connection record by id
   *
   * @param connectionId The connection record id
   * @throws {RecordNotFoundError} If no record is found
   * @return The connection record
   *
   */
  public getById(connectionId: string): Promise<ConnectionRecord> {
    return this.connectionService.getById(this.agentContext, connectionId)
  }

  /**
   * Find a connection record by id
   *
   * @param connectionId the connection record id
   * @returns The connection record or null if not found
   */
  public findById(connectionId: string): Promise<ConnectionRecord | null> {
    return this.connectionService.findById(this.agentContext, connectionId)
  }

  /**
   * Delete a connection record by id
   *
   * @param connectionId the connection record id
   */
  public async deleteById(connectionId: string) {
    const connection = await this.connectionService.getById(this.agentContext, connectionId)

    await this.removeRouting(connection)

    return this.connectionService.deleteById(this.agentContext, connectionId)
  }

  private async removeRouting(connection: ConnectionRecord) {
    if (connection.mediatorId && connection.did) {
      const { didDocument } = await this.didResolverService.resolve(this.agentContext, connection.did)

      if (didDocument) {
        await this.routingService.removeRouting(this.agentContext, {
          recipientKeys: didDocument.recipientKeys,
          mediatorId: connection.mediatorId,
        })
      }
    }
  }

  /**
   * Remove relationship of a connection with any previous did (either ours or theirs), preventing it from accepting
   * messages from them. This is usually called when a DID Rotation flow has been succesful and we are sure that no
   * more messages with older keys will arrive.
   *
   * It will remove routing keys from mediator if applicable.
   *
   * Note: this will not actually delete any DID from the wallet.
   *
   * @param connectionId
   */
  public async removePreviousDids(options: { connectionId: string }) {
    const connection = await this.connectionService.getById(this.agentContext, options.connectionId)

    for (const previousDid of connection.previousDids) {
      const did = await this.didResolverService.resolve(this.agentContext, previousDid)
      if (!did.didDocument) continue
      const mediatorRecord = await getMediationRecordForDidDocument(this.agentContext, did.didDocument)

      if (mediatorRecord) {
        await this.routingService.removeRouting(this.agentContext, {
          recipientKeys: did.didDocument.recipientKeys,
          mediatorId: mediatorRecord.id,
        })
      }
    }

    connection.previousDids = []
    connection.previousTheirDids = []

    await this.connectionService.update(this.agentContext, connection)
  }

  public async findAllByOutOfBandId(outOfBandId: string) {
    return this.connectionService.findAllByOutOfBandId(this.agentContext, outOfBandId)
  }

  /**
   * Retrieve a connection record by thread id
   *
   * @param threadId The thread id
   * @throws {RecordNotFoundError} If no record is found
   * @throws {RecordDuplicateError} If multiple records are found
   * @returns The connection record
   */
  public getByThreadId(threadId: string): Promise<ConnectionRecord> {
    return this.connectionService.getByThreadId(this.agentContext, threadId)
  }

  public async findByDid(did: string): Promise<ConnectionRecord | null> {
    return this.connectionService.findByTheirDid(this.agentContext, did)
  }

  public async findByInvitationDid(invitationDid: string): Promise<ConnectionRecord[]> {
    return this.connectionService.findByInvitationDid(this.agentContext, invitationDid)
  }

  private registerMessageHandlers(messageHandlerRegistry: MessageHandlerRegistry) {
    messageHandlerRegistry.registerMessageHandler(
      new ConnectionRequestHandler(
        this.connectionService,
        this.outOfBandService,
        this.routingService,
        this.didRepository,
        this.config
      )
    )
    messageHandlerRegistry.registerMessageHandler(
      new ConnectionResponseHandler(this.connectionService, this.outOfBandService, this.didResolverService, this.config)
    )
    messageHandlerRegistry.registerMessageHandler(new AckMessageHandler(this.connectionService))
    messageHandlerRegistry.registerMessageHandler(new ConnectionProblemReportHandler(this.connectionService))
    messageHandlerRegistry.registerMessageHandler(
      new TrustPingMessageHandler(this.trustPingService, this.connectionService)
    )
    messageHandlerRegistry.registerMessageHandler(new TrustPingResponseMessageHandler(this.trustPingService))

    messageHandlerRegistry.registerMessageHandler(
      new DidExchangeRequestHandler(
        this.didExchangeProtocol,
        this.outOfBandService,
        this.routingService,
        this.didRepository,
        this.config
      )
    )

    messageHandlerRegistry.registerMessageHandler(
      new DidExchangeResponseHandler(
        this.didExchangeProtocol,
        this.outOfBandService,
        this.connectionService,
        this.didResolverService,
        this.config
      )
    )
    messageHandlerRegistry.registerMessageHandler(
      new DidExchangeCompleteHandler(this.didExchangeProtocol, this.outOfBandService)
    )

    messageHandlerRegistry.registerMessageHandler(new DidRotateHandler(this.didRotateService, this.connectionService))

    messageHandlerRegistry.registerMessageHandler(new DidRotateAckHandler(this.didRotateService))

    messageHandlerRegistry.registerMessageHandler(new HangupHandler(this.didRotateService))

    messageHandlerRegistry.registerMessageHandler(new DidRotateProblemReportHandler(this.didRotateService))
  }
}
