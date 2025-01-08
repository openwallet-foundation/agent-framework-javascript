import type { HandshakeReusedEvent } from './domain/OutOfBandEvents'
import type { AgentMessage } from '../../AgentMessage'
import type { Attachment } from '../../decorators/attachment/Attachment'
import type { Routing } from '../../models'
import type { PlaintextMessage } from '../../types'
import type { Query, QueryOptions } from '@credo-ts/core'

import {
  AgentContext,
  EventEmitter,
  filterContextCorrelationId,
  InjectionSymbols,
  Key,
  CredoError,
  Logger,
  inject,
  injectable,
  JsonEncoder,
  JsonTransformer,
  DidKey,
} from '@credo-ts/core'
import { catchError, EmptyError, first, firstValueFrom, map, of, timeout } from 'rxjs'

import { DidCommModuleConfig } from '../../DidCommModuleConfig'
import { AgentEventTypes, type AgentMessageReceivedEvent } from '../../Events'
import { MessageHandlerRegistry } from '../../MessageHandlerRegistry'
import { MessageSender } from '../../MessageSender'
import { ServiceDecorator } from '../../decorators/service/ServiceDecorator'
import { OutboundMessageContext } from '../../models'
import { DidCommDocumentService } from '../../services'
import {
  parseDidCommProtocolUri,
  supportsIncomingDidCommProtocolUri,
  parseMessageType,
  supportsIncomingMessageType,
} from '../../util/messageType'
import { parseInvitationShortUrl } from '../../util/parseInvitation'
import { ConnectionRecord, ConnectionInvitationMessage, HandshakeProtocol, DidExchangeState } from '../connections'
import { ConnectionsApi } from '../connections/ConnectionsApi'
import { RoutingService } from '../routing/services/RoutingService'

import { OutOfBandService } from './OutOfBandService'
import { convertToNewInvitation, convertToOldInvitation } from './converters'
import { OutOfBandDidCommService } from './domain/OutOfBandDidCommService'
import { OutOfBandEventTypes } from './domain/OutOfBandEvents'
import { OutOfBandRole } from './domain/OutOfBandRole'
import { OutOfBandState } from './domain/OutOfBandState'
import { HandshakeReuseHandler } from './handlers'
import { HandshakeReuseAcceptedHandler } from './handlers/HandshakeReuseAcceptedHandler'
import { outOfBandServiceToInlineKeysNumAlgo2Did } from './helpers'
import { InvitationType, OutOfBandInvitation } from './messages'
import { OutOfBandRepository } from './repository'
import { OutOfBandRecord } from './repository/OutOfBandRecord'
import { OutOfBandRecordMetadataKeys } from './repository/outOfBandRecordMetadataTypes'

const didCommProfiles = ['didcomm/aip1', 'didcomm/aip2;env=rfc19']

export interface CreateOutOfBandInvitationConfig {
  label?: string
  alias?: string // alias for a connection record to be created
  imageUrl?: string
  goalCode?: string
  goal?: string
  handshake?: boolean
  handshakeProtocols?: HandshakeProtocol[]
  messages?: AgentMessage[]
  multiUseInvitation?: boolean
  autoAcceptConnection?: boolean
  routing?: Routing
  appendedAttachments?: Attachment[]

  /**
   * Did to use in the invitation. Cannot be used in combination with `routing`.
   */
  invitationDid?: string
}

export interface CreateLegacyInvitationConfig {
  label?: string
  alias?: string // alias for a connection record to be created
  imageUrl?: string
  multiUseInvitation?: boolean
  autoAcceptConnection?: boolean
  routing?: Routing
}

interface BaseReceiveOutOfBandInvitationConfig {
  label?: string
  alias?: string
  imageUrl?: string
  autoAcceptInvitation?: boolean
  autoAcceptConnection?: boolean
  reuseConnection?: boolean
  routing?: Routing
  acceptInvitationTimeoutMs?: number
  isImplicit?: boolean
  ourDid?: string
}

export type ReceiveOutOfBandInvitationConfig = Omit<BaseReceiveOutOfBandInvitationConfig, 'isImplicit'>

export interface ReceiveOutOfBandImplicitInvitationConfig
  extends Omit<BaseReceiveOutOfBandInvitationConfig, 'isImplicit' | 'reuseConnection'> {
  did: string
  handshakeProtocols?: HandshakeProtocol[]
}

@injectable()
export class OutOfBandApi {
  private outOfBandService: OutOfBandService
  private routingService: RoutingService
  private connectionsApi: ConnectionsApi
  private messageHandlerRegistry: MessageHandlerRegistry
  private didCommDocumentService: DidCommDocumentService
  private messageSender: MessageSender
  private eventEmitter: EventEmitter
  private agentContext: AgentContext
  private logger: Logger

  public constructor(
    messageHandlerRegistry: MessageHandlerRegistry,
    didCommDocumentService: DidCommDocumentService,
    outOfBandService: OutOfBandService,
    routingService: RoutingService,
    connectionsApi: ConnectionsApi,
    messageSender: MessageSender,
    eventEmitter: EventEmitter,
    @inject(InjectionSymbols.Logger) logger: Logger,
    agentContext: AgentContext
  ) {
    this.messageHandlerRegistry = messageHandlerRegistry
    this.didCommDocumentService = didCommDocumentService
    this.agentContext = agentContext
    this.logger = logger
    this.outOfBandService = outOfBandService
    this.routingService = routingService
    this.connectionsApi = connectionsApi
    this.messageSender = messageSender
    this.eventEmitter = eventEmitter
    this.registerMessageHandlers(messageHandlerRegistry)
  }

  /**
   * Creates an outbound out-of-band record containing out-of-band invitation message defined in
   * Aries RFC 0434: Out-of-Band Protocol 1.1.
   *
   * It automatically adds all supported handshake protocols by agent to `handshake_protocols`. You
   * can modify this by setting `handshakeProtocols` in `config` parameter. If you want to create
   * invitation without handshake, you can set `handshake` to `false`.
   *
   * If `config` parameter contains `messages` it adds them to `requests~attach` attribute.
   *
   * Agent role: sender (inviter)
   *
   * @param config configuration of how out-of-band invitation should be created
   * @returns out-of-band record
   */
  public async createInvitation(config: CreateOutOfBandInvitationConfig = {}): Promise<OutOfBandRecord> {
    const multiUseInvitation = config.multiUseInvitation ?? false
    const handshake = config.handshake ?? true
    const customHandshakeProtocols = config.handshakeProtocols
    const autoAcceptConnection = config.autoAcceptConnection ?? this.connectionsApi.config.autoAcceptConnections
    // We don't want to treat an empty array as messages being provided
    const messages = config.messages && config.messages.length > 0 ? config.messages : undefined
    const label = config.label ?? this.agentContext.config.label
    const didcommConfig = this.agentContext.dependencyManager.resolve(DidCommModuleConfig)
    const imageUrl = config.imageUrl ?? didcommConfig.connectionImageUrl
    const appendedAttachments =
      config.appendedAttachments && config.appendedAttachments.length > 0 ? config.appendedAttachments : undefined

    if (!handshake && !messages) {
      throw new CredoError('One or both of handshake_protocols and requests~attach MUST be included in the message.')
    }

    if (!handshake && customHandshakeProtocols) {
      throw new CredoError(`Attribute 'handshake' can not be 'false' when 'handshakeProtocols' is defined.`)
    }

    // For now we disallow creating multi-use invitation with attachments. This would mean we need multi-use
    // credential and presentation exchanges.
    if (messages && multiUseInvitation) {
      throw new CredoError("Attribute 'multiUseInvitation' can not be 'true' when 'messages' is defined.")
    }

    let handshakeProtocols: string[] | undefined
    if (handshake) {
      // Assert ALL custom handshake protocols are supported
      if (customHandshakeProtocols) {
        this.assertHandshakeProtocolsSupported(customHandshakeProtocols)
      }

      // Find supported handshake protocol preserving the order of handshake protocols defined by agent or in config
      handshakeProtocols = this.getSupportedHandshakeProtocols(customHandshakeProtocols).map(
        (p) => p.parsedProtocolUri.protocolUri
      )
    }

    let mediatorId: string | undefined = undefined
    let services: [string] | OutOfBandDidCommService[]
    if (config.routing && config.invitationDid) {
      throw new CredoError("Both 'routing' and 'invitationDid' cannot be provided at the same time.")
    }

    if (config.invitationDid) {
      services = [config.invitationDid]
    } else {
      const routing = config.routing ?? (await this.routingService.getRouting(this.agentContext, {}))
      mediatorId = routing?.mediatorId
      services = routing.endpoints.map((endpoint, index) => {
        return new OutOfBandDidCommService({
          id: `#inline-${index}`,
          serviceEndpoint: endpoint,
          recipientKeys: [routing.recipientKey].map((key) => new DidKey(key).did),
          routingKeys: routing.routingKeys.map((key) => new DidKey(key).did),
        })
      })
    }

    const outOfBandInvitation = new OutOfBandInvitation({
      label,
      goal: config.goal,
      goalCode: config.goalCode,
      imageUrl,
      accept: didCommProfiles,
      services,
      handshakeProtocols,
      appendedAttachments,
    })

    if (messages) {
      messages.forEach((message) => {
        if (message.service) {
          // We can remove `~service` attribute from message. Newer OOB messages have `services` attribute instead.
          message.service = undefined
        }
        outOfBandInvitation.addRequest(message)
      })
    }

    const recipientKeyFingerprints = await this.resolveInvitationRecipientKeyFingerprints(outOfBandInvitation)
    const outOfBandRecord = new OutOfBandRecord({
      mediatorId: mediatorId,
      role: OutOfBandRole.Sender,
      state: OutOfBandState.AwaitResponse,
      alias: config.alias,
      outOfBandInvitation: outOfBandInvitation,
      reusable: multiUseInvitation,
      autoAcceptConnection,
      tags: {
        recipientKeyFingerprints,
      },
    })

    await this.outOfBandService.save(this.agentContext, outOfBandRecord)
    this.outOfBandService.emitStateChangedEvent(this.agentContext, outOfBandRecord, null)

    return outOfBandRecord
  }

  /**
   * Creates an outbound out-of-band record in the same way how `createInvitation` method does it,
   * but it also converts out-of-band invitation message to an "legacy" invitation message defined
   * in RFC 0160: Connection Protocol and returns it together with out-of-band record.
   *
   * Agent role: sender (inviter)
   *
   * @param config configuration of how a connection invitation should be created
   * @returns out-of-band record and connection invitation
   */
  public async createLegacyInvitation(config: CreateLegacyInvitationConfig = {}) {
    const outOfBandRecord = await this.createInvitation({
      ...config,
      handshakeProtocols: [HandshakeProtocol.Connections],
    })

    // Set legacy invitation type
    outOfBandRecord.metadata.set(OutOfBandRecordMetadataKeys.LegacyInvitation, {
      legacyInvitationType: InvitationType.Connection,
    })
    const outOfBandRepository = this.agentContext.dependencyManager.resolve(OutOfBandRepository)
    await outOfBandRepository.update(this.agentContext, outOfBandRecord)

    return { outOfBandRecord, invitation: convertToOldInvitation(outOfBandRecord.outOfBandInvitation) }
  }

  public async createLegacyConnectionlessInvitation<Message extends AgentMessage>(config: {
    /**
     * @deprecated this value is not used anymore, as the legacy connection-less exchange is now
     * integrated with the out of band protocol. The value is kept to not break the API, but will
     * be removed in a future version, and has no effect.
     */
    recordId?: string
    message: Message
    domain: string
    routing?: Routing
  }): Promise<{ message: Message; invitationUrl: string; outOfBandRecord: OutOfBandRecord }> {
    const outOfBandRecord = await this.createInvitation({
      messages: [config.message],
      routing: config.routing,
    })

    // Set legacy invitation type
    outOfBandRecord.metadata.set(OutOfBandRecordMetadataKeys.LegacyInvitation, {
      legacyInvitationType: InvitationType.Connectionless,
    })
    const outOfBandRepository = this.agentContext.dependencyManager.resolve(OutOfBandRepository)
    await outOfBandRepository.update(this.agentContext, outOfBandRecord)

    // Resolve the service and set it on the message
    const resolvedService = await this.outOfBandService.getResolvedServiceForOutOfBandServices(
      this.agentContext,
      outOfBandRecord.outOfBandInvitation.getServices()
    )
    config.message.service = ServiceDecorator.fromResolvedDidCommService(resolvedService)

    return {
      message: config.message,
      invitationUrl: `${config.domain}?d_m=${JsonEncoder.toBase64URL(JsonTransformer.toJSON(config.message))}`,
      outOfBandRecord,
    }
  }

  /**
   * Parses URL, decodes invitation and calls `receiveMessage` with parsed invitation message.
   *
   * Agent role: receiver (invitee)
   *
   * @param invitationUrl url containing a base64 encoded invitation to receive
   * @param config configuration of how out-of-band invitation should be processed
   * @returns out-of-band record and connection record if one has been created
   */
  public async receiveInvitationFromUrl(invitationUrl: string, config: ReceiveOutOfBandInvitationConfig = {}) {
    const message = await this.parseInvitation(invitationUrl)

    return this.receiveInvitation(message, config)
  }

  /**
   * Parses URL containing encoded invitation and returns invitation message.
   *
   * Will fetch the url if the url does not contain a base64 encoded invitation.
   *
   * @param invitationUrl URL containing encoded invitation
   *
   * @returns OutOfBandInvitation
   */
  public async parseInvitation(invitationUrl: string): Promise<OutOfBandInvitation> {
    return parseInvitationShortUrl(invitationUrl, this.agentContext.config.agentDependencies)
  }

  /**
   * Creates inbound out-of-band record and assigns out-of-band invitation message to it if the
   * message is valid. It automatically passes out-of-band invitation for further processing to
   * `acceptInvitation` method. If you don't want to do that you can set `autoAcceptInvitation`
   * attribute in `config` parameter to `false` and accept the message later by calling
   * `acceptInvitation`.
   *
   * It supports both OOB (Aries RFC 0434: Out-of-Band Protocol 1.1) and Connection Invitation
   * (0160: Connection Protocol).
   *
   * Agent role: receiver (invitee)
   *
   * @param invitation either OutOfBandInvitation or ConnectionInvitationMessage
   * @param config config for handling of invitation
   *
   * @returns out-of-band record and connection record if one has been created.
   */
  public async receiveInvitation(
    invitation: OutOfBandInvitation | ConnectionInvitationMessage,
    config: ReceiveOutOfBandInvitationConfig = {}
  ): Promise<{ outOfBandRecord: OutOfBandRecord; connectionRecord?: ConnectionRecord }> {
    return this._receiveInvitation(invitation, config)
  }

  /**
   * Creates inbound out-of-band record from an implicit invitation, given as a public DID the agent
   * should be capable of resolving. It automatically passes out-of-band invitation for further
   * processing to `acceptInvitation` method. If you don't want to do that you can set
   * `autoAcceptInvitation` attribute in `config` parameter to `false` and accept the message later by
   * calling `acceptInvitation`.
   *
   * It supports both OOB (Aries RFC 0434: Out-of-Band Protocol 1.1) and Connection Invitation
   * (0160: Connection Protocol). Handshake protocol to be used depends on handshakeProtocols
   * (DID Exchange by default)
   *
   * Agent role: receiver (invitee)
   *
   * @param config config for creating and handling invitation
   *
   * @returns out-of-band record and connection record if one has been created.
   */
  public async receiveImplicitInvitation(config: ReceiveOutOfBandImplicitInvitationConfig) {
    const handshakeProtocols = this.getSupportedHandshakeProtocols(
      config.handshakeProtocols ?? [HandshakeProtocol.DidExchange]
    ).map((p) => p.parsedProtocolUri.protocolUri)

    const invitation = new OutOfBandInvitation({
      id: config.did,
      label: config.label ?? '',
      services: [config.did],
      handshakeProtocols,
    })

    return this._receiveInvitation(invitation, { ...config, isImplicit: true })
  }

  /**
   * Internal receive invitation method, for both explicit and implicit OOB invitations
   */
  private async _receiveInvitation(
    invitation: OutOfBandInvitation | ConnectionInvitationMessage,
    config: BaseReceiveOutOfBandInvitationConfig = {}
  ): Promise<{ outOfBandRecord: OutOfBandRecord; connectionRecord?: ConnectionRecord }> {
    // Convert to out of band invitation if needed
    const outOfBandInvitation =
      invitation instanceof OutOfBandInvitation ? invitation : convertToNewInvitation(invitation)

    const { handshakeProtocols } = outOfBandInvitation
    const { routing } = config

    const autoAcceptInvitation = config.autoAcceptInvitation ?? true
    const autoAcceptConnection = config.autoAcceptConnection ?? true
    const reuseConnection = config.reuseConnection ?? false
    const label = config.label ?? this.agentContext.config.label
    const alias = config.alias
    const didcommConfig = this.agentContext.dependencyManager.resolve(DidCommModuleConfig)
    const imageUrl = config.imageUrl ?? didcommConfig.connectionImageUrl

    const messages = outOfBandInvitation.getRequests()

    const isConnectionless = handshakeProtocols === undefined || handshakeProtocols.length === 0

    if ((!handshakeProtocols || handshakeProtocols.length === 0) && (!messages || messages?.length === 0)) {
      throw new CredoError('One or both of handshake_protocols and requests~attach MUST be included in the message.')
    }

    // Make sure we haven't received this invitation before
    // It's fine if we created it (means that we are connecting to ourselves) or if it's an implicit
    // invitation (it allows to connect multiple times to the same public did)
    if (!config.isImplicit) {
      const existingOobRecordsFromThisId = await this.outOfBandService.findAllByQuery(this.agentContext, {
        invitationId: outOfBandInvitation.id,
        role: OutOfBandRole.Receiver,
      })
      if (existingOobRecordsFromThisId.length > 0) {
        throw new CredoError(
          `An out of band record with invitation ${outOfBandInvitation.id} has already been received. Invitations should have a unique id.`
        )
      }
    }

    const recipientKeyFingerprints = await this.resolveInvitationRecipientKeyFingerprints(outOfBandInvitation)
    const outOfBandRecord = new OutOfBandRecord({
      role: OutOfBandRole.Receiver,
      state: OutOfBandState.Initial,
      outOfBandInvitation: outOfBandInvitation,
      autoAcceptConnection,
      tags: { recipientKeyFingerprints },
      mediatorId: routing?.mediatorId,
    })

    // If we have routing, and this is a connectionless exchange, or we are not auto accepting the connection
    // we need to store the routing, so it can be used when we send the first message in response to this invitation
    if (routing && (isConnectionless || !autoAcceptInvitation)) {
      this.logger.debug('Storing routing for out of band invitation.')
      outOfBandRecord.metadata.set(OutOfBandRecordMetadataKeys.RecipientRouting, {
        recipientKeyFingerprint: routing.recipientKey.fingerprint,
        routingKeyFingerprints: routing.routingKeys.map((key) => key.fingerprint),
        endpoints: routing.endpoints,
        mediatorId: routing.mediatorId,
      })
    }

    // If the invitation was converted from another legacy format, we store this, as its needed for some flows
    if (outOfBandInvitation.invitationType && outOfBandInvitation.invitationType !== InvitationType.OutOfBand) {
      outOfBandRecord.metadata.set(OutOfBandRecordMetadataKeys.LegacyInvitation, {
        legacyInvitationType: outOfBandInvitation.invitationType,
      })
    }

    await this.outOfBandService.save(this.agentContext, outOfBandRecord)
    this.outOfBandService.emitStateChangedEvent(this.agentContext, outOfBandRecord, null)

    if (autoAcceptInvitation) {
      return await this.acceptInvitation(outOfBandRecord.id, {
        label,
        alias,
        imageUrl,
        autoAcceptConnection,
        reuseConnection,
        routing,
        timeoutMs: config.acceptInvitationTimeoutMs,
        ourDid: config.ourDid,
      })
    }

    return { outOfBandRecord }
  }

  /**
   * Creates a connection if the out-of-band invitation message contains `handshake_protocols`
   * attribute, except for the case when connection already exists and `reuseConnection` is enabled.
   *
   * It passes first supported message from `requests~attach` attribute to the agent, except for the
   * case reuse of connection is applied when it just sends `handshake-reuse` message to existing
   * connection.
   *
   * Agent role: receiver (invitee)
   *
   * @param outOfBandId
   * @param config
   * @returns out-of-band record and connection record if one has been created.
   */
  public async acceptInvitation(
    outOfBandId: string,
    config: {
      autoAcceptConnection?: boolean
      reuseConnection?: boolean
      label?: string
      alias?: string
      imageUrl?: string
      /**
       * Routing for the exchange (either connection or connection-less exchange).
       *
       * If a connection is reused, the routing WILL NOT be used.
       */
      routing?: Routing
      timeoutMs?: number
      ourDid?: string
    }
  ) {
    const outOfBandRecord = await this.outOfBandService.getById(this.agentContext, outOfBandId)

    const { outOfBandInvitation } = outOfBandRecord
    const { label, alias, imageUrl, autoAcceptConnection, reuseConnection, ourDid } = config
    const services = outOfBandInvitation.getServices()
    const messages = outOfBandInvitation.getRequests()
    const timeoutMs = config.timeoutMs ?? 20000

    let routing = config.routing

    // recipient routing from the receiveInvitation method.
    const recipientRouting = outOfBandRecord.metadata.get(OutOfBandRecordMetadataKeys.RecipientRouting)
    if (!routing && recipientRouting) {
      routing = {
        recipientKey: Key.fromFingerprint(recipientRouting.recipientKeyFingerprint),
        routingKeys: recipientRouting.routingKeyFingerprints.map((fingerprint) => Key.fromFingerprint(fingerprint)),
        endpoints: recipientRouting.endpoints,
        mediatorId: recipientRouting.mediatorId,
      }
    }

    const { handshakeProtocols } = outOfBandInvitation

    const existingConnection = await this.findExistingConnection(outOfBandInvitation)

    await this.outOfBandService.updateState(this.agentContext, outOfBandRecord, OutOfBandState.PrepareResponse)

    if (handshakeProtocols && handshakeProtocols.length > 0) {
      this.logger.debug('Out of band message contains handshake protocols.')

      let connectionRecord
      if (existingConnection && reuseConnection) {
        this.logger.debug(
          `Connection already exists and reuse is enabled. Reusing an existing connection with ID ${existingConnection.id}.`
        )

        if (!messages || messages?.length === 0) {
          this.logger.debug('Out of band message does not contain any request messages.')
          const isHandshakeReuseSuccessful = await this.handleHandshakeReuse(outOfBandRecord, existingConnection)

          // Handshake reuse was successful
          if (isHandshakeReuseSuccessful) {
            this.logger.debug(`Handshake reuse successful. Reusing existing connection ${existingConnection.id}.`)
            connectionRecord = existingConnection
          } else {
            // Handshake reuse failed. Not setting connection record
            this.logger.debug(`Handshake reuse failed. Not using existing connection ${existingConnection.id}.`)
          }
        } else {
          // Handshake reuse because we found a connection and we can respond directly to the message
          this.logger.debug(`Reusing existing connection ${existingConnection.id}.`)
          connectionRecord = existingConnection
        }
      }

      // If no existing connection was found, reuseConnection is false, or we didn't receive a
      // handshake-reuse-accepted message we create a new connection
      if (!connectionRecord) {
        this.logger.debug('Connection does not exist or reuse is disabled. Creating a new connection.')
        // Find first supported handshake protocol preserving the order of handshake protocols
        // defined by `handshake_protocols` attribute in the invitation message
        const firstSupportedProtocol = this.getFirstSupportedProtocol(handshakeProtocols)
        connectionRecord = await this.connectionsApi.acceptOutOfBandInvitation(outOfBandRecord, {
          label,
          alias,
          imageUrl,
          autoAcceptConnection,
          protocol: firstSupportedProtocol.handshakeProtocol,
          routing,
          ourDid,
        })
      }

      if (messages && messages.length > 0) {
        this.logger.debug('Out of band message contains request messages.')
        if (connectionRecord.isReady) {
          await this.emitWithConnection(outOfBandRecord, connectionRecord, messages)
        } else {
          // Wait until the connection is ready and then pass the messages to the agent for further processing
          this.connectionsApi
            .returnWhenIsConnected(connectionRecord.id, { timeoutMs })
            .then((connectionRecord) => this.emitWithConnection(outOfBandRecord, connectionRecord, messages))
            .catch((error) => {
              if (error instanceof EmptyError) {
                this.logger.warn(
                  `Agent unsubscribed before connection got into ${DidExchangeState.Completed} state`,
                  error
                )
              } else {
                this.logger.error('Promise waiting for the connection to be complete failed.', error)
              }
            })
        }
      }
      return { outOfBandRecord, connectionRecord }
    } else if (messages) {
      this.logger.debug('Out of band message contains only request messages.')
      if (existingConnection && reuseConnection) {
        this.logger.debug('Connection already exists.', { connectionId: existingConnection.id })
        await this.emitWithConnection(outOfBandRecord, existingConnection, messages)
      } else {
        await this.emitWithServices(outOfBandRecord, services, messages)
      }
    }
    return { outOfBandRecord }
  }

  public async findByReceivedInvitationId(receivedInvitationId: string) {
    return this.outOfBandService.findByReceivedInvitationId(this.agentContext, receivedInvitationId)
  }

  public async findByCreatedInvitationId(createdInvitationId: string) {
    return this.outOfBandService.findByCreatedInvitationId(this.agentContext, createdInvitationId)
  }

  /**
   * Retrieve all out of bands records
   *
   * @returns List containing all  out of band records
   */
  public getAll() {
    return this.outOfBandService.getAll(this.agentContext)
  }

  /**
   * Retrieve all out of bands records by specified query param
   *
   * @returns List containing all out of band records matching specified query params
   */
  public findAllByQuery(query: Query<OutOfBandRecord>, queryOptions?: QueryOptions) {
    return this.outOfBandService.findAllByQuery(this.agentContext, query, queryOptions)
  }

  /**
   * Retrieve a out of band record by id
   *
   * @param outOfBandId The  out of band record id
   * @throws {RecordNotFoundError} If no record is found
   * @return The out of band record
   *
   */
  public getById(outOfBandId: string): Promise<OutOfBandRecord> {
    return this.outOfBandService.getById(this.agentContext, outOfBandId)
  }

  /**
   * Find an out of band record by id
   *
   * @param outOfBandId the  out of band record id
   * @returns The out of band record or null if not found
   */
  public findById(outOfBandId: string): Promise<OutOfBandRecord | null> {
    return this.outOfBandService.findById(this.agentContext, outOfBandId)
  }

  /**
   * Delete an out of band record by id
   *
   * @param outOfBandId the out of band record id
   */
  public async deleteById(outOfBandId: string) {
    const outOfBandRecord = await this.getById(outOfBandId)

    const relatedConnections = await this.connectionsApi.findAllByOutOfBandId(outOfBandId)

    // If it uses mediation and there are no related connections, AND we didn't use a did in the invitation
    // (if that is the case the did is managed outside of this exchange) proceed to delete keys from mediator
    // Note: if OOB Record is reusable, it is safe to delete it because every connection created from
    // it will use its own recipient key
    if (
      outOfBandRecord.mediatorId &&
      outOfBandRecord.outOfBandInvitation.getDidServices().length === 0 &&
      (relatedConnections.length === 0 || outOfBandRecord.reusable)
    ) {
      const recipientKeys = outOfBandRecord.getTags().recipientKeyFingerprints.map((item) => Key.fromFingerprint(item))

      await this.routingService.removeRouting(this.agentContext, {
        recipientKeys,
        mediatorId: outOfBandRecord.mediatorId,
      })
    }

    return this.outOfBandService.deleteById(this.agentContext, outOfBandId)
  }

  private assertHandshakeProtocolsSupported(handshakeProtocols: HandshakeProtocol[]) {
    if (!this.areHandshakeProtocolsSupported(handshakeProtocols)) {
      const supportedProtocols = this.getSupportedHandshakeProtocols()
      throw new CredoError(
        `Handshake protocols [${handshakeProtocols}] are not supported. Supported protocols are [${supportedProtocols}]`
      )
    }
  }

  private areHandshakeProtocolsSupported(handshakeProtocols: HandshakeProtocol[]) {
    const supportedProtocols = this.getSupportedHandshakeProtocols(handshakeProtocols)
    return supportedProtocols.length === handshakeProtocols.length
  }

  private getSupportedHandshakeProtocols(limitToHandshakeProtocols?: HandshakeProtocol[]) {
    const allHandshakeProtocols = limitToHandshakeProtocols ?? Object.values(HandshakeProtocol)

    // Replace .x in the handshake protocol with .0 to allow it to be parsed
    const parsedHandshakeProtocolUris = allHandshakeProtocols.map((h) => ({
      handshakeProtocol: h,
      parsedProtocolUri: parseDidCommProtocolUri(h.replace('.x', '.0')),
    }))

    // Now find all handshake protocols that start with the protocol uri without minor version '<base-uri>/<protocol-name>/<major-version>.'
    const supportedHandshakeProtocols = this.messageHandlerRegistry.filterSupportedProtocolsByProtocolUris(
      parsedHandshakeProtocolUris.map((p) => p.parsedProtocolUri)
    )

    if (supportedHandshakeProtocols.length === 0) {
      throw new CredoError('There is no handshake protocol supported. Agent can not create a connection.')
    }

    // Order protocols according to `parsedHandshakeProtocolUris` array (order of preference)
    const orderedProtocols = parsedHandshakeProtocolUris
      .map((p) => {
        const found = supportedHandshakeProtocols.find((s) =>
          supportsIncomingDidCommProtocolUri(s, p.parsedProtocolUri)
        )
        // We need to override the parsedProtocolUri with the one from the supported protocols, as we used `.0` as the minor
        // version before. But when we return it, we want to return the correct minor version that we actually support
        return found ? { ...p, parsedProtocolUri: found } : null
      })
      .filter((p): p is NonNullable<typeof p> => p !== null)

    return orderedProtocols
  }

  /**
   * Get the first supported protocol based on the handshake protocols provided in the out of band
   * invitation.
   *
   * Returns an enum value from {@link HandshakeProtocol} or throw an error if no protocol is supported.
   * Minor versions are ignored when selecting a supported protocols, so if the `outOfBandInvitationSupportedProtocolsWithMinorVersion`
   * value is `https://didcomm.org/didexchange/1.0` and the agent supports `https://didcomm.org/didexchange/1.1`
   * this will be fine, and the returned value will be {@link HandshakeProtocol.DidExchange}.
   */
  private getFirstSupportedProtocol(protocolUris: string[]) {
    const supportedProtocols = this.getSupportedHandshakeProtocols()
    const parsedProtocolUris = protocolUris.map(parseDidCommProtocolUri)

    const firstSupportedProtocol = supportedProtocols.find((supportedProtocol) =>
      parsedProtocolUris.find((parsedProtocol) =>
        supportsIncomingDidCommProtocolUri(supportedProtocol.parsedProtocolUri, parsedProtocol)
      )
    )

    if (!firstSupportedProtocol) {
      throw new CredoError(
        `Handshake protocols [${protocolUris}] are not supported. Supported protocols are [${supportedProtocols.map(
          (p) => p.handshakeProtocol
        )}]`
      )
    }

    return firstSupportedProtocol
  }

  private async findExistingConnection(outOfBandInvitation: OutOfBandInvitation) {
    this.logger.debug('Searching for an existing connection for out-of-band invitation.', { outOfBandInvitation })

    const invitationDids = [
      ...outOfBandInvitation.invitationDids,
      // Also search for legacy invitationDids based on inline services (TODO: remove in 0.6.0)
      ...outOfBandInvitation.getInlineServices().map(outOfBandServiceToInlineKeysNumAlgo2Did),
    ]

    for (const invitationDid of invitationDids) {
      const connections = await this.connectionsApi.findByInvitationDid(invitationDid)

      this.logger.debug(`Retrieved ${connections.length} connections for invitation did ${invitationDid}`)

      if (connections.length === 1) {
        const [firstConnection] = connections
        return firstConnection
      } else if (connections.length > 1) {
        this.logger.warn(
          `There is more than one connection created from invitationDid ${invitationDid}. Taking the first one.`
        )
        const [firstConnection] = connections
        return firstConnection
      }
      return null
    }
  }

  private async emitWithConnection(
    outOfBandRecord: OutOfBandRecord,
    connectionRecord: ConnectionRecord,
    messages: PlaintextMessage[]
  ) {
    const supportedMessageTypes = this.messageHandlerRegistry.supportedMessageTypes
    const plaintextMessage = messages.find((message) => {
      const parsedMessageType = parseMessageType(message['@type'])
      return supportedMessageTypes.find((type) => supportsIncomingMessageType(parsedMessageType, type))
    })

    if (!plaintextMessage) {
      throw new CredoError('There is no message in requests~attach supported by agent.')
    }

    // Make sure message has correct parent thread id
    this.ensureParentThreadId(outOfBandRecord, plaintextMessage)

    this.logger.debug(`Message with type ${plaintextMessage['@type']} can be processed.`)

    this.eventEmitter.emit<AgentMessageReceivedEvent>(this.agentContext, {
      type: AgentEventTypes.AgentMessageReceived,
      payload: {
        message: plaintextMessage,
        connection: connectionRecord,
        contextCorrelationId: this.agentContext.contextCorrelationId,
      },
    })
  }

  private async emitWithServices(
    outOfBandRecord: OutOfBandRecord,
    services: Array<OutOfBandDidCommService | string>,
    messages: PlaintextMessage[]
  ) {
    if (!services || services.length === 0) {
      throw new CredoError(`There are no services. We can not emit messages`)
    }

    const supportedMessageTypes = this.messageHandlerRegistry.supportedMessageTypes
    const plaintextMessage = messages.find((message) => {
      const parsedMessageType = parseMessageType(message['@type'])
      return supportedMessageTypes.find((type) => supportsIncomingMessageType(parsedMessageType, type))
    })

    if (!plaintextMessage) {
      throw new CredoError('There is no message in requests~attach supported by agent.')
    }

    // Make sure message has correct parent thread id
    this.ensureParentThreadId(outOfBandRecord, plaintextMessage)

    this.logger.debug(`Message with type ${plaintextMessage['@type']} can be processed.`)

    this.eventEmitter.emit<AgentMessageReceivedEvent>(this.agentContext, {
      type: AgentEventTypes.AgentMessageReceived,
      payload: {
        message: plaintextMessage,
        contextCorrelationId: this.agentContext.contextCorrelationId,
      },
    })
  }

  private ensureParentThreadId(outOfBandRecord: OutOfBandRecord, plaintextMessage: PlaintextMessage) {
    const legacyInvitationMetadata = outOfBandRecord.metadata.get(OutOfBandRecordMetadataKeys.LegacyInvitation)

    // We need to set the parent thread id to the invitation id, according to RFC 0434.
    // So if it already has a pthid and it is not the same as the invitation id, we throw an error
    if (
      plaintextMessage['~thread']?.pthid &&
      plaintextMessage['~thread'].pthid !== outOfBandRecord.outOfBandInvitation.id
    ) {
      throw new CredoError(
        `Out of band invitation requests~attach message contains parent thread id ${plaintextMessage['~thread'].pthid} that does not match the invitation id ${outOfBandRecord.outOfBandInvitation.id}`
      )
    }

    // If the invitation is created from a legacy connectionless invitation, we don't need to set the pthid
    // as that's not expected, and it's generated on our side only
    if (legacyInvitationMetadata?.legacyInvitationType === InvitationType.Connectionless) {
      return
    }

    if (!plaintextMessage['~thread']) {
      plaintextMessage['~thread'] = {}
    }

    // The response to an out-of-band message MUST set its ~thread.pthid equal to the @id property of the out-of-band message.
    // By adding the pthid to the message, we ensure that the response will take over this pthid
    plaintextMessage['~thread'].pthid = outOfBandRecord.outOfBandInvitation.id
  }

  private async handleHandshakeReuse(outOfBandRecord: OutOfBandRecord, connectionRecord: ConnectionRecord) {
    const reuseMessage = await this.outOfBandService.createHandShakeReuse(
      this.agentContext,
      outOfBandRecord,
      connectionRecord
    )

    const reuseAcceptedEventPromise = firstValueFrom(
      this.eventEmitter.observable<HandshakeReusedEvent>(OutOfBandEventTypes.HandshakeReused).pipe(
        filterContextCorrelationId(this.agentContext.contextCorrelationId),
        // Find the first reuse event where the handshake reuse accepted matches the reuse message thread
        // TODO: Should we store the reuse state? Maybe we can keep it in memory for now
        first(
          (event) =>
            event.payload.reuseThreadId === reuseMessage.threadId &&
            event.payload.outOfBandRecord.id === outOfBandRecord.id &&
            event.payload.connectionRecord.id === connectionRecord.id
        ),
        // If the event is found, we return the value true
        map(() => true),
        timeout({
          first: 15000,
          meta: 'OutOfBandApi.handleHandshakeReuse',
        }),
        // If timeout is reached, we return false
        catchError(() => of(false))
      )
    )

    const outboundMessageContext = new OutboundMessageContext(reuseMessage, {
      agentContext: this.agentContext,
      connection: connectionRecord,
    })
    await this.messageSender.sendMessage(outboundMessageContext)

    return reuseAcceptedEventPromise
  }

  private async resolveInvitationRecipientKeyFingerprints(outOfBandInvitation: OutOfBandInvitation) {
    const recipientKeyFingerprints: string[] = []

    for (const service of outOfBandInvitation.getServices()) {
      // Resolve dids to DIDDocs to retrieve services
      if (typeof service === 'string') {
        this.logger.debug(`Resolving services for did ${service}.`)
        const resolvedDidCommServices = await this.didCommDocumentService.resolveServicesFromDid(
          this.agentContext,
          service
        )
        recipientKeyFingerprints.push(
          ...resolvedDidCommServices
            .reduce<Key[]>((aggr, { recipientKeys }) => [...aggr, ...recipientKeys], [])
            .map((key) => key.fingerprint)
        )
      } else {
        recipientKeyFingerprints.push(...service.recipientKeys.map((didKey) => DidKey.fromDid(didKey).key.fingerprint))
      }
    }

    return recipientKeyFingerprints
  }

  // TODO: we should probably move these to the out of band module and register the handler there
  private registerMessageHandlers(messageHandlerRegistry: MessageHandlerRegistry) {
    messageHandlerRegistry.registerMessageHandler(new HandshakeReuseHandler(this.outOfBandService))
    messageHandlerRegistry.registerMessageHandler(new HandshakeReuseAcceptedHandler(this.outOfBandService))
  }
}
