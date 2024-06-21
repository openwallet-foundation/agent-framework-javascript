import type { MediationStateChangedEvent } from './RoutingEvents'
import type { MediationRecord } from './repository'
import type { GetRoutingOptions } from './services/RoutingService'
import type { OutboundWebSocketClosedEvent, OutboundWebSocketOpenedEvent } from '../../transport'
import type { ConnectionRecord } from '../connections'

import { firstValueFrom, interval, merge, ReplaySubject, Subject, timer } from 'rxjs'
import { delayWhen, filter, first, takeUntil, tap, throttleTime, timeout } from 'rxjs/operators'

import { AgentContext } from '../../agent'
import { EventEmitter } from '../../agent/EventEmitter'
import { filterContextCorrelationId } from '../../agent/Events'
import { MessageHandlerRegistry } from '../../agent/MessageHandlerRegistry'
import { MessageSender } from '../../agent/MessageSender'
import { OutboundMessageContext } from '../../agent/models'
import { InjectionSymbols } from '../../constants'
import { CredoError } from '../../error'
import { Logger } from '../../logger'
import { inject, injectable } from '../../plugins'
import { TransportEventTypes } from '../../transport'
import { ConnectionMetadataKeys } from '../connections/repository/ConnectionMetadataTypes'
import { ConnectionService } from '../connections/services'
import { DidsApi } from '../dids'
import { verkeyToDidKey } from '../dids/helpers'
import { DiscoverFeaturesApi } from '../discover-features'
import { MessagePickupApi } from '../message-pickup/MessagePickupApi'
import { V1BatchPickupMessage } from '../message-pickup/protocol/v1'
import { V2StatusMessage } from '../message-pickup/protocol/v2'

import { MediationRecipientModuleConfig } from './MediationRecipientModuleConfig'
import { MediatorPickupStrategy } from './MediatorPickupStrategy'
import { RoutingEventTypes } from './RoutingEvents'
import { KeylistUpdateResponseHandler } from './handlers/KeylistUpdateResponseHandler'
import { MediationDenyHandler } from './handlers/MediationDenyHandler'
import { MediationGrantHandler } from './handlers/MediationGrantHandler'
import { KeylistUpdate, KeylistUpdateAction, KeylistUpdateMessage } from './messages'
import { MediationState } from './models/MediationState'
import { MediationRepository } from './repository'
import { MediationRecipientService } from './services/MediationRecipientService'
import { RoutingService } from './services/RoutingService'

@injectable()
export class MediationRecipientApi {
  public config: MediationRecipientModuleConfig

  private mediationRecipientService: MediationRecipientService
  private connectionService: ConnectionService
  private dids: DidsApi
  private messageSender: MessageSender
  private eventEmitter: EventEmitter
  private logger: Logger
  private discoverFeaturesApi: DiscoverFeaturesApi
  private messagePickupApi: MessagePickupApi
  private mediationRepository: MediationRepository
  private routingService: RoutingService
  private agentContext: AgentContext
  private stop$: Subject<boolean>

  // stopMessagePickup$ is used for stop message pickup signal
  private readonly stopMessagePickup$ = new Subject<boolean>()

  public constructor(
    messageHandlerRegistry: MessageHandlerRegistry,
    mediationRecipientService: MediationRecipientService,
    connectionService: ConnectionService,
    dids: DidsApi,
    messageSender: MessageSender,
    eventEmitter: EventEmitter,
    discoverFeaturesApi: DiscoverFeaturesApi,
    messagePickupApi: MessagePickupApi,
    mediationRepository: MediationRepository,
    routingService: RoutingService,
    @inject(InjectionSymbols.Logger) logger: Logger,
    agentContext: AgentContext,
    @inject(InjectionSymbols.Stop$) stop$: Subject<boolean>,
    mediationRecipientModuleConfig: MediationRecipientModuleConfig
  ) {
    this.connectionService = connectionService
    this.dids = dids
    this.mediationRecipientService = mediationRecipientService
    this.messageSender = messageSender
    this.eventEmitter = eventEmitter
    this.logger = logger
    this.discoverFeaturesApi = discoverFeaturesApi
    this.messagePickupApi = messagePickupApi
    this.mediationRepository = mediationRepository
    this.routingService = routingService
    this.agentContext = agentContext
    this.stop$ = stop$
    this.config = mediationRecipientModuleConfig
    this.registerMessageHandlers(messageHandlerRegistry)
  }

  public async initialize() {
    // Poll for messages from mediator
    const defaultMediator = await this.findDefaultMediator()
    if (defaultMediator) {
      this.initiateMessagePickup(defaultMediator).catch((error) => {
        this.logger.warn(`Error initiating message pickup with mediator ${defaultMediator.id}`, { error })
      })
    }
  }

  private async sendMessage(outboundMessageContext: OutboundMessageContext, pickupStrategy?: MediatorPickupStrategy) {
    const mediatorPickupStrategy = pickupStrategy ?? this.config.mediatorPickupStrategy
    const transportPriority =
      mediatorPickupStrategy === MediatorPickupStrategy.Implicit
        ? { schemes: ['wss', 'ws'], restrictive: true }
        : undefined

    await this.messageSender.sendMessage(outboundMessageContext, {
      transportPriority,
      // TODO: add keepAlive: true to enforce through the public api
      // we need to keep the socket alive. It already works this way, but would
      // be good to make more explicit from the public facing API.
      // This would also make it easier to change the internal API later on.
      // keepAlive: true,
    })
  }

  /**
   * Implicit mode consists simply on initiating a long-lived session to a mediator and wait for the
   * messages to arrive automatically.
   *
   * In order to do initiate this session, we open a suitable connection (using WebSocket transport) and
   * send a Trust Ping message.
   *
   * @param mediator
   */
  private async initiateImplicitMode(mediator: MediationRecord) {
    const connection = await this.connectionService.getById(this.agentContext, mediator.connectionId)
    const { message, connectionRecord } = await this.connectionService.createTrustPing(this.agentContext, connection, {
      responseRequested: false,
    })

    const websocketSchemes = ['ws', 'wss']
    const didDocument = connectionRecord.theirDid && (await this.dids.resolveDidDocument(connectionRecord.theirDid))
    const services = didDocument && didDocument?.didCommServices
    const hasWebSocketTransport = services && services.some((s) => websocketSchemes.includes(s.protocolScheme))

    if (!hasWebSocketTransport) {
      throw new CredoError('Cannot open websocket to connection without websocket service endpoint')
    }

    await this.messageSender.sendMessage(
      new OutboundMessageContext(message, { agentContext: this.agentContext, connection: connectionRecord }),
      {
        transportPriority: {
          schemes: websocketSchemes,
          restrictive: true,
          // TODO: add keepAlive: true to enforce through the public api
          // we need to keep the socket alive. It already works this way, but would
          // be good to make more explicit from the public facing API.
          // This would also make it easier to change the internal API later on.
          // keepAlive: true,
        },
      }
    )
  }

  /**
   * Keep track of a persistent transport session with a mediator, trying to reconnect to it as
   * soon as it is disconnected, using a recursive back-off strategy
   *
   * @param mediator mediation record
   * @param pickupStrategy chosen pick up strategy (should be Implicit or PickUp in Live Mode)
   */
  private async monitorMediatorWebSocketEvents(mediator: MediationRecord, pickupStrategy: MediatorPickupStrategy) {
    const { baseMediatorReconnectionIntervalMs, maximumMediatorReconnectionIntervalMs } = this.config
    let interval = baseMediatorReconnectionIntervalMs

    const stopConditions$ = merge(this.stop$, this.stopMessagePickup$).pipe()

    // Reset back off interval when the websocket is successfully opened again
    this.eventEmitter
      .observable<OutboundWebSocketOpenedEvent>(TransportEventTypes.OutboundWebSocketOpenedEvent)
      .pipe(
        // Stop when the agent shuts down or stop message pickup signal is received
        takeUntil(stopConditions$),
        filter((e) => e.payload.connectionId === mediator.connectionId)
      )
      .subscribe(() => {
        interval = baseMediatorReconnectionIntervalMs
      })

    // FIXME: this won't work for tenant agents created by the tenants module as the agent context session
    // could be closed. I'm not sure we want to support this as you probably don't want different tenants opening
    // various websocket connections to mediators. However we should look at throwing an error or making sure
    // it is not possible to use the mediation module with tenant agents.

    // Listens to Outbound websocket closed events and will reopen the websocket connection
    // in a recursive back off strategy if it matches the following criteria:
    // - Agent is not shutdown
    // - Socket was for current mediator connection id
    this.eventEmitter
      .observable<OutboundWebSocketClosedEvent>(TransportEventTypes.OutboundWebSocketClosedEvent)
      .pipe(
        // Stop when the agent shuts down or stop message pickup signal is received
        takeUntil(stopConditions$),
        filter((e) => e.payload.connectionId === mediator.connectionId),
        // Make sure we're not reconnecting multiple times
        throttleTime(interval),
        // Wait for interval time before reconnecting
        delayWhen(() => timer(interval)),
        // Increase the interval (recursive back-off)
        tap(() => {
          interval = Math.min(interval * 2, maximumMediatorReconnectionIntervalMs)
        })
      )
      .subscribe({
        next: async () => {
          this.logger.debug(
            `Websocket connection to mediator with connectionId '${mediator.connectionId}' is closed, attempting to reconnect...`
          )
          try {
            if (pickupStrategy === MediatorPickupStrategy.PickUpV2LiveMode) {
              // Start Pickup v2 protocol in live mode (retrieve any queued message before)
              await this.messagePickupApi.pickupMessages({
                connectionId: mediator.connectionId,
                protocolVersion: 'v2',
                awaitCompletion: true,
              })

              await this.messagePickupApi.setLiveDeliveryMode({
                connectionId: mediator.connectionId,
                liveDelivery: true,
                protocolVersion: 'v2',
              })
            } else {
              await this.initiateImplicitMode(mediator)
            }
          } catch (error) {
            this.logger.warn('Unable to re-open websocket connection to mediator', { error })
          }
        },
        complete: () => this.logger.info(`Stopping pickup of messages from mediator '${mediator.id}'`),
      })
  }

  /**
   * Start a Message Pickup flow with a registered Mediator.
   *
   * @param mediator optional {MediationRecord} corresponding to the mediator to pick messages from. It will use
   * default mediator otherwise
   * @param pickupStrategy optional {MediatorPickupStrategy} to use in the loop. It will use Agent's default
   * strategy or attempt to find it by Discover Features otherwise
   * @returns
   */
  public async initiateMessagePickup(mediator?: MediationRecord, pickupStrategy?: MediatorPickupStrategy) {
    const { mediatorPollingInterval } = this.config
    const mediatorRecord = mediator ?? (await this.findDefaultMediator())
    if (!mediatorRecord) {
      throw new CredoError('There is no mediator to pickup messages from')
    }

    const mediatorPickupStrategy = pickupStrategy ?? (await this.getPickupStrategyForMediator(mediatorRecord))
    const mediatorConnection = await this.connectionService.getById(this.agentContext, mediatorRecord.connectionId)

    switch (mediatorPickupStrategy) {
      case MediatorPickupStrategy.PickUpV1:
      case MediatorPickupStrategy.PickUpV2: {
        const stopConditions$ = merge(this.stop$, this.stopMessagePickup$).pipe()
        // PickUpV1/PickUpV2 means polling every X seconds with batch message
        const protocolVersion = mediatorPickupStrategy === MediatorPickupStrategy.PickUpV2 ? 'v2' : 'v1'

        this.logger.info(
          `Starting explicit pickup of messages from mediator '${mediatorRecord.id}' using ${protocolVersion}`
        )
        const subscription = interval(mediatorPollingInterval)
          .pipe(takeUntil(stopConditions$))
          .subscribe({
            next: async () => {
              await this.messagePickupApi.pickupMessages({
                connectionId: mediatorConnection.id,
                batchSize: this.config.maximumMessagePickup,
                protocolVersion,
              })
            },
            complete: () => this.logger.info(`Stopping pickup of messages from mediator '${mediatorRecord.id}'`),
          })
        return subscription
      }
      case MediatorPickupStrategy.PickUpV2LiveMode:
        // PickUp V2 in Live Mode will retrieve queued messages and then set up live delivery mode
        this.logger.info(`Starting Live Mode pickup of messages from mediator '${mediatorRecord.id}'`)
        await this.monitorMediatorWebSocketEvents(mediatorRecord, mediatorPickupStrategy)

        await this.messagePickupApi.pickupMessages({
          connectionId: mediatorConnection.id,
          protocolVersion: 'v2',
          awaitCompletion: true,
        })

        await this.messagePickupApi.setLiveDeliveryMode({
          connectionId: mediatorConnection.id,
          liveDelivery: true,
          protocolVersion: 'v2',
        })

        break
      case MediatorPickupStrategy.Implicit:
        // Implicit means sending ping once and keeping connection open. This requires a long-lived transport
        // such as WebSockets to work
        this.logger.info(`Starting implicit pickup of messages from mediator '${mediatorRecord.id}'`)
        await this.monitorMediatorWebSocketEvents(mediatorRecord, mediatorPickupStrategy)
        await this.initiateImplicitMode(mediatorRecord)
        break
      default:
        this.logger.info(`Skipping pickup of messages from mediator '${mediatorRecord.id}' due to pickup strategy none`)
    }
  }

  /**
   * Terminate all ongoing Message Pickup loops
   */
  public async stopMessagePickup() {
    this.stopMessagePickup$.next(true)
  }

  private async getPickupStrategyForMediator(mediator: MediationRecord) {
    let mediatorPickupStrategy = mediator.pickupStrategy ?? this.config.mediatorPickupStrategy

    // If mediator pickup strategy is not configured we try to query if batch pickup
    // is supported through the discover features protocol
    if (!mediatorPickupStrategy) {
      const discloseForPickupV2 = await this.discoverFeaturesApi.queryFeatures({
        connectionId: mediator.connectionId,
        protocolVersion: 'v1',
        queries: [{ featureType: 'protocol', match: V2StatusMessage.type.protocolUri }],
        awaitDisclosures: true,
      })

      if (discloseForPickupV2.features?.find((item) => item.id === V2StatusMessage.type.protocolUri)) {
        mediatorPickupStrategy = MediatorPickupStrategy.PickUpV2
      } else {
        const discloseForPickupV1 = await this.discoverFeaturesApi.queryFeatures({
          connectionId: mediator.connectionId,
          protocolVersion: 'v1',
          queries: [{ featureType: 'protocol', match: V1BatchPickupMessage.type.protocolUri }],
          awaitDisclosures: true,
        })
        // Use explicit pickup strategy
        mediatorPickupStrategy = discloseForPickupV1.features?.find(
          (item) => item.id === V1BatchPickupMessage.type.protocolUri
        )
          ? MediatorPickupStrategy.PickUpV1
          : MediatorPickupStrategy.Implicit
      }

      // Store the result so it can be reused next time
      mediator.pickupStrategy = mediatorPickupStrategy
      await this.mediationRepository.update(this.agentContext, mediator)
    }

    return mediatorPickupStrategy
  }

  public async discoverMediation() {
    return this.mediationRecipientService.discoverMediation(this.agentContext)
  }

  public async setDefaultMediator(mediatorRecord: MediationRecord) {
    return this.mediationRecipientService.setDefaultMediator(this.agentContext, mediatorRecord)
  }

  public async requestMediation(connection: ConnectionRecord): Promise<MediationRecord> {
    const { mediationRecord, message } = await this.mediationRecipientService.createRequest(
      this.agentContext,
      connection
    )
    const outboundMessage = new OutboundMessageContext(message, {
      agentContext: this.agentContext,
      connection: connection,
    })

    await this.sendMessage(outboundMessage)
    return mediationRecord
  }

  public async notifyKeylistUpdate(connection: ConnectionRecord, verkey: string, action?: KeylistUpdateAction) {
    // Use our useDidKey configuration unless we know the key formatting other party is using
    let useDidKey = this.agentContext.config.useDidKeyInProtocols

    const useDidKeysConnectionMetadata = connection.metadata.get(ConnectionMetadataKeys.UseDidKeysForProtocol)
    if (useDidKeysConnectionMetadata) {
      useDidKey = useDidKeysConnectionMetadata[KeylistUpdateMessage.type.protocolUri] ?? useDidKey
    }

    const message = this.mediationRecipientService.createKeylistUpdateMessage([
      new KeylistUpdate({
        action: action ?? KeylistUpdateAction.add,
        recipientKey: useDidKey ? verkeyToDidKey(verkey) : verkey,
      }),
    ])

    const outboundMessageContext = new OutboundMessageContext(message, {
      agentContext: this.agentContext,
      connection,
    })
    await this.sendMessage(outboundMessageContext)
  }

  public async findByConnectionId(connectionId: string) {
    return await this.mediationRecipientService.findByConnectionId(this.agentContext, connectionId)
  }

  public async getMediators() {
    return await this.mediationRecipientService.getMediators(this.agentContext)
  }

  public async findDefaultMediator(): Promise<MediationRecord | null> {
    return this.mediationRecipientService.findDefaultMediator(this.agentContext)
  }

  public async findDefaultMediatorConnection(): Promise<ConnectionRecord | null> {
    const mediatorRecord = await this.findDefaultMediator()

    if (mediatorRecord) {
      return this.connectionService.getById(this.agentContext, mediatorRecord.connectionId)
    }

    return null
  }

  public async requestAndAwaitGrant(connection: ConnectionRecord, timeoutMs = 10000): Promise<MediationRecord> {
    const { mediationRecord, message } = await this.mediationRecipientService.createRequest(
      this.agentContext,
      connection
    )

    // Create observable for event
    const observable = this.eventEmitter.observable<MediationStateChangedEvent>(RoutingEventTypes.MediationStateChanged)
    const subject = new ReplaySubject<MediationStateChangedEvent>(1)

    // Apply required filters to observable stream subscribe to replay subject
    observable
      .pipe(
        filterContextCorrelationId(this.agentContext.contextCorrelationId),
        // Only take event for current mediation record
        filter((event) => event.payload.mediationRecord.id === mediationRecord.id),
        // Only take event for previous state requested, current state granted
        filter((event) => event.payload.previousState === MediationState.Requested),
        filter((event) => event.payload.mediationRecord.state === MediationState.Granted),
        // Only wait for first event that matches the criteria
        first(),
        // Do not wait for longer than specified timeout
        timeout({
          first: timeoutMs,
          meta: 'MediationRecipientApi.requestAndAwaitGrant',
        })
      )
      .subscribe(subject)

    // Send mediation request message
    const outboundMessageContext = new OutboundMessageContext(message, {
      agentContext: this.agentContext,
      connection: connection,
      associatedRecord: mediationRecord,
    })
    await this.sendMessage(outboundMessageContext)

    const event = await firstValueFrom(subject)
    return event.payload.mediationRecord
  }

  /**
   * Requests mediation for a given connection and sets that as default mediator.
   *
   * @param connection connection record which will be used for mediation
   * @returns mediation record
   */
  public async provision(connection: ConnectionRecord) {
    this.logger.debug('Connection completed, requesting mediation')

    let mediation = await this.findByConnectionId(connection.id)
    if (!mediation) {
      this.logger.info(`Requesting mediation for connection ${connection.id}`)
      mediation = await this.requestAndAwaitGrant(connection, 60000) // TODO: put timeout as a config parameter
      this.logger.debug('Mediation granted, setting as default mediator')
      await this.setDefaultMediator(mediation)
      this.logger.debug('Default mediator set')
    } else {
      this.logger.debug(`Mediator invitation has already been ${mediation.isReady ? 'granted' : 'requested'}`)
    }

    return mediation
  }

  public async getRouting(options: GetRoutingOptions) {
    return this.routingService.getRouting(this.agentContext, options)
  }

  // Register handlers for the several messages for the mediator.
  private registerMessageHandlers(messageHandlerRegistry: MessageHandlerRegistry) {
    messageHandlerRegistry.registerMessageHandler(new KeylistUpdateResponseHandler(this.mediationRecipientService))
    messageHandlerRegistry.registerMessageHandler(new MediationGrantHandler(this.mediationRecipientService))
    messageHandlerRegistry.registerMessageHandler(new MediationDenyHandler(this.mediationRecipientService))
    //messageHandlerRegistry.registerMessageHandler(new KeylistListHandler(this.mediationRecipientService)) // TODO: write this
  }
}
