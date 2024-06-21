import type {
  DiscloseFeaturesOptions,
  QueryFeaturesOptions,
  DiscoverFeaturesServiceMap,
} from './DiscoverFeaturesApiOptions'
import type { DiscoverFeaturesDisclosureReceivedEvent } from './DiscoverFeaturesEvents'
import type { DiscoverFeaturesService } from './services'
import type { Feature } from '../../agent/models'

import { firstValueFrom, of, ReplaySubject, Subject } from 'rxjs'
import { catchError, filter, first, map, takeUntil, timeout } from 'rxjs/operators'

import { AgentContext } from '../../agent'
import { EventEmitter } from '../../agent/EventEmitter'
import { MessageSender } from '../../agent/MessageSender'
import { OutboundMessageContext } from '../../agent/models'
import { InjectionSymbols } from '../../constants'
import { CredoError } from '../../error'
import { inject, injectable } from '../../plugins'
import { ConnectionService } from '../connections/services'

import { DiscoverFeaturesEventTypes } from './DiscoverFeaturesEvents'
import { DiscoverFeaturesModuleConfig } from './DiscoverFeaturesModuleConfig'
import { V1DiscoverFeaturesService, V2DiscoverFeaturesService } from './protocol'

export interface QueryFeaturesReturnType {
  features?: Feature[]
}

export interface DiscoverFeaturesApi<DFSs extends DiscoverFeaturesService[]> {
  queryFeatures(options: QueryFeaturesOptions<DFSs>): Promise<QueryFeaturesReturnType>
  discloseFeatures(options: DiscloseFeaturesOptions<DFSs>): Promise<void>
}
@injectable()
export class DiscoverFeaturesApi<
  DFSs extends DiscoverFeaturesService[] = [V1DiscoverFeaturesService, V2DiscoverFeaturesService]
> implements DiscoverFeaturesApi<DFSs>
{
  /**
   * Configuration for Discover Features module
   */
  public readonly config: DiscoverFeaturesModuleConfig

  private connectionService: ConnectionService
  private messageSender: MessageSender
  private eventEmitter: EventEmitter
  private stop$: Subject<boolean>
  private agentContext: AgentContext
  private serviceMap: DiscoverFeaturesServiceMap<DFSs>

  public constructor(
    connectionService: ConnectionService,
    messageSender: MessageSender,
    v1Service: V1DiscoverFeaturesService,
    v2Service: V2DiscoverFeaturesService,
    eventEmitter: EventEmitter,
    @inject(InjectionSymbols.Stop$) stop$: Subject<boolean>,
    agentContext: AgentContext,
    config: DiscoverFeaturesModuleConfig
  ) {
    this.connectionService = connectionService
    this.messageSender = messageSender
    this.eventEmitter = eventEmitter
    this.stop$ = stop$
    this.agentContext = agentContext
    this.config = config

    // Dynamically build service map. This will be extracted once services are registered dynamically
    this.serviceMap = [v1Service, v2Service].reduce(
      (serviceMap, service) => ({
        ...serviceMap,
        [service.version]: service,
      }),
      {}
    ) as DiscoverFeaturesServiceMap<DFSs>
  }

  public getService<PVT extends DiscoverFeaturesService['version']>(protocolVersion: PVT): DiscoverFeaturesService {
    if (!this.serviceMap[protocolVersion]) {
      throw new CredoError(`No discover features service registered for protocol version ${protocolVersion}`)
    }

    return this.serviceMap[protocolVersion] as unknown as DiscoverFeaturesService
  }

  /**
   * Send a query to an existing connection for discovering supported features of any kind. If desired, do the query synchronously,
   * meaning that it will await the response (or timeout) before resolving. Otherwise, response can be hooked by subscribing to
   * {DiscoverFeaturesDisclosureReceivedEvent}.
   *
   * Note: V1 protocol only supports a single query and is limited to protocols
   *
   * @param options feature queries to perform, protocol version and optional comment string (only used
   * in V1 protocol). If awaitDisclosures is set, perform the query synchronously with awaitDisclosuresTimeoutMs timeout.
   */
  public async queryFeatures(options: QueryFeaturesOptions<DFSs>) {
    const service = this.getService(options.protocolVersion)

    const connection = await this.connectionService.getById(this.agentContext, options.connectionId)

    const { message: queryMessage } = await service.createQuery({
      queries: options.queries,
      comment: options.comment,
    })

    const outboundMessageContext = new OutboundMessageContext(queryMessage, {
      agentContext: this.agentContext,
      connection,
    })

    const replaySubject = new ReplaySubject<Feature[]>(1)
    if (options.awaitDisclosures) {
      // Listen for response to our feature query
      this.eventEmitter
        .observable<DiscoverFeaturesDisclosureReceivedEvent>(DiscoverFeaturesEventTypes.DisclosureReceived)
        .pipe(
          // Stop when the agent shuts down
          takeUntil(this.stop$),
          // filter by connection id
          filter((e) => e.payload.connection?.id === connection.id),
          // Return disclosures
          map((e) => e.payload.disclosures),
          // Only wait for first event that matches the criteria
          first(),
          // If we don't have an answer in timeoutMs miliseconds (no response, not supported, etc...) error
          timeout({
            first: options.awaitDisclosuresTimeoutMs ?? 7000,
            meta: 'DiscoverFeaturesApi.queryFeatures',
          }), // TODO: Harmonize default timeouts across the framework
          // We want to return false if an error occurred
          catchError(() => of([]))
        )
        .subscribe(replaySubject)
    }

    await this.messageSender.sendMessage(outboundMessageContext)

    return { features: options.awaitDisclosures ? await firstValueFrom(replaySubject) : undefined }
  }

  /**
   * Disclose features to a connection, either proactively or as a response to a query.
   *
   * Features are disclosed based on queries that will be performed to Agent's Feature Registry,
   * meaning that they should be registered prior to disclosure. When sending disclosure as response,
   * these queries will usually match those from the corresponding Query or Queries message.
   *
   * Note: V1 protocol only supports sending disclosures as a response to a query.
   *
   * @param options multiple properties like protocol version to use, disclosure queries and thread id
   * (in case of disclosure as response to query)
   */
  public async discloseFeatures(options: DiscloseFeaturesOptions) {
    const service = this.getService(options.protocolVersion)

    const connection = await this.connectionService.getById(this.agentContext, options.connectionId)
    const { message: disclosuresMessage } = await service.createDisclosure({
      disclosureQueries: options.disclosureQueries,
      threadId: options.threadId,
    })

    const outboundMessageContext = new OutboundMessageContext(disclosuresMessage, {
      agentContext: this.agentContext,
      connection,
    })
    await this.messageSender.sendMessage(outboundMessageContext)
  }
}
