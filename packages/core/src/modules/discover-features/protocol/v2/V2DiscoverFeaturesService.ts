import type { InboundMessageContext } from '../../../../agent/models/InboundMessageContext'
import type {
  DiscoverFeaturesDisclosureReceivedEvent,
  DiscoverFeaturesQueryReceivedEvent,
} from '../../DiscoverFeaturesEvents'
import type {
  CreateQueryOptions,
  DiscoverFeaturesProtocolMsgReturnType,
  CreateDisclosureOptions,
} from '../../DiscoverFeaturesServiceOptions'

import { Dispatcher } from '../../../../agent/Dispatcher'
import { EventEmitter } from '../../../../agent/EventEmitter'
import { FeatureRegistry } from '../../../../agent/FeatureRegistry'
import { InjectionSymbols } from '../../../../constants'
import { Logger } from '../../../../logger'
import { inject, injectable } from '../../../../plugins'
import { DiscoverFeaturesEventTypes } from '../../DiscoverFeaturesEvents'
import { DiscoverFeaturesModuleConfig } from '../../DiscoverFeaturesModuleConfig'
import { DiscoverFeaturesService } from '../../services'

import { V2DisclosuresMessageHandler, V2QueriesMessageHandler } from './handlers'
import { V2QueriesMessage, V2DisclosuresMessage } from './messages'

@injectable()
export class V2DiscoverFeaturesService extends DiscoverFeaturesService {
  public constructor(
    featureRegistry: FeatureRegistry,
    eventEmitter: EventEmitter,
    dispatcher: Dispatcher,
    @inject(InjectionSymbols.Logger) logger: Logger,
    discoverFeaturesModuleConfig: DiscoverFeaturesModuleConfig
  ) {
    super(featureRegistry, eventEmitter, dispatcher, logger, discoverFeaturesModuleConfig)
    this.registerHandlers(dispatcher)
  }

  /**
   * The version of the discover features protocol this service supports
   */
  public readonly version = 'v2'

  private registerHandlers(dispatcher: Dispatcher) {
    dispatcher.registerHandler(new V2DisclosuresMessageHandler(this))
    dispatcher.registerHandler(new V2QueriesMessageHandler(this))
  }

  public async createQuery(
    options: CreateQueryOptions
  ): Promise<DiscoverFeaturesProtocolMsgReturnType<V2QueriesMessage>> {
    const queryMessage = new V2QueriesMessage({ queries: options.queries })

    return { message: queryMessage }
  }

  public async processQuery(
    messageContext: InboundMessageContext<V2QueriesMessage>
  ): Promise<DiscoverFeaturesProtocolMsgReturnType<V2DisclosuresMessage> | void> {
    const { queries, threadId } = messageContext.message

    const connection = messageContext.assertReadyConnection()

    this.eventEmitter.emit<DiscoverFeaturesQueryReceivedEvent>(messageContext.agentContext, {
      type: DiscoverFeaturesEventTypes.QueryReceived,
      payload: {
        message: messageContext.message,
        connection,
        queries,
        protocolVersion: this.version,
        threadId,
      },
    })

    // Process query and send responde automatically if configured to do so, otherwise
    // just send the event and let controller decide
    if (this.discoverFeaturesModuleConfig.autoAcceptQueries) {
      return await this.createDisclosure({
        threadId,
        disclosureQueries: queries,
      })
    }
  }

  public async createDisclosure(
    options: CreateDisclosureOptions
  ): Promise<DiscoverFeaturesProtocolMsgReturnType<V2DisclosuresMessage>> {
    const matches = this.featureRegistry.query(...options.disclosureQueries)

    const discloseMessage = new V2DisclosuresMessage({
      threadId: options.threadId,
      features: matches,
    })

    return { message: discloseMessage }
  }

  public async processDisclosure(messageContext: InboundMessageContext<V2DisclosuresMessage>): Promise<void> {
    const { disclosures, threadId } = messageContext.message

    const connection = messageContext.assertReadyConnection()

    this.eventEmitter.emit<DiscoverFeaturesDisclosureReceivedEvent>(messageContext.agentContext, {
      type: DiscoverFeaturesEventTypes.DisclosureReceived,
      payload: {
        message: messageContext.message,
        connection,
        disclosures,
        protocolVersion: this.version,
        threadId,
      },
    })
  }
}
