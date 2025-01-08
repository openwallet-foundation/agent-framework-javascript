import type { EventEmitter } from '@credo-ts/core'
import type { Logger } from '@credo-ts/core'
import type { AgentMessage } from '../../../AgentMessage'
import type { FeatureRegistry } from '../../../FeatureRegistry'
import type { InboundMessageContext } from '../../../models'
import type { DiscoverFeaturesModuleConfig } from '../DiscoverFeaturesModuleConfig'
import type {
  CreateDisclosureOptions,
  CreateQueryOptions,
  DiscoverFeaturesProtocolMsgReturnType,
} from '../DiscoverFeaturesServiceOptions'

export abstract class DiscoverFeaturesService {
  protected featureRegistry: FeatureRegistry
  protected eventEmitter: EventEmitter
  protected logger: Logger
  protected discoverFeaturesModuleConfig: DiscoverFeaturesModuleConfig

  public constructor(
    featureRegistry: FeatureRegistry,
    eventEmitter: EventEmitter,
    logger: Logger,
    discoverFeaturesModuleConfig: DiscoverFeaturesModuleConfig
  ) {
    this.featureRegistry = featureRegistry
    this.eventEmitter = eventEmitter
    this.logger = logger
    this.discoverFeaturesModuleConfig = discoverFeaturesModuleConfig
  }

  public abstract readonly version: string

  public abstract createQuery(options: CreateQueryOptions): Promise<DiscoverFeaturesProtocolMsgReturnType<AgentMessage>>
  public abstract processQuery(
    messageContext: InboundMessageContext<AgentMessage>
  ): Promise<DiscoverFeaturesProtocolMsgReturnType<AgentMessage> | void>

  public abstract createDisclosure(
    options: CreateDisclosureOptions
  ): Promise<DiscoverFeaturesProtocolMsgReturnType<AgentMessage>>
  public abstract processDisclosure(messageContext: InboundMessageContext<AgentMessage>): Promise<void>
}
