import type { MessagePickupModuleConfigOptions } from './MessagePickupModuleConfig'
import type { MessagePickupProtocol } from './protocol/MessagePickupProtocol'
import type { ApiModule, DependencyManager, AgentContext, Constructor, Optional } from '@credo-ts/core'

import { InjectionSymbols } from '@credo-ts/core'
import { FeatureRegistry } from '../../FeatureRegistry'
import { MessageHandlerRegistry } from '../../MessageHandlerRegistry'

import { MessagePickupApi } from './MessagePickupApi'
import { MessagePickupModuleConfig } from './MessagePickupModuleConfig'
import { V1MessagePickupProtocol, V2MessagePickupProtocol } from './protocol'
import { MessagePickupSessionService } from './services'
import { InMemoryMessagePickupRepository } from './storage'

/**
 * Default protocols that will be registered if the `protocols` property is not configured.
 */
export type DefaultMessagePickupProtocols = [V1MessagePickupProtocol, V2MessagePickupProtocol]

// MessagePickupModuleOptions makes the protocols property optional from the config, as it will set it when not provided.
export type MessagePickupModuleOptions<MessagePickupProtocols extends MessagePickupProtocol[]> = Optional<
  MessagePickupModuleConfigOptions<MessagePickupProtocols>,
  'protocols'
>

export class MessagePickupModule<MessagePickupProtocols extends MessagePickupProtocol[] = DefaultMessagePickupProtocols>
  implements ApiModule
{
  public readonly config: MessagePickupModuleConfig<MessagePickupProtocols>

  // Infer Api type from the config
  public readonly api: Constructor<MessagePickupApi<MessagePickupProtocols>> = MessagePickupApi

  public constructor(config?: MessagePickupModuleOptions<MessagePickupProtocols>) {
    this.config = new MessagePickupModuleConfig({
      ...config,
      protocols: config?.protocols ?? [new V1MessagePickupProtocol(), new V2MessagePickupProtocol()],
    }) as MessagePickupModuleConfig<MessagePickupProtocols>
  }

  /**
   * Registers the dependencies of the message pickup answer module on the dependency manager.
   */
  public register(dependencyManager: DependencyManager) {
    // Config
    dependencyManager.registerInstance(MessagePickupModuleConfig, this.config)

    // Services
    dependencyManager.registerSingleton(MessagePickupSessionService)

    // Message Pickup queue: use provided one or in-memory one if no injection symbol is yet defined
    if (this.config.messagePickupRepository) {
      dependencyManager.registerInstance(InjectionSymbols.MessagePickupRepository, this.config.messagePickupRepository)
    } else {
      if (!dependencyManager.isRegistered(InjectionSymbols.MessagePickupRepository)) {
        dependencyManager.registerSingleton(InjectionSymbols.MessagePickupRepository, InMemoryMessagePickupRepository)
      }
    }
  }

  public async initialize(agentContext: AgentContext): Promise<void> {
    // Protocol needs to register feature registry items and handlers
    const messageHandlerRegistry = agentContext.dependencyManager.resolve(MessageHandlerRegistry)
    const featureRegistry = agentContext.dependencyManager.resolve(FeatureRegistry)

    for (const protocol of this.config.protocols) {
      protocol.register(messageHandlerRegistry, featureRegistry)
    }

    const messagePickupSessionService = agentContext.dependencyManager.resolve(MessagePickupSessionService)

    messagePickupSessionService.start(agentContext)
  }
}
