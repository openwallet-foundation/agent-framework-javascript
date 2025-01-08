import type { DiscoverFeaturesModuleConfigOptions } from './DiscoverFeaturesModuleConfig'
import type { DependencyManager, Module } from '@credo-ts/core'

import { FeatureRegistry } from '../../FeatureRegistry'
import { Protocol } from '../../models'

import { DiscoverFeaturesApi } from './DiscoverFeaturesApi'
import { DiscoverFeaturesModuleConfig } from './DiscoverFeaturesModuleConfig'
import { V1DiscoverFeaturesService } from './protocol/v1'
import { V2DiscoverFeaturesService } from './protocol/v2'
import { AgentContext } from '@credo-ts/core'

export class DiscoverFeaturesModule implements Module {
  public readonly api = DiscoverFeaturesApi
  public readonly config: DiscoverFeaturesModuleConfig

  public constructor(config?: DiscoverFeaturesModuleConfigOptions) {
    this.config = new DiscoverFeaturesModuleConfig(config)
  }

  /**
   * Registers the dependencies of the discover features module on the dependency manager.
   */
  public register(dependencyManager: DependencyManager) {
    // Config
    dependencyManager.registerInstance(DiscoverFeaturesModuleConfig, this.config)

    // Services
    dependencyManager.registerSingleton(V1DiscoverFeaturesService)
    dependencyManager.registerSingleton(V2DiscoverFeaturesService)
  }

  public async initialize(agentContext: AgentContext): Promise<void> {
    // Features
    const featureRegistry = agentContext.dependencyManager.resolve(FeatureRegistry)

    featureRegistry.register(
      new Protocol({
        id: 'https://didcomm.org/discover-features/1.0',
        roles: ['requester', 'responder'],
      }),
      new Protocol({
        id: 'https://didcomm.org/discover-features/2.0',
        roles: ['requester', 'responder'],
      })
    )
  }
}
