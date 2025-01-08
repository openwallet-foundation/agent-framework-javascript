import type { MediationRecipientModuleConfigOptions } from './MediationRecipientModuleConfig'
import type { AgentContext, DependencyManager, Module } from '@credo-ts/core'

import { FeatureRegistry } from '../../FeatureRegistry'
import { Protocol } from '../../models'

import { MediationRecipientApi } from './MediationRecipientApi'
import { MediationRecipientModuleConfig } from './MediationRecipientModuleConfig'
import { MediationRole } from './models'
import { MediationRepository } from './repository'
import { MediationRecipientService, RoutingService } from './services'

export class MediationRecipientModule implements Module {
  public readonly config: MediationRecipientModuleConfig
  public readonly api = MediationRecipientApi

  public constructor(config?: MediationRecipientModuleConfigOptions) {
    this.config = new MediationRecipientModuleConfig(config)
  }

  /**
   * Registers the dependencies of the mediator recipient module on the dependency manager.
   */
  public register(dependencyManager: DependencyManager) {
    // Config
    dependencyManager.registerInstance(MediationRecipientModuleConfig, this.config)

    // Services
    dependencyManager.registerSingleton(MediationRecipientService)
    dependencyManager.registerSingleton(RoutingService)

    // Repositories
    dependencyManager.registerSingleton(MediationRepository)
  }

  public async initialize(agentContext: AgentContext): Promise<void> {
    const featureRegistry = agentContext.dependencyManager.resolve(FeatureRegistry)

    featureRegistry.register(
      new Protocol({
        id: 'https://didcomm.org/coordinate-mediation/1.0',
        roles: [MediationRole.Recipient],
      })
    )
  }
}
