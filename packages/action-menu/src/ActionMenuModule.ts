import type { AgentContext, DependencyManager, Module } from '@credo-ts/core'

import { FeatureRegistry, Protocol } from '@credo-ts/didcomm'

import { ActionMenuApi } from './ActionMenuApi'
import { ActionMenuRole } from './ActionMenuRole'
import { ActionMenuRepository } from './repository'
import { ActionMenuService } from './services'

/**
 * @public
 */
export class ActionMenuModule implements Module {
  public readonly api = ActionMenuApi

  /**
   * Registers the dependencies of the question answer module on the dependency manager.
   */
  public register(dependencyManager: DependencyManager) {
    // Services
    dependencyManager.registerSingleton(ActionMenuService)

    // Repositories
    dependencyManager.registerSingleton(ActionMenuRepository)
  }

  public async initialize(agentContext: AgentContext): Promise<void> {
    // Feature Registry
    const featureRegistry = agentContext.dependencyManager.resolve(FeatureRegistry)

    featureRegistry.register(
      new Protocol({
        id: 'https://didcomm.org/action-menu/1.0',
        roles: [ActionMenuRole.Requester, ActionMenuRole.Responder],
      })
    )
  }
}
