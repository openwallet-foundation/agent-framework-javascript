import type { AgentContext, DependencyManager, Module } from '@credo-ts/core'

import { FeatureRegistry } from '../../FeatureRegistry'
import { Protocol } from '../../models'

import { BasicMessageRole } from './BasicMessageRole'
import { BasicMessagesApi } from './BasicMessagesApi'
import { BasicMessageRepository } from './repository'
import { BasicMessageService } from './services'

export class BasicMessagesModule implements Module {
  public readonly api = BasicMessagesApi

  /**
   * Registers the dependencies of the basic message module on the dependency manager.
   */
  public register(dependencyManager: DependencyManager) {
    // Services
    dependencyManager.registerSingleton(BasicMessageService)

    // Repositories
    dependencyManager.registerSingleton(BasicMessageRepository)
  }

  public async initialize(agentContext: AgentContext): Promise<void> {
    const featureRegistry = agentContext.dependencyManager.resolve(FeatureRegistry)

    featureRegistry.register(
      new Protocol({
        id: 'https://didcomm.org/basicmessage/1.0',
        roles: [BasicMessageRole.Sender, BasicMessageRole.Receiver],
      })
    )
  }
}
