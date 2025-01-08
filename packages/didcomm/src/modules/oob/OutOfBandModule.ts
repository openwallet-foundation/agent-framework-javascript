import { AgentContext } from '@credo-ts/core'
import type { DependencyManager, Module } from '@credo-ts/core'

import { FeatureRegistry } from '../../FeatureRegistry'
import { Protocol } from '../../models'

import { OutOfBandApi } from './OutOfBandApi'
import { OutOfBandService } from './OutOfBandService'
import { OutOfBandRepository } from './repository'

export class OutOfBandModule implements Module {
  public readonly api = OutOfBandApi

  /**
   * Registers the dependencies of the ot of band module on the dependency manager.
   */
  public register(dependencyManager: DependencyManager) {
    // Services
    dependencyManager.registerSingleton(OutOfBandService)

    // Repositories
    dependencyManager.registerSingleton(OutOfBandRepository)
  }

  public async initialize(agentContext: AgentContext): Promise<void> {
    // Features
    const featureRegistry = agentContext.dependencyManager.resolve(FeatureRegistry)

    featureRegistry.register(
      new Protocol({
        id: 'https://didcomm.org/out-of-band/1.1',
        roles: ['sender', 'receiver'],
      })
    )
  }
}
