import type { DummyModuleConfigOptions } from './DummyModuleConfig'
import type { AgentContext, DependencyManager, Module } from '@credo-ts/core'

import { FeatureRegistry, MessageHandlerRegistry, Protocol } from '@credo-ts/didcomm'

import { DummyApi } from './DummyApi'
import { DummyModuleConfig } from './DummyModuleConfig'
import { DummyRequestHandler, DummyResponseHandler } from './handlers'
import { DummyRepository } from './repository'
import { DummyService } from './services'

export class DummyModule implements Module {
  public readonly config: DummyModuleConfig

  public readonly api = DummyApi

  public constructor(config?: DummyModuleConfigOptions) {
    this.config = new DummyModuleConfig(config)
  }

  public register(dependencyManager: DependencyManager) {
    // Config
    dependencyManager.registerInstance(DummyModuleConfig, this.config)

    // Repository
    dependencyManager.registerSingleton(DummyRepository)

    // Service
    dependencyManager.registerSingleton(DummyService)
  }

  public async initialize(agentContext: AgentContext): Promise<void> {
    const messageHandlerRegistry = agentContext.dependencyManager.resolve(MessageHandlerRegistry)
    const featureRegistry = agentContext.dependencyManager.resolve(FeatureRegistry)
    const dummyService = agentContext.dependencyManager.resolve(DummyService)

    messageHandlerRegistry.registerMessageHandlers([
      new DummyRequestHandler(dummyService),
      new DummyResponseHandler(dummyService),
    ])

    featureRegistry.register(
      new Protocol({
        id: 'https://didcomm.org/dummy/1.0',
        roles: ['requester', 'responder'],
      })
    )
  }
}
