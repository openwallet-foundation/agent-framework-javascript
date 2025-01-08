import type { AgentContext, DependencyManager, Module } from '@credo-ts/core'

import { FeatureRegistry, Protocol } from '@credo-ts/didcomm'

import { QuestionAnswerApi } from './QuestionAnswerApi'
import { QuestionAnswerRole } from './QuestionAnswerRole'
import { QuestionAnswerRepository } from './repository'
import { QuestionAnswerService } from './services'

export class QuestionAnswerModule implements Module {
  public readonly api = QuestionAnswerApi

  /**
   * Registers the dependencies of the question answer module on the dependency manager.
   */
  public register(dependencyManager: DependencyManager) {
    // Services
    dependencyManager.registerSingleton(QuestionAnswerService)

    // Repositories
    dependencyManager.registerSingleton(QuestionAnswerRepository)
  }

  public async initialize(agentContext: AgentContext) {
    // Feature Registry
    const featureRegistry = agentContext.dependencyManager.resolve(FeatureRegistry)
    featureRegistry.register(
      new Protocol({
        id: 'https://didcomm.org/questionanswer/1.0',
        roles: [QuestionAnswerRole.Questioner, QuestionAnswerRole.Responder],
      })
    )
  }
}
