import type { DependencyManager, Module } from '../../plugins'

import { AgentConfig } from '../../agent/AgentConfig'

import { DcqlService } from './DcqlService'

/**
 * @public
 */
export class DcqlModule implements Module {
  /**
   * Registers the dependencies of the presentation-exchange module on the dependency manager.
   */
  public register(dependencyManager: DependencyManager) {
    // Warn about experimental module
    dependencyManager
      .resolve(AgentConfig)
      .logger.warn(
        "The 'DcqlModule' module is experimental and could have unexpected breaking changes. When using this module, make sure to use strict versions for all @credo-ts packages."
      )

    // service
    dependencyManager.registerSingleton(DcqlService)
  }
}
