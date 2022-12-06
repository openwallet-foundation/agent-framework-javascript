import type { FeatureRegistry } from '../../agent/FeatureRegistry'
import type { DependencyManager, Module } from '../../plugins'
import type { ProofsModuleConfigOptions } from './ProofsModuleConfig'

import { Protocol } from '../../agent/models/features/Protocol'

import { ProofsApi } from './ProofsApi'
import { ProofsModuleConfig } from './ProofsModuleConfig'
import { V1ProofService } from './protocol/v1'
import { V2ProofService } from './protocol/v2'
import { ProofRepository } from './repository'
import { IndyProofFormatService } from './formats/indy/IndyProofFormatService'
import { PresentationExchangeProofFormatService } from './formats/presentation-exchange/PresentationExchangeProofFormatService'

export class ProofsModule implements Module {
  public readonly config: ProofsModuleConfig

  public constructor(config?: ProofsModuleConfigOptions) {
    this.config = new ProofsModuleConfig(config)
  }

  /**
   * Registers the dependencies of the proofs module on the dependency manager.
   */
  public register(dependencyManager: DependencyManager, featureRegistry: FeatureRegistry) {
    // Api
    dependencyManager.registerContextScoped(ProofsApi)

    // Config
    dependencyManager.registerInstance(ProofsModuleConfig, this.config)

    // Services
    dependencyManager.registerSingleton(V1ProofService)
    dependencyManager.registerSingleton(V2ProofService)

    // Repositories
    dependencyManager.registerSingleton(ProofRepository)

    // Features
    featureRegistry.register(
      new Protocol({
        id: 'https://didcomm.org/present-proof/1.0',
        roles: ['verifier', 'prover'],
      })
    )
    featureRegistry.register(
      new Protocol({
        id: 'https://didcomm.org/present-proof/2.0',
        roles: ['verifier', 'prover'],
      })
    )

    // Proof Formats
    dependencyManager.registerSingleton(IndyProofFormatService)
    dependencyManager.registerSingleton(PresentationExchangeProofFormatService)
  }
}
