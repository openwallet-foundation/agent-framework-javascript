import type { DependencyManager, Module } from '@aries-framework/core'

import {
  AnonCredsHolderServiceSymbol,
  AnonCredsIssuerServiceSymbol,
  AnonCredsVerifierServiceSymbol,
} from '@aries-framework/anoncreds'

import { AnonCredsRsHolderService, AnonCredsRsIssuerService, AnonCredsRsVerifierService } from './anoncreds'

export class AnonCredsRsModule implements Module {
  public register(dependencyManager: DependencyManager) {
    try {
      // eslint-disable-next-line import/no-extraneous-dependencies
      require('@hyperledger/anoncreds-nodejs')
    } catch (error) {
      try {
        require('@hyperledger/anoncreds-react-native')
      } catch (error) {
        throw new Error('Could not load anoncreds bindings')
      }
    }

    // Register services
    dependencyManager.registerInstance(AnonCredsHolderServiceSymbol, AnonCredsRsHolderService)
    dependencyManager.registerInstance(AnonCredsIssuerServiceSymbol, AnonCredsRsIssuerService)
    dependencyManager.registerInstance(AnonCredsVerifierServiceSymbol, AnonCredsRsVerifierService)
  }
}
