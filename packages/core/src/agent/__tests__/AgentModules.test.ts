import type { Module } from '../../plugins'

import { CacheModule } from '../../modules/cache'
import { DidsModule } from '../../modules/dids'
import { DifPresentationExchangeModule } from '../../modules/dif-presentation-exchange'
import { GenericRecordsModule } from '../../modules/generic-records'
import { MdocModule } from '../../modules/mdoc'
import { SdJwtVcModule } from '../../modules/sd-jwt-vc'
import { W3cCredentialsModule } from '../../modules/vc'
import { X509Module } from '../../modules/x509'
import { DependencyManager, injectable } from '../../plugins'
import { WalletModule } from '../../wallet'
import { extendModulesWithDefaultModules, getAgentApi } from '../AgentModules'

@injectable()
class MyApi {}

class MyModuleWithApi implements Module {
  public api = MyApi
  public register() {
    // nothing to register
  }
}

class MyModuleWithoutApi implements Module {
  public register() {
    // nothing to register
  }
}

describe('AgentModules', () => {
  describe('getAgentApi', () => {
    test('returns object with all api instances for modules with public api in dependency manager', () => {
      const dependencyManager = new DependencyManager()

      dependencyManager.registerModules({
        withApi: new MyModuleWithApi(),
        withoutApi: new MyModuleWithoutApi(),
      })

      const api = getAgentApi(dependencyManager)

      expect(api).toEqual({
        withApi: expect.any(MyApi),
      })
    })
  })

  describe('extendModulesWithDefaultModules', () => {
    test('returns default modules if no modules were provided', () => {
      const extendedModules = extendModulesWithDefaultModules()

      expect(extendedModules).toEqual({
        pex: expect.any(DifPresentationExchangeModule),
        genericRecords: expect.any(GenericRecordsModule),
        dids: expect.any(DidsModule),
        wallet: expect.any(WalletModule),
        w3cCredentials: expect.any(W3cCredentialsModule),
        sdJwtVc: expect.any(SdJwtVcModule),
        mdoc: expect.any(MdocModule),
        x509: expect.any(X509Module),
        cache: expect.any(CacheModule),
      })
    })

    test('returns custom and default modules if custom modules are provided', () => {
      const myModule = new MyModuleWithApi()
      const extendedModules = extendModulesWithDefaultModules({
        myModule,
      })

      expect(extendedModules).toEqual({
        pex: expect.any(DifPresentationExchangeModule),
        genericRecords: expect.any(GenericRecordsModule),
        dids: expect.any(DidsModule),
        wallet: expect.any(WalletModule),
        w3cCredentials: expect.any(W3cCredentialsModule),
        cache: expect.any(CacheModule),
        sdJwtVc: expect.any(SdJwtVcModule),
        mdoc: expect.any(MdocModule),
        x509: expect.any(X509Module),
        myModule,
      })
    })

    test('does not override default module if provided as custom module', () => {
      const myModule = new MyModuleWithApi()
      const genericRecords = new GenericRecordsModule()
      const extendedModules = extendModulesWithDefaultModules({
        myModule,
        genericRecords,
      })

      expect(extendedModules).toEqual({
        genericRecords: genericRecords,
        pex: expect.any(DifPresentationExchangeModule),
        dids: expect.any(DidsModule),
        wallet: expect.any(WalletModule),
        w3cCredentials: expect.any(W3cCredentialsModule),
        cache: expect.any(CacheModule),
        sdJwtVc: expect.any(SdJwtVcModule),
        mdoc: expect.any(MdocModule),
        x509: expect.any(X509Module),
        myModule,
      })
    })
  })
})
