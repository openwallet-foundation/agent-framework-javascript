import type { Module } from '../../plugins'

import { BasicMessagesModule } from '../../modules/basic-messages'
import { CacheModule } from '../../modules/cache'
import { ConnectionsModule } from '../../modules/connections'
import { CredentialsModule } from '../../modules/credentials'
import { DcqlModule } from '../../modules/dcql'
import { DidsModule } from '../../modules/dids'
import { DifPresentationExchangeModule } from '../../modules/dif-presentation-exchange'
import { DiscoverFeaturesModule } from '../../modules/discover-features'
import { GenericRecordsModule } from '../../modules/generic-records'
import { MdocModule } from '../../modules/mdoc'
import { MessagePickupModule } from '../../modules/message-pickup'
import { OutOfBandModule } from '../../modules/oob'
import { ProofsModule } from '../../modules/proofs'
import { MediationRecipientModule, MediatorModule } from '../../modules/routing'
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
        connections: expect.any(ConnectionsModule),
        credentials: expect.any(CredentialsModule),
        proofs: expect.any(ProofsModule),
        mediator: expect.any(MediatorModule),
        mediationRecipient: expect.any(MediationRecipientModule),
        messagePickup: expect.any(MessagePickupModule),
        basicMessages: expect.any(BasicMessagesModule),
        pex: expect.any(DifPresentationExchangeModule),
        dcql: expect.any(DcqlModule),
        genericRecords: expect.any(GenericRecordsModule),
        discovery: expect.any(DiscoverFeaturesModule),
        dids: expect.any(DidsModule),
        wallet: expect.any(WalletModule),
        oob: expect.any(OutOfBandModule),
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
        connections: expect.any(ConnectionsModule),
        credentials: expect.any(CredentialsModule),
        proofs: expect.any(ProofsModule),
        mediator: expect.any(MediatorModule),
        mediationRecipient: expect.any(MediationRecipientModule),
        messagePickup: expect.any(MessagePickupModule),
        basicMessages: expect.any(BasicMessagesModule),
        pex: expect.any(DifPresentationExchangeModule),
        dcql: expect.any(DcqlModule),
        genericRecords: expect.any(GenericRecordsModule),
        discovery: expect.any(DiscoverFeaturesModule),
        dids: expect.any(DidsModule),
        wallet: expect.any(WalletModule),
        oob: expect.any(OutOfBandModule),
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
      const connections = new ConnectionsModule()
      const extendedModules = extendModulesWithDefaultModules({
        myModule,
        connections,
      })

      expect(extendedModules).toEqual({
        connections: connections,
        credentials: expect.any(CredentialsModule),
        proofs: expect.any(ProofsModule),
        mediator: expect.any(MediatorModule),
        mediationRecipient: expect.any(MediationRecipientModule),
        messagePickup: expect.any(MessagePickupModule),
        basicMessages: expect.any(BasicMessagesModule),
        pex: expect.any(DifPresentationExchangeModule),
        dcql: expect.any(DcqlModule),
        genericRecords: expect.any(GenericRecordsModule),
        discovery: expect.any(DiscoverFeaturesModule),
        dids: expect.any(DidsModule),
        wallet: expect.any(WalletModule),
        oob: expect.any(OutOfBandModule),
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
