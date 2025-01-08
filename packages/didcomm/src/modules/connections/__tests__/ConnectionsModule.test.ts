import { FeatureRegistry } from '../../../agent/FeatureRegistry'
import { DependencyManager } from '@credo-ts/core/src/plugins/DependencyManager'
import { ConnectionsModule } from '../ConnectionsModule'
import { ConnectionsModuleConfig } from '../ConnectionsModuleConfig'
import { DidExchangeProtocol } from '../DidExchangeProtocol'
import { ConnectionRepository } from '../../../repository/connections'
import { ConnectionService, TrustPingService } from '../services'
import { DidRotateService } from '../services/DidRotateService'

jest.mock('../../../plugins/DependencyManager')
const DependencyManagerMock = DependencyManager as jest.Mock<DependencyManager>

const dependencyManager = new DependencyManagerMock()

jest.mock('../../../agent/FeatureRegistry')
const FeatureRegistryMock = FeatureRegistry as jest.Mock<FeatureRegistry>

const featureRegistry = new FeatureRegistryMock()

describe('ConnectionsModule', () => {
  test('registers dependencies on the dependency manager', () => {
    const connectionsModule = new ConnectionsModule()
    connectionsModule.register(dependencyManager, featureRegistry)

    expect(dependencyManager.registerInstance).toHaveBeenCalledTimes(1)
    expect(dependencyManager.registerInstance).toHaveBeenCalledWith(ConnectionsModuleConfig, connectionsModule.config)

    expect(dependencyManager.registerSingleton).toHaveBeenCalledTimes(5)
    expect(dependencyManager.registerSingleton).toHaveBeenCalledWith(ConnectionService)
    expect(dependencyManager.registerSingleton).toHaveBeenCalledWith(DidExchangeProtocol)
    expect(dependencyManager.registerSingleton).toHaveBeenCalledWith(TrustPingService)
    expect(dependencyManager.registerSingleton).toHaveBeenCalledWith(DidRotateService)
    expect(dependencyManager.registerSingleton).toHaveBeenCalledWith(ConnectionRepository)
  })
})
