import { FeatureRegistry } from '../../../agent/FeatureRegistry'
import { DependencyManager } from '@credo-ts/core/src/plugins/DependencyManager'
import { MediatorModule } from '../MediatorModule'
import { MediationRepository, MediatorRoutingRepository } from '../repository'
import { MediatorService } from '../services'

jest.mock('../../../plugins/DependencyManager')
const DependencyManagerMock = DependencyManager as jest.Mock<DependencyManager>

const dependencyManager = new DependencyManagerMock()

jest.mock('../../../agent/FeatureRegistry')
const FeatureRegistryMock = FeatureRegistry as jest.Mock<FeatureRegistry>

const featureRegistry = new FeatureRegistryMock()
describe('MediatorModule', () => {
  test('registers dependencies on the dependency manager', () => {
    new MediatorModule().register(dependencyManager, featureRegistry)

    expect(dependencyManager.registerSingleton).toHaveBeenCalledTimes(3)
    expect(dependencyManager.registerSingleton).toHaveBeenCalledWith(MediatorService)
    expect(dependencyManager.registerSingleton).toHaveBeenCalledWith(MediationRepository)
    expect(dependencyManager.registerSingleton).toHaveBeenCalledWith(MediatorRoutingRepository)
  })
})
