import { DependencyManager } from '../../../../plugins/DependencyManager'
import { FeatureRegistry } from '../../FeatureRegistry'
import { Protocol } from '../../models'
import { DiscoverFeaturesModule } from '../DiscoverFeaturesModule'
import { V1DiscoverFeaturesService } from '../protocol/v1'
import { V2DiscoverFeaturesService } from '../protocol/v2'

jest.mock('../../../../plugins/DependencyManager')
const DependencyManagerMock = DependencyManager as jest.Mock<DependencyManager>

jest.mock('../../FeatureRegistry')
const FeatureRegistryMock = FeatureRegistry as jest.Mock<FeatureRegistry>

const dependencyManager = new DependencyManagerMock()
const featureRegistry = new FeatureRegistryMock()

describe('DiscoverFeaturesModule', () => {
  test('registers dependencies on the dependency manager', () => {
    new DiscoverFeaturesModule().register(dependencyManager, featureRegistry)

    expect(dependencyManager.registerSingleton).toHaveBeenCalledTimes(2)
    expect(dependencyManager.registerSingleton).toHaveBeenCalledWith(V1DiscoverFeaturesService)
    expect(dependencyManager.registerSingleton).toHaveBeenCalledWith(V2DiscoverFeaturesService)

    expect(featureRegistry.register).toHaveBeenCalledWith(
      new Protocol({
        id: 'https://didcomm.org/discover-features/1.0',
        roles: ['requester', 'responder'],
      }),
      new Protocol({
        id: 'https://didcomm.org/discover-features/2.0',
        roles: ['requester', 'responder'],
      })
    )
  })
})
