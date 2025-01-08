import { FeatureRegistry } from '../../../agent/FeatureRegistry'
import { DependencyManager } from '../../../../plugins/DependencyManager'
import { OutOfBandModule } from '../OutOfBandModule'
import { OutOfBandService } from '../OutOfBandService'
import { OutOfBandRepository } from '../repository/OutOfBandRepository'

jest.mock('../../../plugins/DependencyManager')
const DependencyManagerMock = DependencyManager as jest.Mock<DependencyManager>

const dependencyManager = new DependencyManagerMock()

jest.mock('../../../agent/FeatureRegistry')
const FeatureRegistryMock = FeatureRegistry as jest.Mock<FeatureRegistry>

const featureRegistry = new FeatureRegistryMock()
describe('OutOfBandModule', () => {
  test('registers dependencies on the dependency manager', () => {
    new OutOfBandModule().register(dependencyManager, featureRegistry)

    expect(dependencyManager.registerSingleton).toHaveBeenCalledTimes(2)
    expect(dependencyManager.registerSingleton).toHaveBeenCalledWith(OutOfBandService)
    expect(dependencyManager.registerSingleton).toHaveBeenCalledWith(OutOfBandRepository)
  })
})
