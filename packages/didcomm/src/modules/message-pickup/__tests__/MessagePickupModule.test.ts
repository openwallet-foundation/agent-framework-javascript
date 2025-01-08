import { DependencyManager } from '@credo-ts/core/src/plugins'
import { FeatureRegistry } from '../../../FeatureRegistry'
import { MessagePickupModule } from '../MessagePickupModule'
import { MessagePickupModuleConfig } from '../MessagePickupModuleConfig'
import { MessagePickupSessionService } from '../services'
import { InMemoryMessagePickupRepository } from '../storage'

jest.mock('../../../../plugins')
const DependencyManagerMock = DependencyManager as jest.Mock<DependencyManager>

jest.mock('../../FeatureRegistry')
const FeatureRegistryMock = FeatureRegistry as jest.Mock<FeatureRegistry>

const dependencyManager = new DependencyManagerMock()
const featureRegistry = new FeatureRegistryMock()

describe('MessagePickupModule', () => {
  test('registers dependencies on the dependency manager', () => {
    const module = new MessagePickupModule()
    module.register(dependencyManager, featureRegistry)

    expect(dependencyManager.registerInstance).toHaveBeenCalledTimes(1)
    expect(dependencyManager.registerInstance).toHaveBeenCalledWith(MessagePickupModuleConfig, module.config)

    expect(dependencyManager.registerSingleton).toHaveBeenCalledTimes(2)
    expect(dependencyManager.registerSingleton).toHaveBeenCalledWith(
      InjectionSymbols.MessagePickupRepository,
      InMemoryMessagePickupRepository
    )
    expect(dependencyManager.registerSingleton).toHaveBeenCalledWith(MessagePickupSessionService)
    expect(featureRegistry.register).toHaveBeenCalledTimes(2)
    expect(featureRegistry.register).toHaveBeenCalledWith(
      new Protocol({
        id: 'https://didcomm.org/messagepickup/1.0',
        roles: ['message_holder', 'recipient', 'batch_sender', 'batch_recipient'],
      })
    )
    expect(featureRegistry.register).toHaveBeenCalledWith(
      new Protocol({
        id: 'https://didcomm.org/messagepickup/2.0',
        roles: ['mediator', 'recipient'],
      })
    )
  })
})
