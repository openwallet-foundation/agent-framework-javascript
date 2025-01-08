import type { DependencyManager } from '../../../core/src/plugins/DependencyManager'
import type { FeatureRegistry } from '@credo-ts/didcomm'

import { DrpcModule } from '../DrpcModule'
import { DrpcRepository } from '../repository'
import { DrpcService } from '../services'

const featureRegistry = {
  register: jest.fn(),
} as unknown as FeatureRegistry

const dependencyManager = {
  registerInstance: jest.fn(),
  registerSingleton: jest.fn(),
  registerContextScoped: jest.fn(),
  resolve: () => featureRegistry,
} as unknown as DependencyManager

describe('DrpcModule', () => {
  test('registers dependencies on the dependency manager', () => {
    new DrpcModule().register(dependencyManager)

    expect(dependencyManager.registerSingleton).toHaveBeenCalledTimes(2)
    expect(dependencyManager.registerSingleton).toHaveBeenCalledWith(DrpcService)
    expect(dependencyManager.registerSingleton).toHaveBeenCalledWith(DrpcRepository)
  })
})
