import type { FeatureRegistry } from '../../../FeatureRegistry'
import type { DependencyManager } from '@credo-ts/core'

import { BasicMessagesModule } from '../BasicMessagesModule'
import { BasicMessageRepository } from '../repository'
import { BasicMessageService } from '../services'

const featureRegistry = {
  register: jest.fn(),
} as unknown as FeatureRegistry

const dependencyManager = {
  registerInstance: jest.fn(),
  registerSingleton: jest.fn(),
  registerContextScoped: jest.fn(),
  resolve: () => featureRegistry,
} as unknown as DependencyManager

describe('BasicMessagesModule', () => {
  test('registers dependencies on the dependency manager', () => {
    new BasicMessagesModule().register(dependencyManager)

    expect(dependencyManager.registerSingleton).toHaveBeenCalledTimes(2)
    expect(dependencyManager.registerSingleton).toHaveBeenCalledWith(BasicMessageService)
    expect(dependencyManager.registerSingleton).toHaveBeenCalledWith(BasicMessageRepository)
  })
})
