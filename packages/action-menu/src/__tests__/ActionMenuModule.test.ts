import type { DependencyManager } from '@credo-ts/core'
import type { FeatureRegistry } from '@credo-ts/didcomm'

import { Protocol } from '@credo-ts/didcomm'

import { getAgentContext } from '../../../core/tests'
import { ActionMenuModule } from '../ActionMenuModule'
import { ActionMenuRole } from '../ActionMenuRole'
import { ActionMenuRepository } from '../repository'
import { ActionMenuService } from '../services'

const featureRegistry = {
  register: jest.fn(),
} as unknown as FeatureRegistry

const dependencyManager = {
  registerInstance: jest.fn(),
  registerSingleton: jest.fn(),
  registerContextScoped: jest.fn(),
  resolve: () => featureRegistry,
} as unknown as DependencyManager

describe('ActionMenuModule', () => {
  test('registers dependencies on the dependency manager', async () => {
    const actionMenuModule = new ActionMenuModule()
    actionMenuModule.register(dependencyManager)

    expect(dependencyManager.registerSingleton).toHaveBeenCalledTimes(2)
    expect(dependencyManager.registerSingleton).toHaveBeenCalledWith(ActionMenuService)
    expect(dependencyManager.registerSingleton).toHaveBeenCalledWith(ActionMenuRepository)
    expect(featureRegistry.register).toHaveBeenCalledTimes(0)

    await actionMenuModule.initialize(getAgentContext({ dependencyManager }))

    expect(featureRegistry.register).toHaveBeenCalledTimes(1)
    expect(featureRegistry.register).toHaveBeenCalledWith(
      new Protocol({
        id: 'https://didcomm.org/action-menu/1.0',
        roles: [ActionMenuRole.Requester, ActionMenuRole.Responder],
      })
    )
  })
})
