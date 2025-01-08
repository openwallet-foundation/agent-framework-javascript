import type { DependencyManager } from '../../../plugins/DependencyManager'
import type { FeatureRegistry } from '../../didcomm'
import type { ProofProtocol } from '../protocol/ProofProtocol'

import { ProofsModule } from '../ProofsModule'
import { ProofsModuleConfig } from '../ProofsModuleConfig'
import { V2ProofProtocol } from '../protocol/v2/V2ProofProtocol'
import { ProofRepository } from '../repository'

const featureRegistry = {
  register: jest.fn(),
} as unknown as FeatureRegistry

const dependencyManager = {
  registerInstance: jest.fn(),
  registerSingleton: jest.fn(),
  registerContextScoped: jest.fn(),
  resolve: () => featureRegistry,
} as unknown as DependencyManager

describe('ProofsModule', () => {
  test('registers dependencies on the dependency manager', () => {
    const proofsModule = new ProofsModule({
      proofProtocols: [],
    })
    proofsModule.register(dependencyManager)

    expect(dependencyManager.registerInstance).toHaveBeenCalledTimes(1)
    expect(dependencyManager.registerInstance).toHaveBeenCalledWith(ProofsModuleConfig, proofsModule.config)

    expect(dependencyManager.registerSingleton).toHaveBeenCalledTimes(1)
    expect(dependencyManager.registerSingleton).toHaveBeenCalledWith(ProofRepository)
  })

  test('registers V2ProofProtocol if no proofProtocols are configured', () => {
    const proofsModule = new ProofsModule()

    expect(proofsModule.config.proofProtocols).toEqual([expect.any(V2ProofProtocol)])
  })

  test('calls register on the provided ProofProtocols', () => {
    const registerMock = jest.fn()
    const proofProtocol = {
      register: registerMock,
    } as unknown as ProofProtocol

    const proofsModule = new ProofsModule({
      proofProtocols: [proofProtocol],
    })

    expect(proofsModule.config.proofProtocols).toEqual([proofProtocol])

    proofsModule.register(dependencyManager)

    expect(registerMock).toHaveBeenCalledTimes(1)
    expect(registerMock).toHaveBeenCalledWith(dependencyManager, featureRegistry)
  })
})
