import type { Module } from '../Module'
import type { DependencyContainer } from 'tsyringe'

import { container as rootContainer, injectable, Lifecycle } from 'tsyringe'

import { DependencyManager } from '../DependencyManager'

class Instance {
  public random = Math.random()
}
const instance = new Instance()

describe('DependencyManager', () => {
  let container: DependencyContainer
  let dependencyManager: DependencyManager

  beforeEach(() => {
    container = rootContainer.createChildContainer()
    dependencyManager = new DependencyManager(container)
  })

  afterEach(() => {
    jest.resetAllMocks()
    container.reset()
  })

  describe('registerModules', () => {
    it('calls the register method for all module plugins', () => {
      @injectable()
      class Module1 implements Module {
        public register = jest.fn()
      }

      @injectable()
      class Module2 implements Module {
        public register = jest.fn()
      }

      const module1 = new Module1()
      const module2 = new Module2()

      dependencyManager.registerModules({ module1, module2 })
      expect(module1.register).toHaveBeenCalledTimes(1)
      expect(module1.register).toHaveBeenLastCalledWith(dependencyManager)

      expect(module2.register).toHaveBeenCalledTimes(1)
      expect(module2.register).toHaveBeenLastCalledWith(dependencyManager)

      expect(dependencyManager.registeredModules).toMatchObject({
        module1,
        module2,
      })
    })
  })

  describe('registerSingleton', () => {
    it('calls registerSingleton on the container', () => {
      class Singleton {}

      const registerSingletonSpy = jest.spyOn(container, 'registerSingleton')
      dependencyManager.registerSingleton(Singleton)

      expect(registerSingletonSpy).toHaveBeenLastCalledWith(Singleton, undefined)

      dependencyManager.registerSingleton(Singleton, 'Singleton')

      expect(registerSingletonSpy).toHaveBeenLastCalledWith(Singleton, 'Singleton')
    })
  })

  describe('resolve', () => {
    it('calls resolve on the container', () => {
      // FIXME: somehow this doesn't work if we don't create a child container
      const child = container.createChildContainer()
      const dependencyManager = new DependencyManager(child)
      child.registerInstance(Instance, instance)

      const resolveSpy = jest.spyOn(child, 'resolve')
      expect(dependencyManager.resolve(Instance)).toBe(instance)

      expect(resolveSpy).toHaveBeenCalledWith(Instance)
    })
  })

  describe('isRegistered', () => {
    it('calls isRegistered on the container', () => {
      class Singleton {}

      const isRegisteredSpy = jest.spyOn(container, 'isRegistered')

      expect(dependencyManager.isRegistered(Singleton)).toBe(false)

      expect(isRegisteredSpy).toHaveBeenCalledTimes(1)
    })
  })

  describe('registerInstance', () => {
    it('calls registerInstance on the container', () => {
      class Instance {}
      const instance = new Instance()

      const registerInstanceSpy = jest.spyOn(container, 'registerInstance')

      dependencyManager.registerInstance(Instance, instance)

      expect(registerInstanceSpy).toHaveBeenCalledWith(Instance, instance)
    })
  })

  describe('registerContextScoped', () => {
    it('calls register on the container with Lifecycle.ContainerScoped', () => {
      class SomeService {}

      const registerSpy = jest.spyOn(container, 'register')

      dependencyManager.registerContextScoped(SomeService)
      expect(registerSpy).toHaveBeenCalledWith(SomeService, SomeService, { lifecycle: Lifecycle.ContainerScoped })
      registerSpy.mockClear()

      dependencyManager.registerContextScoped('SomeService', SomeService)
      expect(registerSpy).toHaveBeenCalledWith('SomeService', SomeService, { lifecycle: Lifecycle.ContainerScoped })
    })
  })

  describe('createChild', () => {
    it('calls createChildContainer on the container', () => {
      const createChildSpy = jest.spyOn(container, 'createChildContainer')

      const childDependencyManager = dependencyManager.createChild()
      expect(createChildSpy).toHaveBeenCalledTimes(1)
      expect(childDependencyManager.container).toBe(createChildSpy.mock.results[0].value)
    })

    it('inherits the registeredModules from the parent dependency manager', () => {
      const module = {
        register: jest.fn(),
      }

      dependencyManager.registerModules({
        module1: module,
        module2: module,
      })

      const childDependencyManager = dependencyManager.createChild()
      expect(childDependencyManager.registeredModules).toMatchObject({
        module1: module,
        module2: module,
      })
    })
  })
})
