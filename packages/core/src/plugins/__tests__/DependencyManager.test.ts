import { container as rootContainer, injectable, Lifecycle } from 'tsyringe'

import { DependencyManager } from '../DependencyManager'
import { module } from '../Module'

class Instance {
  public random = Math.random()
}
const instance = new Instance()

const container = rootContainer.createChildContainer()
const dependencyManager = new DependencyManager(container)

describe('DependencyManager', () => {
  afterEach(() => {
    jest.resetAllMocks()
    container.reset()
  })

  describe('registerModules', () => {
    it('calls the register method for all module plugins', () => {
      @module()
      @injectable()
      class Module1 {
        public static register = jest.fn()
      }

      @module()
      @injectable()
      class Module2 {
        public static register = jest.fn()
      }

      dependencyManager.registerModules(Module1, Module2)
      expect(Module1.register).toHaveBeenCalledTimes(1)
      expect(Module1.register).toHaveBeenLastCalledWith(dependencyManager)

      expect(Module2.register).toHaveBeenCalledTimes(1)
      expect(Module2.register).toHaveBeenLastCalledWith(dependencyManager)
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
  })
})
