import type { DependencyManager } from '../../../plugins'

import { X509ModuleConfig, X509Module, type X509ModuleConfigOptions, X509Service } from './../index'

const dependencyManager = {
  registerInstance: jest.fn(),
  registerSingleton: jest.fn(),
  registerContextScoped: jest.fn(),
  resolve: jest.fn().mockReturnValue({ logger: { warn: jest.fn() } }),
} as unknown as DependencyManager

describe('X509ServiceModule', () => {
  test('registers dependencies on the dependency manager', async () => {
    const options: X509ModuleConfigOptions = { trustedCertificates: ['certificate'] }
    const x509Module = new X509Module(options)

    x509Module.register(dependencyManager)

    expect(dependencyManager.registerInstance).toHaveBeenCalledTimes(1)
    expect(dependencyManager.registerInstance).toHaveBeenCalledWith(X509ModuleConfig, new X509ModuleConfig(options))

    expect(dependencyManager.registerSingleton).toHaveBeenCalledTimes(1)
    expect(dependencyManager.registerSingleton).toHaveBeenCalledWith(X509Service)

    expect(x509Module.config.trustedCertificates).toBeDefined()
    expect(x509Module.config.trustedCertificates).toHaveLength(1)
    expect(x509Module.config.trustedCertificates).toContain('certificate')

    x509Module.config.addTrustedCertificate('certificate2')
    expect(x509Module.config.trustedCertificates).toHaveLength(2)

    x509Module.config.setTrustedCertificates(undefined)
    expect(x509Module.config.trustedCertificates).toBeUndefined()
  })
})
