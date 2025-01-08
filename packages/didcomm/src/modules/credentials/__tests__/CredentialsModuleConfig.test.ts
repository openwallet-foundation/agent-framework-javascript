import type { CredentialProtocol } from '../protocol/CredentialProtocol'

import { CredentialsModuleConfig } from '../CredentialsModuleConfig'
import { AutoAcceptCredential } from '../models'

describe('CredentialsModuleConfig', () => {
  test('sets default values', () => {
    const config = new CredentialsModuleConfig({
      credentialProtocols: [],
    })

    expect(config.autoAcceptCredentials).toBe(AutoAcceptCredential.Never)
    expect(config.credentialProtocols).toEqual([])
  })

  test('sets values', () => {
    const credentialProtocol = jest.fn() as unknown as CredentialProtocol
    const config = new CredentialsModuleConfig({
      autoAcceptCredentials: AutoAcceptCredential.Always,
      credentialProtocols: [credentialProtocol],
    })

    expect(config.autoAcceptCredentials).toBe(AutoAcceptCredential.Always)
    expect(config.credentialProtocols).toEqual([credentialProtocol])
  })
})
