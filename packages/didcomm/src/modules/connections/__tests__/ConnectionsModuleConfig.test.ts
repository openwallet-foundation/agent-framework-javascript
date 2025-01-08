import { ConnectionsModuleConfig } from '../ConnectionsModuleConfig'

describe('ConnectionsModuleConfig', () => {
  test('sets default values', () => {
    const config = new ConnectionsModuleConfig()

    expect(config.autoAcceptConnections).toBe(false)
  })

  test('sets values', () => {
    const config = new ConnectionsModuleConfig({
      autoAcceptConnections: true,
    })

    expect(config.autoAcceptConnections).toBe(true)
  })
})
