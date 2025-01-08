import { DidCommModuleConfig } from '../DidCommModuleConfig'

describe('DidCommModuleConfig', () => {
  describe('endpoints', () => {
    it('should return the config endpoint if no inbound connection is available', () => {
      const endpoint = 'https://local-url.com'

      const didcommConfig = new DidCommModuleConfig({ endpoints: [endpoint] })

      expect(didcommConfig.endpoints).toEqual([endpoint])
    })

    it("should return ['didcomm:transport/queue'] if no inbound connection or config endpoint or host/port is available", () => {
      const didcommConfig = new DidCommModuleConfig()

      expect(didcommConfig.endpoints).toStrictEqual(['didcomm:transport/queue'])
    })

    it('should return the new config endpoint after setter is called', () => {
      const endpoint = 'https://local-url.com'
      const newEndpoint = 'https://new-local-url.com'

      const didcommConfig = new DidCommModuleConfig({ endpoints: [endpoint] })

      didcommConfig.endpoints = [newEndpoint]
      expect(didcommConfig.endpoints).toEqual([newEndpoint])
    })
  })
})
