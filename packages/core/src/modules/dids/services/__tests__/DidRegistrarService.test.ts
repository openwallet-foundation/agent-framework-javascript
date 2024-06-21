import type { DidDocument, DidRegistrar } from '../../domain'
import type { DidResolverService } from '../DidResolverService'

import { getAgentConfig, getAgentContext, mockFunction } from '../../../../../tests/helpers'
import { DidsModuleConfig } from '../../DidsModuleConfig'
import { DidRegistrarService } from '../DidRegistrarService'

const agentConfig = getAgentConfig('DidResolverService')
const agentContext = getAgentContext()

const didRegistrarMock = {
  supportedMethods: ['key'],
  create: jest.fn(),
  update: jest.fn(),
  deactivate: jest.fn(),
} as DidRegistrar

const didResolverMock = {
  invalidateCacheForDid: jest.fn(),
} as unknown as DidResolverService

const didRegistrarService = new DidRegistrarService(
  agentConfig.logger,
  new DidsModuleConfig({
    registrars: [didRegistrarMock],
  }),
  didResolverMock
)

describe('DidResolverService', () => {
  afterEach(() => {
    jest.clearAllMocks()
  })

  describe('create', () => {
    it('should correctly find and call the correct registrar for a specified did', async () => {
      const returnValue = {
        didDocumentMetadata: {},
        didRegistrationMetadata: {},
        didState: {
          state: 'failed',
          reason: ':(',
        },
      } as const
      mockFunction(didRegistrarMock.create).mockResolvedValue(returnValue)

      const result = await didRegistrarService.create(agentContext, { did: 'did:key:xxxx' })
      expect(result).toEqual(returnValue)

      expect(didRegistrarMock.create).toHaveBeenCalledTimes(1)
      expect(didRegistrarMock.create).toHaveBeenCalledWith(agentContext, { did: 'did:key:xxxx' })
    })

    it('should return error state failed if no did or method is provided', async () => {
      const result = await didRegistrarService.create(agentContext, {})

      expect(result).toEqual({
        didDocumentMetadata: {},
        didRegistrationMetadata: {},
        didState: {
          state: 'failed',
          did: undefined,
          reason: 'Either did OR method must be specified',
        },
      })
    })

    it('should return error state failed if both did and method are provided', async () => {
      const result = await didRegistrarService.create(agentContext, { did: 'did:key:xxxx', method: 'key' })

      expect(result).toEqual({
        didDocumentMetadata: {},
        didRegistrationMetadata: {},
        didState: {
          state: 'failed',
          did: 'did:key:xxxx',
          reason: 'Either did OR method must be specified',
        },
      })
    })

    it('should return error state failed if no method could be extracted from the did or method', async () => {
      const result = await didRegistrarService.create(agentContext, { did: 'did:a' })

      expect(result).toEqual({
        didDocumentMetadata: {},
        didRegistrationMetadata: {},
        didState: {
          state: 'failed',
          did: 'did:a',
          reason: 'Could not extract method from did did:a',
        },
      })
    })

    it('should return error with state failed if the did has no registrar', async () => {
      const result = await didRegistrarService.create(agentContext, { did: 'did:something:123' })

      expect(result).toEqual({
        didDocumentMetadata: {},
        didRegistrationMetadata: {},
        didState: {
          state: 'failed',
          did: 'did:something:123',
          reason: "Unsupported did method: 'something'",
        },
      })
    })
  })

  describe('update', () => {
    it('should correctly find and call the correct registrar for a specified did', async () => {
      const returnValue = {
        didDocumentMetadata: {},
        didRegistrationMetadata: {},
        didState: {
          state: 'failed',
          reason: ':(',
        },
      } as const
      mockFunction(didRegistrarMock.update).mockResolvedValue(returnValue)

      const didDocument = {} as unknown as DidDocument

      const result = await didRegistrarService.update(agentContext, { did: 'did:key:xxxx', didDocument })
      expect(result).toEqual(returnValue)

      expect(didResolverMock.invalidateCacheForDid).toHaveBeenCalledTimes(1)
      expect(didRegistrarMock.update).toHaveBeenCalledTimes(1)
      expect(didRegistrarMock.update).toHaveBeenCalledWith(agentContext, { did: 'did:key:xxxx', didDocument })
    })

    it('should return error state failed if no method could be extracted from the did', async () => {
      const result = await didRegistrarService.update(agentContext, { did: 'did:a', didDocument: {} as DidDocument })

      expect(result).toEqual({
        didDocumentMetadata: {},
        didRegistrationMetadata: {},
        didState: {
          state: 'failed',
          did: 'did:a',
          reason: 'Could not extract method from did did:a',
        },
      })
    })

    it('should return error with state failed if the did has no registrar', async () => {
      const result = await didRegistrarService.update(agentContext, {
        did: 'did:something:123',
        didDocument: {} as DidDocument,
      })

      expect(result).toEqual({
        didDocumentMetadata: {},
        didRegistrationMetadata: {},
        didState: {
          state: 'failed',
          did: 'did:something:123',
          reason: "Unsupported did method: 'something'",
        },
      })
    })
  })

  describe('deactivate', () => {
    it('should correctly find and call the correct registrar for a specified did', async () => {
      const returnValue = {
        didDocumentMetadata: {},
        didRegistrationMetadata: {},
        didState: {
          state: 'failed',
          reason: ':(',
        },
      } as const
      mockFunction(didRegistrarMock.deactivate).mockResolvedValue(returnValue)

      const result = await didRegistrarService.deactivate(agentContext, { did: 'did:key:xxxx' })
      expect(result).toEqual(returnValue)

      expect(didResolverMock.invalidateCacheForDid).toHaveBeenCalledTimes(1)
      expect(didRegistrarMock.deactivate).toHaveBeenCalledTimes(1)
      expect(didRegistrarMock.deactivate).toHaveBeenCalledWith(agentContext, { did: 'did:key:xxxx' })
    })

    it('should return error state failed if no method could be extracted from the did', async () => {
      const result = await didRegistrarService.deactivate(agentContext, { did: 'did:a' })

      expect(result).toEqual({
        didDocumentMetadata: {},
        didRegistrationMetadata: {},
        didState: {
          state: 'failed',
          did: 'did:a',
          reason: 'Could not extract method from did did:a',
        },
      })
    })

    it('should return error with state failed if the did has no registrar', async () => {
      const result = await didRegistrarService.deactivate(agentContext, { did: 'did:something:123' })

      expect(result).toEqual({
        didDocumentMetadata: {},
        didRegistrationMetadata: {},
        didState: {
          state: 'failed',
          did: 'did:something:123',
          reason: "Unsupported did method: 'something'",
        },
      })
    })
  })
})
