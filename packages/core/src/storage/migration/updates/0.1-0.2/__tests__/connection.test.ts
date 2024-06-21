import { getAgentConfig, getAgentContext, mockFunction } from '../../../../../../tests/helpers'
import { Agent } from '../../../../../agent/Agent'
import {
  ConnectionRecord,
  ConnectionRole,
  ConnectionState,
  DidExchangeRole,
  DidExchangeState,
} from '../../../../../modules/connections'
import { ConnectionRepository } from '../../../../../modules/connections/repository/ConnectionRepository'
import { DidDocumentRole } from '../../../../../modules/dids/domain/DidDocumentRole'
import { DidRecord } from '../../../../../modules/dids/repository'
import { DidRepository } from '../../../../../modules/dids/repository/DidRepository'
import { OutOfBandRole } from '../../../../../modules/oob/domain/OutOfBandRole'
import { OutOfBandState } from '../../../../../modules/oob/domain/OutOfBandState'
import { OutOfBandRecord } from '../../../../../modules/oob/repository'
import { OutOfBandRepository } from '../../../../../modules/oob/repository/OutOfBandRepository'
import { JsonTransformer } from '../../../../../utils'
import * as testModule from '../connection'

import didPeer4kgVt6CidfKgo1MoWMqsQX from './__fixtures__/didPeer4kgVt6CidfKgo1MoWMqsQX.json'
import didPeerR1xKJw17sUoXhejEpugMYJ from './__fixtures__/didPeerR1xKJw17sUoXhejEpugMYJ.json'
import legacyDidPeer4kgVt6CidfKgo1MoWMqsQX from './__fixtures__/legacyDidPeer4kgVt6CidfKgo1MoWMqsQX.json'
import legacyDidPeerR1xKJw17sUoXhejEpugMYJ from './__fixtures__/legacyDidPeerR1xKJw17sUoXhejEpugMYJ.json'

const agentConfig = getAgentConfig('Migration ConnectionRecord 0.1-0.2')
const agentContext = getAgentContext()

jest.mock('../../../../../modules/connections/repository/ConnectionRepository')
const ConnectionRepositoryMock = ConnectionRepository as jest.Mock<ConnectionRepository>
const connectionRepository = new ConnectionRepositoryMock()

jest.mock('../../../../../modules/dids/repository/DidRepository')
const DidRepositoryMock = DidRepository as jest.Mock<DidRepository>
const didRepository = new DidRepositoryMock()

jest.mock('../../../../../modules/oob/repository/OutOfBandRepository')
const OutOfBandRepositoryMock = OutOfBandRepository as jest.Mock<OutOfBandRepository>
const outOfBandRepository = new OutOfBandRepositoryMock()

jest.mock('../../../../../agent/Agent', () => {
  return {
    Agent: jest.fn(() => ({
      config: agentConfig,
      context: agentContext,
      dependencyManager: {
        resolve: jest.fn((cls) => {
          if (cls === ConnectionRepository) {
            return connectionRepository
          } else if (cls === DidRepository) {
            return didRepository
          } else if (cls === OutOfBandRepository) {
            return outOfBandRepository
          }

          throw new Error(`No instance found for ${cls}`)
        }),
      },
    })),
  }
})

const connectionJson = {
  role: 'inviter',
  state: 'invited',
  did: legacyDidPeerR1xKJw17sUoXhejEpugMYJ.id,
  didDoc: legacyDidPeerR1xKJw17sUoXhejEpugMYJ,
  theirDid: legacyDidPeer4kgVt6CidfKgo1MoWMqsQX.id,
  theirDidDoc: legacyDidPeer4kgVt6CidfKgo1MoWMqsQX,
  invitation: {
    '@type': 'https://didcomm.org/connections/1.0/invitation',
    '@id': '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
    recipientKeys: ['E6D1m3eERqCueX4ZgMCY14B4NceAr6XP2HyVqt55gDhu'],
    serviceEndpoint: 'https://example.com',
    label: 'test',
  },
  createdAt: '2020-04-08T15:51:43.819Z',
}

const connectionJsonNewDidStateRole = {
  role: 'responder',
  state: 'invitation-sent',
  did: didPeerR1xKJw17sUoXhejEpugMYJ.id,
  theirDid: didPeer4kgVt6CidfKgo1MoWMqsQX.id,
  invitation: {
    '@type': 'https://didcomm.org/connections/1.0/invitation',
    '@id': '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
    recipientKeys: ['E6D1m3eERqCueX4ZgMCY14B4NceAr6XP2HyVqt55gDhu'],
    serviceEndpoint: 'https://example.com',
    label: 'test',
  },
  createdAt: '2020-04-08T15:51:43.819Z',
  autoAcceptConnection: true,
  multiUseInvitation: false,
  mediatorId: 'a-mediator-id',
}

// Mock typed object
const AgentMock = Agent as jest.Mock<Agent>

describe('0.1-0.2 | Connection', () => {
  let agent: Agent

  beforeEach(() => {
    agent = new AgentMock()
  })

  afterEach(() => {
    jest.clearAllMocks()
  })

  describe('migrateCredentialRecordToV0_2()', () => {
    it('should fetch all records and apply the needed updates', async () => {
      const input = JsonTransformer.fromJSON(connectionJson, ConnectionRecord)
      const records = [input]

      mockFunction(connectionRepository.getAll).mockResolvedValue(records)

      // Not records exist yet
      mockFunction(outOfBandRepository.findByQuery).mockResolvedValue([])
      mockFunction(didRepository.findById).mockResolvedValue(null)

      await testModule.migrateConnectionRecordToV0_2(agent)

      expect(connectionRepository.getAll).toHaveBeenCalledTimes(1)
      expect(connectionRepository.update).toHaveBeenCalledTimes(records.length)
      const [[, updatedConnectionRecord]] = mockFunction(connectionRepository.update).mock.calls

      // Check first object is transformed correctly.
      //  - removed invitation, theirDidDoc, didDoc
      //  - Added invitationDid
      //  - Updated did, theirDid
      expect(updatedConnectionRecord.toJSON()).toEqual({
        _tags: {},
        metadata: {},
        createdAt: '2020-04-08T15:51:43.819Z',
        role: 'responder',
        state: 'invitation-sent',
        did: didPeerR1xKJw17sUoXhejEpugMYJ.id,
        invitationDid:
          'did:peer:2.SeyJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsInQiOiJkaWQtY29tbXVuaWNhdGlvbiIsInByaW9yaXR5IjowLCJyZWNpcGllbnRLZXlzIjpbImRpZDprZXk6ejZNa3NZVTRNSHRmbU5oTm0xdUdNdkFOcjlqNENCdjJGeW1qaUp0UmdBMzZiU1ZII3o2TWtzWVU0TUh0Zm1OaE5tMXVHTXZBTnI5ajRDQnYyRnltamlKdFJnQTM2YlNWSCJdfQ',
        theirDid: didPeer4kgVt6CidfKgo1MoWMqsQX.id,
        outOfBandId: expect.any(String),
        connectionTypes: [],
        previousDids: [],
        previousTheirDids: [],
      })
    })
  })

  describe('updateConnectionRoleAndState', () => {
    it('should update the connection role and state to did exchange values', async () => {
      const connectionRecord = JsonTransformer.fromJSON(
        { ...connectionJson, state: 'requested', role: 'invitee' },
        ConnectionRecord
      )

      await testModule.updateConnectionRoleAndState(agent, connectionRecord)

      expect(connectionRecord.toJSON()).toEqual({
        _tags: {},
        metadata: {},
        createdAt: '2020-04-08T15:51:43.819Z',
        role: 'requester',
        state: 'request-sent',
        did: legacyDidPeerR1xKJw17sUoXhejEpugMYJ.id,
        didDoc: legacyDidPeerR1xKJw17sUoXhejEpugMYJ,
        theirDid: legacyDidPeer4kgVt6CidfKgo1MoWMqsQX.id,
        theirDidDoc: legacyDidPeer4kgVt6CidfKgo1MoWMqsQX,
        invitation: {
          '@type': 'https://didcomm.org/connections/1.0/invitation',
          '@id': '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
          recipientKeys: ['E6D1m3eERqCueX4ZgMCY14B4NceAr6XP2HyVqt55gDhu'],
          serviceEndpoint: 'https://example.com',
          label: 'test',
        },
        connectionTypes: [],
        previousDids: [],
        previousTheirDids: [],
      })
    })
  })

  describe('extractDidDocument', () => {
    it('should extract the did document from the connection record and update the did to a did:peer did', async () => {
      const connectionRecord = JsonTransformer.fromJSON(connectionJson, ConnectionRecord)

      // No did record exists yet
      mockFunction(didRepository.findById).mockResolvedValue(null)

      await testModule.extractDidDocument(agent, connectionRecord)

      expect(connectionRecord.toJSON()).toEqual({
        _tags: {},
        metadata: {},
        createdAt: '2020-04-08T15:51:43.819Z',
        role: 'inviter',
        state: 'invited',
        did: didPeerR1xKJw17sUoXhejEpugMYJ.id,
        theirDid: didPeer4kgVt6CidfKgo1MoWMqsQX.id,
        invitation: {
          '@type': 'https://didcomm.org/connections/1.0/invitation',
          '@id': '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
          recipientKeys: ['E6D1m3eERqCueX4ZgMCY14B4NceAr6XP2HyVqt55gDhu'],
          serviceEndpoint: 'https://example.com',
          label: 'test',
        },
        connectionTypes: [],
        previousDids: [],
        previousTheirDids: [],
      })
    })

    it('should create a DidRecord for didDoc and theirDidDoc', async () => {
      const connectionRecord = JsonTransformer.fromJSON(connectionJson, ConnectionRecord)

      // No did record exists yet
      mockFunction(didRepository.findById).mockResolvedValue(null)

      await testModule.extractDidDocument(agent, connectionRecord)

      expect(didRepository.save).toHaveBeenCalledTimes(2)

      const [[, didRecord], [, theirDidRecord]] = mockFunction(didRepository.save).mock.calls

      expect(didRecord.toJSON()).toMatchObject({
        id: didPeerR1xKJw17sUoXhejEpugMYJ.id,
        role: DidDocumentRole.Created,
        didDocument: didPeerR1xKJw17sUoXhejEpugMYJ,
        createdAt: connectionRecord.createdAt.toISOString(),
        metadata: {
          '_internal/legacyDid': {
            unqualifiedDid: legacyDidPeerR1xKJw17sUoXhejEpugMYJ.id,
            didDocumentString: JSON.stringify(legacyDidPeerR1xKJw17sUoXhejEpugMYJ),
          },
        },
      })
      expect(didRecord.getTags()).toMatchObject({
        recipientKeyFingerprints: [
          'z6MksYU4MHtfmNhNm1uGMvANr9j4CBv2FymjiJtRgA36bSVH',
          'z6MksYU4MHtfmNhNm1uGMvANr9j4CBv2FymjiJtRgA36bSVH',
        ],
      })

      expect(theirDidRecord.toJSON()).toMatchObject({
        id: didPeer4kgVt6CidfKgo1MoWMqsQX.id,
        role: DidDocumentRole.Received,
        didDocument: didPeer4kgVt6CidfKgo1MoWMqsQX,
        createdAt: connectionRecord.createdAt.toISOString(),
        metadata: {
          '_internal/legacyDid': {
            unqualifiedDid: legacyDidPeer4kgVt6CidfKgo1MoWMqsQX.id,
            didDocumentString: JSON.stringify(legacyDidPeer4kgVt6CidfKgo1MoWMqsQX),
          },
        },
      })
      expect(theirDidRecord.getTags()).toMatchObject({
        recipientKeyFingerprints: [
          'z6MkjKUBV9DDUj7cgW8UbDJZhPcHCH8up26Lrr8YqkAS4wcb',
          'z6MkjKUBV9DDUj7cgW8UbDJZhPcHCH8up26Lrr8YqkAS4wcb',
        ],
      })
    })

    it('should not extract the did document if it does not exist on the connection record', async () => {
      const connectionRecord = JsonTransformer.fromJSON(
        { ...connectionJson, didDoc: undefined, theirDidDoc: undefined },
        ConnectionRecord
      )

      await testModule.extractDidDocument(agent, connectionRecord)

      expect(didRepository.findById).not.toHaveBeenCalled()
      expect(didRepository.save).not.toHaveBeenCalled()

      // Should be the same as the input
      expect(connectionRecord.toJSON()).toEqual({
        ...connectionJson,
        didDoc: undefined,
        theirDidDoc: undefined,
        metadata: {},
        _tags: {},
        connectionTypes: [],
        previousDids: [],
        previousTheirDids: [],
      })
    })

    it('should not create a did record if a did record for the did already exists', async () => {
      const connectionRecord = JsonTransformer.fromJSON(connectionJson, ConnectionRecord)

      const didRecord = JsonTransformer.fromJSON(
        {
          id: didPeerR1xKJw17sUoXhejEpugMYJ.id,
          role: DidDocumentRole.Created,
          didDocument: didPeerR1xKJw17sUoXhejEpugMYJ,
          createdAt: connectionRecord.createdAt.toISOString(),
          metadata: {
            '_internal/legacyDid': {
              unqualifiedDid: legacyDidPeerR1xKJw17sUoXhejEpugMYJ.id,
              didDocumentString: JSON.stringify(legacyDidPeerR1xKJw17sUoXhejEpugMYJ),
            },
          },
          _tags: {
            recipientKeys: ['R1xKJw17sUoXhejEpugMYJ#4', 'E6D1m3eERqCueX4ZgMCY14B4NceAr6XP2HyVqt55gDhu'],
          },
        },
        DidRecord
      )

      const theirDidRecord = JsonTransformer.fromJSON(
        {
          id: didPeer4kgVt6CidfKgo1MoWMqsQX.id,
          role: DidDocumentRole.Received,
          didDocument: didPeer4kgVt6CidfKgo1MoWMqsQX,
          createdAt: connectionRecord.createdAt.toISOString(),
          metadata: {
            '_internal/legacyDid': {
              unqualifiedDid: legacyDidPeer4kgVt6CidfKgo1MoWMqsQX.id,
              didDocumentString: JSON.stringify(legacyDidPeer4kgVt6CidfKgo1MoWMqsQX),
            },
          },
          _tags: {
            recipientKeys: ['4kgVt6CidfKgo1MoWMqsQX#4', '5sD8ttxn9Bd9a1HmueLirJ4HNhs4Q8qzAqDd1UCR9iqD'],
          },
        },
        DidRecord
      )

      // Both did records already exist
      mockFunction(didRepository.findById).mockImplementation((_, id) =>
        Promise.resolve(id === didPeerR1xKJw17sUoXhejEpugMYJ.id ? didRecord : theirDidRecord)
      )

      await testModule.extractDidDocument(agent, connectionRecord)

      expect(didRepository.save).not.toHaveBeenCalled()
      expect(didRepository.findById).toHaveBeenNthCalledWith(1, agentContext, didPeerR1xKJw17sUoXhejEpugMYJ.id)
      expect(didRepository.findById).toHaveBeenNthCalledWith(2, agentContext, didPeer4kgVt6CidfKgo1MoWMqsQX.id)

      expect(connectionRecord.toJSON()).toEqual({
        _tags: {},
        metadata: {},
        createdAt: '2020-04-08T15:51:43.819Z',
        role: 'inviter',
        state: 'invited',
        did: didPeerR1xKJw17sUoXhejEpugMYJ.id,
        theirDid: didPeer4kgVt6CidfKgo1MoWMqsQX.id,
        invitation: {
          '@type': 'https://didcomm.org/connections/1.0/invitation',
          '@id': '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
          recipientKeys: ['E6D1m3eERqCueX4ZgMCY14B4NceAr6XP2HyVqt55gDhu'],
          serviceEndpoint: 'https://example.com',
          label: 'test',
        },
        connectionTypes: [],
        previousDids: [],
        previousTheirDids: [],
      })
    })
  })

  describe('migrateToOobRecord', () => {
    it('should extract the invitation from the connection record and generate an invitation did', async () => {
      const connectionRecord = JsonTransformer.fromJSON(connectionJsonNewDidStateRole, ConnectionRecord)

      // No did record exists yet
      mockFunction(outOfBandRepository.findByQuery).mockResolvedValue([])

      await testModule.migrateToOobRecord(agent, connectionRecord)

      expect(connectionRecord.toJSON()).toEqual({
        _tags: {},
        metadata: {},
        createdAt: '2020-04-08T15:51:43.819Z',
        role: 'responder',
        state: 'invitation-sent',
        did: didPeerR1xKJw17sUoXhejEpugMYJ.id,
        theirDid: didPeer4kgVt6CidfKgo1MoWMqsQX.id,
        invitationDid:
          'did:peer:2.SeyJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsInQiOiJkaWQtY29tbXVuaWNhdGlvbiIsInByaW9yaXR5IjowLCJyZWNpcGllbnRLZXlzIjpbImRpZDprZXk6ejZNa3NZVTRNSHRmbU5oTm0xdUdNdkFOcjlqNENCdjJGeW1qaUp0UmdBMzZiU1ZII3o2TWtzWVU0TUh0Zm1OaE5tMXVHTXZBTnI5ajRDQnYyRnltamlKdFJnQTM2YlNWSCJdfQ',
        outOfBandId: expect.any(String),
        autoAcceptConnection: true,
        mediatorId: 'a-mediator-id',
        connectionTypes: [],
        previousDids: [],
        previousTheirDids: [],
      })
    })

    it('should create an OutOfBandRecord from the invitation and store the outOfBandId in the connection record', async () => {
      const connectionRecord = JsonTransformer.fromJSON(connectionJsonNewDidStateRole, ConnectionRecord)

      // No did record exists yet
      mockFunction(outOfBandRepository.findByQuery).mockResolvedValue([])

      await testModule.migrateToOobRecord(agent, connectionRecord)

      const [[, outOfBandRecord]] = mockFunction(outOfBandRepository.save).mock.calls

      expect(outOfBandRepository.save).toHaveBeenCalledTimes(1)
      expect(connectionRecord.outOfBandId).toEqual(outOfBandRecord.id)

      expect(outOfBandRecord.toJSON()).toEqual({
        id: expect.any(String),
        _tags: { recipientKeyFingerprints: ['z6MksYU4MHtfmNhNm1uGMvANr9j4CBv2FymjiJtRgA36bSVH'] },
        metadata: {},
        // Checked below
        outOfBandInvitation: {
          '@type': 'https://didcomm.org/out-of-band/1.1/invitation',
          services: [
            {
              id: '#inline',
              serviceEndpoint: 'https://example.com',
              type: 'did-communication',
              recipientKeys: ['did:key:z6MksYU4MHtfmNhNm1uGMvANr9j4CBv2FymjiJtRgA36bSVH'],
            },
          ],
          '@id': '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
          label: 'test',
          accept: ['didcomm/aip1', 'didcomm/aip2;env=rfc19'],
          handshake_protocols: ['https://didcomm.org/connections/1.0'],
        },
        role: OutOfBandRole.Sender,
        state: OutOfBandState.AwaitResponse,
        autoAcceptConnection: true,
        reusable: false,
        mediatorId: 'a-mediator-id',
        createdAt: connectionRecord.createdAt.toISOString(),
      })
    })

    it('should create an OutOfBandRecord if an OutOfBandRecord with the invitation id already exists, but the recipientKeys are different', async () => {
      const connectionRecord = JsonTransformer.fromJSON(connectionJsonNewDidStateRole, ConnectionRecord)

      // Out of band record does not exist yet
      mockFunction(outOfBandRepository.findByQuery).mockResolvedValueOnce([])

      await testModule.migrateToOobRecord(agent, connectionRecord)

      expect(outOfBandRepository.findByQuery).toHaveBeenCalledTimes(1)
      expect(outOfBandRepository.findByQuery).toHaveBeenNthCalledWith(1, agentContext, {
        invitationId: '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
        recipientKeyFingerprints: ['z6MksYU4MHtfmNhNm1uGMvANr9j4CBv2FymjiJtRgA36bSVH'],
        role: OutOfBandRole.Sender,
      })

      // Expect the out of band record to be created
      expect(outOfBandRepository.save).toHaveBeenCalled()
    })

    it('should not create an OutOfBandRecord if an OutOfBandRecord with the invitation id and recipientKeys already exists', async () => {
      const connectionRecord = JsonTransformer.fromJSON(connectionJsonNewDidStateRole, ConnectionRecord)

      const outOfBandRecord = JsonTransformer.fromJSON(
        {
          id: '3c52cc26-577d-4200-8753-05f1f425c342',
          _tags: {},
          metadata: {},
          // Checked below
          outOfBandInvitation: {
            '@type': 'https://didcomm.org/out-of-band/1.1/invitation',
            services: [
              {
                id: '#inline',
                serviceEndpoint: 'https://example.com',
                type: 'did-communication',
                recipientKeys: ['did:key:z6MksYU4MHtfmNhNm1uGMvANr9j4CBv2FymjiJtRgA36bSVH'],
              },
            ],
            '@id': '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
            label: 'test',
            accept: ['didcomm/aip1', 'didcomm/aip2;env=rfc19'],
            handshake_protocols: ['https://didcomm.org/connections/1.0'],
          },
          role: OutOfBandRole.Sender,
          state: OutOfBandState.AwaitResponse,
          autoAcceptConnection: true,
          did: didPeerR1xKJw17sUoXhejEpugMYJ.id,
          reusable: false,
          mediatorId: 'a-mediator-id',
          createdAt: connectionRecord.createdAt.toISOString(),
        },
        OutOfBandRecord
      )

      // Out of band record does not exist yet
      mockFunction(outOfBandRepository.findByQuery).mockResolvedValueOnce([outOfBandRecord])

      await testModule.migrateToOobRecord(agent, connectionRecord)

      expect(outOfBandRepository.findByQuery).toHaveBeenCalledTimes(1)
      expect(outOfBandRepository.findByQuery).toHaveBeenNthCalledWith(1, agentContext, {
        invitationId: '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
        recipientKeyFingerprints: ['z6MksYU4MHtfmNhNm1uGMvANr9j4CBv2FymjiJtRgA36bSVH'],
        role: OutOfBandRole.Sender,
      })
      expect(outOfBandRepository.save).not.toHaveBeenCalled()

      expect(connectionRecord.toJSON()).toEqual({
        _tags: {},
        metadata: {},
        createdAt: '2020-04-08T15:51:43.819Z',
        role: 'responder',
        state: 'invitation-sent',
        did: didPeerR1xKJw17sUoXhejEpugMYJ.id,
        theirDid: didPeer4kgVt6CidfKgo1MoWMqsQX.id,
        invitationDid:
          'did:peer:2.SeyJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsInQiOiJkaWQtY29tbXVuaWNhdGlvbiIsInByaW9yaXR5IjowLCJyZWNpcGllbnRLZXlzIjpbImRpZDprZXk6ejZNa3NZVTRNSHRmbU5oTm0xdUdNdkFOcjlqNENCdjJGeW1qaUp0UmdBMzZiU1ZII3o2TWtzWVU0TUh0Zm1OaE5tMXVHTXZBTnI5ajRDQnYyRnltamlKdFJnQTM2YlNWSCJdfQ',
        autoAcceptConnection: true,
        mediatorId: 'a-mediator-id',
        outOfBandId: outOfBandRecord.id,
        connectionTypes: [],
        previousDids: [],
        previousTheirDids: [],
      })
    })

    it('should update the existing out of band record to reusable and state await response if the connection record is a multiUseInvitation', async () => {
      const connectionRecord = JsonTransformer.fromJSON(
        { ...connectionJsonNewDidStateRole, multiUseInvitation: true },
        ConnectionRecord
      )

      const outOfBandRecord = JsonTransformer.fromJSON(
        {
          id: '3c52cc26-577d-4200-8753-05f1f425c342',
          _tags: {},
          metadata: {},
          // Checked below
          outOfBandInvitation: {
            '@type': 'https://didcomm.org/out-of-band/1.1/invitation',
            services: [
              {
                id: '#inline',
                serviceEndpoint: 'https://example.com',
                type: 'did-communication',
                recipientKeys: ['did:key:z6MksYU4MHtfmNhNm1uGMvANr9j4CBv2FymjiJtRgA36bSVH'],
              },
            ],
            '@id': '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
            label: 'test',
            accept: ['didcomm/aip1', 'didcomm/aip2;env=rfc19'],
            handshake_protocols: ['https://didcomm.org/connections/1.0'],
          },
          role: OutOfBandRole.Sender,
          state: OutOfBandState.AwaitResponse,
          autoAcceptConnection: true,
          did: didPeerR1xKJw17sUoXhejEpugMYJ.id,
          reusable: false,
          mediatorId: 'a-mediator-id',
          createdAt: connectionRecord.createdAt.toISOString(),
        },
        OutOfBandRecord
      )

      // Out of band record already exists
      mockFunction(outOfBandRepository.findByQuery).mockResolvedValueOnce([outOfBandRecord])

      await testModule.migrateToOobRecord(agent, connectionRecord)

      expect(outOfBandRepository.findByQuery).toHaveBeenCalledTimes(1)
      expect(outOfBandRepository.findByQuery).toHaveBeenNthCalledWith(1, agentContext, {
        invitationId: '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
        recipientKeyFingerprints: ['z6MksYU4MHtfmNhNm1uGMvANr9j4CBv2FymjiJtRgA36bSVH'],
        role: OutOfBandRole.Sender,
      })
      expect(outOfBandRepository.save).not.toHaveBeenCalled()
      expect(outOfBandRepository.update).toHaveBeenCalledWith(agentContext, outOfBandRecord)
      expect(connectionRepository.delete).toHaveBeenCalledWith(agentContext, connectionRecord)

      expect(outOfBandRecord.toJSON()).toEqual({
        id: '3c52cc26-577d-4200-8753-05f1f425c342',
        _tags: {},
        metadata: {},
        outOfBandInvitation: {
          '@type': 'https://didcomm.org/out-of-band/1.1/invitation',
          services: [
            {
              id: '#inline',
              serviceEndpoint: 'https://example.com',
              type: 'did-communication',
              recipientKeys: ['did:key:z6MksYU4MHtfmNhNm1uGMvANr9j4CBv2FymjiJtRgA36bSVH'],
            },
          ],
          '@id': '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
          label: 'test',
          accept: ['didcomm/aip1', 'didcomm/aip2;env=rfc19'],
          handshake_protocols: ['https://didcomm.org/connections/1.0'],
        },
        role: OutOfBandRole.Sender,
        state: OutOfBandState.AwaitResponse,
        autoAcceptConnection: true,
        did: didPeerR1xKJw17sUoXhejEpugMYJ.id,
        reusable: true,
        mediatorId: 'a-mediator-id',
        createdAt: connectionRecord.createdAt.toISOString(),
      })
    })
  })

  describe('oobStateFromDidExchangeRoleAndState', () => {
    it('should return the correct state for all connection role and state combinations', () => {
      expect(
        testModule.oobStateFromDidExchangeRoleAndState(DidExchangeRole.Responder, DidExchangeState.InvitationSent)
      ).toEqual(OutOfBandState.AwaitResponse)
      expect(
        testModule.oobStateFromDidExchangeRoleAndState(DidExchangeRole.Responder, DidExchangeState.RequestReceived)
      ).toEqual(OutOfBandState.Done)
      expect(
        testModule.oobStateFromDidExchangeRoleAndState(DidExchangeRole.Responder, DidExchangeState.ResponseSent)
      ).toEqual(OutOfBandState.Done)
      expect(
        testModule.oobStateFromDidExchangeRoleAndState(DidExchangeRole.Responder, DidExchangeState.Completed)
      ).toEqual(OutOfBandState.Done)
      expect(
        testModule.oobStateFromDidExchangeRoleAndState(DidExchangeRole.Responder, DidExchangeState.Abandoned)
      ).toEqual(OutOfBandState.Done)
      expect(testModule.oobStateFromDidExchangeRoleAndState(DidExchangeRole.Requester, DidExchangeState.Start)).toEqual(
        OutOfBandState.PrepareResponse
      )

      expect(
        testModule.oobStateFromDidExchangeRoleAndState(DidExchangeRole.Requester, DidExchangeState.InvitationReceived)
      ).toEqual(OutOfBandState.PrepareResponse)
      expect(
        testModule.oobStateFromDidExchangeRoleAndState(DidExchangeRole.Requester, DidExchangeState.RequestSent)
      ).toEqual(OutOfBandState.Done)
      expect(
        testModule.oobStateFromDidExchangeRoleAndState(DidExchangeRole.Requester, DidExchangeState.ResponseReceived)
      ).toEqual(OutOfBandState.Done)
      expect(
        testModule.oobStateFromDidExchangeRoleAndState(DidExchangeRole.Requester, DidExchangeState.Completed)
      ).toEqual(OutOfBandState.Done)
      expect(
        testModule.oobStateFromDidExchangeRoleAndState(DidExchangeRole.Requester, DidExchangeState.Abandoned)
      ).toEqual(OutOfBandState.Done)
      expect(testModule.oobStateFromDidExchangeRoleAndState(DidExchangeRole.Responder, DidExchangeState.Start)).toEqual(
        OutOfBandState.AwaitResponse
      )
    })
  })

  describe('didExchangeStateAndRoleFromRoleAndState', () => {
    it('should return the correct state for all connection role and state combinations', () => {
      expect(
        testModule.didExchangeStateAndRoleFromRoleAndState(ConnectionRole.Inviter, ConnectionState.Invited)
      ).toEqual([DidExchangeRole.Responder, DidExchangeState.InvitationSent])
      expect(
        testModule.didExchangeStateAndRoleFromRoleAndState(ConnectionRole.Inviter, ConnectionState.Requested)
      ).toEqual([DidExchangeRole.Responder, DidExchangeState.RequestReceived])
      expect(
        testModule.didExchangeStateAndRoleFromRoleAndState(ConnectionRole.Inviter, ConnectionState.Responded)
      ).toEqual([DidExchangeRole.Responder, DidExchangeState.ResponseSent])
      expect(
        testModule.didExchangeStateAndRoleFromRoleAndState(ConnectionRole.Inviter, ConnectionState.Complete)
      ).toEqual([DidExchangeRole.Responder, DidExchangeState.Completed])

      expect(
        testModule.didExchangeStateAndRoleFromRoleAndState(ConnectionRole.Invitee, ConnectionState.Invited)
      ).toEqual([DidExchangeRole.Requester, DidExchangeState.InvitationReceived])
      expect(
        testModule.didExchangeStateAndRoleFromRoleAndState(ConnectionRole.Invitee, ConnectionState.Requested)
      ).toEqual([DidExchangeRole.Requester, DidExchangeState.RequestSent])
      expect(
        testModule.didExchangeStateAndRoleFromRoleAndState(ConnectionRole.Invitee, ConnectionState.Responded)
      ).toEqual([DidExchangeRole.Requester, DidExchangeState.ResponseReceived])
      expect(
        testModule.didExchangeStateAndRoleFromRoleAndState(ConnectionRole.Invitee, ConnectionState.Complete)
      ).toEqual([DidExchangeRole.Requester, DidExchangeState.Completed])
    })

    it('should return did exchange role if role is already did exchange role', () => {
      expect(
        testModule.didExchangeStateAndRoleFromRoleAndState(DidExchangeRole.Responder, DidExchangeState.RequestSent)
      ).toEqual([DidExchangeRole.Responder, expect.anything()])

      expect(
        testModule.didExchangeStateAndRoleFromRoleAndState(DidExchangeRole.Requester, ConnectionState.Requested)
      ).toEqual([DidExchangeRole.Requester, expect.anything()])
    })

    it('should return the input state if state is not a valid connection state', () => {
      expect(
        testModule.didExchangeStateAndRoleFromRoleAndState(
          DidExchangeRole.Responder,
          'something-weird' as ConnectionState
        )
      ).toEqual([DidExchangeRole.Responder, 'something-weird'])
    })
  })
})
