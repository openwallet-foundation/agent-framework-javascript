import type { CredentialRecordBinding } from '../../../modules/credentials'

import { JsonTransformer } from '@credo-ts/core/src/utils'
import { getAgentConfig, getAgentContext, mockFunction } from '@credo-ts/core/tests/helpers'

import { Agent } from '../../../../../core/src/agent/Agent'
import { CredentialExchangeRecord, CredentialState } from '../../../modules/credentials'
import { CredentialRepository } from '../../../modules/credentials/repository/CredentialRepository'
import { DidCommMessageRole } from '../../../repository'
import { DidCommMessageRepository } from '../../../repository/DidCommMessageRepository'
import * as testModule from '../credential'

const agentConfig = getAgentConfig('Migration CredentialRecord 0.1-0.2')
const agentContext = getAgentContext()

jest.mock('../../../modules/credentials/repository/CredentialRepository')
const CredentialRepositoryMock = CredentialRepository as jest.Mock<CredentialRepository>
const credentialRepository = new CredentialRepositoryMock()

jest.mock('../../../repository/DidCommMessageRepository')
const DidCommMessageRepositoryMock = DidCommMessageRepository as jest.Mock<DidCommMessageRepository>
const didCommMessageRepository = new DidCommMessageRepositoryMock()

jest.mock('../../../../../core/src/agent/Agent', () => {
  return {
    Agent: jest.fn(() => ({
      config: agentConfig,
      context: agentContext,
      dependencyManager: {
        resolve: jest.fn((token) =>
          token === CredentialRepositoryMock ? credentialRepository : didCommMessageRepository
        ),
      },
    })),
  }
})

// Mock typed object
const AgentMock = Agent as jest.Mock<Agent>

describe('0.1-0.2 | Credential', () => {
  let agent: Agent

  beforeEach(() => {
    agent = new AgentMock()
  })

  afterEach(() => {
    mockFunction(didCommMessageRepository.save).mockReset()
  })

  describe('migrateCredentialRecordToV0_2()', () => {
    it('should fetch all records and apply the needed updates ', async () => {
      const records: CredentialExchangeRecord[] = [
        getCredential({
          credentialId: 'credentialId1',
          metadata: {
            schemaId: 'schemaId',
            credentialDefinitionId: 'credentialDefinitionId',
            anotherObject: {
              someNested: 'value',
            },
            requestMetadata: {
              the: {
                indy: {
                  meta: 'data',
                },
              },
            },
          },
        }),
      ]

      mockFunction(credentialRepository.getAll).mockResolvedValue(records)

      await testModule.migrateCredentialRecordToV0_2(agent)

      expect(credentialRepository.getAll).toHaveBeenCalledTimes(1)
      expect(credentialRepository.update).toHaveBeenCalledTimes(records.length)

      const updatedRecord = mockFunction(credentialRepository.update).mock.calls[0][1]

      // Check first object is transformed correctly
      expect(updatedRecord.toJSON()).toMatchObject({
        credentials: [
          {
            credentialRecordId: 'credentialId1',
            credentialRecordType: 'indy',
          },
        ],
        protocolVersion: 'v1',
        metadata: {
          '_internal/indyCredential': {
            schemaId: 'schemaId',
            credentialDefinitionId: 'credentialDefinitionId',
          },
          anotherObject: {
            someNested: 'value',
          },
          '_internal/indyRequest': {
            the: {
              indy: {
                meta: 'data',
              },
            },
          },
        },
      })
    })
  })

  describe('updateIndyMetadata()', () => {
    it('should correctly update the old top-level keys into the nested structure', async () => {
      const credentialRecord = getCredential({
        metadata: {
          schemaId: 'schemaId',
          credentialDefinitionId: 'schemaId',
          anotherObject: {
            someNested: 'value',
          },
          requestMetadata: {
            the: {
              indy: {
                meta: 'data',
              },
            },
          },
        },
      })

      await testModule.updateIndyMetadata(agent, credentialRecord)

      expect(credentialRecord).toMatchObject({
        metadata: {
          data: {
            '_internal/indyCredential': {
              schemaId: 'schemaId',
              credentialDefinitionId: 'schemaId',
            },
            anotherObject: {
              someNested: 'value',
            },
            '_internal/indyRequest': {
              the: {
                indy: {
                  meta: 'data',
                },
              },
            },
          },
        },
      })
    })

    it('should not fail if some the top-level metadata keys do not exist', async () => {
      const credentialRecord = getCredential({
        metadata: {
          schemaId: 'schemaId',
          anotherObject: {
            someNested: 'value',
          },
        },
      })

      await testModule.updateIndyMetadata(agent, credentialRecord)

      expect(credentialRecord).toMatchObject({
        metadata: {
          data: {
            '_internal/indyCredential': {
              schemaId: 'schemaId',
            },
            anotherObject: {
              someNested: 'value',
            },
          },
        },
      })
    })

    it('should not fail if all of the top-level metadata keys do not exist', async () => {
      const credentialRecord = getCredential({
        metadata: {
          anotherObject: {
            someNested: 'value',
          },
        },
      })

      await testModule.updateIndyMetadata(agent, credentialRecord)

      expect(credentialRecord).toMatchObject({
        metadata: {
          data: {
            anotherObject: {
              someNested: 'value',
            },
          },
        },
      })
    })
  })

  describe('migrateInternalCredentialRecordProperties()', () => {
    it('should set the protocol version to v1 if not set on the record', async () => {
      const credentialRecord = getCredential({})

      await testModule.migrateInternalCredentialRecordProperties(agent, credentialRecord)

      expect(credentialRecord).toMatchObject({
        protocolVersion: 'v1',
      })
    })

    it('should not set the protocol version if a value is already set', async () => {
      const credentialRecord = getCredential({
        protocolVersion: 'v2',
      })

      await testModule.migrateInternalCredentialRecordProperties(agent, credentialRecord)

      expect(credentialRecord).toMatchObject({
        protocolVersion: 'v2',
      })
    })

    it('should migrate the credentialId to credentials array if present', async () => {
      const credentialRecord = getCredential({
        credentialId: 'theCredentialId',
      })

      await testModule.migrateInternalCredentialRecordProperties(agent, credentialRecord)

      expect(credentialRecord.toJSON()).toMatchObject({
        protocolVersion: 'v1',
        credentials: [
          {
            credentialRecordId: 'theCredentialId',
            credentialRecordType: 'indy',
          },
        ],
      })
    })

    it('should migrate the credentialId if not present', async () => {
      const credentialRecord = getCredential({})

      await testModule.migrateInternalCredentialRecordProperties(agent, credentialRecord)

      expect(credentialRecord.toJSON()).toMatchObject({
        protocolVersion: 'v1',
        credentialId: undefined,
        credentials: [],
      })
    })
  })

  describe('moveDidCommMessages()', () => {
    it('should move the proposalMessage, offerMessage, requestMessage and credentialMessage to the didCommMessageRepository', async () => {
      const proposalMessage = { '@type': 'ProposalMessage' }
      const offerMessage = { '@type': 'OfferMessage' }
      const requestMessage = { '@type': 'RequestMessage' }
      const credentialMessage = { '@type': 'CredentialMessage' }

      const credentialRecord = getCredential({
        id: 'theCredentialId',
        state: CredentialState.Done,
        credentials: [
          {
            credentialRecordId: 'theCredentialRecordId',
            credentialRecordType: 'indy',
          },
        ],
        proposalMessage,
        offerMessage,
        requestMessage,
        credentialMessage,
      })

      await testModule.moveDidCommMessages(agent, credentialRecord)

      expect(didCommMessageRepository.save).toHaveBeenCalledTimes(4)
      const [[, proposalMessageRecord], [, offerMessageRecord], [, requestMessageRecord], [, credentialMessageRecord]] =
        mockFunction(didCommMessageRepository.save).mock.calls

      expect(proposalMessageRecord).toMatchObject({
        role: DidCommMessageRole.Sender,
        associatedRecordId: 'theCredentialId',
        message: proposalMessage,
      })

      expect(offerMessageRecord).toMatchObject({
        role: DidCommMessageRole.Receiver,
        associatedRecordId: 'theCredentialId',
        message: offerMessage,
      })

      expect(requestMessageRecord).toMatchObject({
        role: DidCommMessageRole.Sender,
        associatedRecordId: 'theCredentialId',
        message: requestMessage,
      })

      expect(credentialMessageRecord).toMatchObject({
        role: DidCommMessageRole.Receiver,
        associatedRecordId: 'theCredentialId',
        message: credentialMessage,
      })

      expect(credentialRecord.toJSON()).toEqual({
        _tags: {},
        credentialId: undefined,
        metadata: {},
        protocolVersion: undefined,
        id: 'theCredentialId',
        state: CredentialState.Done,
        credentials: [
          {
            credentialRecordId: 'theCredentialRecordId',
            credentialRecordType: 'indy',
          },
        ],
      })
    })

    it('should only move the messages which exist in the record', async () => {
      const proposalMessage = { '@type': 'ProposalMessage' }
      const offerMessage = { '@type': 'OfferMessage' }

      const credentialRecord = getCredential({
        id: 'theCredentialId',
        state: CredentialState.Done,
        credentials: [
          {
            credentialRecordId: 'theCredentialRecordId',
            credentialRecordType: 'indy',
          },
        ],
        proposalMessage,
        offerMessage,
      })

      await testModule.moveDidCommMessages(agent, credentialRecord)

      expect(didCommMessageRepository.save).toHaveBeenCalledTimes(2)
      const [[, proposalMessageRecord], [, offerMessageRecord]] = mockFunction(didCommMessageRepository.save).mock.calls

      expect(proposalMessageRecord).toMatchObject({
        role: DidCommMessageRole.Sender,
        associatedRecordId: 'theCredentialId',
        message: proposalMessage,
      })

      expect(offerMessageRecord).toMatchObject({
        role: DidCommMessageRole.Receiver,
        associatedRecordId: 'theCredentialId',
        message: offerMessage,
      })

      expect(credentialRecord.toJSON()).toEqual({
        _tags: {},
        credentialId: undefined,
        metadata: {},
        protocolVersion: undefined,
        id: 'theCredentialId',
        state: CredentialState.Done,
        credentials: [
          {
            credentialRecordId: 'theCredentialRecordId',
            credentialRecordType: 'indy',
          },
        ],
      })
    })

    it('should determine the correct DidCommMessageRole for each message', async () => {
      const proposalMessage = { '@type': 'ProposalMessage' }
      const offerMessage = { '@type': 'OfferMessage' }
      const requestMessage = { '@type': 'RequestMessage' }
      const credentialMessage = { '@type': 'CredentialMessage' }

      const credentialRecord = getCredential({
        id: 'theCredentialId',
        state: CredentialState.Done,
        proposalMessage,
        offerMessage,
        requestMessage,
        credentialMessage,
      })

      await testModule.moveDidCommMessages(agent, credentialRecord)

      expect(didCommMessageRepository.save).toHaveBeenCalledTimes(4)
      const [[, proposalMessageRecord], [, offerMessageRecord], [, requestMessageRecord], [, credentialMessageRecord]] =
        mockFunction(didCommMessageRepository.save).mock.calls

      expect(proposalMessageRecord).toMatchObject({
        role: DidCommMessageRole.Receiver,
        associatedRecordId: 'theCredentialId',
        message: proposalMessage,
      })

      expect(offerMessageRecord).toMatchObject({
        role: DidCommMessageRole.Sender,
        associatedRecordId: 'theCredentialId',
        message: offerMessage,
      })

      expect(requestMessageRecord).toMatchObject({
        role: DidCommMessageRole.Receiver,
        associatedRecordId: 'theCredentialId',
        message: requestMessage,
      })

      expect(credentialMessageRecord).toMatchObject({
        role: DidCommMessageRole.Sender,
        associatedRecordId: 'theCredentialId',
        message: credentialMessage,
      })

      expect(credentialRecord.toJSON()).toEqual({
        _tags: {},
        credentialId: undefined,
        metadata: {},
        protocolVersion: undefined,
        id: 'theCredentialId',
        credentials: [],
        state: CredentialState.Done,
      })
    })
  })

  describe('getCredentialRole', () => {
    it('should return CredentialRole.Holder if the credentials array is not empty', () => {
      const credentialRecord = getCredential({
        credentials: [
          {
            credentialRecordId: 'theCredentialRecordId',
            credentialRecordType: 'indy',
          },
        ],
      })

      expect(testModule.getCredentialRole(credentialRecord)).toBe(testModule.V01_02MigrationCredentialRole.Holder)
    })

    it('should return CredentialRole.Issuer if state is Done and credentials array is empty', () => {
      const credentialRecord = getCredential({
        state: CredentialState.Done,
        credentials: [],
      })

      expect(testModule.getCredentialRole(credentialRecord)).toBe(testModule.V01_02MigrationCredentialRole.Issuer)
    })

    it('should return CredentialRole.Holder if the value is a holder state', () => {
      const holderStates = [
        CredentialState.Declined,
        CredentialState.ProposalSent,
        CredentialState.OfferReceived,
        CredentialState.RequestSent,
        CredentialState.CredentialReceived,
      ]

      for (const holderState of holderStates) {
        expect(
          testModule.getCredentialRole(
            getCredential({
              state: holderState,
            })
          )
        ).toBe(testModule.V01_02MigrationCredentialRole.Holder)
      }
    })

    it('should return CredentialRole.Issuer if the state is not a holder state no credentials are in the array and the state is not Done', () => {
      expect(
        testModule.getCredentialRole(
          getCredential({
            state: CredentialState.CredentialIssued,
          })
        )
      ).toBe(testModule.V01_02MigrationCredentialRole.Issuer)
    })
  })
})

function getCredential({
  metadata,
  credentialId,
  protocolVersion,
  proposalMessage,
  offerMessage,
  requestMessage,
  credentialMessage,
  state,
  credentials,
  id,
}: {
  metadata?: Record<string, unknown>
  credentialId?: string
  protocolVersion?: string
  /* eslint-disable @typescript-eslint/no-explicit-any */
  proposalMessage?: any
  offerMessage?: any
  requestMessage?: any
  credentialMessage?: any
  /* eslint-enable @typescript-eslint/no-explicit-any */
  state?: CredentialState
  credentials?: CredentialRecordBinding[]
  id?: string
}) {
  return JsonTransformer.fromJSON(
    {
      protocolVersion,
      credentialId,
      metadata,
      proposalMessage,
      offerMessage,
      requestMessage,
      credentialMessage,
      state,
      credentials,
      id,
    },
    CredentialExchangeRecord
  )
}
