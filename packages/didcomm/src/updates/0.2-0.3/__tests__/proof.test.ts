import { Agent } from '../../../../../core/src/agent/Agent'
import { JsonTransformer } from '../../../../../core/src/utils'
import { getAgentConfig, getAgentContext, mockFunction } from '../../../../../core/tests/helpers'
import { ProofExchangeRecord, ProofState } from '../../../modules/proofs'
import { ProofRepository } from '../../../modules/proofs/repository/ProofRepository'
import { DidCommMessageRole } from '../../../repository'
import { DidCommMessageRepository } from '../../../repository/DidCommMessageRepository'
import * as testModule from '../proof'

const agentConfig = getAgentConfig('Migration ProofExchangeRecord 0.2-0.3')
const agentContext = getAgentContext()

jest.mock('../../../../../modules/proofs/repository/ProofRepository')
const ProofRepositoryMock = ProofRepository as jest.Mock<ProofRepository>
const proofRepository = new ProofRepositoryMock()

jest.mock('../../../../../modules/didcomm/repository/DidCommMessageRepository')
const DidCommMessageRepositoryMock = DidCommMessageRepository as jest.Mock<DidCommMessageRepository>
const didCommMessageRepository = new DidCommMessageRepositoryMock()

jest.mock('../../../../..//core/src/agent/Agent', () => {
  return {
    Agent: jest.fn(() => ({
      config: agentConfig,
      context: agentContext,
      dependencyManager: {
        resolve: jest.fn((token) => (token === ProofRepositoryMock ? proofRepository : didCommMessageRepository)),
      },
    })),
  }
})

// Mock typed object
const AgentMock = Agent as jest.Mock<Agent>

describe('0.2-0.3 | Proof', () => {
  let agent: Agent

  beforeEach(() => {
    agent = new AgentMock()
  })

  afterEach(() => {
    mockFunction(didCommMessageRepository.save).mockReset()
  })

  describe('migrateProofExchangeRecordToV0_3()', () => {
    it('should fetch all records and apply the needed updates ', async () => {
      const records: ProofExchangeRecord[] = [getProof({})]

      mockFunction(proofRepository.getAll).mockResolvedValue(records)

      await testModule.migrateProofExchangeRecordToV0_3(agent)

      expect(proofRepository.getAll).toHaveBeenCalledTimes(1)
      expect(proofRepository.update).toHaveBeenCalledTimes(records.length)

      const updatedRecord = mockFunction(proofRepository.update).mock.calls[0][1]

      // Check first object is transformed correctly
      expect(updatedRecord.toJSON()).toMatchObject({
        protocolVersion: 'v1',
      })
    })
  })

  describe('migrateInternalProofExchangeRecordProperties()', () => {
    it('should set the protocol version to v1 if not set on the record', async () => {
      const proofRecord = getProof({})

      await testModule.migrateInternalProofExchangeRecordProperties(agent, proofRecord)

      expect(proofRecord).toMatchObject({
        protocolVersion: 'v1',
      })
    })

    it('should not set the protocol version if a value is already set', async () => {
      const proofRecord = getProof({
        protocolVersion: 'v2',
      })

      await testModule.migrateInternalProofExchangeRecordProperties(agent, proofRecord)

      expect(proofRecord).toMatchObject({
        protocolVersion: 'v2',
      })
    })
  })

  describe('moveDidCommMessages()', () => {
    it('should move the proposalMessage, requestMessage and presentationMessage to the didCommMessageRepository', async () => {
      const proposalMessage = { '@type': 'ProposalMessage' }
      const requestMessage = { '@type': 'RequestMessage' }
      const presentationMessage = { '@type': 'ProofMessage' }

      const proofRecord = getProof({
        id: 'theProofId',
        state: ProofState.Done,
        proposalMessage,
        requestMessage,
        presentationMessage,
      })

      await testModule.moveDidCommMessages(agent, proofRecord)

      expect(didCommMessageRepository.save).toHaveBeenCalledTimes(3)
      const [[, proposalMessageRecord], [, requestMessageRecord], [, presentationMessageRecord]] = mockFunction(
        didCommMessageRepository.save
      ).mock.calls

      expect(proposalMessageRecord).toMatchObject({
        role: DidCommMessageRole.Sender,
        associatedRecordId: 'theProofId',
        message: proposalMessage,
      })

      expect(requestMessageRecord).toMatchObject({
        role: DidCommMessageRole.Receiver,
        associatedRecordId: 'theProofId',
        message: requestMessage,
      })

      expect(presentationMessageRecord).toMatchObject({
        role: DidCommMessageRole.Sender,
        associatedRecordId: 'theProofId',
        message: presentationMessage,
      })

      expect(proofRecord.toJSON()).toEqual({
        _tags: {},
        protocolVersion: undefined,
        id: 'theProofId',
        state: ProofState.Done,
        metadata: {},
        isVerified: undefined,
      })
    })

    it('should only move the messages which exist in the record', async () => {
      const proposalMessage = { '@type': 'ProposalMessage' }

      const proofRecord = getProof({
        id: 'theProofId',
        state: ProofState.Done,
        proposalMessage,
        isVerified: true,
      })

      await testModule.moveDidCommMessages(agent, proofRecord)

      expect(didCommMessageRepository.save).toHaveBeenCalledTimes(1)
      const [[, proposalMessageRecord]] = mockFunction(didCommMessageRepository.save).mock.calls

      expect(proposalMessageRecord).toMatchObject({
        role: DidCommMessageRole.Receiver,
        associatedRecordId: 'theProofId',
        message: proposalMessage,
      })

      expect(proofRecord.toJSON()).toEqual({
        _tags: {},
        protocolVersion: undefined,
        id: 'theProofId',
        state: ProofState.Done,
        metadata: {},
        isVerified: true,
        presentationMessage: undefined,
        requestMessage: undefined,
      })
    })

    it('should determine the correct DidCommMessageRole for each message', async () => {
      const proposalMessage = { '@type': 'ProposalMessage' }
      const requestMessage = { '@type': 'RequestMessage' }
      const presentationMessage = { '@type': 'ProofMessage' }

      const proofRecord = getProof({
        id: 'theProofId',
        state: ProofState.Done,
        proposalMessage,
        requestMessage,
        presentationMessage,
      })

      await testModule.moveDidCommMessages(agent, proofRecord)

      expect(didCommMessageRepository.save).toHaveBeenCalledTimes(3)
      const [[, proposalMessageRecord], [, requestMessageRecord], [, presentationMessageRecord]] = mockFunction(
        didCommMessageRepository.save
      ).mock.calls

      expect(proposalMessageRecord).toMatchObject({
        role: DidCommMessageRole.Sender,
        associatedRecordId: 'theProofId',
        message: proposalMessage,
      })

      expect(requestMessageRecord).toMatchObject({
        role: DidCommMessageRole.Receiver,
        associatedRecordId: 'theProofId',
        message: requestMessage,
      })

      expect(presentationMessageRecord).toMatchObject({
        role: DidCommMessageRole.Sender,
        associatedRecordId: 'theProofId',
        message: presentationMessage,
      })

      expect(proofRecord.toJSON()).toEqual({
        _tags: {},
        metadata: {},
        protocolVersion: undefined,
        id: 'theProofId',
        state: ProofState.Done,
      })
    })
  })

  describe('getProofRole', () => {
    it('should return ProofRole.Verifier if isVerified is set', () => {
      expect(
        testModule.getProofRole(
          getProof({
            isVerified: true,
          })
        )
      ).toBe(testModule.V02_03MigrationProofRole.Verifier)

      expect(
        testModule.getProofRole(
          getProof({
            isVerified: false,
          })
        )
      ).toBe(testModule.V02_03MigrationProofRole.Verifier)
    })

    it('should return ProofRole.Prover if state is Done and isVerified is not set', () => {
      const proofRecord = getProof({
        state: ProofState.Done,
      })

      expect(testModule.getProofRole(proofRecord)).toBe(testModule.V02_03MigrationProofRole.Prover)
    })

    it('should return ProofRole.Prover if the value is a prover state', () => {
      const holderStates = [
        ProofState.Declined,
        ProofState.ProposalSent,
        ProofState.RequestReceived,
        ProofState.PresentationSent,
      ]

      for (const holderState of holderStates) {
        expect(
          testModule.getProofRole(
            getProof({
              state: holderState,
            })
          )
        ).toBe(testModule.V02_03MigrationProofRole.Prover)
      }
    })

    it('should return ProofRole.Verifier if the state is not a prover state, isVerified is not set and the state is not Done', () => {
      expect(
        testModule.getProofRole(
          getProof({
            state: ProofState.PresentationReceived,
          })
        )
      ).toBe(testModule.V02_03MigrationProofRole.Verifier)
    })
  })
})

function getProof({
  protocolVersion,
  proposalMessage,
  requestMessage,
  presentationMessage,
  state,
  isVerified,
  id,
}: {
  protocolVersion?: string
  /* eslint-disable @typescript-eslint/no-explicit-any */
  proposalMessage?: any
  requestMessage?: any
  presentationMessage?: any
  /* eslint-enable @typescript-eslint/no-explicit-any */
  state?: ProofState
  isVerified?: boolean
  id?: string
}) {
  return JsonTransformer.fromJSON(
    {
      protocolVersion,
      proposalMessage,
      requestMessage,
      presentationMessage,
      state,
      isVerified,
      id,
    },
    ProofExchangeRecord
  )
}
