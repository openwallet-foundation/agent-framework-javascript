import type { CredentialRecordBinding } from '../../../modules/credentials'

import { Agent } from '../../../../../core/src/agent/Agent'
import { JsonTransformer } from '../../../../../core/src/utils'
import { getAgentConfig, getAgentContext, mockFunction } from '../../../../../core/tests'
import { CredentialRole, CredentialState, CredentialExchangeRecord } from '../../../modules/credentials'
import { CredentialRepository } from '../../../modules/credentials/repository/CredentialRepository'
import { DidCommMessageRole, DidCommMessageRecord } from '../../../repository'
import { DidCommMessageRepository } from '../../../repository/DidCommMessageRepository'
import * as testModule from '../credentialExchangeRecord'

const agentConfig = getAgentConfig('Migration - Credential Exchange Record - 0.4-0.5')
const agentContext = getAgentContext()

jest.mock('../../../modules/credentials/repository/CredentialRepository')
const CredentialRepositoryMock = CredentialRepository as jest.Mock<CredentialRepository>
const credentialRepository = new CredentialRepositoryMock()

jest.mock('../../../repository/DidCommMessageRepository')
const DidCommMessageRepositoryMock = DidCommMessageRepository as jest.Mock<DidCommMessageRepository>
const didCommMessageRepository = new DidCommMessageRepositoryMock()

jest.mock('../../../../../core/src/agent/Agent', () => ({
  Agent: jest.fn(() => ({
    config: agentConfig,
    context: agentContext,
    dependencyManager: {
      resolve: jest.fn((injectionToken) =>
        injectionToken === CredentialRepository ? credentialRepository : didCommMessageRepository
      ),
    },
  })),
}))

// Mock typed object
const AgentMock = Agent as jest.Mock<Agent>

describe('0.4-0.5 | Migration | Credential Exchange Record', () => {
  let agent: Agent

  beforeAll(() => {
    agent = new AgentMock()
  })

  afterEach(() => {
    jest.clearAllMocks()
  })

  describe('migrateCredentialExchangeRecordToV0_5()', () => {
    it('should fetch all records and apply the needed updates ', async () => {
      const records: CredentialExchangeRecord[] = [getCredentialRecord({ state: CredentialState.OfferSent })]

      mockFunction(credentialRepository.getAll).mockResolvedValue(records)

      await testModule.migrateCredentialExchangeRecordToV0_5(agent)

      expect(credentialRepository.getAll).toHaveBeenCalledTimes(1)
      expect(credentialRepository.update).toHaveBeenCalledTimes(1)

      const [, credentialRecord] = mockFunction(credentialRepository.update).mock.calls[0]
      expect(credentialRecord.toJSON()).toMatchObject({
        role: CredentialRole.Issuer,
      })
    })
  })

  describe('migrateRole()', () => {
    // according to: https://github.com/hyperledger/aries-rfcs/blob/main/features/0036-issue-credential/README.md#states
    genMigrateRoleTests(CredentialState.ProposalReceived, CredentialRole.Issuer)
    genMigrateRoleTests(CredentialState.OfferSent, CredentialRole.Issuer)
    genMigrateRoleTests(CredentialState.RequestReceived, CredentialRole.Issuer)
    genMigrateRoleTests(CredentialState.CredentialIssued, CredentialRole.Issuer)
    genMigrateRoleTests(CredentialState.Done, CredentialRole.Issuer, { doneStateWithCredentials: false })

    genMigrateRoleTests(CredentialState.ProposalSent, CredentialRole.Holder)
    genMigrateRoleTests(CredentialState.OfferReceived, CredentialRole.Holder)
    genMigrateRoleTests(CredentialState.RequestSent, CredentialRole.Holder)
    genMigrateRoleTests(CredentialState.CredentialReceived, CredentialRole.Holder)
    genMigrateRoleTests(CredentialState.Done, CredentialRole.Holder, { doneStateWithCredentials: true })
    genMigrateRoleTests(CredentialState.Declined, CredentialRole.Holder)

    genMigrateRoleTests(CredentialState.Abandoned, CredentialRole.Issuer, {
      didCommMessage: { messageName: 'propose-credential', didCommMessageRole: DidCommMessageRole.Receiver },
    })
    genMigrateRoleTests(CredentialState.Abandoned, CredentialRole.Holder, {
      didCommMessage: { messageName: 'propose-credential', didCommMessageRole: DidCommMessageRole.Sender },
    })

    genMigrateRoleTests(CredentialState.Abandoned, CredentialRole.Holder, {
      didCommMessage: { messageName: 'offer-credential', didCommMessageRole: DidCommMessageRole.Receiver },
    })
    genMigrateRoleTests(CredentialState.Abandoned, CredentialRole.Issuer, {
      didCommMessage: { messageName: 'offer-credential', didCommMessageRole: DidCommMessageRole.Sender },
    })

    genMigrateRoleTests(CredentialState.Abandoned, CredentialRole.Issuer, {
      didCommMessage: { messageName: 'request-credential', didCommMessageRole: DidCommMessageRole.Receiver },
    })
    genMigrateRoleTests(CredentialState.Abandoned, CredentialRole.Holder, {
      didCommMessage: { messageName: 'request-credential', didCommMessageRole: DidCommMessageRole.Sender },
    })
  })

  function genMigrateRoleTests(
    state: CredentialState,
    expectedRole: CredentialRole,
    {
      doneStateWithCredentials,
      didCommMessage,
    }: {
      doneStateWithCredentials?: boolean
      didCommMessage?: {
        messageName: 'propose-credential' | 'offer-credential' | 'request-credential'
        didCommMessageRole: DidCommMessageRole
      }
    } = {}
  ) {
    it(`Should migrate state: '${state}' to role: '${expectedRole}'${
      doneStateWithCredentials !== undefined
        ? ` when record ${doneStateWithCredentials ? 'has' : 'does not have'} credentials property`
        : ''
    }`, async () => {
      const record = getCredentialRecord({
        state,
        credentials: doneStateWithCredentials
          ? [{ credentialRecordId: 'some-id', credentialRecordType: 'some-record' }]
          : undefined,
      })

      if (didCommMessage) {
        mockFunction(didCommMessageRepository.findByQuery).mockResolvedValueOnce([
          new DidCommMessageRecord({
            message: {
              '@id': '123',
              '@type': `https://didcomm.org/issue-credential/1.0/${didCommMessage.messageName}`,
            },
            role: didCommMessage.didCommMessageRole,
            associatedRecordId: record.id,
          }),
        ])
      }

      await testModule.migrateRole(agent, record)

      expect(record.toJSON()).toMatchObject({
        role: expectedRole,
      })

      if (didCommMessage) {
        expect(didCommMessageRepository.findByQuery).toHaveBeenCalledTimes(1)
        expect(didCommMessageRepository.findByQuery).toHaveBeenCalledWith(agent.context, {
          associatedRecordId: record.id,
          $or: [
            { messageName: 'offer-credential' },
            { messageName: 'propose-credential' },
            { messageName: 'request-credential' },
          ],
        })
      }
    })
  }
})

function getCredentialRecord({
  id,
  metadata,
  credentials,
  state,
}: {
  id?: string
  metadata?: Record<string, unknown>
  credentials?: CredentialRecordBinding[]
  state?: CredentialState
}) {
  return JsonTransformer.fromJSON(
    {
      id: id ?? 'credential-id',
      metadata,
      credentials,
      state,
    },
    CredentialExchangeRecord
  )
}
