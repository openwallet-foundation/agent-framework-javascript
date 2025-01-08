import { Agent } from '../../../../../core/src/agent/Agent'
import { JsonTransformer } from '../../../../../core/src/utils'
import { getAgentConfig, getAgentContext, mockFunction } from '../../../../../core/tests/helpers'
import { MediationRole, MediationRecord } from '../../../modules/routing'
import { MediationRepository } from '../../../modules/routing/repository/MediationRepository'
import * as testModule from '../mediation'

const agentConfig = getAgentConfig('Migration MediationRecord 0.1-0.2')
const agentContext = getAgentContext()

jest.mock('../../../modules/routing/repository/MediationRepository')
const MediationRepositoryMock = MediationRepository as jest.Mock<MediationRepository>
const mediationRepository = new MediationRepositoryMock()

jest.mock('../../../../../core/src/agent/Agent', () => {
  return {
    Agent: jest.fn(() => ({
      config: agentConfig,
      context: agentContext,
      dependencyManager: {
        resolve: jest.fn(() => mediationRepository),
      },
    })),
  }
})

// Mock typed object
const AgentMock = Agent as jest.Mock<Agent>

describe('0.1-0.2 | Mediation', () => {
  let agent: Agent

  beforeEach(() => {
    agent = new AgentMock()
  })

  describe('migrateMediationRecordToV0_2()', () => {
    it('should fetch all records and apply the needed updates ', async () => {
      const records: MediationRecord[] = [
        getMediationRecord({
          role: MediationRole.Mediator,
          endpoint: 'firstEndpoint',
        }),
        getMediationRecord({
          role: MediationRole.Recipient,
          endpoint: 'secondEndpoint',
        }),
      ]

      mockFunction(mediationRepository.getAll).mockResolvedValue(records)

      await testModule.migrateMediationRecordToV0_2(agent, {
        mediationRoleUpdateStrategy: 'allMediator',
      })

      expect(mediationRepository.getAll).toHaveBeenCalledTimes(1)
      expect(mediationRepository.update).toHaveBeenCalledTimes(records.length)

      // Check second object is transformed correctly
      expect(mediationRepository.update).toHaveBeenNthCalledWith(
        2,
        agentContext,
        getMediationRecord({
          role: MediationRole.Mediator,
          endpoint: 'secondEndpoint',
        })
      )

      expect(records).toMatchObject([
        {
          role: MediationRole.Mediator,
          endpoint: 'firstEndpoint',
        },
        {
          role: MediationRole.Mediator,
          endpoint: 'secondEndpoint',
        },
      ])
    })
  })

  describe('updateMediationRole()', () => {
    it(`should update the role to ${MediationRole.Mediator} if no endpoint exists on the record and mediationRoleUpdateStrategy is 'recipientIfEndpoint'`, async () => {
      const mediationRecord = getMediationRecord({
        role: MediationRole.Recipient,
      })

      await testModule.updateMediationRole(agent, mediationRecord, {
        mediationRoleUpdateStrategy: 'recipientIfEndpoint',
      })

      expect(mediationRecord).toMatchObject({
        role: MediationRole.Mediator,
      })
    })

    it(`should update the role to ${MediationRole.Recipient} if an endpoint exists on the record and mediationRoleUpdateStrategy is 'recipientIfEndpoint'`, async () => {
      const mediationRecord = getMediationRecord({
        role: MediationRole.Mediator,
        endpoint: 'something',
      })

      await testModule.updateMediationRole(agent, mediationRecord, {
        mediationRoleUpdateStrategy: 'recipientIfEndpoint',
      })

      expect(mediationRecord).toMatchObject({
        role: MediationRole.Recipient,
        endpoint: 'something',
      })
    })

    it(`should not update the role if mediationRoleUpdateStrategy is 'doNotChange'`, async () => {
      const mediationRecordMediator = getMediationRecord({
        role: MediationRole.Mediator,
        endpoint: 'something',
      })
      const mediationRecordRecipient = getMediationRecord({
        role: MediationRole.Recipient,
        endpoint: 'something',
      })

      await testModule.updateMediationRole(agent, mediationRecordMediator, {
        mediationRoleUpdateStrategy: 'doNotChange',
      })

      expect(mediationRecordMediator).toMatchObject({
        role: MediationRole.Mediator,
        endpoint: 'something',
      })

      await testModule.updateMediationRole(agent, mediationRecordRecipient, {
        mediationRoleUpdateStrategy: 'doNotChange',
      })

      expect(mediationRecordRecipient).toMatchObject({
        role: MediationRole.Recipient,
        endpoint: 'something',
      })
    })

    it(`should update the role to ${MediationRole.Recipient} if mediationRoleUpdateStrategy is 'allRecipient'`, async () => {
      const mediationRecord = getMediationRecord({
        role: MediationRole.Mediator,
        endpoint: 'something',
      })

      await testModule.updateMediationRole(agent, mediationRecord, {
        mediationRoleUpdateStrategy: 'allRecipient',
      })

      expect(mediationRecord).toMatchObject({
        role: MediationRole.Recipient,
        endpoint: 'something',
      })
    })

    it(`should update the role to ${MediationRole.Mediator} if mediationRoleUpdateStrategy is 'allMediator'`, async () => {
      const mediationRecord = getMediationRecord({
        role: MediationRole.Recipient,
        endpoint: 'something',
      })

      await testModule.updateMediationRole(agent, mediationRecord, {
        mediationRoleUpdateStrategy: 'allMediator',
      })

      expect(mediationRecord).toMatchObject({
        role: MediationRole.Mediator,
        endpoint: 'something',
      })
    })
  })
})

function getMediationRecord({ role, endpoint }: { role: MediationRole; endpoint?: string }) {
  return JsonTransformer.fromJSON(
    {
      role,
      endpoint,
    },
    MediationRecord
  )
}
