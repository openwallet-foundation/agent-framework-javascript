import type { MediationRecordProps } from '../../../modules'
import type { ConnectionRecordProps, CustomConnectionTags } from '../../../modules/connections'

import { Agent } from '../../../../..//core/src/agent/Agent'
import { JsonTransformer } from '../../../../..//core/src/utils'
import { getAgentConfig, getAgentContext, mockFunction } from '../../../../..//core/tests/helpers'
import { MediationRecord, MediationRole, MediationState } from '../../../modules'
import { ConnectionRecord, ConnectionType, DidExchangeRole, DidExchangeState } from '../../../modules/connections'
import { ConnectionRepository } from '../../../modules/connections/repository/ConnectionRepository'
import { MediationRepository } from '../../../modules/routing/repository/MediationRepository'
import * as testModule from '../connection'

const agentConfig = getAgentConfig('Migration ConnectionRecord 0.2-0.3')
const agentContext = getAgentContext()

jest.mock('../../../modules/connections/repository/ConnectionRepository')
const ConnectionRepositoryMock = ConnectionRepository as jest.Mock<ConnectionRepository>
const connectionRepository = new ConnectionRepositoryMock()

jest.mock('../../../modules/routing/repository/MediationRepository')
const MediationRepositoryMock = MediationRepository as jest.Mock<MediationRepository>
const mediationRepository = new MediationRepositoryMock()

jest.mock('../../../../../agent/Agent', () => {
  return {
    Agent: jest.fn(() => ({
      config: agentConfig,
      context: agentContext,
      dependencyManager: {
        resolve: jest.fn((token) => (token === ConnectionRepositoryMock ? connectionRepository : mediationRepository)),
      },
    })),
  }
})

const AgentMock = Agent as jest.Mock<Agent>

describe('0.2-0.3 | Connection', () => {
  let agent: Agent

  beforeEach(() => {
    agent = AgentMock()
  })

  describe('migrateConnectionRecordToV0_3', () => {
    it('should fetch all records and apply the needed updates', async () => {
      const connectionRecordsProps = [
        getConnection({
          state: DidExchangeState.Completed,
          role: DidExchangeRole.Responder,
          id: 'theConnectionId',
        }),
        getConnection({
          state: DidExchangeState.Completed,
          role: DidExchangeRole.Responder,
          id: 'theConnectionId2',
        }),
      ]

      const mediationRecordsProps = [
        getMediator({
          state: MediationState.Granted,
          role: MediationRole.Recipient,
          connectionId: 'theConnectionId',
          threadId: 'theThreadId',
        }),
      ]

      const connectionRecords: ConnectionRecord[] = connectionRecordsProps

      mockFunction(connectionRepository.getAll).mockResolvedValue(connectionRecords)

      const mediationRecords: MediationRecord[] = mediationRecordsProps

      mockFunction(mediationRepository.getAll).mockResolvedValue(mediationRecords)

      await testModule.migrateConnectionRecordToV0_3(agent)

      expect(connectionRepository.getAll).toBeCalledTimes(1)
      expect(mediationRepository.getAll).toBeCalledTimes(1)
      expect(connectionRepository.update).toBeCalledTimes(connectionRecords.length)
    })
  })

  describe('migrateConnectionRecordMediatorTags', () => {
    it('should set the mediator connection type on the record, connection type tags should be undefined', async () => {
      const connectionRecordProps = {
        state: DidExchangeState.Completed,
        role: DidExchangeRole.Responder,
        id: 'theConnectionId',
      }

      const connectionRecord = getConnection(connectionRecordProps)

      await testModule.migrateConnectionRecordTags(agent, connectionRecord, new Set(['theConnectionId']))

      expect(connectionRecord.toJSON()).toEqual({
        ...connectionRecordProps,
        connectionTypes: [ConnectionType.Mediator],
        _tags: {
          connectionType: undefined,
        },
        previousDids: [],
        previousTheirDids: [],
        metadata: {},
      })
    })

    it('should add the mediator connection type to existing types on the record, connection type tags should be undefined', async () => {
      const connectionRecordProps = {
        state: DidExchangeState.Completed,
        role: DidExchangeRole.Responder,
        id: 'theConnectionId',
        _tags: {
          connectionType: ['theConnectionType'],
        },
      }

      const connectionRecord = getConnection(connectionRecordProps)

      await testModule.migrateConnectionRecordTags(agent, connectionRecord, new Set(['theConnectionId']))

      expect(connectionRecord.toJSON()).toEqual({
        ...connectionRecordProps,
        connectionTypes: ['theConnectionType', ConnectionType.Mediator],
        _tags: {
          connectionType: undefined,
        },
        previousDids: [],
        previousTheirDids: [],
        metadata: {},
      })
    })

    it('should not set the mediator connection type on the record, connection type tags should be undefined', async () => {
      const connectionRecordProps = {
        state: DidExchangeState.Completed,
        role: DidExchangeRole.Responder,
        id: 'theConnectionId',
      }

      const connectionRecord = getConnection(connectionRecordProps)

      await testModule.migrateConnectionRecordTags(agent, connectionRecord)

      expect(connectionRecord.toJSON()).toEqual({
        ...connectionRecordProps,
        connectionTypes: [],
        previousDids: [],
        previousTheirDids: [],
        _tags: {
          connectionType: undefined,
        },
        metadata: {},
      })
    })

    it('should not add the mediator connection type to existing types on the record, connection type tags should be undefined', async () => {
      const connectionRecordProps = {
        state: DidExchangeState.Completed,
        role: DidExchangeRole.Responder,
        id: 'theConnectionId',
        _tags: {
          connectionType: ['theConnectionType'],
        },
      }

      const connectionRecord = getConnection(connectionRecordProps)

      await testModule.migrateConnectionRecordTags(agent, connectionRecord)

      expect(connectionRecord.toJSON()).toEqual({
        ...connectionRecordProps,
        connectionTypes: ['theConnectionType'],
        _tags: {
          connectionType: undefined,
        },
        metadata: {},
        previousDids: [],
        previousTheirDids: [],
      })
    })
  })
})

function getConnection({ state, role, id, _tags }: ConnectionRecordProps & { _tags?: CustomConnectionTags }) {
  return JsonTransformer.fromJSON({ state, role, id, _tags }, ConnectionRecord)
}

function getMediator({ state, role, connectionId, threadId }: MediationRecordProps) {
  return JsonTransformer.fromJSON({ state, role, connectionId, threadId }, MediationRecord)
}
