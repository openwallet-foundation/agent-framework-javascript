import type { StorageService } from '@credo-ts/core'

import { EventEmitter, JsonTransformer } from '@credo-ts/core'
import { Subject } from 'rxjs'

import { InMemoryStorageService } from '../../../../../tests/InMemoryStorageService'
import { getAgentConfig, getAgentContext, mockFunction } from '../../../../core/tests'
import { ConnectionInvitationMessage } from '../../modules'
import { DidCommMessageRecord } from '../DidCommMessageRecord'
import { DidCommMessageRepository } from '../DidCommMessageRepository'
import { DidCommMessageRole } from '../DidCommMessageRole'

jest.mock('../../../../../tests/InMemoryStorageService')

const StorageMock = InMemoryStorageService as unknown as jest.Mock<InMemoryStorageService<DidCommMessageRecord>>

const invitationJson = {
  '@type': 'https://didcomm.org/connections/1.0/invitation',
  '@id': '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
  recipientKeys: ['recipientKeyOne', 'recipientKeyTwo'],
  serviceEndpoint: 'https://example.com',
  label: 'test',
}

const config = getAgentConfig('DidCommMessageRepository')
const agentContext = getAgentContext()

describe('DidCommMessageRepository', () => {
  let repository: DidCommMessageRepository
  let storageMock: StorageService<DidCommMessageRecord>
  let eventEmitter: EventEmitter

  beforeEach(async () => {
    storageMock = new StorageMock()
    eventEmitter = new EventEmitter(config.agentDependencies, new Subject())
    repository = new DidCommMessageRepository(storageMock, eventEmitter)
  })

  const getRecord = ({ id }: { id?: string } = {}) => {
    return new DidCommMessageRecord({
      id,
      message: invitationJson,
      role: DidCommMessageRole.Receiver,
      associatedRecordId: '16ca6665-29f6-4333-a80e-d34db6bfe0b0',
    })
  }

  describe('getAgentMessage()', () => {
    it('should get the record using the storage service', async () => {
      const record = getRecord({ id: 'test-id' })
      mockFunction(storageMock.findByQuery).mockReturnValue(Promise.resolve([record]))

      const invitation = await repository.findAgentMessage(agentContext, {
        messageClass: ConnectionInvitationMessage,
        associatedRecordId: '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
      })

      expect(storageMock.findByQuery).toBeCalledWith(
        agentContext,
        DidCommMessageRecord,
        {
          associatedRecordId: '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
          messageName: 'invitation',
          protocolName: 'connections',
          protocolMajorVersion: '1',
        },
        undefined
      )
      expect(invitation).toBeInstanceOf(ConnectionInvitationMessage)
    })
  })
  describe('findAgentMessage()', () => {
    it('should get the record using the storage service', async () => {
      const record = getRecord({ id: 'test-id' })
      mockFunction(storageMock.findByQuery).mockReturnValue(Promise.resolve([record]))

      const invitation = await repository.findAgentMessage(agentContext, {
        messageClass: ConnectionInvitationMessage,
        associatedRecordId: '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
      })

      expect(storageMock.findByQuery).toBeCalledWith(
        agentContext,
        DidCommMessageRecord,
        {
          associatedRecordId: '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
          messageName: 'invitation',
          protocolName: 'connections',
          protocolMajorVersion: '1',
        },
        undefined
      )
      expect(invitation).toBeInstanceOf(ConnectionInvitationMessage)
    })

    it("should return null because the record doesn't exist", async () => {
      mockFunction(storageMock.findByQuery).mockReturnValue(Promise.resolve([]))

      const invitation = await repository.findAgentMessage(agentContext, {
        messageClass: ConnectionInvitationMessage,
        associatedRecordId: '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
      })

      expect(storageMock.findByQuery).toBeCalledWith(
        agentContext,
        DidCommMessageRecord,
        {
          associatedRecordId: '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
          messageName: 'invitation',
          protocolName: 'connections',
          protocolMajorVersion: '1',
        },
        undefined
      )
      expect(invitation).toBeNull()
    })
  })

  describe('saveAgentMessage()', () => {
    it('should transform and save the agent message', async () => {
      await repository.saveAgentMessage(agentContext, {
        role: DidCommMessageRole.Receiver,
        agentMessage: JsonTransformer.fromJSON(invitationJson, ConnectionInvitationMessage),
        associatedRecordId: '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
      })

      expect(storageMock.save).toBeCalledWith(
        agentContext,
        expect.objectContaining({
          role: DidCommMessageRole.Receiver,
          message: invitationJson,
          associatedRecordId: '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
        })
      )
    })
  })

  describe('saveOrUpdateAgentMessage()', () => {
    it('should transform and save the agent message', async () => {
      mockFunction(storageMock.findByQuery).mockReturnValue(Promise.resolve([]))
      await repository.saveOrUpdateAgentMessage(agentContext, {
        role: DidCommMessageRole.Receiver,
        agentMessage: JsonTransformer.fromJSON(invitationJson, ConnectionInvitationMessage),
        associatedRecordId: '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
      })

      expect(storageMock.save).toBeCalledWith(
        agentContext,
        expect.objectContaining({
          role: DidCommMessageRole.Receiver,
          message: invitationJson,
          associatedRecordId: '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
        })
      )
    })

    it('should transform and update the agent message', async () => {
      const record = getRecord({ id: 'test-id' })
      mockFunction(storageMock.findByQuery).mockReturnValue(Promise.resolve([record]))
      await repository.saveOrUpdateAgentMessage(agentContext, {
        role: DidCommMessageRole.Receiver,
        agentMessage: JsonTransformer.fromJSON(invitationJson, ConnectionInvitationMessage),
        associatedRecordId: '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
      })

      expect(storageMock.findByQuery).toBeCalledWith(
        agentContext,
        DidCommMessageRecord,
        {
          associatedRecordId: '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
          messageName: 'invitation',
          protocolName: 'connections',
          protocolMajorVersion: '1',
        },
        undefined
      )
      expect(storageMock.update).toBeCalledWith(agentContext, record)
    })
  })
})
