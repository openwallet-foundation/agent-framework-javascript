import type { AgentContext } from '../../agent'
import type { TagsBase } from '../BaseRecord'
import type { RecordDeletedEvent, RecordSavedEvent, RecordUpdatedEvent } from '../RepositoryEvents'

import { Subject } from 'rxjs'

import { getAgentConfig, getAgentContext, mockFunction } from '../../../tests/helpers'
import { EventEmitter } from '../../agent/EventEmitter'
import { AriesFrameworkError, RecordDuplicateError, RecordNotFoundError } from '../../error'
import { IndyStorageService } from '../IndyStorageService'
import { Repository } from '../Repository'
import { RepositoryEventTypes } from '../RepositoryEvents'

import { TestRecord } from './TestRecord'

jest.mock('../IndyStorageService')

const StorageMock = IndyStorageService as unknown as jest.Mock<IndyStorageService<TestRecord>>

const config = getAgentConfig('Repository')

describe('Repository', () => {
  let repository: Repository<TestRecord>
  let storageMock: IndyStorageService<TestRecord>
  let agentContext: AgentContext
  let eventEmitter: EventEmitter

  beforeEach(async () => {
    storageMock = new StorageMock()
    eventEmitter = new EventEmitter(config.agentDependencies, new Subject())
    repository = new Repository(TestRecord, storageMock, eventEmitter)
    agentContext = getAgentContext()
  })

  const getRecord = ({ id, tags }: { id?: string; tags?: TagsBase } = {}) => {
    return new TestRecord({
      id,
      foo: 'bar',
      tags: tags ?? { myTag: 'foobar' },
    })
  }

  describe('save()', () => {
    it('should save the record using the storage service', async () => {
      const record = getRecord({ id: 'test-id' })
      await repository.save(agentContext, record)

      expect(storageMock.save).toBeCalledWith(agentContext, record)
    })

    it(`should emit saved event`, async () => {
      const eventListenerMock = jest.fn()
      eventEmitter.on<RecordSavedEvent<TestRecord>>(RepositoryEventTypes.RecordSaved, eventListenerMock)

      // given
      const record = getRecord({ id: 'test-id' })

      // when
      await repository.save(agentContext, record)

      // then
      expect(eventListenerMock).toHaveBeenCalledWith({
        type: 'RecordSaved',
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          record: expect.objectContaining({
            id: 'test-id',
          }),
        },
      })
    })
  })

  describe('update()', () => {
    it('should update the record using the storage service', async () => {
      const record = getRecord({ id: 'test-id' })
      await repository.update(agentContext, record)

      expect(storageMock.update).toBeCalledWith(agentContext, record)
    })

    it(`should emit updated event`, async () => {
      const eventListenerMock = jest.fn()
      eventEmitter.on<RecordUpdatedEvent<TestRecord>>(RepositoryEventTypes.RecordUpdated, eventListenerMock)

      // given
      const record = getRecord({ id: 'test-id' })

      // when
      await repository.update(agentContext, record)

      // then
      expect(eventListenerMock).toHaveBeenCalledWith({
        type: 'RecordUpdated',
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          record: expect.objectContaining({
            id: 'test-id',
          }),
        },
      })
    })
  })

  describe('delete()', () => {
    it('should delete the record using the storage service', async () => {
      const record = getRecord({ id: 'test-id' })
      await repository.delete(agentContext, record)

      expect(storageMock.delete).toBeCalledWith(agentContext, record)
    })

    it(`should emit deleted event`, async () => {
      const eventListenerMock = jest.fn()
      eventEmitter.on<RecordDeletedEvent<TestRecord>>(RepositoryEventTypes.RecordDeleted, eventListenerMock)

      // given
      const record = getRecord({ id: 'test-id' })

      // when
      await repository.delete(agentContext, record)

      // then
      expect(eventListenerMock).toHaveBeenCalledWith({
        type: 'RecordDeleted',
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          record: expect.objectContaining({
            id: 'test-id',
          }),
        },
      })
    })
  })

  describe('getById()', () => {
    it('should get the record using the storage service', async () => {
      const record = getRecord({ id: 'test-id' })
      mockFunction(storageMock.getById).mockReturnValue(Promise.resolve(record))

      const returnValue = await repository.getById(agentContext, 'test-id')

      expect(storageMock.getById).toBeCalledWith(agentContext, TestRecord, 'test-id')
      expect(returnValue).toBe(record)
    })
  })

  describe('findById()', () => {
    it('should get the record using the storage service', async () => {
      const record = getRecord({ id: 'test-id' })
      mockFunction(storageMock.getById).mockReturnValue(Promise.resolve(record))

      const returnValue = await repository.findById(agentContext, 'test-id')

      expect(storageMock.getById).toBeCalledWith(agentContext, TestRecord, 'test-id')
      expect(returnValue).toBe(record)
    })

    it('should return null if the storage service throws RecordNotFoundError', async () => {
      mockFunction(storageMock.getById).mockReturnValue(
        Promise.reject(new RecordNotFoundError('Not found', { recordType: TestRecord.type }))
      )

      const returnValue = await repository.findById(agentContext, 'test-id')

      expect(storageMock.getById).toBeCalledWith(agentContext, TestRecord, 'test-id')
      expect(returnValue).toBeNull()
    })

    it('should return null if the storage service throws an error that is not RecordNotFoundError', async () => {
      mockFunction(storageMock.getById).mockReturnValue(Promise.reject(new AriesFrameworkError('Not found')))

      expect(repository.findById(agentContext, 'test-id')).rejects.toThrowError(AriesFrameworkError)
      expect(storageMock.getById).toBeCalledWith(agentContext, TestRecord, 'test-id')
    })
  })

  describe('getAll()', () => {
    it('should get the records using the storage service', async () => {
      const record = getRecord({ id: 'test-id' })
      const record2 = getRecord({ id: 'test-id2' })
      mockFunction(storageMock.getAll).mockReturnValue(Promise.resolve([record, record2]))

      const returnValue = await repository.getAll(agentContext)

      expect(storageMock.getAll).toBeCalledWith(agentContext, TestRecord)
      expect(returnValue).toEqual(expect.arrayContaining([record, record2]))
    })
  })

  describe('findByQuery()', () => {
    it('should get the records using the storage service', async () => {
      const record = getRecord({ id: 'test-id' })
      const record2 = getRecord({ id: 'test-id2' })
      mockFunction(storageMock.findByQuery).mockReturnValue(Promise.resolve([record, record2]))

      const returnValue = await repository.findByQuery(agentContext, { something: 'interesting' })

      expect(storageMock.findByQuery).toBeCalledWith(agentContext, TestRecord, { something: 'interesting' })
      expect(returnValue).toEqual(expect.arrayContaining([record, record2]))
    })
  })

  describe('findSingleByQuery()', () => {
    it('should get the record using the storage service', async () => {
      const record = getRecord({ id: 'test-id' })
      mockFunction(storageMock.findByQuery).mockReturnValue(Promise.resolve([record]))

      const returnValue = await repository.findSingleByQuery(agentContext, { something: 'interesting' })

      expect(storageMock.findByQuery).toBeCalledWith(agentContext, TestRecord, { something: 'interesting' })
      expect(returnValue).toBe(record)
    })

    it('should return null if the no records are returned by the storage service', async () => {
      mockFunction(storageMock.findByQuery).mockReturnValue(Promise.resolve([]))

      const returnValue = await repository.findSingleByQuery(agentContext, { something: 'interesting' })

      expect(storageMock.findByQuery).toBeCalledWith(agentContext, TestRecord, { something: 'interesting' })
      expect(returnValue).toBeNull()
    })

    it('should throw RecordDuplicateError if more than one record is returned by the storage service', async () => {
      const record = getRecord({ id: 'test-id' })
      const record2 = getRecord({ id: 'test-id2' })
      mockFunction(storageMock.findByQuery).mockReturnValue(Promise.resolve([record, record2]))

      expect(repository.findSingleByQuery(agentContext, { something: 'interesting' })).rejects.toThrowError(
        RecordDuplicateError
      )
      expect(storageMock.findByQuery).toBeCalledWith(agentContext, TestRecord, { something: 'interesting' })
    })
  })

  describe('getSingleByQuery()', () => {
    it('should get the record using the storage service', async () => {
      const record = getRecord({ id: 'test-id' })
      mockFunction(storageMock.findByQuery).mockReturnValue(Promise.resolve([record]))

      const returnValue = await repository.getSingleByQuery(agentContext, { something: 'interesting' })

      expect(storageMock.findByQuery).toBeCalledWith(agentContext, TestRecord, { something: 'interesting' })
      expect(returnValue).toBe(record)
    })

    it('should throw RecordNotFoundError if no records are returned by the storage service', async () => {
      mockFunction(storageMock.findByQuery).mockReturnValue(Promise.resolve([]))

      expect(repository.getSingleByQuery(agentContext, { something: 'interesting' })).rejects.toThrowError(
        RecordNotFoundError
      )
      expect(storageMock.findByQuery).toBeCalledWith(agentContext, TestRecord, { something: 'interesting' })
    })

    it('should throw RecordDuplicateError if more than one record is returned by the storage service', async () => {
      const record = getRecord({ id: 'test-id' })
      const record2 = getRecord({ id: 'test-id2' })
      mockFunction(storageMock.findByQuery).mockReturnValue(Promise.resolve([record, record2]))

      expect(repository.getSingleByQuery(agentContext, { something: 'interesting' })).rejects.toThrowError(
        RecordDuplicateError
      )
      expect(storageMock.findByQuery).toBeCalledWith(agentContext, TestRecord, { something: 'interesting' })
    })
  })
})
