import type { AgentContext, TagsBase } from '@credo-ts/core'

import { TypedArrayEncoder, SigningProviderRegistry, RecordDuplicateError, RecordNotFoundError } from '@credo-ts/core'
import { ariesAskar } from '@hyperledger/aries-askar-nodejs'

import { TestRecord } from '../../../../core/src/storage/__tests__/TestRecord'
import { agentDependencies, getAgentConfig, getAgentContext } from '../../../../core/tests/helpers'
import { AskarWallet } from '../../wallet/AskarWallet'
import { AskarStorageService } from '../AskarStorageService'
import { askarQueryFromSearchQuery } from '../utils'

const startDate = Date.now()

describe('AskarStorageService', () => {
  let wallet: AskarWallet
  let storageService: AskarStorageService<TestRecord>
  let agentContext: AgentContext

  beforeEach(async () => {
    const agentConfig = getAgentConfig('AskarStorageServiceTest')

    wallet = new AskarWallet(agentConfig.logger, new agentDependencies.FileSystem(), new SigningProviderRegistry([]))
    agentContext = getAgentContext({
      wallet,
      agentConfig,
    })
    await wallet.createAndOpen(agentConfig.walletConfig)
    storageService = new AskarStorageService<TestRecord>()
  })

  afterEach(async () => {
    await wallet.delete()
  })

  const insertRecord = async ({ id, tags }: { id?: string; tags?: TagsBase }) => {
    const props = {
      id,
      foo: 'bar',
      tags: tags ?? { myTag: 'foobar' },
    }
    const record = new TestRecord(props)
    await storageService.save(agentContext, record)
    return record
  }

  describe('tag transformation', () => {
    it('should correctly transform tag values to string before storing', async () => {
      const record = await insertRecord({
        id: 'test-id',
        tags: {
          someBoolean: true,
          someOtherBoolean: false,
          someStringValue: 'string',
          anArrayValue: ['foo', 'bar'],
          anArrayValueWhereValuesContainColon: ['foo:bar:test', 'https://google.com'],
          // booleans are stored as '1' and '0' so we store the string values '1' and '0' as 'n__1' and 'n__0'
          someStringNumberValue: '1',
          anotherStringNumberValue: '0',
        },
      })

      const retrieveRecord = await wallet.withSession((session) =>
        ariesAskar.sessionFetch({
          category: record.type,
          name: record.id,
          // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          sessionHandle: session.handle!,
          forUpdate: false,
        })
      )

      expect(JSON.parse(retrieveRecord?.getTags(0) ?? '{}')).toEqual({
        someBoolean: '1',
        someOtherBoolean: '0',
        someStringValue: 'string',
        'anArrayValue:foo': '1',
        'anArrayValue:bar': '1',
        'anArrayValueWhereValuesContainColon:foo:bar:test': '1',
        'anArrayValueWhereValuesContainColon:https://google.com': '1',
        someStringNumberValue: 'n__1',
        anotherStringNumberValue: 'n__0',
      })
    })

    it('should correctly transform tag values from string after retrieving', async () => {
      await wallet.withSession(
        async (session) =>
          await ariesAskar.sessionUpdate({
            category: TestRecord.type,
            name: 'some-id',
            // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
            sessionHandle: session.handle!,
            value: TypedArrayEncoder.fromString('{}'),
            tags: {
              someBoolean: '1',
              someOtherBoolean: '0',
              someStringValue: 'string',
              // Before 0.5.0, there was a bug where array values that contained a : would be incorrectly
              // parsed back into a record as we would split on ':' and thus only the first part would be included
              // in the record as the tag value. If the record was never re-saved it would work well, as well as if the
              // record tag was generated dynamically before save (as then the incorrectly transformed back value would be
              // overwritten again on save).
              'anArrayValueWhereValuesContainColon:foo:bar:test': '1',
              'anArrayValueWhereValuesContainColon:https://google.com': '1',
              'anArrayValue:foo': '1',
              'anArrayValue:bar': '1',
              // booleans are stored as '1' and '0' so we store the string values '1' and '0' as 'n__1' and 'n__0'
              someStringNumberValue: 'n__1',
              anotherStringNumberValue: 'n__0',
            },
            operation: 0, // EntryOperation.Insert
          })
      )

      const record = await storageService.getById(agentContext, TestRecord, 'some-id')

      expect(record.getTags()).toEqual({
        someBoolean: true,
        someOtherBoolean: false,
        someStringValue: 'string',
        anArrayValue: expect.arrayContaining(['bar', 'foo']),
        anArrayValueWhereValuesContainColon: expect.arrayContaining(['foo:bar:test', 'https://google.com']),
        someStringNumberValue: '1',
        anotherStringNumberValue: '0',
      })
    })
  })

  describe('save()', () => {
    it('should throw RecordDuplicateError if a record with the id already exists', async () => {
      const record = await insertRecord({ id: 'test-id' })

      return expect(() => storageService.save(agentContext, record)).rejects.toThrowError(RecordDuplicateError)
    })

    it('should save the record', async () => {
      const record = await insertRecord({ id: 'test-id' })
      const found = await storageService.getById(agentContext, TestRecord, 'test-id')

      expect(record).toEqual(found)
    })

    it('updatedAt should have a new value after a save', async () => {
      const record = await insertRecord({ id: 'test-id' })
      expect(record.updatedAt?.getTime()).toBeGreaterThan(startDate)
    })
  })

  describe('getById()', () => {
    it('should throw RecordNotFoundError if the record does not exist', async () => {
      return expect(() => storageService.getById(agentContext, TestRecord, 'does-not-exist')).rejects.toThrowError(
        RecordNotFoundError
      )
    })

    it('should return the record by id', async () => {
      const record = await insertRecord({ id: 'test-id' })
      const found = await storageService.getById(agentContext, TestRecord, 'test-id')

      expect(found).toEqual(record)
    })
  })

  describe('update()', () => {
    it('should throw RecordNotFoundError if the record does not exist', async () => {
      const record = new TestRecord({
        id: 'test-id',
        foo: 'test',
        tags: { some: 'tag' },
      })

      return expect(() => storageService.update(agentContext, record)).rejects.toThrowError(RecordNotFoundError)
    })

    it('should update the record', async () => {
      const record = await insertRecord({ id: 'test-id' })

      record.replaceTags({ ...record.getTags(), foo: 'bar' })
      record.foo = 'foobaz'
      await storageService.update(agentContext, record)

      const retrievedRecord = await storageService.getById(agentContext, TestRecord, record.id)
      expect(retrievedRecord).toEqual(record)
    })

    it('updatedAt should have a new value after an update', async () => {
      const record = await insertRecord({ id: 'test-id' })
      expect(record.updatedAt?.getTime()).toBeGreaterThan(startDate)
    })
  })

  describe('delete()', () => {
    it('should throw RecordNotFoundError if the record does not exist', async () => {
      const record = new TestRecord({
        id: 'test-id',
        foo: 'test',
        tags: { some: 'tag' },
      })

      return expect(() => storageService.delete(agentContext, record)).rejects.toThrowError(RecordNotFoundError)
    })

    it('should delete the record', async () => {
      const record = await insertRecord({ id: 'test-id' })
      await storageService.delete(agentContext, record)

      return expect(() => storageService.getById(agentContext, TestRecord, record.id)).rejects.toThrowError(
        RecordNotFoundError
      )
    })
  })

  describe('getAll()', () => {
    it('should retrieve all records', async () => {
      const createdRecords = await Promise.all(
        Array(5)
          .fill(undefined)
          .map((_, index) => insertRecord({ id: `record-${index}` }))
      )

      const records = await storageService.getAll(agentContext, TestRecord)

      expect(records).toEqual(expect.arrayContaining(createdRecords))
    })
  })

  describe('findByQuery()', () => {
    it('should retrieve all records that match the query', async () => {
      const expectedRecord = await insertRecord({ tags: { myTag: 'foobar' } })
      const expectedRecord2 = await insertRecord({ tags: { myTag: 'foobar' } })
      await insertRecord({ tags: { myTag: 'notfoobar' } })

      const records = await storageService.findByQuery(agentContext, TestRecord, { myTag: 'foobar' })

      expect(records.length).toBe(2)
      expect(records).toEqual(expect.arrayContaining([expectedRecord, expectedRecord2]))
    })

    it('finds records using $and statements', async () => {
      const expectedRecord = await insertRecord({ tags: { myTag: 'foo', anotherTag: 'bar' } })
      await insertRecord({ tags: { myTag: 'notfoobar' } })

      const records = await storageService.findByQuery(agentContext, TestRecord, {
        $and: [{ myTag: 'foo' }, { anotherTag: 'bar' }],
      })

      expect(records.length).toBe(1)
      expect(records[0]).toEqual(expectedRecord)
    })

    it('finds records using $or statements', async () => {
      const expectedRecord = await insertRecord({ tags: { myTag: 'foo' } })
      const expectedRecord2 = await insertRecord({ tags: { anotherTag: 'bar' } })
      await insertRecord({ tags: { myTag: 'notfoobar' } })

      const records = await storageService.findByQuery(agentContext, TestRecord, {
        $or: [{ myTag: 'foo' }, { anotherTag: 'bar' }],
      })

      expect(records.length).toBe(2)
      expect(records).toEqual(expect.arrayContaining([expectedRecord, expectedRecord2]))
    })

    it('finds records using $not statements', async () => {
      const expectedRecord = await insertRecord({ tags: { myTag: 'foo' } })
      const expectedRecord2 = await insertRecord({ tags: { anotherTag: 'bar' } })
      await insertRecord({ tags: { myTag: 'notfoobar' } })

      const records = await storageService.findByQuery(agentContext, TestRecord, {
        $not: { myTag: 'notfoobar' },
      })

      expect(records.length).toBe(2)
      expect(records).toEqual(expect.arrayContaining([expectedRecord, expectedRecord2]))
    })

    it('correctly transforms an advanced query into a valid WQL query', async () => {
      const expectedQuery = {
        $and: [
          {
            $and: undefined,
            $not: undefined,
            $or: [
              { myTag: '1', $and: undefined, $or: undefined, $not: undefined },
              { myTag: '0', $and: undefined, $or: undefined, $not: undefined },
            ],
          },
          {
            $or: undefined,
            $not: undefined,
            $and: [
              { theNumber: 'n__0', $and: undefined, $or: undefined, $not: undefined },
              { theNumber: 'n__1', $and: undefined, $or: undefined, $not: undefined },
            ],
          },
        ],
        $or: [
          {
            'aValue:foo': '1',
            'aValue:bar': '1',
            $and: undefined,
            $or: undefined,
            $not: undefined,
          },
        ],
        $not: { myTag: 'notfoobar', $and: undefined, $or: undefined, $not: undefined },
      }

      expect(
        askarQueryFromSearchQuery<TestRecord>({
          $and: [
            {
              $or: [{ myTag: true }, { myTag: false }],
            },
            {
              $and: [{ theNumber: '0' }, { theNumber: '1' }],
            },
          ],
          $or: [
            {
              aValue: ['foo', 'bar'],
            },
          ],
          $not: { myTag: 'notfoobar' },
        })
      ).toEqual(expectedQuery)
    })

    it('should retrieve correct paginated records', async () => {
      await insertRecord({ tags: { myTag: 'notfoobar' } })
      await insertRecord({ tags: { myTag: 'foobar' } })
      await insertRecord({ tags: { myTag: 'foobar' } })
      await insertRecord({ tags: { myTag: 'notfoobar' } })

      const records = await storageService.findByQuery(agentContext, TestRecord, {}, { offset: 3, limit: 2 })

      expect(records.length).toBe(1)
    })

    it('should retrieve correct paginated records that match the query', async () => {
      await insertRecord({ tags: { myTag: 'notfoobar' } })
      const expectedRecord1 = await insertRecord({ tags: { myTag: 'foobar' } })
      const expectedRecord2 = await insertRecord({ tags: { myTag: 'foobar' } })
      await insertRecord({ tags: { myTag: 'notfoobar' } })

      const records = await storageService.findByQuery(
        agentContext,
        TestRecord,
        {
          myTag: 'foobar',
        },
        { offset: 0, limit: 2 }
      )

      expect(records.length).toBe(2)
      expect(records).toEqual(expect.arrayContaining([expectedRecord1, expectedRecord2]))
    })
  })
})
