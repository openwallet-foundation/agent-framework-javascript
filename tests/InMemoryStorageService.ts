import type { AgentContext } from '../packages/core/src/agent'
import type { BaseRecord, TagsBase } from '../packages/core/src/storage/BaseRecord'
import type {
  StorageService,
  BaseRecordConstructor,
  Query,
  QueryOptions,
} from '../packages/core/src/storage/StorageService'

import { InMemoryWallet } from './InMemoryWallet'

import { RecordNotFoundError, RecordDuplicateError, JsonTransformer, injectable } from '@credo-ts/core'

interface StorageRecord {
  value: Record<string, unknown>
  tags: Record<string, unknown>
  type: string
  id: string
}

interface InMemoryRecords {
  [id: string]: StorageRecord
}

interface ContextCorrelationIdToRecords {
  [contextCorrelationId: string]: {
    records: InMemoryRecords
    creationDate: Date
  }
}

@injectable()
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export class InMemoryStorageService<T extends BaseRecord<any, any, any> = BaseRecord<any, any, any>>
  implements StorageService<T>
{
  public contextCorrelationIdToRecords: ContextCorrelationIdToRecords = {}

  private recordToInstance(record: StorageRecord, recordClass: BaseRecordConstructor<T>): T {
    const instance = JsonTransformer.fromJSON<T>(record.value, recordClass)
    instance.id = record.id
    instance.replaceTags(record.tags as TagsBase)

    return instance
  }

  private getRecordsForContext(agentContext: AgentContext): InMemoryRecords {
    const contextCorrelationId = agentContext.contextCorrelationId

    if (!this.contextCorrelationIdToRecords[contextCorrelationId]) {
      this.contextCorrelationIdToRecords[contextCorrelationId] = {
        records: {},
        creationDate: new Date(),
      }
    } else if (agentContext.wallet instanceof InMemoryWallet && agentContext.wallet.activeWalletId) {
      const walletCreationDate = agentContext.wallet.inMemoryWallets[agentContext.wallet.activeWalletId].creationDate
      const storageCreationDate = this.contextCorrelationIdToRecords[contextCorrelationId].creationDate

      // If the storage was created before the wallet, it means the wallet has been deleted in the meantime
      // and thus we need to recreate the storage as we don't want to serve records from the previous wallet
      // FIXME: this is a flaw in our wallet/storage model. I think wallet should be for keys, and storage
      // for records and you can create them separately. But that's a bigger change.
      if (storageCreationDate < walletCreationDate) {
        this.contextCorrelationIdToRecords[contextCorrelationId] = {
          records: {},
          creationDate: new Date(),
        }
      }
    }

    return this.contextCorrelationIdToRecords[contextCorrelationId].records
  }

  /** @inheritDoc */
  public async save(agentContext: AgentContext, record: T) {
    record.updatedAt = new Date()
    const value = JsonTransformer.toJSON(record)

    if (this.getRecordsForContext(agentContext)[record.id]) {
      throw new RecordDuplicateError(`Record with id ${record.id} already exists`, { recordType: record.type })
    }

    this.getRecordsForContext(agentContext)[record.id] = {
      value,
      id: record.id,
      type: record.type,
      tags: record.getTags(),
    }
  }

  /** @inheritDoc */
  public async update(agentContext: AgentContext, record: T): Promise<void> {
    record.updatedAt = new Date()
    const value = JsonTransformer.toJSON(record)
    delete value._tags

    if (!this.getRecordsForContext(agentContext)[record.id]) {
      throw new RecordNotFoundError(`record with id ${record.id} not found.`, {
        recordType: record.type,
      })
    }

    this.getRecordsForContext(agentContext)[record.id] = {
      value,
      id: record.id,
      type: record.type,
      tags: record.getTags(),
    }
  }

  /** @inheritDoc */
  public async delete(agentContext: AgentContext, record: T) {
    if (!this.getRecordsForContext(agentContext)[record.id]) {
      throw new RecordNotFoundError(`record with id ${record.id} not found.`, {
        recordType: record.type,
      })
    }

    delete this.getRecordsForContext(agentContext)[record.id]
  }

  /** @inheritDoc */
  public async deleteById(
    agentContext: AgentContext,
    recordClass: BaseRecordConstructor<T>,
    id: string
  ): Promise<void> {
    if (!this.getRecordsForContext(agentContext)[id]) {
      throw new RecordNotFoundError(`record with id ${id} not found.`, {
        recordType: recordClass.type,
      })
    }

    delete this.getRecordsForContext(agentContext)[id]
  }

  /** @inheritDoc */
  public async getById(agentContext: AgentContext, recordClass: BaseRecordConstructor<T>, id: string): Promise<T> {
    const record = this.getRecordsForContext(agentContext)[id]

    if (!record) {
      throw new RecordNotFoundError(`record with id ${id} not found.`, {
        recordType: recordClass.type,
      })
    }

    return this.recordToInstance(record, recordClass)
  }

  /** @inheritDoc */
  public async getAll(agentContext: AgentContext, recordClass: BaseRecordConstructor<T>): Promise<T[]> {
    const records = Object.values(this.getRecordsForContext(agentContext))
      .filter((record) => record.type === recordClass.type)
      .map((record) => this.recordToInstance(record, recordClass))

    return records
  }

  /** @inheritDoc */
  public async findByQuery(
    agentContext: AgentContext,
    recordClass: BaseRecordConstructor<T>,
    query: Query<T>,
    queryOptions?: QueryOptions
  ): Promise<T[]> {
    const { offset = 0, limit } = queryOptions || {}

    const allRecords = Object.values(this.getRecordsForContext(agentContext))
      .filter((record) => record.type === recordClass.type)
      .filter((record) => filterByQuery(record, query))

    const slicedRecords = limit !== undefined ? allRecords.slice(offset, offset + limit) : allRecords.slice(offset)

    return slicedRecords.map((record) => this.recordToInstance(record, recordClass))
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function filterByQuery<T extends BaseRecord<any, any, any>>(record: StorageRecord, query: Query<T>) {
  const { $and, $or, $not, ...restQuery } = query

  if ($not) {
    throw new Error('$not query not supported in in memory storage')
  }

  // Top level query
  if (!matchSimpleQuery(record, restQuery)) return false

  // All $and queries MUST match
  if ($and) {
    const allAndMatch = ($and as Query<T>[]).every((and) => filterByQuery(record, and))
    if (!allAndMatch) return false
  }

  // Only one $or queries has to match
  if ($or) {
    const oneOrMatch = ($or as Query<T>[]).some((or) => filterByQuery(record, or))
    if (!oneOrMatch) return false
  }

  return true
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function matchSimpleQuery<T extends BaseRecord<any, any, any>>(record: StorageRecord, query: Query<T>) {
  const tags = record.tags as TagsBase

  for (const [key, value] of Object.entries(query)) {
    // We don't query for value undefined, the value should be null in that case
    if (value === undefined) continue

    // TODO: support null
    if (Array.isArray(value)) {
      const tagValue = tags[key]
      if (!Array.isArray(tagValue) || !value.every((v) => tagValue.includes(v))) {
        return false
      }
    } else if (tags[key] !== value) {
      return false
    }
  }

  return true
}
