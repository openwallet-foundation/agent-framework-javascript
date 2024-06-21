import type {
  BaseRecordConstructor,
  AgentContext,
  BaseRecord,
  Query,
  QueryOptions,
  StorageService,
} from '@credo-ts/core'

import { RecordDuplicateError, WalletError, RecordNotFoundError, injectable, JsonTransformer } from '@credo-ts/core'
import { Scan } from '@hyperledger/aries-askar-shared'

import { AskarErrorCode, isAskarError } from '../utils/askarError'
import { assertAskarWallet } from '../utils/assertAskarWallet'

import { askarQueryFromSearchQuery, recordToInstance, transformFromRecordTagValues } from './utils'

@injectable()
export class AskarStorageService<T extends BaseRecord> implements StorageService<T> {
  /** @inheritDoc */
  public async save(agentContext: AgentContext, record: T) {
    assertAskarWallet(agentContext.wallet)

    record.updatedAt = new Date()

    const value = JsonTransformer.serialize(record)
    const tags = transformFromRecordTagValues(record.getTags()) as Record<string, string>

    try {
      await agentContext.wallet.withSession((session) =>
        session.insert({ category: record.type, name: record.id, value, tags })
      )
    } catch (error) {
      if (isAskarError(error, AskarErrorCode.Duplicate)) {
        throw new RecordDuplicateError(`Record with id ${record.id} already exists`, { recordType: record.type })
      }

      throw new WalletError('Error saving record', { cause: error })
    }
  }

  /** @inheritDoc */
  public async update(agentContext: AgentContext, record: T): Promise<void> {
    assertAskarWallet(agentContext.wallet)

    record.updatedAt = new Date()

    const value = JsonTransformer.serialize(record)
    const tags = transformFromRecordTagValues(record.getTags()) as Record<string, string>

    try {
      await agentContext.wallet.withSession((session) =>
        session.replace({ category: record.type, name: record.id, value, tags })
      )
    } catch (error) {
      if (isAskarError(error, AskarErrorCode.NotFound)) {
        throw new RecordNotFoundError(`record with id ${record.id} not found.`, {
          recordType: record.type,
          cause: error,
        })
      }

      throw new WalletError('Error updating record', { cause: error })
    }
  }

  /** @inheritDoc */
  public async delete(agentContext: AgentContext, record: T) {
    assertAskarWallet(agentContext.wallet)

    try {
      await agentContext.wallet.withSession((session) => session.remove({ category: record.type, name: record.id }))
    } catch (error) {
      if (isAskarError(error, AskarErrorCode.NotFound)) {
        throw new RecordNotFoundError(`record with id ${record.id} not found.`, {
          recordType: record.type,
          cause: error,
        })
      }
      throw new WalletError('Error deleting record', { cause: error })
    }
  }

  /** @inheritDoc */
  public async deleteById(
    agentContext: AgentContext,
    recordClass: BaseRecordConstructor<T>,
    id: string
  ): Promise<void> {
    assertAskarWallet(agentContext.wallet)

    try {
      await agentContext.wallet.withSession((session) => session.remove({ category: recordClass.type, name: id }))
    } catch (error) {
      if (isAskarError(error, AskarErrorCode.NotFound)) {
        throw new RecordNotFoundError(`record with id ${id} not found.`, {
          recordType: recordClass.type,
          cause: error,
        })
      }
      throw new WalletError('Error deleting record', { cause: error })
    }
  }

  /** @inheritDoc */
  public async getById(agentContext: AgentContext, recordClass: BaseRecordConstructor<T>, id: string): Promise<T> {
    assertAskarWallet(agentContext.wallet)

    try {
      const record = await agentContext.wallet.withSession((session) =>
        session.fetch({ category: recordClass.type, name: id })
      )
      if (!record) {
        throw new RecordNotFoundError(`record with id ${id} not found.`, {
          recordType: recordClass.type,
        })
      }
      return recordToInstance(record, recordClass)
    } catch (error) {
      if (error instanceof RecordNotFoundError) throw error
      throw new WalletError(`Error getting record ${recordClass.name}`, { cause: error })
    }
  }

  /** @inheritDoc */
  public async getAll(agentContext: AgentContext, recordClass: BaseRecordConstructor<T>): Promise<T[]> {
    assertAskarWallet(agentContext.wallet)

    const records = await agentContext.wallet.withSession((session) => session.fetchAll({ category: recordClass.type }))

    const instances = []
    for (const record of records) {
      instances.push(recordToInstance(record, recordClass))
    }
    return instances
  }

  /** @inheritDoc */
  public async findByQuery(
    agentContext: AgentContext,
    recordClass: BaseRecordConstructor<T>,
    query: Query<T>,
    queryOptions?: QueryOptions
  ): Promise<T[]> {
    const wallet = agentContext.wallet
    assertAskarWallet(wallet)

    const askarQuery = askarQueryFromSearchQuery(query)

    const scan = new Scan({
      category: recordClass.type,
      store: wallet.store,
      tagFilter: askarQuery,
      profile: wallet.profile,
      offset: queryOptions?.offset,
      limit: queryOptions?.limit,
    })

    const instances = []
    try {
      const records = await scan.fetchAll()
      for (const record of records) {
        instances.push(recordToInstance(record, recordClass))
      }
      return instances
    } catch (error) {
      throw new WalletError(`Error executing query. ${error.message}`, { cause: error })
    }
  }
}
