/* eslint-disable @typescript-eslint/no-explicit-any */
import type { BaseRecord, TagsBase } from './BaseRecord'
import type { AgentContext } from '../agent'
import type { Constructor } from '../utils/mixins'

// https://stackoverflow.com/questions/51954558/how-can-i-remove-a-wider-type-from-a-union-type-without-removing-its-subtypes-in/51955852#51955852
export type SimpleQuery<T extends BaseRecord<any, any, any>> = T extends BaseRecord<infer DefaultTags, infer CustomTags>
  ? DefaultTags extends TagsBase
    ? Partial<ReturnType<T['getTags']>> & TagsBase
    : CustomTags extends TagsBase
    ? Partial<ReturnType<T['getTags']>> & TagsBase
    : Partial<DefaultTags & CustomTags> & TagsBase
  : Partial<ReturnType<T['getTags']>> & TagsBase

interface AdvancedQuery<T extends BaseRecord<any, any, any>> {
  $and?: Query<T>[]
  $or?: Query<T>[]
  $not?: Query<T>
}

export type QueryOptions = {
  limit?: number
  offset?: number
}

export type Query<T extends BaseRecord<any, any, any>> = AdvancedQuery<T> | SimpleQuery<T>

export interface BaseRecordConstructor<T> extends Constructor<T> {
  type: string
}

export interface StorageService<T extends BaseRecord<any, any, any>> {
  /**
   * Save record in storage
   *
   * @param record the record to store
   * @throws {RecordDuplicateError} if a record with this id already exists
   */
  save(agentContext: AgentContext, record: T): Promise<void>

  /**
   * Update record in storage
   *
   * @param record the record to update
   * @throws {RecordNotFoundError} if a record with this id and type does not exist
   */
  update(agentContext: AgentContext, record: T): Promise<void>

  /**
   * Delete record from storage
   *
   * @param record the record to delete
   * @throws {RecordNotFoundError} if a record with this id and type does not exist
   */
  delete(agentContext: AgentContext, record: T): Promise<void>

  /**
   * Delete record by id.
   *
   * @param recordClass the record class to delete the record for
   * @param id the id of the record to delete from storage
   * @throws {RecordNotFoundError} if a record with this id and type does not exist
   */
  deleteById(agentContext: AgentContext, recordClass: BaseRecordConstructor<T>, id: string): Promise<void>

  /**
   * Get record by id.
   *
   * @param recordClass the record class to get the record for
   * @param id the id of the record to retrieve from storage
   * @throws {RecordNotFoundError} if a record with this id and type does not exist
   */
  getById(agentContext: AgentContext, recordClass: BaseRecordConstructor<T>, id: string): Promise<T>

  /**
   * Get all records by specified record class.
   *
   * @param recordClass the record class to get records for
   */
  getAll(agentContext: AgentContext, recordClass: BaseRecordConstructor<T>): Promise<T[]>

  /**
   * Find all records by specified record class and query.
   *
   * @param recordClass the record class to find records for
   * @param query the query to use for finding records
   * @param queryOptions optional parameters to customize the query execution (e.g., limit, offset)
   *
   */
  findByQuery(
    agentContext: AgentContext,
    recordClass: BaseRecordConstructor<T>,
    query: Query<T>,
    queryOptions?: QueryOptions
  ): Promise<T[]>
}
