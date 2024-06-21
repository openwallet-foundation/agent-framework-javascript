import type { GenericRecord, SaveGenericRecordOption } from './repository/GenericRecord'
import type { Query, QueryOptions } from '../../storage/StorageService'

import { AgentContext } from '../../agent'
import { InjectionSymbols } from '../../constants'
import { Logger } from '../../logger'
import { inject, injectable } from '../../plugins'

import { GenericRecordService } from './services/GenericRecordService'

export type ContentType = {
  content: string
}

@injectable()
export class GenericRecordsApi {
  private genericRecordsService: GenericRecordService
  private logger: Logger
  private agentContext: AgentContext

  public constructor(
    genericRecordsService: GenericRecordService,
    @inject(InjectionSymbols.Logger) logger: Logger,
    agentContext: AgentContext
  ) {
    this.genericRecordsService = genericRecordsService
    this.logger = logger
    this.agentContext = agentContext
  }

  public async save({ content, tags, id }: SaveGenericRecordOption) {
    try {
      const record = await this.genericRecordsService.save(this.agentContext, {
        id,
        content: content,
        tags: tags,
      })
      return record
    } catch (error) {
      this.logger.error('Error while saving generic-record', {
        error,
        content,
        errorMessage: error instanceof Error ? error.message : error,
      })
      throw error
    }
  }

  public async delete(record: GenericRecord): Promise<void> {
    try {
      await this.genericRecordsService.delete(this.agentContext, record)
    } catch (error) {
      this.logger.error('Error while saving generic-record', {
        error,
        content: record.content,
        errorMessage: error instanceof Error ? error.message : error,
      })
      throw error
    }
  }

  public async deleteById(id: string): Promise<void> {
    await this.genericRecordsService.deleteById(this.agentContext, id)
  }

  public async update(record: GenericRecord): Promise<void> {
    try {
      await this.genericRecordsService.update(this.agentContext, record)
    } catch (error) {
      this.logger.error('Error while update generic-record', {
        error,
        content: record.content,
        errorMessage: error instanceof Error ? error.message : error,
      })
      throw error
    }
  }

  public async findById(id: string) {
    return this.genericRecordsService.findById(this.agentContext, id)
  }

  public async findAllByQuery(query: Query<GenericRecord>, queryOptions?: QueryOptions): Promise<GenericRecord[]> {
    return this.genericRecordsService.findAllByQuery(this.agentContext, query, queryOptions)
  }

  public async getAll(): Promise<GenericRecord[]> {
    return this.genericRecordsService.getAll(this.agentContext)
  }
}
