import type { GenericRecord, GenericRecordTags, SaveGenericRecordOption } from './repository/GenericRecord'

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

  public async save({ content, tags }: SaveGenericRecordOption) {
    try {
      const record = await this.genericRecordsService.save(this.agentContext, {
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

  public async findAllByQuery(query: Partial<GenericRecordTags>): Promise<GenericRecord[]> {
    return this.genericRecordsService.findAllByQuery(this.agentContext, query)
  }

  public async getAll(): Promise<GenericRecord[]> {
    return this.genericRecordsService.getAll(this.agentContext)
  }
}
