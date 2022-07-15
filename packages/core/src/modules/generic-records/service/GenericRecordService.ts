import type { AgentContext } from '../../../agent'
import type { GenericRecordTags, SaveGenericRecordOption } from '../repository/GenericRecord'

import { AriesFrameworkError } from '../../../error'
import { injectable } from '../../../plugins'
import { GenericRecord } from '../repository/GenericRecord'
import { GenericRecordsRepository } from '../repository/GenericRecordsRepository'

@injectable()
export class GenericRecordService {
  private genericRecordsRepository: GenericRecordsRepository

  public constructor(genericRecordsRepository: GenericRecordsRepository) {
    this.genericRecordsRepository = genericRecordsRepository
  }

  public async save(agentContext: AgentContext, { content, tags }: SaveGenericRecordOption) {
    const genericRecord = new GenericRecord({
      content: content,
      tags: tags,
    })

    try {
      await this.genericRecordsRepository.save(agentContext, genericRecord)
      return genericRecord
    } catch (error) {
      throw new AriesFrameworkError(
        `Unable to store the genericRecord record with id ${genericRecord.id}. Message: ${error}`
      )
    }
  }

  public async delete(agentContext: AgentContext, record: GenericRecord): Promise<void> {
    try {
      await this.genericRecordsRepository.delete(agentContext, record)
    } catch (error) {
      throw new AriesFrameworkError(`Unable to delete the genericRecord record with id ${record.id}. Message: ${error}`)
    }
  }

  public async update(agentContext: AgentContext, record: GenericRecord): Promise<void> {
    try {
      await this.genericRecordsRepository.update(agentContext, record)
    } catch (error) {
      throw new AriesFrameworkError(`Unable to update the genericRecord record with id ${record.id}. Message: ${error}`)
    }
  }

  public async findAllByQuery(agentContext: AgentContext, query: Partial<GenericRecordTags>) {
    return this.genericRecordsRepository.findByQuery(agentContext, query)
  }

  public async findById(agentContext: AgentContext, id: string): Promise<GenericRecord | null> {
    return this.genericRecordsRepository.findById(agentContext, id)
  }

  public async getAll(agentContext: AgentContext) {
    return this.genericRecordsRepository.getAll(agentContext)
  }
}
