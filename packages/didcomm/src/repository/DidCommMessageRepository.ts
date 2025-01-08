import type { DidCommMessageRole } from './DidCommMessageRole'
import type { AgentContext } from '@credo-ts/core'
import type { AgentMessage, ConstructableAgentMessage } from '../AgentMessage'

import { EventEmitter, InjectionSymbols, inject, injectable, Repository, StorageService } from '@credo-ts/core'

import { parseMessageType } from '../util/messageType'

import { DidCommMessageRecord } from './DidCommMessageRecord'

@injectable()
export class DidCommMessageRepository extends Repository<DidCommMessageRecord> {
  public constructor(
    @inject(InjectionSymbols.StorageService) storageService: StorageService<DidCommMessageRecord>,
    eventEmitter: EventEmitter
  ) {
    super(DidCommMessageRecord, storageService, eventEmitter)
  }

  public async saveAgentMessage(
    agentContext: AgentContext,
    { role, agentMessage, associatedRecordId }: SaveAgentMessageOptions
  ) {
    const didCommMessageRecord = new DidCommMessageRecord({
      message: agentMessage.toJSON(),
      role,
      associatedRecordId,
    })

    await this.save(agentContext, didCommMessageRecord)
  }

  public async saveOrUpdateAgentMessage(agentContext: AgentContext, options: SaveAgentMessageOptions) {
    const { messageName, protocolName, protocolMajorVersion } = parseMessageType(options.agentMessage.type)

    const record = await this.findSingleByQuery(agentContext, {
      associatedRecordId: options.associatedRecordId,
      messageName: messageName,
      protocolName: protocolName,
      protocolMajorVersion: String(protocolMajorVersion),
    })

    if (record) {
      record.message = options.agentMessage.toJSON()
      record.role = options.role
      await this.update(agentContext, record)
      return
    }

    await this.saveAgentMessage(agentContext, options)
  }

  public async getAgentMessage<MessageClass extends ConstructableAgentMessage = ConstructableAgentMessage>(
    agentContext: AgentContext,
    { associatedRecordId, messageClass, role }: GetAgentMessageOptions<MessageClass>
  ): Promise<InstanceType<MessageClass>> {
    const record = await this.getSingleByQuery(agentContext, {
      associatedRecordId,
      messageName: messageClass.type.messageName,
      protocolName: messageClass.type.protocolName,
      protocolMajorVersion: String(messageClass.type.protocolMajorVersion),
      role,
    })

    return record.getMessageInstance(messageClass)
  }
  public async findAgentMessage<MessageClass extends ConstructableAgentMessage = ConstructableAgentMessage>(
    agentContext: AgentContext,
    { associatedRecordId, messageClass, role }: GetAgentMessageOptions<MessageClass>
  ): Promise<InstanceType<MessageClass> | null> {
    const record = await this.findSingleByQuery(agentContext, {
      associatedRecordId,
      messageName: messageClass.type.messageName,
      protocolName: messageClass.type.protocolName,
      protocolMajorVersion: String(messageClass.type.protocolMajorVersion),
      role,
    })

    return record?.getMessageInstance(messageClass) ?? null
  }
}

export interface SaveAgentMessageOptions {
  role: DidCommMessageRole
  agentMessage: AgentMessage
  associatedRecordId: string
}

export interface GetAgentMessageOptions<MessageClass extends typeof AgentMessage> {
  associatedRecordId: string
  messageClass: MessageClass
  role?: DidCommMessageRole
}
