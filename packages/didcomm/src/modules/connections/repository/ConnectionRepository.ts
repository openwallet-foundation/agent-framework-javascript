import type { AgentContext } from '@credo-ts/core'
import type { DidExchangeRole } from '../models'

import { EventEmitter, InjectionSymbols, injectable, inject, Repository, StorageService } from '@credo-ts/core'

import { ConnectionRecord } from './ConnectionRecord'

@injectable()
export class ConnectionRepository extends Repository<ConnectionRecord> {
  public constructor(
    @inject(InjectionSymbols.StorageService) storageService: StorageService<ConnectionRecord>,
    eventEmitter: EventEmitter
  ) {
    super(ConnectionRecord, storageService, eventEmitter)
  }

  public async findByDids(agentContext: AgentContext, { ourDid, theirDid }: { ourDid: string; theirDid: string }) {
    return this.findSingleByQuery(agentContext, {
      $or: [
        {
          did: ourDid,
          theirDid,
        },
        { did: ourDid, previousTheirDids: [theirDid] },
        { previousDids: [ourDid], theirDid },
      ],
    })
  }

  public getByThreadId(agentContext: AgentContext, threadId: string): Promise<ConnectionRecord> {
    return this.getSingleByQuery(agentContext, { threadId })
  }

  public getByRoleAndThreadId(
    agentContext: AgentContext,
    role: DidExchangeRole,
    threadId: string
  ): Promise<ConnectionRecord> {
    return this.getSingleByQuery(agentContext, { threadId, role })
  }
}
