import type { AgentContext } from '@credo-ts/core'

import { EventEmitter, InjectionSymbols, inject, injectable, Repository, StorageService } from '@credo-ts/core'

import { MediationRecord } from './MediationRecord'

@injectable()
export class MediationRepository extends Repository<MediationRecord> {
  public constructor(
    @inject(InjectionSymbols.StorageService) storageService: StorageService<MediationRecord>,
    eventEmitter: EventEmitter
  ) {
    super(MediationRecord, storageService, eventEmitter)
  }

  public getSingleByRecipientKey(agentContext: AgentContext, recipientKey: string) {
    return this.getSingleByQuery(agentContext, {
      recipientKeys: [recipientKey],
    })
  }

  public async getByConnectionId(agentContext: AgentContext, connectionId: string): Promise<MediationRecord> {
    return this.getSingleByQuery(agentContext, { connectionId })
  }
}
