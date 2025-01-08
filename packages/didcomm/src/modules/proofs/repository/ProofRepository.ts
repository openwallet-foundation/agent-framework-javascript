import type { AgentContext } from '@credo-ts/core'

import { EventEmitter, InjectionSymbols, inject, injectable, Repository, StorageService } from '@credo-ts/core'

import { ProofExchangeRecord } from './ProofExchangeRecord'

@injectable()
export class ProofRepository extends Repository<ProofExchangeRecord> {
  public constructor(
    @inject(InjectionSymbols.StorageService) storageService: StorageService<ProofExchangeRecord>,
    eventEmitter: EventEmitter
  ) {
    super(ProofExchangeRecord, storageService, eventEmitter)
  }

  /**
   * Retrieve a proof record by connection id and thread id
   *
   * @param connectionId The connection id
   * @param threadId The thread id
   * @throws {RecordNotFoundError} If no record is found
   * @throws {RecordDuplicateError} If multiple records are found
   * @returns The proof record
   */
  public async getByThreadAndConnectionId(
    agentContext: AgentContext,
    threadId: string,
    connectionId?: string
  ): Promise<ProofExchangeRecord> {
    return this.getSingleByQuery(agentContext, { threadId, connectionId })
  }

  /**
   * Retrieve proof records by connection id and parent thread id
   *
   * @param connectionId The connection id
   * @param parentThreadId The parent thread id
   * @returns List containing all proof records matching the given query
   */
  public async getByParentThreadAndConnectionId(
    agentContext: AgentContext,
    parentThreadId: string,
    connectionId?: string
  ): Promise<ProofExchangeRecord[]> {
    return this.findByQuery(agentContext, { parentThreadId, connectionId })
  }
}
