import type { AgentContext } from '@aries-framework/core'

import { Repository, StorageService, InjectionSymbols, EventEmitter, inject, injectable } from '@aries-framework/core'

import { OpenId4VcVerifierRecord } from './OpenId4VcVerifierRecord'

@injectable()
export class OpenId4VcVerifierRepository extends Repository<OpenId4VcVerifierRecord> {
  public constructor(
    @inject(InjectionSymbols.StorageService) storageService: StorageService<OpenId4VcVerifierRecord>,
    eventEmitter: EventEmitter
  ) {
    super(OpenId4VcVerifierRecord, storageService, eventEmitter)
  }

  public findByVerifierId(agentContext: AgentContext, verifierId: string) {
    return this.findSingleByQuery(agentContext, { verifierId })
  }

  public getByVerifierId(agentContext: AgentContext, verifierId: string) {
    return this.getSingleByQuery(agentContext, { verifierId })
  }
}
