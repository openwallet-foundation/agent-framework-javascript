import { EventEmitter, InjectionSymbols, inject, injectable, Repository, StorageService } from '@credo-ts/core'

import { MediatorRoutingRecord } from './MediatorRoutingRecord'

@injectable()
export class MediatorRoutingRepository extends Repository<MediatorRoutingRecord> {
  public readonly MEDIATOR_ROUTING_RECORD_ID = 'MEDIATOR_ROUTING_RECORD'

  public constructor(
    @inject(InjectionSymbols.StorageService) storageService: StorageService<MediatorRoutingRecord>,
    eventEmitter: EventEmitter
  ) {
    super(MediatorRoutingRecord, storageService, eventEmitter)
  }
}
