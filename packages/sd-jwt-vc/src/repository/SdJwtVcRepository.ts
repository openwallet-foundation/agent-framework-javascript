import { EventEmitter, InjectionSymbols, inject, injectable, Repository, StorageService } from '@aries-framework/core'

import { SdJwtVcRecord } from './SdJwtVcRecord'

@injectable()
export class SdJwtVcRepository extends Repository<SdJwtVcRecord> {
  public constructor(
    @inject(InjectionSymbols.StorageService) storageService: StorageService<SdJwtVcRecord>,
    eventEmitter: EventEmitter
  ) {
    super(SdJwtVcRecord, storageService, eventEmitter)
  }
}
