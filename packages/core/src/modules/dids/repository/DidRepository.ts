import type { Key } from '../../../crypto'

import { inject, scoped, Lifecycle } from 'tsyringe'

import { InjectionSymbols } from '../../../constants'
import { Repository } from '../../../storage/Repository'
import { StorageService } from '../../../storage/StorageService'

import { DidRecord } from './DidRecord'

@scoped(Lifecycle.ContainerScoped)
export class DidRepository extends Repository<DidRecord> {
  public constructor(@inject(InjectionSymbols.StorageService) storageService: StorageService<DidRecord>) {
    super(DidRecord, storageService)
  }

  public findByRecipientKey(recipientKey: Key) {
    return this.findSingleByQuery({ recipientKeyFingerprints: [recipientKey.fingerprint] })
  }

  public findAllByRecipientKey(recipientKey: Key) {
    return this.findByQuery({ recipientKeyFingerprints: [recipientKey.fingerprint] })
  }
}
