import { inject, scoped, Lifecycle } from 'tsyringe'

import { InjectionSymbols } from '../../../constants'
import { Repository } from '../../../storage/Repository'
import { StorageService } from '../../../storage/StorageService'

import { ConnectionRecord } from './ConnectionRecord'

@scoped(Lifecycle.ContainerScoped)
export class ConnectionRepository extends Repository<ConnectionRecord> {
  public constructor(@inject(InjectionSymbols.StorageService) storageService: StorageService<ConnectionRecord>) {
    super(ConnectionRecord, storageService)
  }
}
