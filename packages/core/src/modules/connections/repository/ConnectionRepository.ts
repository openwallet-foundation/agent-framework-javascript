import { EventEmitter } from '../../../agent/EventEmitter'
import { InjectionSymbols } from '../../../constants'
import { inject, injectable } from '../../../plugins'
import { Repository } from '../../../storage/Repository'
import { StorageService } from '../../../storage/StorageService'

import { ConnectionRecord } from './ConnectionRecord'

@injectable()
export class ConnectionRepository extends Repository<ConnectionRecord> {
  public constructor(
    @inject(InjectionSymbols.StorageService) storageService: StorageService<ConnectionRecord>,
    eventEmitter: EventEmitter
  ) {
    super(ConnectionRecord, storageService, eventEmitter)
  }

  public async findByDids({ ourDid, theirDid }: { ourDid: string; theirDid: string }) {
    return this.findSingleByQuery({
      did: ourDid,
      theirDid,
    })
  }

  public getByThreadId(threadId: string): Promise<ConnectionRecord> {
    return this.getSingleByQuery({ threadId })
  }
}
