import type { GossipStorageInterface, WitnessState } from '@sicpa-dlab/witness-gossip-protocol-ts'

import AsyncLock from 'async-lock'

import { injectable } from '../../../plugins'
import { WitnessStateRecord, WitnessStateRepository } from '../repository'

@injectable()
export class WitnessGossipStateService implements GossipStorageInterface {
  private witnessStateRepository: WitnessStateRepository
  private witnessStateLock: AsyncLock

  public constructor(witnessStateRepository: WitnessStateRepository) {
    this.witnessStateRepository = witnessStateRepository
    this.witnessStateLock = new AsyncLock()
  }

  public async getWitnessState(): Promise<WitnessState> {
    const record = await this.witnessStateRepository.getSingleByQuery({})
    return record.witnessState
  }

  public async storeWitnessState(witnessState: WitnessState): Promise<void> {
    const record = await this.witnessStateRepository.getSingleByQuery({})
    record.witnessState = witnessState
    await this.witnessStateRepository.update(record)
  }

  /** @inheritDoc {StorageService#safeMutation} */
  public async safeOperationWithWitnessState<T>(operation: () => Promise<T>): Promise<T> {
    return this.witnessStateLock.acquire(
      WitnessStateRecord.id,
      async () => {
        return operation()
      },
      { maxOccupationTime: 60 * 1000 }
    )
  }
}
