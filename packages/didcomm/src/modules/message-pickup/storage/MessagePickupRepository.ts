import type {
  AddMessageOptions,
  GetAvailableMessageCountOptions,
  RemoveMessagesOptions,
  TakeFromQueueOptions,
} from './MessagePickupRepositoryOptions'
import type { QueuedMessage } from './QueuedMessage'

export interface MessagePickupRepository {
  getAvailableMessageCount(options: GetAvailableMessageCountOptions): number | Promise<number>
  takeFromQueue(options: TakeFromQueueOptions): QueuedMessage[] | Promise<QueuedMessage[]>
  addMessage(options: AddMessageOptions): string | Promise<string>
  removeMessages(options: RemoveMessagesOptions): void | Promise<void>
}
