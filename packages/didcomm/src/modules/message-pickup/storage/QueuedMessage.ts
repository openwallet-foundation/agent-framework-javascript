import type { EncryptedMessage } from '../../../types'

/**
 * Basic representation of an encrypted message in a Message Pickup Queue
 * - id: Message Pickup repository's specific queued message id (unrelated to DIDComm message id)
 * - receivedAt: reception time (i.e. time when the message has been added to the queue)
 * - encryptedMessage: packed message
 */
export type QueuedMessage = {
  id: string
  receivedAt?: Date
  encryptedMessage: EncryptedMessage
}
