import type { EncryptedMessage } from '../types'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function isValidJweStructure(message: any): message is EncryptedMessage {
  return Boolean(
    message &&
      typeof message === 'object' &&
      message !== null &&
      typeof message.protected === 'string' &&
      message.iv &&
      message.ciphertext &&
      message.tag
  )
}
