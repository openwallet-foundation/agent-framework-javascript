import type { PlaintextMessage } from '../types'

export function getThreadIdFromPlainTextMessage(message: PlaintextMessage) {
  return message['~thread']?.thid ?? message['@id']
}
