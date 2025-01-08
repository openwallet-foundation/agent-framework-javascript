import type { Key } from '@credo-ts/core'

export interface Routing {
  endpoints: string[]
  recipientKey: Key
  routingKeys: Key[]
  mediatorId?: string
}
