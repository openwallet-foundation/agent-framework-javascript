import type { BaseAgent } from '@credo-ts/core'

import { migrateConnectionRecordToV0_3 } from './connection'
import { migrateProofExchangeRecordToV0_3 } from './proof'

export async function updateV0_2ToV0_3<Agent extends BaseAgent>(agent: Agent): Promise<void> {
  await migrateProofExchangeRecordToV0_3(agent)
  await migrateConnectionRecordToV0_3(agent)
}
