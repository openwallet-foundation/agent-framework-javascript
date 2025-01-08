import type { BaseAgent } from '../../../../agent/BaseAgent'

import { migrateW3cCredentialRecordToV0_5 } from './w3cCredentialRecord'

export async function updateV0_4ToV0_5<Agent extends BaseAgent>(agent: Agent): Promise<void> {
  await migrateW3cCredentialRecordToV0_5(agent)
}
