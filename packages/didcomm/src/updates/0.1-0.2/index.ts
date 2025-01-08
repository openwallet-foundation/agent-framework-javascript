import type { BaseAgent, UpdateConfig } from '@credo-ts/core'

import { migrateConnectionRecordToV0_2 } from './connection'
import { migrateCredentialRecordToV0_2 } from './credential'
import { migrateMediationRecordToV0_2 } from './mediation'

// FIXME: Properly support custom configuration parameters in
// module updates
export async function updateV0_1ToV0_2<Agent extends BaseAgent>(agent: Agent, config: UpdateConfig): Promise<void> {
  await migrateCredentialRecordToV0_2(agent)
  await migrateMediationRecordToV0_2(agent, config.v0_1ToV0_2)
  await migrateConnectionRecordToV0_2(agent)
}
