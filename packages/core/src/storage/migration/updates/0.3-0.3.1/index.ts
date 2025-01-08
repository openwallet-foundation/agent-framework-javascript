import type { BaseAgent } from '../../../../agent/BaseAgent'
import type { UpdateConfig } from '../../updates'

import { migrateDidRecordToV0_3_1 } from './did'

// FIXME: optional update config parameter
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export async function updateV0_3ToV0_3_1<Agent extends BaseAgent>(agent: Agent, _config: UpdateConfig): Promise<void> {
  await migrateDidRecordToV0_3_1(agent)
}
