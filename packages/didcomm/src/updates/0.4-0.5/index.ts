import type { BaseAgent } from '@credo-ts/core'

import { migrateCredentialExchangeRecordToV0_5 } from './credentialExchangeRecord'
import { migrateProofExchangeRecordToV0_5 } from './proofExchangeRecord'

export async function updateV0_4ToV0_5<Agent extends BaseAgent>(agent: Agent): Promise<void> {
  await migrateCredentialExchangeRecordToV0_5(agent)
  await migrateProofExchangeRecordToV0_5(agent)
}
