import type { ConnectionRecord } from '../../modules/connections'
import type { BaseAgent } from '@credo-ts/core'

import { ConnectionType, ConnectionRepository } from '../../modules/connections'
import { MediationRepository } from '../../modules/routing'

/**
 * Migrate the {@link ConnectionRecord} to a 0.3 compatible format.
 *
 * @param agent
 */
export async function migrateConnectionRecordToV0_3<Agent extends BaseAgent>(agent: Agent) {
  agent.config.logger.info('Migrating connection records to storage version 0.3')
  const connectionRepository = agent.dependencyManager.resolve(ConnectionRepository)
  const mediationRepository = agent.dependencyManager.resolve(MediationRepository)

  agent.config.logger.debug('Fetching all connection records from storage')
  const allConnections = await connectionRepository.getAll(agent.context)
  agent.config.logger.debug(`Found a total of ${allConnections.length} connection records to update`)

  agent.config.logger.debug('Fetching all mediation records from storage')
  const allMediators = await mediationRepository.getAll(agent.context)
  agent.config.logger.debug(`Found a total of ${allMediators.length} mediation records`)

  const mediatorConnectionIds = new Set(allMediators.map((mediator) => mediator.connectionId))

  for (const connectionRecord of allConnections) {
    agent.config.logger.debug(`Migrating connection record with id ${connectionRecord.id} to storage version 0.3`)

    await migrateConnectionRecordTags(agent, connectionRecord, mediatorConnectionIds)
    await connectionRepository.update(agent.context, connectionRecord)

    agent.config.logger.debug(
      `Successfully migrated connection record with id ${connectionRecord.id} to storage version 0.3`
    )
  }
}

/**
 *
 * @param agent
 * @param connectionRecord
 */
export async function migrateConnectionRecordTags<Agent extends BaseAgent>(
  agent: Agent,
  connectionRecord: ConnectionRecord,
  mediatorConnectionIds: Set<string> = new Set()
) {
  agent.config.logger.debug(
    `Migrating internal connection record type tags ${connectionRecord.id} to storage version 0.3`
  )

  // Old connection records will have tags set in the 'connectionType' property
  const connectionTypeTags = (connectionRecord.getTags().connectionType || []) as [string]
  const connectionTypes = [...connectionTypeTags]

  if (mediatorConnectionIds.has(connectionRecord.id) && !connectionTypes.includes(ConnectionType.Mediator)) {
    connectionTypes.push(ConnectionType.Mediator)
  }

  connectionRecord.connectionTypes = connectionTypes
  connectionRecord.setTag('connectionType', undefined)

  agent.config.logger.debug(
    `Successfully migrated internal connection record type tags ${connectionRecord.id} to storage version 0.3`
  )
}
