import { StorageUpdateService } from '@credo-ts/core'

import { Agent } from '../../../core/src/agent/Agent'
import { CURRENT_FRAMEWORK_STORAGE_VERSION } from '../../../core/src/storage/migration/updates'
import { askarPostgresStorageConfig, getAskarPostgresAgentOptions } from '../../tests/helpers'

const agentOptions = getAskarPostgresAgentOptions('Migration', {}, askarPostgresStorageConfig)

describe('migration with postgres backend', () => {
  test('Automatic update on agent startup', async () => {
    // Initialize agent and set its storage version to 0.1 in order to force automatic update in the next startup
    let agent = new Agent(agentOptions)
    await agent.initialize()

    let storageUpdateService = agent.dependencyManager.resolve(StorageUpdateService)
    await storageUpdateService.setCurrentStorageVersion(agent.context, '0.1')
    await agent.shutdown()

    // Now start agent with auto update storage
    agent = new Agent({ ...agentOptions, config: { ...agentOptions.config, autoUpdateStorageOnStartup: true } })
    storageUpdateService = agent.dependencyManager.resolve(StorageUpdateService)

    // Should fail because export is not supported when using postgres
    await expect(agent.initialize()).rejects.toThrow(/backend does not support export/)

    expect(await storageUpdateService.getCurrentStorageVersion(agent.context)).toEqual('0.1')
    await agent.shutdown()

    // Now start agent with auto update storage, but this time disable backup
    agent = new Agent({
      ...agentOptions,
      config: { ...agentOptions.config, autoUpdateStorageOnStartup: true, backupBeforeStorageUpdate: false },
    })

    // Should work OK
    await agent.initialize()
    expect(await storageUpdateService.getCurrentStorageVersion(agent.context)).toEqual(
      CURRENT_FRAMEWORK_STORAGE_VERSION
    )
    await agent.shutdown()

    await agent.wallet.delete()
  })
})
