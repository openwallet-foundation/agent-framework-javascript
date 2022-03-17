import type { AgentDependencies } from '../../agent/AgentDependencies'
import type { Logger } from '../../logger'
import type { WalletConfig } from '../../types'
import type { UpgradeOptions } from './upgrades'

import { Agent } from '../../agent/Agent'
import { AriesFrameworkError } from '../../error'
import { uuid } from '../../utils/uuid'

import { StorageUpgradeService } from './StorageUpgradeService'
import { StorageUpgradeError } from './error/StorageUpgradeError'
import { supportedUpgrades } from './upgrades'
import { isFirstVersionHigherThanSecond, parseVersionString } from './version'

export interface UpgradeConfig {
  walletConfig: WalletConfig
  logger?: Logger
  upgradeOptions: UpgradeOptions
}

export class UpgradeAssistant {
  private agent: Agent
  private storageUpgradeService: StorageUpgradeService
  private walletConfig: WalletConfig
  private upgradeConfig: UpgradeConfig

  public constructor(upgradeConfig: UpgradeConfig, agentDependencies: AgentDependencies) {
    this.walletConfig = upgradeConfig.walletConfig
    this.upgradeConfig = upgradeConfig

    this.agent = new Agent(
      {
        label: 'Upgrade Assistant',
        walletConfig: upgradeConfig.walletConfig,
        logger: upgradeConfig.logger,
      },
      agentDependencies
    )

    this.storageUpgradeService = this.agent.injectionContainer.resolve(StorageUpgradeService)
  }

  public async initialize() {
    if (this.agent.isInitialized) {
      throw new AriesFrameworkError('Agent already initialized')
    }

    await this.agent.initialize()
  }

  public async isUpToDate() {
    return this.storageUpgradeService.isUpToDate()
  }

  public async getNeededUpgrades() {
    const currentStorageVersion = parseVersionString(await this.storageUpgradeService.getCurrentStorageVersion())

    // Filter upgrades. We don't want older upgrades we already applied
    // or aren't needed because the wallet was created after the upgrade script was made
    const neededUpgrades = supportedUpgrades.filter((upgrade) => {
      const toVersion = parseVersionString(upgrade.toVersion)

      // if an upgrade toVersion is higher than currentStorageVersion we want to to include the upgrade
      return isFirstVersionHigherThanSecond(toVersion, currentStorageVersion)
    })

    // The current storage version is too old to upgrade
    if (
      neededUpgrades.length > 0 &&
      isFirstVersionHigherThanSecond(parseVersionString(neededUpgrades[0].fromVersion), currentStorageVersion)
    ) {
      throw new AriesFrameworkError(
        `First fromVersion is higher than current storage version. You need to use an older version of the framework to upgrade to at least version ${neededUpgrades[0].fromVersion}`
      )
    }

    return neededUpgrades
  }

  public async upgrade() {
    const upgradeIdentifier = uuid()

    try {
      this.agent.config.logger.info(`Starting upgrade of agent storage with upgradeIdentifier ${upgradeIdentifier}`)
      const neededUpgrades = await this.getNeededUpgrades()

      if (neededUpgrades.length == 0) {
        this.agent.config.logger.info('No upgrade needed. Agent storage is up to date.')
        return
      }

      const fromVersion = neededUpgrades[0].fromVersion
      const toVersion = neededUpgrades[neededUpgrades.length - 1].toVersion
      this.agent.config.logger.info(
        `Starting upgrade process. Total of ${neededUpgrades.length} update(s) will be applied to update the agent storage from version ${fromVersion} to version ${toVersion}`
      )

      // Create backup in case migration goes wrong
      await this.createBackup(upgradeIdentifier)

      try {
        for (const upgrade of neededUpgrades) {
          this.agent.config.logger.info(
            `Starting upgrade of agent storage from version ${upgrade.fromVersion} to version ${upgrade.toVersion}`
          )
          await upgrade.doUpgrade(this.agent, this.upgradeConfig.upgradeOptions)

          // Update the framework version in storage
          await this.storageUpgradeService.setCurrentStorageVersion(upgrade.toVersion)
          this.agent.config.logger.info(
            `Successfully updated agent storage from version ${upgrade.fromVersion} to version ${upgrade.toVersion}`
          )
        }
      } catch (error) {
        this.agent.config.logger.fatal('An error occurred while updating the wallet. Restoring backup', {
          error,
        })
        // In the case of an error we want to restore the backup
        await this.restoreBackup(upgradeIdentifier)
      }
    } catch (error) {
      throw new StorageUpgradeError(`Error upgrading storage (upgradeIdentifier: ${upgradeIdentifier})`, {
        cause: error,
      })
    }
  }

  public async shutdown() {
    await this.agent.shutdown()
  }

  private async createBackup(backupIdentifier: string) {
    const fileSystem = this.agent.config.fileSystem
    const backupPath = `${fileSystem.basePath}/afj/backup/${backupIdentifier}`

    await this.agent.wallet.export({ key: this.walletConfig.key, path: backupPath })
    this.agent.config.logger.info('Created backup of the wallet', {
      backupPath,
    })
  }

  private async restoreBackup(backupIdentifier: string) {
    const fileSystem = this.agent.config.fileSystem
    const backupPath = `${fileSystem.basePath}/afj/backup/${backupIdentifier}`

    // FIXME: this feels risky. How can we restore a backup without removing the corrupted wallet?
    // await this.agent.wallet.delete()
    await this.agent.wallet.import(this.walletConfig, { key: this.walletConfig.key, path: backupPath })
    await this.agent.wallet.initialize(this.walletConfig)

    this.agent.config.logger.info(`Successfully restored wallet from backup ${backupIdentifier}`, {
      backupPath,
    })
  }
}
