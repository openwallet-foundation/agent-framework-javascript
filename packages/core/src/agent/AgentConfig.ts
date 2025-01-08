import type { AgentDependencies } from './AgentDependencies'
import type { Logger } from '../logger'
import type { InitConfig } from '../types'

import { ConsoleLogger, LogLevel } from '../logger'

export class AgentConfig {
  private initConfig: InitConfig
  public label: string
  public logger: Logger
  public readonly agentDependencies: AgentDependencies

  public constructor(initConfig: InitConfig, agentDependencies: AgentDependencies) {
    this.initConfig = initConfig
    this.label = initConfig.label
    this.logger = initConfig.logger ?? new ConsoleLogger(LogLevel.off)
    this.agentDependencies = agentDependencies
  }

  /**
   * @todo move to context configuration
   */
  public get walletConfig() {
    return this.initConfig.walletConfig
  }

  public get allowInsecureHttpUrls() {
    return this.initConfig.allowInsecureHttpUrls ?? false
  }

  public get autoUpdateStorageOnStartup() {
    return this.initConfig.autoUpdateStorageOnStartup ?? false
  }

  public get backupBeforeStorageUpdate() {
    return this.initConfig.backupBeforeStorageUpdate ?? true
  }

  public extend(config: Partial<InitConfig>): AgentConfig {
    return new AgentConfig(
      { ...this.initConfig, logger: this.logger, label: this.label, ...config },
      this.agentDependencies
    )
  }

  public toJSON() {
    return {
      ...this.initConfig,
      walletConfig: {
        ...this.walletConfig,
        key: this.walletConfig?.key ? '[*****]' : undefined,
        storage: {
          ...this.walletConfig?.storage,
          credentials: this.walletConfig?.storage?.credentials ? '[*****]' : undefined,
        },
      },
      logger: this.logger.logLevel,
      agentDependencies: Boolean(this.agentDependencies),
      label: this.label,
    }
  }
}
