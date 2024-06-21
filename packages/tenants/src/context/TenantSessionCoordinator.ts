import type { TenantRecord } from '../repository'
import type { MutexInterface } from 'async-mutex'

import {
  AgentConfig,
  AgentContext,
  CredoError,
  inject,
  injectable,
  InjectionSymbols,
  Logger,
  WalletApi,
  WalletError,
} from '@credo-ts/core'
import { Mutex, withTimeout } from 'async-mutex'

import { TenantsModuleConfig } from '../TenantsModuleConfig'

import { TenantSessionMutex } from './TenantSessionMutex'

/**
 * Coordinates all agent context instance for tenant sessions.
 *
 * This class keeps a mapping of tenant ids (context correlation ids) to agent context sessions mapping. Each mapping contains the agent context,
 * the current session count and a mutex for making operations against the session mapping (opening / closing an agent context). The mutex ensures
 * we're not susceptible to race conditions where multiple calls to open/close an agent context are made at the same time. Even though JavaScript is
 * single threaded, promises can introduce race conditions as one process can stop and another process can be picked up.
 *
 * NOTE: the implementation doesn't yet cache agent context objects after they aren't being used for any sessions anymore. This means if a wallet is being used
 * often in a short time it will be opened/closed very often. This is an improvement to be made in the near future.
 */
@injectable()
export class TenantSessionCoordinator {
  private rootAgentContext: AgentContext
  private logger: Logger
  private tenantAgentContextMapping: TenantAgentContextMapping = {}
  private sessionMutex: TenantSessionMutex
  private tenantsModuleConfig: TenantsModuleConfig

  public constructor(
    rootAgentContext: AgentContext,
    @inject(InjectionSymbols.Logger) logger: Logger,
    tenantsModuleConfig: TenantsModuleConfig
  ) {
    this.rootAgentContext = rootAgentContext
    this.logger = logger
    this.tenantsModuleConfig = tenantsModuleConfig

    this.sessionMutex = new TenantSessionMutex(
      this.logger,
      this.tenantsModuleConfig.sessionLimit,
      // TODO: we should probably allow a higher session acquire timeout if the storage is being updated?
      this.tenantsModuleConfig.sessionAcquireTimeout
    )
  }

  public getSessionCountForTenant(tenantId: string) {
    return this.tenantAgentContextMapping[tenantId]?.sessionCount ?? 0
  }

  /**
   * Get agent context to use for a session. If an agent context for this tenant does not exist yet
   * it will create it and store it for later use. If the agent context does already exist it will
   * be returned.
   *
   * @parm tenantRecord The tenant record for which to get the agent context
   */
  public async getContextForSession(
    tenantRecord: TenantRecord,
    {
      runInMutex,
    }: {
      /** optional callback that will be run inside the mutex lock */
      runInMutex?: (agentContext: AgentContext) => Promise<void>
    } = {}
  ): Promise<AgentContext> {
    this.logger.debug(`Getting context for session with tenant '${tenantRecord.id}'`)

    // Wait for a session to be available
    await this.sessionMutex.acquireSession()

    try {
      return await this.mutexForTenant(tenantRecord.id).runExclusive(async () => {
        this.logger.debug(`Acquired lock for tenant '${tenantRecord.id}' to get context`)
        const tenantSessions = this.getTenantSessionsMapping(tenantRecord.id)

        // If we don't have an agent context already, create one and initialize it
        if (!tenantSessions.agentContext) {
          this.logger.debug(`No agent context has been initialized for tenant '${tenantRecord.id}', creating one`)
          tenantSessions.agentContext = await this.createAgentContext(tenantRecord)
        }

        // If we already have a context with sessions in place return the context and increment
        // the session count.
        tenantSessions.sessionCount++
        this.logger.debug(
          `Increased agent context session count for tenant '${tenantRecord.id}' to ${tenantSessions.sessionCount}`
        )

        if (runInMutex) {
          try {
            await runInMutex(tenantSessions.agentContext)
          } catch (error) {
            // If the runInMutex failed we should release the session again
            tenantSessions.sessionCount--
            this.logger.debug(
              `Decreased agent context session count for tenant '${tenantSessions.agentContext.contextCorrelationId}' to ${tenantSessions.sessionCount} due to failure in mutex script`,
              error
            )

            if (tenantSessions.sessionCount <= 0 && tenantSessions.agentContext) {
              await this.closeAgentContext(tenantSessions.agentContext)
              delete this.tenantAgentContextMapping[tenantSessions.agentContext.contextCorrelationId]
            }

            throw error
          }
        }

        return tenantSessions.agentContext
      })
    } catch (error) {
      this.logger.debug(
        `Releasing session because an error occurred while getting the context for tenant ${tenantRecord.id}`,
        {
          errorMessage: error.message,
        }
      )
      // If there was an error acquiring the session, we MUST release it, otherwise this will lead to deadlocks over time.
      this.sessionMutex.releaseSession()

      // Re-throw error
      throw error
    }
  }

  /**
   * End a session for the provided agent context. It will decrease the session count for the agent context.
   * If the number of sessions is zero after the context for this session has been ended, the agent context will be closed.
   */
  public async endAgentContextSession(agentContext: AgentContext): Promise<void> {
    this.logger.debug(
      `Ending session for agent context with contextCorrelationId ${agentContext.contextCorrelationId}'`
    )
    const hasTenantSessionMapping = this.hasTenantSessionMapping(agentContext.contextCorrelationId)

    // Custom handling for the root agent context. We don't keep track of the total number of sessions for the root
    // agent context, and we always keep the dependency manager intact.
    if (!hasTenantSessionMapping && agentContext.contextCorrelationId === this.rootAgentContext.contextCorrelationId) {
      this.logger.debug('Ending session for root agent context. Not disposing dependency manager')
      return
    }

    // This should not happen
    if (!hasTenantSessionMapping) {
      this.logger.error(
        `Unknown agent context with contextCorrelationId '${agentContext.contextCorrelationId}'.  Cannot end session`
      )
      throw new CredoError(
        `Unknown agent context with contextCorrelationId '${agentContext.contextCorrelationId}'. Cannot end session`
      )
    }

    await this.mutexForTenant(agentContext.contextCorrelationId).runExclusive(async () => {
      this.logger.debug(`Acquired lock for tenant '${agentContext.contextCorrelationId}' to end session context`)
      const tenantSessions = this.getTenantSessionsMapping(agentContext.contextCorrelationId)

      // TODO: check if session count is already 0
      tenantSessions.sessionCount--
      this.logger.debug(
        `Decreased agent context session count for tenant '${agentContext.contextCorrelationId}' to ${tenantSessions.sessionCount}`
      )

      if (tenantSessions.sessionCount <= 0 && tenantSessions.agentContext) {
        await this.closeAgentContext(tenantSessions.agentContext)
        delete this.tenantAgentContextMapping[agentContext.contextCorrelationId]
      }
    })

    // Release a session so new sessions can be acquired
    this.sessionMutex.releaseSession()
  }

  private hasTenantSessionMapping<T extends string>(tenantId: T): boolean {
    return this.tenantAgentContextMapping[tenantId] !== undefined
  }

  private getTenantSessionsMapping(tenantId: string): TenantContextSessions {
    let tenantSessionMapping = this.tenantAgentContextMapping[tenantId]
    if (tenantSessionMapping) return tenantSessionMapping

    tenantSessionMapping = {
      sessionCount: 0,
      mutex: withTimeout(
        new Mutex(),
        // NOTE: It can take a while to create an indy wallet. We're using RAW key derivation which should
        // be fast enough to not cause a problem. This wil also only be problem when the wallet is being created
        // for the first time or being acquired while wallet initialization is in progress.
        this.tenantsModuleConfig.sessionAcquireTimeout,
        new CredoError(`Error acquiring lock for tenant ${tenantId}. Wallet initialization or shutdown took too long.`)
      ),
    }
    this.tenantAgentContextMapping[tenantId] = tenantSessionMapping

    return tenantSessionMapping
  }

  private mutexForTenant(tenantId: string) {
    const tenantSessions = this.getTenantSessionsMapping(tenantId)

    return tenantSessions.mutex
  }

  private async createAgentContext(tenantRecord: TenantRecord) {
    const tenantDependencyManager = this.rootAgentContext.dependencyManager.createChild()

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { id, key, keyDerivationMethod, ...strippedWalletConfig } = this.rootAgentContext.config?.walletConfig ?? {}
    const tenantConfig = this.rootAgentContext.config.extend({
      ...tenantRecord.config,
      walletConfig: {
        ...strippedWalletConfig,
        ...tenantRecord.config.walletConfig,
      },
    })

    const agentContext = new AgentContext({
      contextCorrelationId: tenantRecord.id,
      dependencyManager: tenantDependencyManager,
    })

    tenantDependencyManager.registerInstance(AgentContext, agentContext)
    tenantDependencyManager.registerInstance(AgentConfig, tenantConfig)

    // NOTE: we're using the wallet api here because that correctly handle creating if it doesn't exist yet
    // and will also write the storage version to the storage, which is needed by the update assistant. We either
    // need to move this out of the module, or just keep using the module here.
    const walletApi = agentContext.dependencyManager.resolve(WalletApi)

    if (!tenantConfig.walletConfig) {
      throw new WalletError('Cannot initialize tenant without Wallet config.')
    }
    await walletApi.initialize(tenantConfig.walletConfig)

    return agentContext
  }

  private async closeAgentContext(agentContext: AgentContext) {
    this.logger.debug(`Closing agent context for tenant '${agentContext.contextCorrelationId}'`)
    await agentContext.dependencyManager.dispose()
  }
}

interface TenantContextSessions {
  sessionCount: number
  agentContext?: AgentContext
  mutex: MutexInterface
}

export interface TenantAgentContextMapping {
  [tenantId: string]: TenantContextSessions | undefined
}
