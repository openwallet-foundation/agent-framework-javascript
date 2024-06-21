import type {
  CreateTenantOptions,
  GetTenantAgentOptions,
  UpdateTenantStorageOptions,
  WithTenantAgentCallback,
} from './TenantsApiOptions'
import type { TenantRecord } from './repository'
import type { DefaultAgentModules, ModulesMap, Query, QueryOptions } from '@credo-ts/core'

import {
  isStorageUpToDate,
  AgentContext,
  inject,
  injectable,
  InjectionSymbols,
  Logger,
  UpdateAssistant,
} from '@credo-ts/core'

import { TenantAgent } from './TenantAgent'
import { TenantAgentContextProvider } from './context/TenantAgentContextProvider'
import { TenantRecordService } from './services'

@injectable()
export class TenantsApi<AgentModules extends ModulesMap = DefaultAgentModules> {
  public readonly rootAgentContext: AgentContext
  private tenantRecordService: TenantRecordService
  private agentContextProvider: TenantAgentContextProvider
  private logger: Logger

  public constructor(
    tenantRecordService: TenantRecordService,
    rootAgentContext: AgentContext,
    @inject(InjectionSymbols.AgentContextProvider) agentContextProvider: TenantAgentContextProvider,
    @inject(InjectionSymbols.Logger) logger: Logger
  ) {
    this.tenantRecordService = tenantRecordService
    this.rootAgentContext = rootAgentContext
    this.agentContextProvider = agentContextProvider
    this.logger = logger
  }

  public async getTenantAgent({ tenantId }: GetTenantAgentOptions): Promise<TenantAgent<AgentModules>> {
    this.logger.debug(`Getting tenant agent for tenant '${tenantId}'`)
    const tenantContext = await this.agentContextProvider.getAgentContextForContextCorrelationId(tenantId)

    this.logger.trace(`Got tenant context for tenant '${tenantId}'`)
    const tenantAgent = new TenantAgent<AgentModules>(tenantContext)
    await tenantAgent.initialize()
    this.logger.trace(`Initializing tenant agent for tenant '${tenantId}'`)

    return tenantAgent
  }

  public async withTenantAgent<ReturnValue>(
    options: GetTenantAgentOptions,
    withTenantAgentCallback: WithTenantAgentCallback<AgentModules, ReturnValue>
  ): Promise<ReturnValue> {
    this.logger.debug(`Getting tenant agent for tenant '${options.tenantId}' in with tenant agent callback`)
    const tenantAgent = await this.getTenantAgent(options)

    try {
      this.logger.debug(`Calling tenant agent callback for tenant '${options.tenantId}'`)
      const result = await withTenantAgentCallback(tenantAgent)
      return result
    } catch (error) {
      this.logger.error(`Error in tenant agent callback for tenant '${options.tenantId}'`, { error })
      throw error
    } finally {
      this.logger.debug(`Ending tenant agent session for tenant '${options.tenantId}'`)
      await tenantAgent.endSession()
    }
  }

  public async createTenant(options: CreateTenantOptions) {
    this.logger.debug(`Creating tenant with label ${options.config.label}`)
    const tenantRecord = await this.tenantRecordService.createTenant(this.rootAgentContext, options.config)

    // This initializes the tenant agent, creates the wallet etc...
    const tenantAgent = await this.getTenantAgent({ tenantId: tenantRecord.id })
    await tenantAgent.endSession()

    this.logger.info(`Successfully created tenant '${tenantRecord.id}'`)

    return tenantRecord
  }

  public async getTenantById(tenantId: string) {
    this.logger.debug(`Getting tenant by id '${tenantId}'`)
    return this.tenantRecordService.getTenantById(this.rootAgentContext, tenantId)
  }

  public async findTenantsByLabel(label: string) {
    this.logger.debug(`Finding tenants by label '${label}'`)
    return this.tenantRecordService.findTenantsByLabel(this.rootAgentContext, label)
  }

  public async deleteTenantById(tenantId: string) {
    this.logger.debug(`Deleting tenant by id '${tenantId}'`)
    // TODO: force remove context from the context provider (or session manager)
    const tenantAgent = await this.getTenantAgent({ tenantId })

    this.logger.trace(`Deleting wallet for tenant '${tenantId}'`)
    await tenantAgent.wallet.delete()
    this.logger.trace(`Shutting down agent for tenant '${tenantId}'`)
    await tenantAgent.endSession()

    return this.tenantRecordService.deleteTenantById(this.rootAgentContext, tenantId)
  }

  public async updateTenant(tenant: TenantRecord) {
    await this.tenantRecordService.updateTenant(this.rootAgentContext, tenant)
  }

  public async findTenantsByQuery(query: Query<TenantRecord>, queryOptions?: QueryOptions) {
    return this.tenantRecordService.findTenantsByQuery(this.rootAgentContext, query, queryOptions)
  }

  public async getAllTenants() {
    this.logger.debug('Getting all tenants')
    return this.tenantRecordService.getAllTenants(this.rootAgentContext)
  }

  public async updateTenantStorage({ tenantId, updateOptions }: UpdateTenantStorageOptions) {
    this.logger.debug(`Updating tenant storage for tenant '${tenantId}'`)
    const tenantRecord = await this.tenantRecordService.getTenantById(this.rootAgentContext, tenantId)

    if (isStorageUpToDate(tenantRecord.storageVersion)) {
      this.logger.debug(`Tenant storage for tenant '${tenantId}' is already up to date. Skipping update`)
      return
    }

    await this.agentContextProvider.updateTenantStorage(tenantRecord, updateOptions)
  }

  public async getTenantsWithOutdatedStorage() {
    const outdatedTenants = await this.tenantRecordService.findTenantsByQuery(this.rootAgentContext, {
      $not: {
        storageVersion: UpdateAssistant.frameworkStorageVersion,
      },
    })

    return outdatedTenants
  }
}
