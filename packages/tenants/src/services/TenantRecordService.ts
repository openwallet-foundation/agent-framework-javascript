import type { TenantConfig } from '../models/TenantConfig'
import type { AgentContext, Key, Query, QueryOptions } from '@credo-ts/core'

import { UpdateAssistant, injectable, utils, KeyDerivationMethod } from '@credo-ts/core'

import { TenantRepository, TenantRecord, TenantRoutingRepository, TenantRoutingRecord } from '../repository'

@injectable()
export class TenantRecordService {
  private tenantRepository: TenantRepository
  private tenantRoutingRepository: TenantRoutingRepository

  public constructor(tenantRepository: TenantRepository, tenantRoutingRepository: TenantRoutingRepository) {
    this.tenantRepository = tenantRepository
    this.tenantRoutingRepository = tenantRoutingRepository
  }

  public async createTenant(agentContext: AgentContext, config: Omit<TenantConfig, 'walletConfig'>) {
    const tenantId = utils.uuid()

    const walletId = `tenant-${tenantId}`
    const walletKey = await agentContext.wallet.generateWalletKey()

    const tenantRecord = new TenantRecord({
      id: tenantId,
      config: {
        ...config,
        walletConfig: {
          id: walletId,
          key: walletKey,
          keyDerivationMethod: KeyDerivationMethod.Raw,
        },
      },
      storageVersion: UpdateAssistant.frameworkStorageVersion,
    })

    await this.tenantRepository.save(agentContext, tenantRecord)

    return tenantRecord
  }

  public async getTenantById(agentContext: AgentContext, tenantId: string) {
    return this.tenantRepository.getById(agentContext, tenantId)
  }

  public async findTenantsByLabel(agentContext: AgentContext, label: string) {
    return this.tenantRepository.findByLabel(agentContext, label)
  }

  public async getAllTenants(agentContext: AgentContext) {
    return this.tenantRepository.getAll(agentContext)
  }

  public async deleteTenantById(agentContext: AgentContext, tenantId: string) {
    const tenantRecord = await this.getTenantById(agentContext, tenantId)

    const tenantRoutingRecords = await this.tenantRoutingRepository.findByQuery(agentContext, {
      tenantId: tenantRecord.id,
    })

    // Delete all tenant routing records
    await Promise.all(
      tenantRoutingRecords.map((tenantRoutingRecord) =>
        this.tenantRoutingRepository.delete(agentContext, tenantRoutingRecord)
      )
    )

    // Delete tenant record
    await this.tenantRepository.delete(agentContext, tenantRecord)
  }

  public async updateTenant(agentContext: AgentContext, tenantRecord: TenantRecord) {
    return this.tenantRepository.update(agentContext, tenantRecord)
  }

  public async findTenantsByQuery(agentContext: AgentContext, query: Query<TenantRecord>, queryOptions?: QueryOptions) {
    return this.tenantRepository.findByQuery(agentContext, query, queryOptions)
  }

  public async findTenantRoutingRecordByRecipientKey(
    agentContext: AgentContext,
    recipientKey: Key
  ): Promise<TenantRoutingRecord | null> {
    return this.tenantRoutingRepository.findByRecipientKey(agentContext, recipientKey)
  }

  public async addTenantRoutingRecord(
    agentContext: AgentContext,
    tenantId: string,
    recipientKey: Key
  ): Promise<TenantRoutingRecord> {
    const tenantRoutingRecord = new TenantRoutingRecord({
      tenantId,
      recipientKeyFingerprint: recipientKey.fingerprint,
    })

    await this.tenantRoutingRepository.save(agentContext, tenantRoutingRecord)

    return tenantRoutingRecord
  }
}
