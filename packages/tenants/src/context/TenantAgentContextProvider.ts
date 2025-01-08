import type { TenantRecord } from '../repository'
import type { AgentContextProvider, UpdateAssistantUpdateOptions } from '@credo-ts/core'
import type { RoutingCreatedEvent, EncryptedMessage } from '@credo-ts/didcomm'

import {
  isStorageUpToDate,
  UpdateAssistant,
  CredoError,
  injectable,
  AgentContext,
  EventEmitter,
  inject,
  Logger,
  InjectionSymbols,
  KeyType,
  Key,
  JsonEncoder,
  isJsonObject,
} from '@credo-ts/core'
import { RoutingEventTypes, isValidJweStructure } from '@credo-ts/didcomm'

import { TenantAgent } from '../TenantAgent'
import { TenantRecordService } from '../services'

import { TenantSessionCoordinator } from './TenantSessionCoordinator'

@injectable()
export class TenantAgentContextProvider implements AgentContextProvider {
  private tenantRecordService: TenantRecordService
  private rootAgentContext: AgentContext
  private eventEmitter: EventEmitter
  private logger: Logger
  private tenantSessionCoordinator: TenantSessionCoordinator

  public constructor(
    tenantRecordService: TenantRecordService,
    rootAgentContext: AgentContext,
    eventEmitter: EventEmitter,
    tenantSessionCoordinator: TenantSessionCoordinator,
    @inject(InjectionSymbols.Logger) logger: Logger
  ) {
    this.tenantRecordService = tenantRecordService
    this.rootAgentContext = rootAgentContext
    this.eventEmitter = eventEmitter
    this.tenantSessionCoordinator = tenantSessionCoordinator
    this.logger = logger

    // Start listener for newly created routing keys, so we can register a mapping for each new key for the tenant
    this.listenForRoutingKeyCreatedEvents()
  }

  public async getAgentContextForContextCorrelationId(contextCorrelationId: string) {
    // It could be that the root agent context is requested, in that case we return the root agent context
    if (contextCorrelationId === this.rootAgentContext.contextCorrelationId) {
      return this.rootAgentContext
    }

    // TODO: maybe we can look at not having to retrieve the tenant record if there's already a context available.
    const tenantRecord = await this.tenantRecordService.getTenantById(this.rootAgentContext, contextCorrelationId)
    const shouldUpdate = !isStorageUpToDate(tenantRecord.storageVersion)

    // If the tenant storage is not up to date, and autoUpdate is disabled we throw an error
    if (shouldUpdate && !this.rootAgentContext.config.autoUpdateStorageOnStartup) {
      throw new CredoError(
        `Current agent storage for tenant ${tenantRecord.id} is not up to date. ` +
          `To prevent the tenant state from getting corrupted the tenant initialization is aborted. ` +
          `Make sure to update the tenant storage (currently at ${tenantRecord.storageVersion}) to the latest version (${UpdateAssistant.frameworkStorageVersion}). ` +
          `You can also downgrade your version of Credo.`
      )
    }

    const agentContext = await this.tenantSessionCoordinator.getContextForSession(tenantRecord, {
      runInMutex: shouldUpdate ? (agentContext) => this._updateTenantStorage(tenantRecord, agentContext) : undefined,
    })

    this.logger.debug(`Created tenant agent context for tenant '${contextCorrelationId}'`)

    return agentContext
  }

  public async getContextForInboundMessage(inboundMessage: unknown, options?: { contextCorrelationId?: string }) {
    this.logger.debug('Getting context for inbound message in tenant agent context provider', {
      contextCorrelationId: options?.contextCorrelationId,
    })

    let tenantId = options?.contextCorrelationId
    let recipientKeys: Key[] = []

    if (!tenantId && isValidJweStructure(inboundMessage)) {
      this.logger.trace("Inbound message is a JWE, extracting tenant id from JWE's protected header")
      recipientKeys = this.getRecipientKeysFromEncryptedMessage(inboundMessage)

      this.logger.trace(`Found ${recipientKeys.length} recipient keys in JWE's protected header`)

      // FIXME: what if there are multiple recipients in the same agent? If we receive the messages twice we will process it for
      // the first found recipient multiple times. This is however a case I've never seen before and will add quite some complexity
      // to resolve. I think we're fine to ignore this case for now.
      for (const recipientKey of recipientKeys) {
        const tenantRoutingRecord = await this.tenantRecordService.findTenantRoutingRecordByRecipientKey(
          this.rootAgentContext,
          recipientKey
        )

        if (tenantRoutingRecord) {
          this.logger.debug(`Found tenant routing record for recipient key ${recipientKeys[0].fingerprint}`, {
            tenantId: tenantRoutingRecord.tenantId,
          })
          tenantId = tenantRoutingRecord.tenantId
          break
        }
      }
    }

    if (!tenantId) {
      this.logger.error("Couldn't determine tenant id for inbound message. Unable to create context", {
        inboundMessage,
        recipientKeys: recipientKeys.map((key) => key.fingerprint),
      })
      throw new CredoError("Couldn't determine tenant id for inbound message. Unable to create context")
    }

    const agentContext = await this.getAgentContextForContextCorrelationId(tenantId)

    return agentContext
  }

  public async endSessionForAgentContext(agentContext: AgentContext) {
    await this.tenantSessionCoordinator.endAgentContextSession(agentContext)
  }

  private getRecipientKeysFromEncryptedMessage(jwe: EncryptedMessage): Key[] {
    const jweProtected = JsonEncoder.fromBase64(jwe.protected)
    if (!Array.isArray(jweProtected.recipients)) return []

    const recipientKeys: Key[] = []

    for (const recipient of jweProtected.recipients) {
      // Check if recipient.header.kid is a string
      if (isJsonObject(recipient) && isJsonObject(recipient.header) && typeof recipient.header.kid === 'string') {
        // This won't work with other key types, we should detect what the encoding is of kid, and based on that
        // determine how we extract the key from the message
        const key = Key.fromPublicKeyBase58(recipient.header.kid, KeyType.Ed25519)
        recipientKeys.push(key)
      }
    }

    return recipientKeys
  }

  private async registerRecipientKeyForTenant(tenantId: string, recipientKey: Key) {
    this.logger.debug(`Registering recipient key ${recipientKey.fingerprint} for tenant ${tenantId}`)
    const tenantRecord = await this.tenantRecordService.getTenantById(this.rootAgentContext, tenantId)
    await this.tenantRecordService.addTenantRoutingRecord(this.rootAgentContext, tenantRecord.id, recipientKey)
  }

  private listenForRoutingKeyCreatedEvents() {
    this.logger.debug('Listening for routing key created events in tenant agent context provider')
    this.eventEmitter.on<RoutingCreatedEvent>(RoutingEventTypes.RoutingCreatedEvent, async (event) => {
      const contextCorrelationId = event.metadata.contextCorrelationId
      const recipientKey = event.payload.routing.recipientKey

      // We don't want to register the key if it's for the root agent context
      if (contextCorrelationId === this.rootAgentContext.contextCorrelationId) return

      this.logger.debug(
        `Received routing key created event for tenant ${contextCorrelationId}, registering recipient key ${recipientKey.fingerprint} in base wallet`
      )
      await this.registerRecipientKeyForTenant(contextCorrelationId, recipientKey)
    })
  }

  /**
   * Method to allow updating the tenant storage, this method can be called from the TenantsApi
   * to update the storage for a tenant manually
   */
  public async updateTenantStorage(tenantRecord: TenantRecord, updateOptions?: UpdateAssistantUpdateOptions) {
    const agentContext = await this.tenantSessionCoordinator.getContextForSession(tenantRecord, {
      // runInMutex allows us to run the updateTenantStorage method in a mutex lock
      // prevent other sessions from being started while the update is in progress
      runInMutex: (agentContext) => this._updateTenantStorage(tenantRecord, agentContext, updateOptions),
    })

    // End sesion afterwards
    await agentContext.endSession()
  }

  /**
   * Handle the case where the tenant storage is outdated. If auto-update is disabled we will throw an error
   * and not update the storage. If auto-update is enabled we will update the storage.
   *
   * When this method is called we can be sure that we are in the mutex runExclusive lock and thus other sessions
   * will not be able to open a session for this tenant until we're done.
   *
   * NOTE: We don't support multi-instance locking for now. That means you can only have a single instance open and
   * it will prevent multiple processes from updating the tenant storage at the same time. However if multi-instances
   * are used, we can't prevent multiple instances from updating the tenant storage at the same time.
   * In the future we can make the tenantSessionCoordinator an interface and allowing a instance-tenant-lock as well
   * as an tenant-lock (across all instances)
   */
  private async _updateTenantStorage(
    tenantRecord: TenantRecord,
    agentContext: AgentContext,
    updateOptions?: UpdateAssistantUpdateOptions
  ) {
    try {
      // Update the tenant storage
      const tenantAgent = new TenantAgent(agentContext)
      const updateAssistant = new UpdateAssistant(tenantAgent)
      await updateAssistant.initialize()
      await updateAssistant.update({
        ...updateOptions,
        backupBeforeStorageUpdate:
          updateOptions?.backupBeforeStorageUpdate ?? agentContext.config.backupBeforeStorageUpdate,
      })

      // Update the storage version in the tenant record
      tenantRecord.storageVersion = await updateAssistant.getCurrentAgentStorageVersion()
      const tenantRecordService = this.rootAgentContext.dependencyManager.resolve(TenantRecordService)
      await tenantRecordService.updateTenant(this.rootAgentContext, tenantRecord)
    } catch (error) {
      this.logger.error(`Error occurred while updating tenant storage for tenant ${tenantRecord.id}`, error)
      throw error
    }
  }
}
