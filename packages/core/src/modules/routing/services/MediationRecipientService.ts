import type { GetRoutingOptions, RemoveRoutingOptions } from './RoutingService'
import type { AgentContext } from '../../../agent'
import type { AgentMessage } from '../../../agent/AgentMessage'
import type { InboundMessageContext } from '../../../agent/models/InboundMessageContext'
import type { Query, QueryOptions } from '../../../storage/StorageService'
import type { ConnectionRecord } from '../../connections'
import type { Routing } from '../../connections/services/ConnectionService'
import type { MediationStateChangedEvent, KeylistUpdatedEvent } from '../RoutingEvents'
import type { MediationDenyMessage } from '../messages'

import { firstValueFrom, ReplaySubject } from 'rxjs'
import { filter, first, timeout } from 'rxjs/operators'

import { EventEmitter } from '../../../agent/EventEmitter'
import { filterContextCorrelationId } from '../../../agent/Events'
import { MessageSender } from '../../../agent/MessageSender'
import { OutboundMessageContext } from '../../../agent/models'
import { Key, KeyType } from '../../../crypto'
import { CredoError } from '../../../error'
import { injectable } from '../../../plugins'
import { ConnectionType } from '../../connections/models/ConnectionType'
import { ConnectionMetadataKeys } from '../../connections/repository/ConnectionMetadataTypes'
import { ConnectionService } from '../../connections/services/ConnectionService'
import { DidKey } from '../../dids'
import { didKeyToVerkey, isDidKey } from '../../dids/helpers'
import { RoutingEventTypes } from '../RoutingEvents'
import {
  KeylistUpdateAction,
  KeylistUpdateResponseMessage,
  MediationRequestMessage,
  MediationGrantMessage,
} from '../messages'
import { KeylistUpdate, KeylistUpdateMessage } from '../messages/KeylistUpdateMessage'
import { MediationRole, MediationState } from '../models'
import { MediationRecord } from '../repository/MediationRecord'
import { MediationRepository } from '../repository/MediationRepository'

@injectable()
export class MediationRecipientService {
  private mediationRepository: MediationRepository
  private eventEmitter: EventEmitter
  private connectionService: ConnectionService
  private messageSender: MessageSender

  public constructor(
    connectionService: ConnectionService,
    messageSender: MessageSender,
    mediatorRepository: MediationRepository,
    eventEmitter: EventEmitter
  ) {
    this.mediationRepository = mediatorRepository
    this.eventEmitter = eventEmitter
    this.connectionService = connectionService
    this.messageSender = messageSender
  }

  public async createRequest(
    agentContext: AgentContext,
    connection: ConnectionRecord
  ): Promise<MediationProtocolMsgReturnType<MediationRequestMessage>> {
    const message = new MediationRequestMessage({})

    const mediationRecord = new MediationRecord({
      threadId: message.threadId,
      state: MediationState.Requested,
      role: MediationRole.Recipient,
      connectionId: connection.id,
    })

    await this.connectionService.addConnectionType(agentContext, connection, ConnectionType.Mediator)

    await this.mediationRepository.save(agentContext, mediationRecord)
    this.emitStateChangedEvent(agentContext, mediationRecord, null)

    return { mediationRecord, message }
  }

  public async processMediationGrant(messageContext: InboundMessageContext<MediationGrantMessage>) {
    // Assert ready connection
    const connection = messageContext.assertReadyConnection()

    // Mediation record must already exists to be updated to granted status
    const mediationRecord = await this.mediationRepository.getByConnectionId(messageContext.agentContext, connection.id)

    // Assert
    mediationRecord.assertState(MediationState.Requested)
    mediationRecord.assertRole(MediationRole.Recipient)

    // Update record
    mediationRecord.endpoint = messageContext.message.endpoint

    // Update connection metadata to use their key format in further protocol messages
    const connectionUsesDidKey = messageContext.message.routingKeys.some(isDidKey)
    await this.updateUseDidKeysFlag(
      messageContext.agentContext,
      connection,
      MediationGrantMessage.type.protocolUri,
      connectionUsesDidKey
    )

    // According to RFC 0211 keys should be a did key, but base58 encoded verkey was used before
    // RFC was accepted. This converts the key to a public key base58 if it is a did key.
    mediationRecord.routingKeys = messageContext.message.routingKeys.map(didKeyToVerkey)
    return await this.updateState(messageContext.agentContext, mediationRecord, MediationState.Granted)
  }

  public async processKeylistUpdateResults(messageContext: InboundMessageContext<KeylistUpdateResponseMessage>) {
    // Assert ready connection
    const connection = messageContext.assertReadyConnection()

    const mediationRecord = await this.mediationRepository.getByConnectionId(messageContext.agentContext, connection.id)

    // Assert
    mediationRecord.assertReady()
    mediationRecord.assertRole(MediationRole.Recipient)

    const keylist = messageContext.message.updated

    // Update connection metadata to use their key format in further protocol messages
    const connectionUsesDidKey = keylist.some((key) => isDidKey(key.recipientKey))
    await this.updateUseDidKeysFlag(
      messageContext.agentContext,
      connection,
      KeylistUpdateResponseMessage.type.protocolUri,
      connectionUsesDidKey
    )

    // update keylist in mediationRecord
    for (const update of keylist) {
      if (update.action === KeylistUpdateAction.add) {
        mediationRecord.addRecipientKey(didKeyToVerkey(update.recipientKey))
      } else if (update.action === KeylistUpdateAction.remove) {
        mediationRecord.removeRecipientKey(didKeyToVerkey(update.recipientKey))
      }
    }

    await this.mediationRepository.update(messageContext.agentContext, mediationRecord)
    this.eventEmitter.emit<KeylistUpdatedEvent>(messageContext.agentContext, {
      type: RoutingEventTypes.RecipientKeylistUpdated,
      payload: {
        mediationRecord,
        keylist,
      },
    })
  }

  public async keylistUpdateAndAwait(
    agentContext: AgentContext,
    mediationRecord: MediationRecord,
    updates: { recipientKey: Key; action: KeylistUpdateAction }[],
    timeoutMs = 15000 // TODO: this should be a configurable value in agent config
  ): Promise<MediationRecord> {
    const connection = await this.connectionService.getById(agentContext, mediationRecord.connectionId)

    // Use our useDidKey configuration unless we know the key formatting other party is using
    let useDidKey = agentContext.config.useDidKeyInProtocols

    const useDidKeysConnectionMetadata = connection.metadata.get(ConnectionMetadataKeys.UseDidKeysForProtocol)
    if (useDidKeysConnectionMetadata) {
      useDidKey = useDidKeysConnectionMetadata[KeylistUpdateMessage.type.protocolUri] ?? useDidKey
    }

    const message = this.createKeylistUpdateMessage(
      updates.map(
        (item) =>
          new KeylistUpdate({
            action: item.action,
            recipientKey: useDidKey ? new DidKey(item.recipientKey).did : item.recipientKey.publicKeyBase58,
          })
      )
    )

    mediationRecord.assertReady()
    mediationRecord.assertRole(MediationRole.Recipient)

    // Create observable for event
    const observable = this.eventEmitter.observable<KeylistUpdatedEvent>(RoutingEventTypes.RecipientKeylistUpdated)
    const subject = new ReplaySubject<KeylistUpdatedEvent>(1)

    // Apply required filters to observable stream and create promise to subscribe to observable
    observable
      .pipe(
        filterContextCorrelationId(agentContext.contextCorrelationId),
        // Only take event for current mediation record
        filter((event) => mediationRecord.id === event.payload.mediationRecord.id),
        // Only wait for first event that matches the criteria
        first(),
        // Do not wait for longer than specified timeout
        timeout({
          first: timeoutMs,
          meta: 'MediationRecipientService.keylistUpdateAndAwait',
        })
      )
      .subscribe(subject)

    const outboundMessageContext = new OutboundMessageContext(message, { agentContext, connection })
    await this.messageSender.sendMessage(outboundMessageContext)

    const keylistUpdate = await firstValueFrom(subject)
    return keylistUpdate.payload.mediationRecord
  }

  public createKeylistUpdateMessage(updates: KeylistUpdate[]): KeylistUpdateMessage {
    const keylistUpdateMessage = new KeylistUpdateMessage({
      updates,
    })
    return keylistUpdateMessage
  }

  public async addMediationRouting(
    agentContext: AgentContext,
    routing: Routing,
    { mediatorId, useDefaultMediator = true }: GetRoutingOptions = {}
  ): Promise<Routing> {
    let mediationRecord: MediationRecord | null = null

    if (mediatorId) {
      mediationRecord = await this.getById(agentContext, mediatorId)
    } else if (useDefaultMediator) {
      // If no mediatorId is provided, and useDefaultMediator is true (default)
      // We use the default mediator if available
      mediationRecord = await this.findDefaultMediator(agentContext)
    }

    // Return early if no mediation record
    if (!mediationRecord) return routing

    // new did has been created and mediator needs to be updated with the public key.
    mediationRecord = await this.keylistUpdateAndAwait(agentContext, mediationRecord, [
      {
        recipientKey: routing.recipientKey,
        action: KeylistUpdateAction.add,
      },
    ])

    return {
      ...routing,
      mediatorId: mediationRecord.id,
      endpoints: mediationRecord.endpoint ? [mediationRecord.endpoint] : routing.endpoints,
      routingKeys: mediationRecord.routingKeys.map((key) => Key.fromPublicKeyBase58(key, KeyType.Ed25519)),
    }
  }

  public async removeMediationRouting(
    agentContext: AgentContext,
    { recipientKeys, mediatorId }: RemoveRoutingOptions
  ): Promise<void> {
    const mediationRecord = await this.getById(agentContext, mediatorId)

    if (!mediationRecord) {
      throw new CredoError('No mediation record to remove routing from has been found')
    }

    await this.keylistUpdateAndAwait(
      agentContext,
      mediationRecord,
      recipientKeys.map((item) => {
        return {
          recipientKey: item,
          action: KeylistUpdateAction.remove,
        }
      })
    )
  }

  public async processMediationDeny(messageContext: InboundMessageContext<MediationDenyMessage>) {
    const connection = messageContext.assertReadyConnection()

    // Mediation record already exists
    const mediationRecord = await this.findByConnectionId(messageContext.agentContext, connection.id)

    if (!mediationRecord) {
      throw new Error(`No mediation has been requested for this connection id: ${connection.id}`)
    }

    // Assert
    mediationRecord.assertRole(MediationRole.Recipient)
    mediationRecord.assertState(MediationState.Requested)

    // Update record
    await this.updateState(messageContext.agentContext, mediationRecord, MediationState.Denied)

    return mediationRecord
  }

  /**
   * Update the record to a new state and emit an state changed event. Also updates the record
   * in storage.
   *
   * @param MediationRecord The proof record to update the state for
   * @param newState The state to update to
   *
   */
  private async updateState(agentContext: AgentContext, mediationRecord: MediationRecord, newState: MediationState) {
    const previousState = mediationRecord.state
    mediationRecord.state = newState
    await this.mediationRepository.update(agentContext, mediationRecord)

    this.emitStateChangedEvent(agentContext, mediationRecord, previousState)
    return mediationRecord
  }

  private emitStateChangedEvent(
    agentContext: AgentContext,
    mediationRecord: MediationRecord,
    previousState: MediationState | null
  ) {
    this.eventEmitter.emit<MediationStateChangedEvent>(agentContext, {
      type: RoutingEventTypes.MediationStateChanged,
      payload: {
        mediationRecord: mediationRecord.clone(),
        previousState,
      },
    })
  }

  public async getById(agentContext: AgentContext, id: string): Promise<MediationRecord> {
    return this.mediationRepository.getById(agentContext, id)
  }

  public async findByConnectionId(agentContext: AgentContext, connectionId: string): Promise<MediationRecord | null> {
    return this.mediationRepository.findSingleByQuery(agentContext, { connectionId })
  }

  public async getMediators(agentContext: AgentContext): Promise<MediationRecord[]> {
    return this.mediationRepository.getAll(agentContext)
  }

  public async findAllMediatorsByQuery(
    agentContext: AgentContext,
    query: Query<MediationRecord>,
    queryOptions?: QueryOptions
  ): Promise<MediationRecord[]> {
    return await this.mediationRepository.findByQuery(agentContext, query, queryOptions)
  }

  public async findDefaultMediator(agentContext: AgentContext): Promise<MediationRecord | null> {
    return this.mediationRepository.findSingleByQuery(agentContext, { default: true })
  }

  public async discoverMediation(
    agentContext: AgentContext,
    mediatorId?: string
  ): Promise<MediationRecord | undefined> {
    // If mediatorId is passed, always use it (and error if it is not found)
    if (mediatorId) {
      return this.mediationRepository.getById(agentContext, mediatorId)
    }

    const defaultMediator = await this.findDefaultMediator(agentContext)
    if (defaultMediator) {
      if (defaultMediator.state !== MediationState.Granted) {
        throw new CredoError(
          `Mediation State for ${defaultMediator.id} is not granted, but is set as default mediator!`
        )
      }

      return defaultMediator
    }
  }

  public async setDefaultMediator(agentContext: AgentContext, mediator: MediationRecord) {
    const mediationRecords = await this.mediationRepository.findByQuery(agentContext, { default: true })

    for (const record of mediationRecords) {
      record.setTag('default', false)
      await this.mediationRepository.update(agentContext, record)
    }

    // Set record coming in tag to true and then update.
    mediator.setTag('default', true)
    await this.mediationRepository.update(agentContext, mediator)
  }

  public async clearDefaultMediator(agentContext: AgentContext) {
    const mediationRecord = await this.findDefaultMediator(agentContext)

    if (mediationRecord) {
      mediationRecord.setTag('default', false)
      await this.mediationRepository.update(agentContext, mediationRecord)
    }
  }

  private async updateUseDidKeysFlag(
    agentContext: AgentContext,
    connection: ConnectionRecord,
    protocolUri: string,
    connectionUsesDidKey: boolean
  ) {
    const useDidKeysForProtocol = connection.metadata.get(ConnectionMetadataKeys.UseDidKeysForProtocol) ?? {}
    useDidKeysForProtocol[protocolUri] = connectionUsesDidKey
    connection.metadata.set(ConnectionMetadataKeys.UseDidKeysForProtocol, useDidKeysForProtocol)
    await this.connectionService.update(agentContext, connection)
  }
}

export interface MediationProtocolMsgReturnType<MessageType extends AgentMessage> {
  message: MessageType
  mediationRecord: MediationRecord
}
