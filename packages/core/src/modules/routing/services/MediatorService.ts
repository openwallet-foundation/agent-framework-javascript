import type { AgentContext } from '../../../agent'
import type { InboundMessageContext } from '../../../agent/models/InboundMessageContext'
import type { Query, QueryOptions } from '../../../storage/StorageService'
import type { ConnectionRecord } from '../../connections'
import type { MediationStateChangedEvent } from '../RoutingEvents'
import type { ForwardMessage, MediationRequestMessage } from '../messages'

import { EventEmitter } from '../../../agent/EventEmitter'
import { MessageSender } from '../../../agent/MessageSender'
import { InjectionSymbols } from '../../../constants'
import { KeyType } from '../../../crypto'
import { CredoError, RecordDuplicateError } from '../../../error'
import { Logger } from '../../../logger'
import { injectable, inject } from '../../../plugins'
import { ConnectionService } from '../../connections'
import { ConnectionMetadataKeys } from '../../connections/repository/ConnectionMetadataTypes'
import { didKeyToVerkey, isDidKey, verkeyToDidKey } from '../../dids/helpers'
import { MessagePickupApi } from '../../message-pickup'
import { MessagePickupSessionRole } from '../../message-pickup/MessagePickupSession'
import { MediatorModuleConfig } from '../MediatorModuleConfig'
import { MessageForwardingStrategy } from '../MessageForwardingStrategy'
import { RoutingEventTypes } from '../RoutingEvents'
import {
  KeylistUpdateMessage,
  KeylistUpdateAction,
  KeylistUpdated,
  KeylistUpdateResponseMessage,
  KeylistUpdateResult,
  MediationGrantMessage,
} from '../messages'
import { MediationRole } from '../models/MediationRole'
import { MediationState } from '../models/MediationState'
import { MediatorRoutingRecord } from '../repository'
import { MediationRecord } from '../repository/MediationRecord'
import { MediationRepository } from '../repository/MediationRepository'
import { MediatorRoutingRepository } from '../repository/MediatorRoutingRepository'

@injectable()
export class MediatorService {
  private logger: Logger
  private mediationRepository: MediationRepository
  private mediatorRoutingRepository: MediatorRoutingRepository
  private messagePickupApi: MessagePickupApi
  private eventEmitter: EventEmitter
  private connectionService: ConnectionService

  public constructor(
    mediationRepository: MediationRepository,
    mediatorRoutingRepository: MediatorRoutingRepository,
    messagePickupApi: MessagePickupApi,
    eventEmitter: EventEmitter,
    @inject(InjectionSymbols.Logger) logger: Logger,
    connectionService: ConnectionService
  ) {
    this.mediationRepository = mediationRepository
    this.mediatorRoutingRepository = mediatorRoutingRepository
    this.messagePickupApi = messagePickupApi
    this.eventEmitter = eventEmitter
    this.logger = logger
    this.connectionService = connectionService
  }

  private async getRoutingKeys(agentContext: AgentContext) {
    const mediatorRoutingRecord = await this.findMediatorRoutingRecord(agentContext)

    if (mediatorRoutingRecord) {
      // Return the routing keys
      this.logger.debug(`Returning mediator routing keys ${mediatorRoutingRecord.routingKeys}`)
      return mediatorRoutingRecord.routingKeys
    }
    throw new CredoError(`Mediator has not been initialized yet.`)
  }

  public async processForwardMessage(messageContext: InboundMessageContext<ForwardMessage>): Promise<void> {
    const { message, agentContext } = messageContext

    // TODO: update to class-validator validation
    if (!message.to) {
      throw new CredoError('Invalid Message: Missing required attribute "to"')
    }

    const mediationRecord = await this.mediationRepository.getSingleByRecipientKey(agentContext, message.to)

    // Assert mediation record is ready to be used
    mediationRecord.assertReady()
    mediationRecord.assertRole(MediationRole.Mediator)

    const connection = await this.connectionService.getById(agentContext, mediationRecord.connectionId)
    connection.assertReady()

    const messageForwardingStrategy =
      agentContext.dependencyManager.resolve(MediatorModuleConfig).messageForwardingStrategy
    const messageSender = agentContext.dependencyManager.resolve(MessageSender)

    switch (messageForwardingStrategy) {
      case MessageForwardingStrategy.QueueOnly:
        await this.messagePickupApi.queueMessage({
          connectionId: mediationRecord.connectionId,
          recipientDids: [verkeyToDidKey(message.to)],
          message: message.message,
        })
        break
      case MessageForwardingStrategy.QueueAndLiveModeDelivery: {
        await this.messagePickupApi.queueMessage({
          connectionId: mediationRecord.connectionId,
          recipientDids: [verkeyToDidKey(message.to)],
          message: message.message,
        })
        const session = await this.messagePickupApi.getLiveModeSession({
          connectionId: mediationRecord.connectionId,
          role: MessagePickupSessionRole.MessageHolder,
        })
        if (session) {
          await this.messagePickupApi.deliverMessagesFromQueue({
            pickupSessionId: session.id,
            recipientDid: verkeyToDidKey(message.to),
          })
        }
        break
      }
      case MessageForwardingStrategy.DirectDelivery:
        // The message inside the forward message is packed so we just send the packed
        // message to the connection associated with it
        await messageSender.sendPackage(agentContext, {
          connection,
          recipientKey: verkeyToDidKey(message.to),
          encryptedMessage: message.message,
        })
    }
  }

  public async processKeylistUpdateRequest(messageContext: InboundMessageContext<KeylistUpdateMessage>) {
    // Assert Ready connection
    const connection = messageContext.assertReadyConnection()

    const { message } = messageContext
    const keylist: KeylistUpdated[] = []

    const mediationRecord = await this.mediationRepository.getByConnectionId(messageContext.agentContext, connection.id)

    mediationRecord.assertReady()
    mediationRecord.assertRole(MediationRole.Mediator)

    // Update connection metadata to use their key format in further protocol messages
    const connectionUsesDidKey = message.updates.some((update) => isDidKey(update.recipientKey))
    await this.updateUseDidKeysFlag(
      messageContext.agentContext,
      connection,
      KeylistUpdateMessage.type.protocolUri,
      connectionUsesDidKey
    )

    for (const update of message.updates) {
      const updated = new KeylistUpdated({
        action: update.action,
        recipientKey: update.recipientKey,
        result: KeylistUpdateResult.NoChange,
      })

      // According to RFC 0211 key should be a did key, but base58 encoded verkey was used before
      // RFC was accepted. This converts the key to a public key base58 if it is a did key.
      const publicKeyBase58 = didKeyToVerkey(update.recipientKey)

      if (update.action === KeylistUpdateAction.add) {
        mediationRecord.addRecipientKey(publicKeyBase58)
        updated.result = KeylistUpdateResult.Success

        keylist.push(updated)
      } else if (update.action === KeylistUpdateAction.remove) {
        const success = mediationRecord.removeRecipientKey(publicKeyBase58)
        updated.result = success ? KeylistUpdateResult.Success : KeylistUpdateResult.NoChange
        keylist.push(updated)
      }
    }

    await this.mediationRepository.update(messageContext.agentContext, mediationRecord)

    return new KeylistUpdateResponseMessage({ keylist, threadId: message.threadId })
  }

  public async createGrantMediationMessage(agentContext: AgentContext, mediationRecord: MediationRecord) {
    // Assert
    mediationRecord.assertState(MediationState.Requested)
    mediationRecord.assertRole(MediationRole.Mediator)

    await this.updateState(agentContext, mediationRecord, MediationState.Granted)

    // Use our useDidKey configuration, as this is the first interaction for this protocol
    const useDidKey = agentContext.config.useDidKeyInProtocols

    const message = new MediationGrantMessage({
      endpoint: agentContext.config.endpoints[0],
      routingKeys: useDidKey
        ? (await this.getRoutingKeys(agentContext)).map(verkeyToDidKey)
        : await this.getRoutingKeys(agentContext),
      threadId: mediationRecord.threadId,
    })

    return { mediationRecord, message }
  }

  public async processMediationRequest(messageContext: InboundMessageContext<MediationRequestMessage>) {
    // Assert ready connection
    const connection = messageContext.assertReadyConnection()

    const mediationRecord = new MediationRecord({
      connectionId: connection.id,
      role: MediationRole.Mediator,
      state: MediationState.Requested,
      threadId: messageContext.message.threadId,
    })

    await this.mediationRepository.save(messageContext.agentContext, mediationRecord)
    this.emitStateChangedEvent(messageContext.agentContext, mediationRecord, null)

    return mediationRecord
  }

  public async findById(agentContext: AgentContext, mediatorRecordId: string): Promise<MediationRecord | null> {
    return this.mediationRepository.findById(agentContext, mediatorRecordId)
  }

  public async getById(agentContext: AgentContext, mediatorRecordId: string): Promise<MediationRecord> {
    return this.mediationRepository.getById(agentContext, mediatorRecordId)
  }

  public async getAll(agentContext: AgentContext): Promise<MediationRecord[]> {
    return await this.mediationRepository.getAll(agentContext)
  }

  public async findMediatorRoutingRecord(agentContext: AgentContext): Promise<MediatorRoutingRecord | null> {
    const routingRecord = await this.mediatorRoutingRepository.findById(
      agentContext,
      this.mediatorRoutingRepository.MEDIATOR_ROUTING_RECORD_ID
    )

    return routingRecord
  }

  public async createMediatorRoutingRecord(agentContext: AgentContext): Promise<MediatorRoutingRecord | null> {
    const routingKey = await agentContext.wallet.createKey({
      keyType: KeyType.Ed25519,
    })

    const routingRecord = new MediatorRoutingRecord({
      id: this.mediatorRoutingRepository.MEDIATOR_ROUTING_RECORD_ID,
      // FIXME: update to fingerprint to include the key type
      routingKeys: [routingKey.publicKeyBase58],
    })

    try {
      await this.mediatorRoutingRepository.save(agentContext, routingRecord)
      this.eventEmitter.emit(agentContext, {
        type: RoutingEventTypes.RoutingCreatedEvent,
        payload: {
          routing: {
            endpoints: agentContext.config.endpoints,
            routingKeys: [],
            recipientKey: routingKey,
          },
        },
      })
    } catch (error) {
      // This addresses some race conditions issues where we first check if the record exists
      // then we create one if it doesn't, but another process has created one in the meantime
      // Although not the most elegant solution, it addresses the issues
      if (error instanceof RecordDuplicateError) {
        // the record already exists, which is our intended end state
        // we can ignore this error and fetch the existing record
        return this.mediatorRoutingRepository.getById(
          agentContext,
          this.mediatorRoutingRepository.MEDIATOR_ROUTING_RECORD_ID
        )
      } else {
        throw error
      }
    }

    return routingRecord
  }

  public async findAllByQuery(
    agentContext: AgentContext,
    query: Query<MediationRecord>,
    queryOptions?: QueryOptions
  ): Promise<MediationRecord[]> {
    return await this.mediationRepository.findByQuery(agentContext, query, queryOptions)
  }

  private async updateState(agentContext: AgentContext, mediationRecord: MediationRecord, newState: MediationState) {
    const previousState = mediationRecord.state

    mediationRecord.state = newState

    await this.mediationRepository.update(agentContext, mediationRecord)

    this.emitStateChangedEvent(agentContext, mediationRecord, previousState)
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
