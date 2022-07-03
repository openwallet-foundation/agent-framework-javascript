import type { AgentContext } from '../../../agent'
import type { AgentMessage } from '../../../agent/AgentMessage'
import type { AgentMessageReceivedEvent } from '../../../agent/Events'
import type { InboundMessageContext } from '../../../agent/models/InboundMessageContext'
import type { EncryptedMessage } from '../../../types'
import type { ConnectionRecord } from '../../connections'
import type { Routing } from '../../connections/services/ConnectionService'
import type { MediationStateChangedEvent, KeylistUpdatedEvent } from '../RoutingEvents'
import type {
  KeylistUpdateResponseMessage,
  MediationDenyMessage,
  MediationGrantMessage,
  MessageDeliveryMessage,
} from '../messages'
import type { StatusMessage } from '../messages/StatusMessage'
import type { GetRoutingOptions } from './RoutingService'

import { firstValueFrom, ReplaySubject } from 'rxjs'
import { filter, first, timeout } from 'rxjs/operators'

import { EventEmitter } from '../../../agent/EventEmitter'
import { AgentEventTypes } from '../../../agent/Events'
import { MessageSender } from '../../../agent/MessageSender'
import { createOutboundMessage } from '../../../agent/helpers'
import { KeyType } from '../../../crypto'
import { AriesFrameworkError } from '../../../error'
import { injectable } from '../../../plugins'
import { JsonTransformer } from '../../../utils'
import { ConnectionService } from '../../connections/services/ConnectionService'
import { Key } from '../../dids'
import { ProblemReportError } from '../../problem-reports'
import { RoutingEventTypes } from '../RoutingEvents'
import { RoutingProblemReportReason } from '../error'
import {
  StatusRequestMessage,
  DeliveryRequestMessage,
  MessagesReceivedMessage,
  KeylistUpdateAction,
  MediationRequestMessage,
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

  public async createStatusRequest(
    mediationRecord: MediationRecord,
    config: {
      recipientKey?: string
    } = {}
  ) {
    mediationRecord.assertRole(MediationRole.Recipient)
    mediationRecord.assertReady()

    const { recipientKey } = config
    const statusRequest = new StatusRequestMessage({
      recipientKey,
    })

    return statusRequest
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
    mediationRecord.routingKeys = messageContext.message.routingKeys
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

    // update keylist in mediationRecord
    for (const update of keylist) {
      if (update.action === KeylistUpdateAction.add) {
        mediationRecord.addRecipientKey(update.recipientKey)
      } else if (update.action === KeylistUpdateAction.remove) {
        mediationRecord.removeRecipientKey(update.recipientKey)
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
    verKey: string,
    timeoutMs = 15000 // TODO: this should be a configurable value in agent config
  ): Promise<MediationRecord> {
    const message = this.createKeylistUpdateMessage(verKey)
    const connection = await this.connectionService.getById(agentContext, mediationRecord.connectionId)

    mediationRecord.assertReady()
    mediationRecord.assertRole(MediationRole.Recipient)

    // Create observable for event
    const observable = this.eventEmitter.observable<KeylistUpdatedEvent>(RoutingEventTypes.RecipientKeylistUpdated)
    const subject = new ReplaySubject<KeylistUpdatedEvent>(1)

    // Apply required filters to observable stream and create promise to subscribe to observable
    observable
      .pipe(
        // Only take event for current mediation record
        filter((event) => mediationRecord.id === event.payload.mediationRecord.id),
        // Only wait for first event that matches the criteria
        first(),
        // Do not wait for longer than specified timeout
        timeout(timeoutMs)
      )
      .subscribe(subject)

    const outboundMessage = createOutboundMessage(connection, message)
    await this.messageSender.sendMessage(agentContext, outboundMessage)

    const keylistUpdate = await firstValueFrom(subject)
    return keylistUpdate.payload.mediationRecord
  }

  public createKeylistUpdateMessage(verkey: string): KeylistUpdateMessage {
    const keylistUpdateMessage = new KeylistUpdateMessage({
      updates: [
        new KeylistUpdate({
          action: KeylistUpdateAction.add,
          recipientKey: verkey,
        }),
      ],
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
    mediationRecord = await this.keylistUpdateAndAwait(
      agentContext,
      mediationRecord,
      routing.recipientKey.publicKeyBase58
    )

    return {
      ...routing,
      endpoints: mediationRecord.endpoint ? [mediationRecord.endpoint] : routing.endpoints,
      routingKeys: mediationRecord.routingKeys.map((key) => Key.fromPublicKeyBase58(key, KeyType.Ed25519)),
    }
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

  public async processStatus(messageContext: InboundMessageContext<StatusMessage>) {
    const connection = messageContext.assertReadyConnection()
    const { message: statusMessage } = messageContext
    const { messageCount, recipientKey } = statusMessage

    const mediationRecord = await this.mediationRepository.getByConnectionId(messageContext.agentContext, connection.id)

    mediationRecord.assertReady()
    mediationRecord.assertRole(MediationRole.Recipient)

    //No messages to be sent
    if (messageCount === 0) {
      const { message, connectionRecord } = await this.connectionService.createTrustPing(
        messageContext.agentContext,
        connection,
        {
          responseRequested: false,
        }
      )
      const websocketSchemes = ['ws', 'wss']

      await this.messageSender.sendMessage(
        messageContext.agentContext,
        createOutboundMessage(connectionRecord, message),
        {
          transportPriority: {
            schemes: websocketSchemes,
            restrictive: true,
            // TODO: add keepAlive: true to enforce through the public api
            // we need to keep the socket alive. It already works this way, but would
            // be good to make more explicit from the public facing API.
            // This would also make it easier to change the internal API later on.
            // keepAlive: true,
          },
        }
      )

      return null
    }
    const { maximumMessagePickup } = messageContext.agentContext.config
    const limit = messageCount < maximumMessagePickup ? messageCount : maximumMessagePickup

    const deliveryRequestMessage = new DeliveryRequestMessage({
      limit,
      recipientKey,
    })

    return deliveryRequestMessage
  }

  public async processDelivery(messageContext: InboundMessageContext<MessageDeliveryMessage>) {
    const connection = messageContext.assertReadyConnection()

    const { appendedAttachments } = messageContext.message

    const mediationRecord = await this.mediationRepository.getByConnectionId(messageContext.agentContext, connection.id)

    mediationRecord.assertReady()
    mediationRecord.assertRole(MediationRole.Recipient)

    if (!appendedAttachments)
      throw new ProblemReportError('Error processing attachments', {
        problemCode: RoutingProblemReportReason.ErrorProcessingAttachments,
      })

    const ids: string[] = []
    for (const attachment of appendedAttachments) {
      ids.push(attachment.id)

      this.eventEmitter.emit<AgentMessageReceivedEvent>(messageContext.agentContext, {
        type: AgentEventTypes.AgentMessageReceived,
        payload: {
          message: attachment.getDataAsJson<EncryptedMessage>(),
        },
      })
    }

    return new MessagesReceivedMessage({
      messageIdList: ids,
    })
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
    const clonedMediationRecord = JsonTransformer.clone(mediationRecord)
    this.eventEmitter.emit<MediationStateChangedEvent>(agentContext, {
      type: RoutingEventTypes.MediationStateChanged,
      payload: {
        mediationRecord: clonedMediationRecord,
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
        throw new AriesFrameworkError(
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
}

export interface MediationProtocolMsgReturnType<MessageType extends AgentMessage> {
  message: MessageType
  mediationRecord: MediationRecord
}
