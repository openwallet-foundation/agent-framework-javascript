import type { AgentContext } from '../../../agent'
import type { InboundMessageContext } from '../../../agent/models/InboundMessageContext'
import type { EncryptedMessage } from '../../../types'
import type { MediationStateChangedEvent } from '../RoutingEvents'
import type { ForwardMessage, KeylistUpdateMessage, MediationRequestMessage } from '../messages'

import { EventEmitter } from '../../../agent/EventEmitter'
import { InjectionSymbols } from '../../../constants'
import { AriesFrameworkError } from '../../../error'
import { Logger } from '../../../logger'
import { injectable, inject } from '../../../plugins'
import { JsonTransformer } from '../../../utils/JsonTransformer'
import { RoutingEventTypes } from '../RoutingEvents'
import {
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
  private eventEmitter: EventEmitter
  private _mediatorRoutingRecord?: MediatorRoutingRecord

  public constructor(
    mediationRepository: MediationRepository,
    mediatorRoutingRepository: MediatorRoutingRepository,
    eventEmitter: EventEmitter,
    @inject(InjectionSymbols.Logger) logger: Logger
  ) {
    this.mediationRepository = mediationRepository
    this.mediatorRoutingRepository = mediatorRoutingRepository
    this.eventEmitter = eventEmitter
    this.logger = logger
  }

  private async getRoutingKeys(agentContext: AgentContext) {
    this.logger.debug('Retrieving mediator routing keys')
    // If the routing record is not loaded yet, retrieve it from storage
    if (!this._mediatorRoutingRecord) {
      this.logger.debug('Mediator routing record not loaded yet, retrieving from storage')
      let routingRecord = await this.mediatorRoutingRepository.findById(
        agentContext,
        this.mediatorRoutingRepository.MEDIATOR_ROUTING_RECORD_ID
      )

      // If we don't have a routing record yet, create it
      if (!routingRecord) {
        this.logger.debug('Mediator routing record does not exist yet, creating routing keys and record')
        const { verkey } = await agentContext.wallet.createDid()

        routingRecord = new MediatorRoutingRecord({
          id: this.mediatorRoutingRepository.MEDIATOR_ROUTING_RECORD_ID,
          routingKeys: [verkey],
        })

        await this.mediatorRoutingRepository.save(agentContext, routingRecord)
      }

      this._mediatorRoutingRecord = routingRecord
    }

    // Return the routing keys
    this.logger.debug(`Returning mediator routing keys ${this._mediatorRoutingRecord.routingKeys}`)
    return this._mediatorRoutingRecord.routingKeys
  }

  public async processForwardMessage(
    messageContext: InboundMessageContext<ForwardMessage>
  ): Promise<{ mediationRecord: MediationRecord; encryptedMessage: EncryptedMessage }> {
    const { message } = messageContext

    // TODO: update to class-validator validation
    if (!message.to) {
      throw new AriesFrameworkError('Invalid Message: Missing required attribute "to"')
    }

    const mediationRecord = await this.mediationRepository.getSingleByRecipientKey(
      messageContext.agentContext,
      message.to
    )

    // Assert mediation record is ready to be used
    mediationRecord.assertReady()
    mediationRecord.assertRole(MediationRole.Mediator)

    return {
      encryptedMessage: message.message,
      mediationRecord,
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

    for (const update of message.updates) {
      const updated = new KeylistUpdated({
        action: update.action,
        recipientKey: update.recipientKey,
        result: KeylistUpdateResult.NoChange,
      })
      if (update.action === KeylistUpdateAction.add) {
        mediationRecord.addRecipientKey(update.recipientKey)
        updated.result = KeylistUpdateResult.Success

        keylist.push(updated)
      } else if (update.action === KeylistUpdateAction.remove) {
        const success = mediationRecord.removeRecipientKey(update.recipientKey)
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

    const message = new MediationGrantMessage({
      endpoint: agentContext.config.endpoints[0],
      routingKeys: await this.getRoutingKeys(agentContext),
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
    const clonedMediationRecord = JsonTransformer.clone(mediationRecord)
    this.eventEmitter.emit<MediationStateChangedEvent>(agentContext, {
      type: RoutingEventTypes.MediationStateChanged,
      payload: {
        mediationRecord: clonedMediationRecord,
        previousState,
      },
    })
  }
}
