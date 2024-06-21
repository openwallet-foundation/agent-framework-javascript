import type { ProofProtocol } from './ProofProtocol'
import type {
  CreateProofProposalOptions,
  CreateProofRequestOptions,
  DeleteProofOptions,
  GetProofFormatDataReturn,
  CreateProofProblemReportOptions,
  ProofProtocolMsgReturnType,
  AcceptPresentationOptions,
  AcceptProofProposalOptions,
  AcceptProofRequestOptions,
  GetCredentialsForRequestOptions,
  GetCredentialsForRequestReturn,
  NegotiateProofProposalOptions,
  NegotiateProofRequestOptions,
  SelectCredentialsForRequestOptions,
  SelectCredentialsForRequestReturn,
} from './ProofProtocolOptions'
import type { AgentMessage } from '../../../agent/AgentMessage'
import type { FeatureRegistry } from '../../../agent/FeatureRegistry'
import type { AgentContext } from '../../../agent/context/AgentContext'
import type { InboundMessageContext } from '../../../agent/models/InboundMessageContext'
import type { DependencyManager } from '../../../plugins'
import type { Query, QueryOptions } from '../../../storage/StorageService'
import type { ProblemReportMessage } from '../../problem-reports'
import type { ProofStateChangedEvent } from '../ProofEvents'
import type { ExtractProofFormats, ProofFormatService } from '../formats'
import type { ProofRole } from '../models'
import type { ProofExchangeRecord } from '../repository'

import { EventEmitter } from '../../../agent/EventEmitter'
import { DidCommMessageRepository } from '../../../storage/didcomm'
import { ConnectionService } from '../../connections'
import { ProofEventTypes } from '../ProofEvents'
import { ProofState } from '../models/ProofState'
import { ProofRepository } from '../repository'

export abstract class BaseProofProtocol<PFs extends ProofFormatService[] = ProofFormatService[]>
  implements ProofProtocol<PFs>
{
  public abstract readonly version: string

  public abstract register(dependencyManager: DependencyManager, featureRegistry: FeatureRegistry): void

  // methods for proposal
  public abstract createProposal(
    agentContext: AgentContext,
    options: CreateProofProposalOptions<PFs>
  ): Promise<ProofProtocolMsgReturnType<AgentMessage>>
  public abstract processProposal(messageContext: InboundMessageContext<AgentMessage>): Promise<ProofExchangeRecord>
  public abstract acceptProposal(
    agentContext: AgentContext,
    options: AcceptProofProposalOptions<PFs>
  ): Promise<ProofProtocolMsgReturnType<AgentMessage>>
  public abstract negotiateProposal(
    agentContext: AgentContext,
    options: NegotiateProofProposalOptions<PFs>
  ): Promise<ProofProtocolMsgReturnType<AgentMessage>>

  // methods for request
  public abstract createRequest(
    agentContext: AgentContext,
    options: CreateProofRequestOptions<PFs>
  ): Promise<ProofProtocolMsgReturnType<AgentMessage>>
  public abstract processRequest(messageContext: InboundMessageContext<AgentMessage>): Promise<ProofExchangeRecord>
  public abstract acceptRequest(
    agentContext: AgentContext,
    options: AcceptProofRequestOptions<PFs>
  ): Promise<ProofProtocolMsgReturnType<AgentMessage>>
  public abstract negotiateRequest(
    agentContext: AgentContext,
    options: NegotiateProofRequestOptions<PFs>
  ): Promise<ProofProtocolMsgReturnType<AgentMessage>>

  // retrieving credentials for request
  public abstract getCredentialsForRequest(
    agentContext: AgentContext,
    options: GetCredentialsForRequestOptions<PFs>
  ): Promise<GetCredentialsForRequestReturn<PFs>>
  public abstract selectCredentialsForRequest(
    agentContext: AgentContext,
    options: SelectCredentialsForRequestOptions<PFs>
  ): Promise<SelectCredentialsForRequestReturn<PFs>>

  // methods for presentation
  public abstract processPresentation(messageContext: InboundMessageContext<AgentMessage>): Promise<ProofExchangeRecord>
  public abstract acceptPresentation(
    agentContext: AgentContext,
    options: AcceptPresentationOptions
  ): Promise<ProofProtocolMsgReturnType<AgentMessage>>

  // methods for ack
  public abstract processAck(messageContext: InboundMessageContext<AgentMessage>): Promise<ProofExchangeRecord>
  // method for problem report
  public abstract createProblemReport(
    agentContext: AgentContext,
    options: CreateProofProblemReportOptions
  ): Promise<ProofProtocolMsgReturnType<ProblemReportMessage>>

  public abstract findProposalMessage(agentContext: AgentContext, proofExchangeId: string): Promise<AgentMessage | null>
  public abstract findRequestMessage(agentContext: AgentContext, proofExchangeId: string): Promise<AgentMessage | null>
  public abstract findPresentationMessage(
    agentContext: AgentContext,
    proofExchangeId: string
  ): Promise<AgentMessage | null>
  public abstract getFormatData(
    agentContext: AgentContext,
    proofExchangeId: string
  ): Promise<GetProofFormatDataReturn<ExtractProofFormats<PFs>>>

  public async processProblemReport(
    messageContext: InboundMessageContext<ProblemReportMessage>
  ): Promise<ProofExchangeRecord> {
    const { message: proofProblemReportMessage, agentContext, connection } = messageContext

    const connectionService = agentContext.dependencyManager.resolve(ConnectionService)

    agentContext.config.logger.debug(`Processing problem report with message id ${proofProblemReportMessage.id}`)

    const proofRecord = await this.getByProperties(agentContext, {
      threadId: proofProblemReportMessage.threadId,
    })

    // Assert
    await connectionService.assertConnectionOrOutOfBandExchange(messageContext, {
      expectedConnectionId: proofRecord.connectionId,
    })

    //  This makes sure that the sender of the incoming message is authorized to do so.
    if (!proofRecord?.connectionId) {
      await connectionService.matchIncomingMessageToRequestMessageInOutOfBandExchange(messageContext, {
        expectedConnectionId: proofRecord?.connectionId,
      })

      proofRecord.connectionId = connection?.id
    }

    // Update record
    proofRecord.errorMessage = `${proofProblemReportMessage.description.code}: ${proofProblemReportMessage.description.en}`
    await this.updateState(agentContext, proofRecord, ProofState.Abandoned)
    return proofRecord
  }

  /**
   * Update the record to a new state and emit an state changed event. Also updates the record
   * in storage.
   *
   * @param proofRecord The proof record to update the state for
   * @param newState The state to update to
   *
   */
  public async updateState(agentContext: AgentContext, proofRecord: ProofExchangeRecord, newState: ProofState) {
    const proofRepository = agentContext.dependencyManager.resolve(ProofRepository)

    agentContext.config.logger.debug(
      `Updating proof record ${proofRecord.id} to state ${newState} (previous=${proofRecord.state})`
    )

    const previousState = proofRecord.state
    proofRecord.state = newState
    await proofRepository.update(agentContext, proofRecord)

    this.emitStateChangedEvent(agentContext, proofRecord, previousState)
  }

  protected emitStateChangedEvent(
    agentContext: AgentContext,
    proofRecord: ProofExchangeRecord,
    previousState: ProofState | null
  ) {
    const eventEmitter = agentContext.dependencyManager.resolve(EventEmitter)

    eventEmitter.emit<ProofStateChangedEvent>(agentContext, {
      type: ProofEventTypes.ProofStateChanged,
      payload: {
        proofRecord: proofRecord.clone(),
        previousState: previousState,
      },
    })
  }

  /**
   * Retrieve a proof record by id
   *
   * @param proofRecordId The proof record id
   * @throws {RecordNotFoundError} If no record is found
   * @return The proof record
   *
   */
  public getById(agentContext: AgentContext, proofRecordId: string): Promise<ProofExchangeRecord> {
    const proofRepository = agentContext.dependencyManager.resolve(ProofRepository)

    return proofRepository.getById(agentContext, proofRecordId)
  }

  /**
   * Retrieve all proof records
   *
   * @returns List containing all proof records
   */
  public getAll(agentContext: AgentContext): Promise<ProofExchangeRecord[]> {
    const proofRepository = agentContext.dependencyManager.resolve(ProofRepository)

    return proofRepository.getAll(agentContext)
  }

  public async findAllByQuery(
    agentContext: AgentContext,
    query: Query<ProofExchangeRecord>,
    queryOptions?: QueryOptions
  ): Promise<ProofExchangeRecord[]> {
    const proofRepository = agentContext.dependencyManager.resolve(ProofRepository)

    return proofRepository.findByQuery(agentContext, query, queryOptions)
  }

  /**
   * Find a proof record by id
   *
   * @param proofRecordId the proof record id
   * @returns The proof record or null if not found
   */
  public findById(agentContext: AgentContext, proofRecordId: string): Promise<ProofExchangeRecord | null> {
    const proofRepository = agentContext.dependencyManager.resolve(ProofRepository)

    return proofRepository.findById(agentContext, proofRecordId)
  }

  public async delete(
    agentContext: AgentContext,
    proofRecord: ProofExchangeRecord,
    options?: DeleteProofOptions
  ): Promise<void> {
    const proofRepository = agentContext.dependencyManager.resolve(ProofRepository)
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    await proofRepository.delete(agentContext, proofRecord)

    const deleteAssociatedDidCommMessages = options?.deleteAssociatedDidCommMessages ?? true

    if (deleteAssociatedDidCommMessages) {
      const didCommMessages = await didCommMessageRepository.findByQuery(agentContext, {
        associatedRecordId: proofRecord.id,
      })
      for (const didCommMessage of didCommMessages) {
        await didCommMessageRepository.delete(agentContext, didCommMessage)
      }
    }
  }

  /**
   * Retrieve a proof record by connection id and thread id
   *
   * @param properties Properties to query by
   *
   * @throws {RecordNotFoundError} If no record is found
   * @throws {RecordDuplicateError} If multiple records are found
   *
   * @returns The proof record
   */
  public getByProperties(
    agentContext: AgentContext,
    properties: {
      threadId: string
      role?: ProofRole
      connectionId?: string
    }
  ): Promise<ProofExchangeRecord> {
    const { threadId, connectionId, role } = properties
    const proofRepository = agentContext.dependencyManager.resolve(ProofRepository)

    return proofRepository.getSingleByQuery(agentContext, {
      connectionId,
      threadId,
      role,
    })
  }

  /**
   * Find a proof record by connection id and thread id, returns null if not found
   *
   * @param properties Properties to query by
   *
   * @returns The proof record
   */
  public findByProperties(
    agentContext: AgentContext,
    properties: {
      threadId: string
      role?: ProofRole
      connectionId?: string
    }
  ): Promise<ProofExchangeRecord | null> {
    const { role, connectionId, threadId } = properties
    const proofRepository = agentContext.dependencyManager.resolve(ProofRepository)

    return proofRepository.findSingleByQuery(agentContext, {
      connectionId,
      threadId,
      role,
    })
  }

  public async update(agentContext: AgentContext, proofRecord: ProofExchangeRecord) {
    const proofRepository = agentContext.dependencyManager.resolve(ProofRepository)

    return await proofRepository.update(agentContext, proofRecord)
  }
}
