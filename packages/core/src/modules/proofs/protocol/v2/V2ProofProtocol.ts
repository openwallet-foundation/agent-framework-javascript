import type { AgentContext } from '../../../../agent'
import type { AgentMessage } from '../../../../agent/AgentMessage'
import type { FeatureRegistry } from '../../../../agent/FeatureRegistry'
import type { InboundMessageContext } from '../../../../agent/models/InboundMessageContext'
import type { DependencyManager } from '../../../../plugins'
import type { ProblemReportMessage } from '../../../problem-reports'
import type {
  ExtractProofFormats,
  ProofFormat,
  ProofFormatCredentialForRequestPayload,
  ProofFormatPayload,
} from '../../formats'
import type { ProofFormatService } from '../../formats/ProofFormatService'
import type { ProofFormatSpec } from '../../models/ProofFormatSpec'
import type { ProofProtocol } from '../ProofProtocol'
import type {
  AcceptPresentationOptions,
  AcceptProofProposalOptions,
  AcceptProofRequestOptions,
  CreateProofProblemReportOptions,
  CreateProofProposalOptions,
  CreateProofRequestOptions,
  ProofFormatDataMessagePayload,
  GetCredentialsForRequestOptions,
  GetCredentialsForRequestReturn,
  GetProofFormatDataReturn,
  NegotiateProofProposalOptions,
  NegotiateProofRequestOptions,
  ProofProtocolMsgReturnType,
  SelectCredentialsForRequestOptions,
  SelectCredentialsForRequestReturn,
} from '../ProofProtocolOptions'

import { Protocol } from '../../../../agent/models'
import { CredoError } from '../../../../error'
import { DidCommMessageRepository, DidCommMessageRole } from '../../../../storage/didcomm'
import { uuid } from '../../../../utils/uuid'
import { AckStatus } from '../../../common'
import { ConnectionService } from '../../../connections'
import { ProofsModuleConfig } from '../../ProofsModuleConfig'
import { PresentationProblemReportReason } from '../../errors/PresentationProblemReportReason'
import { AutoAcceptProof, ProofRole, ProofState } from '../../models'
import { ProofExchangeRecord, ProofRepository } from '../../repository'
import { composeAutoAccept } from '../../utils'
import { BaseProofProtocol } from '../BaseProofProtocol'

import { ProofFormatCoordinator } from './ProofFormatCoordinator'
import { V2PresentationProblemReportError } from './errors'
import { V2PresentationAckHandler } from './handlers/V2PresentationAckHandler'
import { V2PresentationHandler } from './handlers/V2PresentationHandler'
import { V2PresentationProblemReportHandler } from './handlers/V2PresentationProblemReportHandler'
import { V2ProposePresentationHandler } from './handlers/V2ProposePresentationHandler'
import { V2RequestPresentationHandler } from './handlers/V2RequestPresentationHandler'
import { V2PresentationAckMessage, V2RequestPresentationMessage } from './messages'
import { V2PresentationMessage } from './messages/V2PresentationMessage'
import { V2PresentationProblemReportMessage } from './messages/V2PresentationProblemReportMessage'
import { V2ProposePresentationMessage } from './messages/V2ProposePresentationMessage'

export interface V2ProofProtocolConfig<ProofFormatServices extends ProofFormatService[]> {
  proofFormats: ProofFormatServices
}

export class V2ProofProtocol<PFs extends ProofFormatService[] = ProofFormatService[]>
  extends BaseProofProtocol
  implements ProofProtocol<PFs>
{
  private proofFormatCoordinator = new ProofFormatCoordinator<PFs>()
  private proofFormats: PFs

  public constructor({ proofFormats }: V2ProofProtocolConfig<PFs>) {
    super()

    this.proofFormats = proofFormats
  }

  /**
   * The version of the present proof protocol this service supports
   */
  public readonly version = 'v2' as const

  public register(dependencyManager: DependencyManager, featureRegistry: FeatureRegistry) {
    // Register message handlers for the Present Proof V2 Protocol
    dependencyManager.registerMessageHandlers([
      new V2ProposePresentationHandler(this),
      new V2RequestPresentationHandler(this),
      new V2PresentationHandler(this),
      new V2PresentationAckHandler(this),
      new V2PresentationProblemReportHandler(this),
    ])

    // Register Present Proof V2 in feature registry, with supported roles
    featureRegistry.register(
      new Protocol({
        id: 'https://didcomm.org/present-proof/2.0',
        roles: ['prover', 'verifier'],
      })
    )
  }

  public async createProposal(
    agentContext: AgentContext,
    {
      connectionRecord,
      proofFormats,
      comment,
      autoAcceptProof,
      goalCode,
      goal,
      parentThreadId,
    }: CreateProofProposalOptions<PFs>
  ): Promise<{ proofRecord: ProofExchangeRecord; message: AgentMessage }> {
    const proofRepository = agentContext.dependencyManager.resolve(ProofRepository)

    const formatServices = this.getFormatServices(proofFormats)
    if (formatServices.length === 0) {
      throw new CredoError(`Unable to create proposal. No supported formats`)
    }

    const proofRecord = new ProofExchangeRecord({
      connectionId: connectionRecord.id,
      threadId: uuid(),
      parentThreadId,
      state: ProofState.ProposalSent,
      role: ProofRole.Prover,
      protocolVersion: 'v2',
      autoAcceptProof,
    })

    const proposalMessage = await this.proofFormatCoordinator.createProposal(agentContext, {
      proofFormats,
      proofRecord,
      formatServices,
      comment,
      goalCode,
      goal,
    })

    agentContext.config.logger.debug('Save record and emit state change event')
    await proofRepository.save(agentContext, proofRecord)
    this.emitStateChangedEvent(agentContext, proofRecord, null)

    return {
      proofRecord,
      message: proposalMessage,
    }
  }

  /**
   * Method called by {@link V2ProposeCredentialHandler} on reception of a propose presentation message
   * We do the necessary processing here to accept the proposal and do the state change, emit event etc.
   * @param messageContext the inbound propose presentation message
   * @returns proof record appropriate for this incoming message (once accepted)
   */
  public async processProposal(
    messageContext: InboundMessageContext<V2ProposePresentationMessage>
  ): Promise<ProofExchangeRecord> {
    const { message: proposalMessage, connection, agentContext } = messageContext

    agentContext.config.logger.debug(`Processing presentation proposal with id ${proposalMessage.id}`)

    const proofRepository = agentContext.dependencyManager.resolve(ProofRepository)
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)
    const connectionService = agentContext.dependencyManager.resolve(ConnectionService)

    let proofRecord = await this.findByProperties(messageContext.agentContext, {
      threadId: proposalMessage.threadId,
      role: ProofRole.Verifier,
      connectionId: connection?.id,
    })

    const formatServices = this.getFormatServicesFromMessage(proposalMessage.formats)
    if (formatServices.length === 0) {
      throw new CredoError(`Unable to process proposal. No supported formats`)
    }

    // credential record already exists
    if (proofRecord) {
      const lastReceivedMessage = await didCommMessageRepository.findAgentMessage(messageContext.agentContext, {
        associatedRecordId: proofRecord.id,
        messageClass: V2ProposePresentationMessage,
        role: DidCommMessageRole.Receiver,
      })
      const lastSentMessage = await didCommMessageRepository.findAgentMessage(messageContext.agentContext, {
        associatedRecordId: proofRecord.id,
        messageClass: V2RequestPresentationMessage,
        role: DidCommMessageRole.Sender,
      })

      // Assert
      proofRecord.assertProtocolVersion('v2')
      proofRecord.assertState(ProofState.RequestSent)
      await connectionService.assertConnectionOrOutOfBandExchange(messageContext, {
        lastReceivedMessage,
        lastSentMessage,
        expectedConnectionId: proofRecord.connectionId,
      })

      await this.proofFormatCoordinator.processProposal(messageContext.agentContext, {
        proofRecord,
        formatServices,
        message: proposalMessage,
      })

      await this.updateState(messageContext.agentContext, proofRecord, ProofState.ProposalReceived)

      return proofRecord
    } else {
      // Assert
      await connectionService.assertConnectionOrOutOfBandExchange(messageContext)

      // No proof record exists with thread id
      proofRecord = new ProofExchangeRecord({
        connectionId: connection?.id,
        threadId: proposalMessage.threadId,
        state: ProofState.ProposalReceived,
        role: ProofRole.Verifier,
        protocolVersion: 'v2',
        parentThreadId: proposalMessage.thread?.parentThreadId,
      })

      await this.proofFormatCoordinator.processProposal(messageContext.agentContext, {
        proofRecord,
        formatServices,
        message: proposalMessage,
      })

      // Save record and emit event
      await proofRepository.save(messageContext.agentContext, proofRecord)
      this.emitStateChangedEvent(messageContext.agentContext, proofRecord, null)

      return proofRecord
    }
  }

  public async acceptProposal(
    agentContext: AgentContext,
    {
      proofRecord,
      proofFormats,
      autoAcceptProof,
      comment,
      goalCode,
      goal,
      willConfirm,
    }: AcceptProofProposalOptions<PFs>
  ): Promise<ProofProtocolMsgReturnType<V2RequestPresentationMessage>> {
    // Assert
    proofRecord.assertProtocolVersion('v2')
    proofRecord.assertState(ProofState.ProposalReceived)

    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    // Use empty proofFormats if not provided to denote all formats should be accepted
    let formatServices = this.getFormatServices(proofFormats ?? {})

    // if no format services could be extracted from the proofFormats
    // take all available format services from the proposal message
    if (formatServices.length === 0) {
      const proposalMessage = await didCommMessageRepository.getAgentMessage(agentContext, {
        associatedRecordId: proofRecord.id,
        messageClass: V2ProposePresentationMessage,
        role: DidCommMessageRole.Receiver,
      })

      formatServices = this.getFormatServicesFromMessage(proposalMessage.formats)
    }

    // If the format services list is still empty, throw an error as we don't support any
    // of the formats
    if (formatServices.length === 0) {
      throw new CredoError(`Unable to accept proposal. No supported formats provided as input or in proposal message`)
    }

    const requestMessage = await this.proofFormatCoordinator.acceptProposal(agentContext, {
      proofRecord,
      formatServices,
      comment,
      proofFormats,
      goalCode,
      goal,
      willConfirm,
      // Not supported at the moment
      presentMultiple: false,
    })

    proofRecord.autoAcceptProof = autoAcceptProof ?? proofRecord.autoAcceptProof
    await this.updateState(agentContext, proofRecord, ProofState.RequestSent)

    return { proofRecord, message: requestMessage }
  }

  /**
   * Negotiate a proof proposal as verifier (by sending a proof request message) to the connection
   * associated with the proof record.
   *
   * @param options configuration for the request see {@link NegotiateProofProposalOptions}
   * @returns Proof exchange record associated with the proof request
   *
   */
  public async negotiateProposal(
    agentContext: AgentContext,
    {
      proofRecord,
      proofFormats,
      autoAcceptProof,
      comment,
      goalCode,
      goal,
      willConfirm,
    }: NegotiateProofProposalOptions<PFs>
  ): Promise<ProofProtocolMsgReturnType<V2RequestPresentationMessage>> {
    // Assert
    proofRecord.assertProtocolVersion('v2')
    proofRecord.assertState(ProofState.ProposalReceived)

    if (!proofRecord.connectionId) {
      throw new CredoError(
        `No connectionId found for proof record '${proofRecord.id}'. Connection-less verification does not support negotiation.`
      )
    }

    const formatServices = this.getFormatServices(proofFormats)
    if (formatServices.length === 0) {
      throw new CredoError(`Unable to create request. No supported formats`)
    }

    const requestMessage = await this.proofFormatCoordinator.createRequest(agentContext, {
      formatServices,
      proofFormats,
      proofRecord,
      comment,
      goalCode,
      goal,
      willConfirm,
      // Not supported at the moment
      presentMultiple: false,
    })

    proofRecord.autoAcceptProof = autoAcceptProof ?? proofRecord.autoAcceptProof
    await this.updateState(agentContext, proofRecord, ProofState.RequestSent)

    return { proofRecord, message: requestMessage }
  }

  /**
   * Create a {@link V2RequestPresentationMessage} as beginning of protocol process.
   * @returns Object containing request message and associated credential record
   *
   */
  public async createRequest(
    agentContext: AgentContext,
    {
      proofFormats,
      autoAcceptProof,
      comment,
      connectionRecord,
      parentThreadId,
      goalCode,
      goal,
      willConfirm,
    }: CreateProofRequestOptions<PFs>
  ): Promise<ProofProtocolMsgReturnType<V2RequestPresentationMessage>> {
    const proofRepository = agentContext.dependencyManager.resolve(ProofRepository)

    const formatServices = this.getFormatServices(proofFormats)
    if (formatServices.length === 0) {
      throw new CredoError(`Unable to create request. No supported formats`)
    }

    const proofRecord = new ProofExchangeRecord({
      connectionId: connectionRecord?.id,
      threadId: uuid(),
      state: ProofState.RequestSent,
      role: ProofRole.Verifier,
      autoAcceptProof,
      protocolVersion: 'v2',
      parentThreadId,
    })

    const requestMessage = await this.proofFormatCoordinator.createRequest(agentContext, {
      formatServices,
      proofFormats,
      proofRecord,
      comment,
      goalCode,
      goal,
      willConfirm,
    })

    agentContext.config.logger.debug(
      `Saving record and emitting state changed for proof exchange record ${proofRecord.id}`
    )
    await proofRepository.save(agentContext, proofRecord)
    this.emitStateChangedEvent(agentContext, proofRecord, null)

    return { proofRecord, message: requestMessage }
  }

  /**
   * Process a received {@link V2RequestPresentationMessage}. This will not accept the proof request
   * or send a proof. It will only update the existing proof record with
   * the information from the proof request message. Use {@link createCredential}
   * after calling this method to create a proof.
   *z
   * @param messageContext The message context containing a v2 proof request message
   * @returns proof record associated with the proof request message
   *
   */
  public async processRequest(
    messageContext: InboundMessageContext<V2RequestPresentationMessage>
  ): Promise<ProofExchangeRecord> {
    const { message: requestMessage, connection, agentContext } = messageContext

    const proofRepository = agentContext.dependencyManager.resolve(ProofRepository)
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)
    const connectionService = agentContext.dependencyManager.resolve(ConnectionService)

    agentContext.config.logger.debug(`Processing proof request with id ${requestMessage.id}`)

    let proofRecord = await this.findByProperties(messageContext.agentContext, {
      threadId: requestMessage.threadId,
      role: ProofRole.Prover,
      connectionId: connection?.id,
    })

    const formatServices = this.getFormatServicesFromMessage(requestMessage.formats)
    if (formatServices.length === 0) {
      throw new CredoError(`Unable to process request. No supported formats`)
    }

    // proof record already exists
    if (proofRecord) {
      const lastSentMessage = await didCommMessageRepository.findAgentMessage(messageContext.agentContext, {
        associatedRecordId: proofRecord.id,
        messageClass: V2ProposePresentationMessage,
        role: DidCommMessageRole.Sender,
      })

      const lastReceivedMessage = await didCommMessageRepository.findAgentMessage(messageContext.agentContext, {
        associatedRecordId: proofRecord.id,
        messageClass: V2RequestPresentationMessage,
        role: DidCommMessageRole.Receiver,
      })

      // Assert
      proofRecord.assertProtocolVersion('v2')
      proofRecord.assertState(ProofState.ProposalSent)
      await connectionService.assertConnectionOrOutOfBandExchange(messageContext, {
        lastReceivedMessage,
        lastSentMessage,
        expectedConnectionId: proofRecord.connectionId,
      })

      await this.proofFormatCoordinator.processRequest(messageContext.agentContext, {
        proofRecord,
        formatServices,
        message: requestMessage,
      })

      await this.updateState(messageContext.agentContext, proofRecord, ProofState.RequestReceived)
      return proofRecord
    } else {
      // Assert
      await connectionService.assertConnectionOrOutOfBandExchange(messageContext)

      // No proof record exists with thread id
      agentContext.config.logger.debug('No proof record found for request, creating a new one')
      proofRecord = new ProofExchangeRecord({
        connectionId: connection?.id,
        threadId: requestMessage.threadId,
        state: ProofState.RequestReceived,
        role: ProofRole.Prover,
        protocolVersion: 'v2',
        parentThreadId: requestMessage.thread?.parentThreadId,
      })

      await this.proofFormatCoordinator.processRequest(messageContext.agentContext, {
        proofRecord,
        formatServices,
        message: requestMessage,
      })

      // Save in repository
      agentContext.config.logger.debug('Saving proof record and emit request-received event')
      await proofRepository.save(messageContext.agentContext, proofRecord)

      this.emitStateChangedEvent(messageContext.agentContext, proofRecord, null)
      return proofRecord
    }
  }

  public async acceptRequest(
    agentContext: AgentContext,
    { proofRecord, autoAcceptProof, comment, proofFormats, goalCode, goal }: AcceptProofRequestOptions<PFs>
  ) {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    // Assert
    proofRecord.assertProtocolVersion('v2')
    proofRecord.assertState(ProofState.RequestReceived)

    // Use empty proofFormats if not provided to denote all formats should be accepted
    let formatServices = this.getFormatServices(proofFormats ?? {})

    // if no format services could be extracted from the proofFormats
    // take all available format services from the request message
    if (formatServices.length === 0) {
      const requestMessage = await didCommMessageRepository.getAgentMessage(agentContext, {
        associatedRecordId: proofRecord.id,
        messageClass: V2RequestPresentationMessage,
        role: DidCommMessageRole.Receiver,
      })

      formatServices = this.getFormatServicesFromMessage(requestMessage.formats)
    }

    // If the format services list is still empty, throw an error as we don't support any
    // of the formats
    if (formatServices.length === 0) {
      throw new CredoError(`Unable to accept request. No supported formats provided as input or in request message`)
    }
    const message = await this.proofFormatCoordinator.acceptRequest(agentContext, {
      proofRecord,
      formatServices,
      comment,
      proofFormats,
      goalCode,
      goal,
      // Sending multiple presentation messages not supported at the moment
      lastPresentation: true,
    })

    proofRecord.autoAcceptProof = autoAcceptProof ?? proofRecord.autoAcceptProof
    await this.updateState(agentContext, proofRecord, ProofState.PresentationSent)

    return { proofRecord, message }
  }

  /**
   * Create a {@link V2ProposePresentationMessage} as response to a received credential request.
   * To create a proposal not bound to an existing proof exchange, use {@link createProposal}.
   *
   * @param options configuration to use for the proposal
   * @returns Object containing proposal message and associated proof record
   *
   */
  public async negotiateRequest(
    agentContext: AgentContext,
    { proofRecord, proofFormats, autoAcceptProof, comment, goalCode, goal }: NegotiateProofRequestOptions<PFs>
  ): Promise<ProofProtocolMsgReturnType<V2ProposePresentationMessage>> {
    // Assert
    proofRecord.assertProtocolVersion('v2')
    proofRecord.assertState(ProofState.RequestReceived)

    if (!proofRecord.connectionId) {
      throw new CredoError(
        `No connectionId found for proof record '${proofRecord.id}'. Connection-less verification does not support negotiation.`
      )
    }

    const formatServices = this.getFormatServices(proofFormats)
    if (formatServices.length === 0) {
      throw new CredoError(`Unable to create proposal. No supported formats`)
    }

    const proposalMessage = await this.proofFormatCoordinator.createProposal(agentContext, {
      formatServices,
      proofFormats,
      proofRecord,
      comment,
      goalCode,
      goal,
    })

    proofRecord.autoAcceptProof = autoAcceptProof ?? proofRecord.autoAcceptProof
    await this.updateState(agentContext, proofRecord, ProofState.ProposalSent)

    return { proofRecord, message: proposalMessage }
  }

  public async getCredentialsForRequest(
    agentContext: AgentContext,
    { proofRecord, proofFormats }: GetCredentialsForRequestOptions<PFs>
  ): Promise<GetCredentialsForRequestReturn<PFs>> {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    // Assert
    proofRecord.assertProtocolVersion('v2')
    proofRecord.assertState(ProofState.RequestReceived)

    // Use empty proofFormats if not provided to denote all formats should be accepted
    let formatServices = this.getFormatServices(proofFormats ?? {})

    // if no format services could be extracted from the proofFormats
    // take all available format services from the request message
    if (formatServices.length === 0) {
      const requestMessage = await didCommMessageRepository.getAgentMessage(agentContext, {
        associatedRecordId: proofRecord.id,
        messageClass: V2RequestPresentationMessage,
        role: DidCommMessageRole.Receiver,
      })

      formatServices = this.getFormatServicesFromMessage(requestMessage.formats)
    }

    // If the format services list is still empty, throw an error as we don't support any
    // of the formats
    if (formatServices.length === 0) {
      throw new CredoError(
        `Unable to get credentials for request. No supported formats provided as input or in request message`
      )
    }

    const result = await this.proofFormatCoordinator.getCredentialsForRequest(agentContext, {
      formatServices,
      proofFormats,
      proofRecord,
    })

    return {
      proofFormats: result,
    }
  }

  public async selectCredentialsForRequest(
    agentContext: AgentContext,
    { proofRecord, proofFormats }: SelectCredentialsForRequestOptions<PFs>
  ): Promise<SelectCredentialsForRequestReturn<PFs>> {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    // Assert
    proofRecord.assertProtocolVersion('v2')
    proofRecord.assertState(ProofState.RequestReceived)

    // Use empty proofFormats if not provided to denote all formats should be accepted
    let formatServices = this.getFormatServices(proofFormats ?? {})

    // if no format services could be extracted from the proofFormats
    // take all available format services from the request message
    if (formatServices.length === 0) {
      const requestMessage = await didCommMessageRepository.getAgentMessage(agentContext, {
        associatedRecordId: proofRecord.id,
        messageClass: V2RequestPresentationMessage,
        role: DidCommMessageRole.Receiver,
      })

      formatServices = this.getFormatServicesFromMessage(requestMessage.formats)
    }

    // If the format services list is still empty, throw an error as we don't support any
    // of the formats
    if (formatServices.length === 0) {
      throw new CredoError(
        `Unable to get credentials for request. No supported formats provided as input or in request message`
      )
    }

    const result = await this.proofFormatCoordinator.selectCredentialsForRequest(agentContext, {
      formatServices,
      proofFormats,
      proofRecord,
    })

    return {
      proofFormats: result,
    }
  }

  public async processPresentation(
    messageContext: InboundMessageContext<V2PresentationMessage>
  ): Promise<ProofExchangeRecord> {
    const { message: presentationMessage, connection, agentContext } = messageContext

    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)
    const connectionService = agentContext.dependencyManager.resolve(ConnectionService)

    agentContext.config.logger.debug(`Processing presentation with id ${presentationMessage.id}`)

    const proofRecord = await this.getByProperties(messageContext.agentContext, {
      threadId: presentationMessage.threadId,
      role: ProofRole.Verifier,
    })

    const lastSentMessage = await didCommMessageRepository.getAgentMessage(messageContext.agentContext, {
      associatedRecordId: proofRecord.id,
      messageClass: V2RequestPresentationMessage,
      role: DidCommMessageRole.Sender,
    })

    const lastReceivedMessage = await didCommMessageRepository.findAgentMessage(messageContext.agentContext, {
      associatedRecordId: proofRecord.id,
      messageClass: V2ProposePresentationMessage,
      role: DidCommMessageRole.Receiver,
    })

    // Assert
    proofRecord.assertProtocolVersion('v2')
    proofRecord.assertState(ProofState.RequestSent)
    await connectionService.assertConnectionOrOutOfBandExchange(messageContext, {
      lastReceivedMessage,
      lastSentMessage,
      expectedConnectionId: proofRecord.connectionId,
    })

    // This makes sure that the sender of the incoming message is authorized to do so.
    if (!proofRecord.connectionId) {
      await connectionService.matchIncomingMessageToRequestMessageInOutOfBandExchange(messageContext, {
        expectedConnectionId: proofRecord.connectionId,
      })

      proofRecord.connectionId = connection?.id
    }

    const formatServices = this.getFormatServicesFromMessage(presentationMessage.formats)
    // Abandon if no supported formats
    if (formatServices.length === 0) {
      proofRecord.errorMessage = `Unable to process presentation. No supported formats`
      await this.updateState(messageContext.agentContext, proofRecord, ProofState.Abandoned)
      throw new V2PresentationProblemReportError(proofRecord.errorMessage, {
        problemCode: PresentationProblemReportReason.Abandoned,
      })
    }

    const result = await this.proofFormatCoordinator.processPresentation(messageContext.agentContext, {
      proofRecord,
      formatServices,
      requestMessage: lastSentMessage,
      message: presentationMessage,
    })

    proofRecord.isVerified = result.isValid
    if (result.isValid) {
      await this.updateState(messageContext.agentContext, proofRecord, ProofState.PresentationReceived)
    } else {
      proofRecord.errorMessage = result.message
      proofRecord.isVerified = false
      await this.updateState(messageContext.agentContext, proofRecord, ProofState.Abandoned)
      throw new V2PresentationProblemReportError(proofRecord.errorMessage, {
        problemCode: PresentationProblemReportReason.Abandoned,
      })
    }

    return proofRecord
  }

  public async acceptPresentation(
    agentContext: AgentContext,
    { proofRecord }: AcceptPresentationOptions
  ): Promise<ProofProtocolMsgReturnType<V2PresentationAckMessage>> {
    proofRecord.assertProtocolVersion('v2')
    proofRecord.assertState(ProofState.PresentationReceived)

    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    // assert we've received the final presentation
    const presentation = await didCommMessageRepository.getAgentMessage(agentContext, {
      associatedRecordId: proofRecord.id,
      messageClass: V2PresentationMessage,
      role: DidCommMessageRole.Receiver,
    })

    if (!presentation.lastPresentation) {
      throw new CredoError(
        `Trying to send an ack message while presentation with id ${presentation.id} indicates this is not the last presentation (presentation.last_presentation is set to false)`
      )
    }

    const message = new V2PresentationAckMessage({
      threadId: proofRecord.threadId,
      status: AckStatus.OK,
    })

    message.setThread({
      threadId: proofRecord.threadId,
      parentThreadId: proofRecord.parentThreadId,
    })

    await this.updateState(agentContext, proofRecord, ProofState.Done)

    return {
      message,
      proofRecord,
    }
  }

  public async processAck(
    messageContext: InboundMessageContext<V2PresentationAckMessage>
  ): Promise<ProofExchangeRecord> {
    const { message: ackMessage, connection, agentContext } = messageContext

    agentContext.config.logger.debug(`Processing proof ack with id ${ackMessage.id}`)

    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)
    const connectionService = agentContext.dependencyManager.resolve(ConnectionService)

    const proofRecord = await this.getByProperties(messageContext.agentContext, {
      threadId: ackMessage.threadId,
      role: ProofRole.Prover,
      connectionId: connection?.id,
    })
    proofRecord.connectionId = connection?.id

    const lastReceivedMessage = await didCommMessageRepository.getAgentMessage(messageContext.agentContext, {
      associatedRecordId: proofRecord.id,
      messageClass: V2RequestPresentationMessage,
      role: DidCommMessageRole.Receiver,
    })

    const lastSentMessage = await didCommMessageRepository.getAgentMessage(messageContext.agentContext, {
      associatedRecordId: proofRecord.id,
      messageClass: V2PresentationMessage,
      role: DidCommMessageRole.Sender,
    })

    // Assert
    proofRecord.assertProtocolVersion('v2')
    proofRecord.assertState(ProofState.PresentationSent)
    await connectionService.assertConnectionOrOutOfBandExchange(messageContext, {
      lastReceivedMessage,
      lastSentMessage,
      expectedConnectionId: proofRecord.connectionId,
    })

    // Update record
    await this.updateState(messageContext.agentContext, proofRecord, ProofState.Done)

    return proofRecord
  }

  public async createProblemReport(
    _agentContext: AgentContext,
    { description, proofRecord }: CreateProofProblemReportOptions
  ): Promise<ProofProtocolMsgReturnType<ProblemReportMessage>> {
    const message = new V2PresentationProblemReportMessage({
      description: {
        en: description,
        code: PresentationProblemReportReason.Abandoned,
      },
    })

    message.setThread({
      threadId: proofRecord.threadId,
      parentThreadId: proofRecord.parentThreadId,
    })

    return {
      proofRecord,
      message,
    }
  }

  public async shouldAutoRespondToProposal(
    agentContext: AgentContext,
    options: {
      proofRecord: ProofExchangeRecord
      proposalMessage: V2ProposePresentationMessage
    }
  ): Promise<boolean> {
    const { proofRecord, proposalMessage } = options
    const proofsModuleConfig = agentContext.dependencyManager.resolve(ProofsModuleConfig)

    const autoAccept = composeAutoAccept(proofRecord.autoAcceptProof, proofsModuleConfig.autoAcceptProofs)

    // Handle always / never cases
    if (autoAccept === AutoAcceptProof.Always) return true
    if (autoAccept === AutoAcceptProof.Never) return false

    const requestMessage = await this.findRequestMessage(agentContext, proofRecord.id)
    if (!requestMessage) return false

    // NOTE: we take the formats from the requestMessage so we always check all services that we last sent
    // Otherwise we'll only check the formats from the proposal, which could be different from the formats
    // we use.
    const formatServices = this.getFormatServicesFromMessage(requestMessage.formats)

    for (const formatService of formatServices) {
      const requestAttachment = this.proofFormatCoordinator.getAttachmentForService(
        formatService,
        requestMessage.formats,
        requestMessage.requestAttachments
      )

      const proposalAttachment = this.proofFormatCoordinator.getAttachmentForService(
        formatService,
        proposalMessage.formats,
        proposalMessage.proposalAttachments
      )

      const shouldAutoRespondToFormat = await formatService.shouldAutoRespondToProposal(agentContext, {
        proofRecord,
        requestAttachment,
        proposalAttachment,
      })
      // If any of the formats return false, we should not auto accept
      if (!shouldAutoRespondToFormat) return false
    }

    return true
  }

  public async shouldAutoRespondToRequest(
    agentContext: AgentContext,
    options: {
      proofRecord: ProofExchangeRecord
      requestMessage: V2RequestPresentationMessage
    }
  ): Promise<boolean> {
    const { proofRecord, requestMessage } = options
    const proofsModuleConfig = agentContext.dependencyManager.resolve(ProofsModuleConfig)

    const autoAccept = composeAutoAccept(proofRecord.autoAcceptProof, proofsModuleConfig.autoAcceptProofs)

    // Handle always / never cases
    if (autoAccept === AutoAcceptProof.Always) return true
    if (autoAccept === AutoAcceptProof.Never) return false

    const proposalMessage = await this.findProposalMessage(agentContext, proofRecord.id)
    if (!proposalMessage) return false

    // NOTE: we take the formats from the proposalMessage so we always check all services that we last sent
    // Otherwise we'll only check the formats from the request, which could be different from the formats
    // we use.
    const formatServices = this.getFormatServicesFromMessage(proposalMessage.formats)

    for (const formatService of formatServices) {
      const proposalAttachment = this.proofFormatCoordinator.getAttachmentForService(
        formatService,
        proposalMessage.formats,
        proposalMessage.proposalAttachments
      )

      const requestAttachment = this.proofFormatCoordinator.getAttachmentForService(
        formatService,
        requestMessage.formats,
        requestMessage.requestAttachments
      )

      const shouldAutoRespondToFormat = await formatService.shouldAutoRespondToRequest(agentContext, {
        proofRecord,
        requestAttachment,
        proposalAttachment,
      })

      // If any of the formats return false, we should not auto accept
      if (!shouldAutoRespondToFormat) return false
    }

    return true
  }

  public async shouldAutoRespondToPresentation(
    agentContext: AgentContext,
    options: { proofRecord: ProofExchangeRecord; presentationMessage: V2PresentationMessage }
  ): Promise<boolean> {
    const { proofRecord, presentationMessage } = options
    const proofsModuleConfig = agentContext.dependencyManager.resolve(ProofsModuleConfig)

    // If this isn't the last presentation yet, we should not auto accept
    if (!presentationMessage.lastPresentation) return false

    const autoAccept = composeAutoAccept(proofRecord.autoAcceptProof, proofsModuleConfig.autoAcceptProofs)

    // Handle always / never cases
    if (autoAccept === AutoAcceptProof.Always) return true
    if (autoAccept === AutoAcceptProof.Never) return false

    const proposalMessage = await this.findProposalMessage(agentContext, proofRecord.id)

    const requestMessage = await this.findRequestMessage(agentContext, proofRecord.id)
    if (!requestMessage) return false
    if (!requestMessage.willConfirm) return false

    // NOTE: we take the formats from the requestMessage so we always check all services that we last sent
    // Otherwise we'll only check the formats from the credential, which could be different from the formats
    // we use.
    const formatServices = this.getFormatServicesFromMessage(requestMessage.formats)

    for (const formatService of formatServices) {
      const proposalAttachment = proposalMessage
        ? this.proofFormatCoordinator.getAttachmentForService(
            formatService,
            proposalMessage.formats,
            proposalMessage.proposalAttachments
          )
        : undefined

      const requestAttachment = this.proofFormatCoordinator.getAttachmentForService(
        formatService,
        requestMessage.formats,
        requestMessage.requestAttachments
      )

      const presentationAttachment = this.proofFormatCoordinator.getAttachmentForService(
        formatService,
        presentationMessage.formats,
        presentationMessage.presentationAttachments
      )

      const shouldAutoRespondToFormat = await formatService.shouldAutoRespondToPresentation(agentContext, {
        proofRecord,
        presentationAttachment,
        requestAttachment,
        proposalAttachment,
      })

      // If any of the formats return false, we should not auto accept
      if (!shouldAutoRespondToFormat) return false
    }
    return true
  }

  public async findRequestMessage(
    agentContext: AgentContext,
    proofRecordId: string
  ): Promise<V2RequestPresentationMessage | null> {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    return await didCommMessageRepository.findAgentMessage(agentContext, {
      associatedRecordId: proofRecordId,
      messageClass: V2RequestPresentationMessage,
    })
  }

  public async findPresentationMessage(
    agentContext: AgentContext,
    proofRecordId: string
  ): Promise<V2PresentationMessage | null> {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    return await didCommMessageRepository.findAgentMessage(agentContext, {
      associatedRecordId: proofRecordId,
      messageClass: V2PresentationMessage,
    })
  }

  public async findProposalMessage(
    agentContext: AgentContext,
    proofRecordId: string
  ): Promise<V2ProposePresentationMessage | null> {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    return await didCommMessageRepository.findAgentMessage(agentContext, {
      associatedRecordId: proofRecordId,
      messageClass: V2ProposePresentationMessage,
    })
  }

  public async getFormatData(agentContext: AgentContext, proofRecordId: string): Promise<GetProofFormatDataReturn> {
    // TODO: we could looking at fetching all record using a single query and then filtering based on the type of the message.
    const [proposalMessage, requestMessage, presentationMessage] = await Promise.all([
      this.findProposalMessage(agentContext, proofRecordId),
      this.findRequestMessage(agentContext, proofRecordId),
      this.findPresentationMessage(agentContext, proofRecordId),
    ])

    // Create object with the keys and the message formats/attachments. We can then loop over this in a generic
    // way so we don't have to add the same operation code four times
    const messages = {
      proposal: [proposalMessage?.formats, proposalMessage?.proposalAttachments],
      request: [requestMessage?.formats, requestMessage?.requestAttachments],
      presentation: [presentationMessage?.formats, presentationMessage?.presentationAttachments],
    } as const

    const formatData: GetProofFormatDataReturn = {}

    // We loop through all of the message keys as defined above
    for (const [messageKey, [formats, attachments]] of Object.entries(messages)) {
      // Message can be undefined, so we continue if it is not defined
      if (!formats || !attachments) continue

      // Find all format services associated with the message
      const formatServices = this.getFormatServicesFromMessage(formats)

      const messageFormatData: ProofFormatDataMessagePayload = {}

      // Loop through all of the format services, for each we will extract the attachment data and assign this to the object
      // using the unique format key (e.g. indy)
      for (const formatService of formatServices) {
        const attachment = this.proofFormatCoordinator.getAttachmentForService(formatService, formats, attachments)
        messageFormatData[formatService.formatKey] = attachment.getDataAsJson()
      }

      formatData[messageKey as keyof GetProofFormatDataReturn] = messageFormatData
    }

    return formatData
  }

  /**
   * Get all the format service objects for a given proof format from an incoming message
   * @param messageFormats the format objects containing the format name (eg indy)
   * @return the proof format service objects in an array - derived from format object keys
   */
  private getFormatServicesFromMessage(messageFormats: ProofFormatSpec[]): ProofFormatService[] {
    const formatServices = new Set<ProofFormatService>()

    for (const msg of messageFormats) {
      const service = this.getFormatServiceForFormat(msg.format)
      if (service) formatServices.add(service)
    }

    return Array.from(formatServices)
  }

  /**
   * Get all the format service objects for a given proof format
   * @param proofFormats the format object containing various optional parameters
   * @return the proof format service objects in an array - derived from format object keys
   */
  private getFormatServices<M extends keyof ProofFormat['proofFormats']>(
    proofFormats: M extends 'selectCredentialsForRequest' | 'getCredentialsForRequest'
      ? ProofFormatCredentialForRequestPayload<ExtractProofFormats<PFs>, M, 'input'>
      : ProofFormatPayload<ExtractProofFormats<PFs>, M>
  ): ProofFormatService[] {
    const formats = new Set<ProofFormatService>()

    for (const formatKey of Object.keys(proofFormats)) {
      const formatService = this.getFormatServiceForFormatKey(formatKey)

      if (formatService) formats.add(formatService)
    }

    return Array.from(formats)
  }

  private getFormatServiceForFormatKey(formatKey: string): ProofFormatService | null {
    const formatService = this.proofFormats.find((proofFormats) => proofFormats.formatKey === formatKey)

    return formatService ?? null
  }

  private getFormatServiceForFormat(format: string): ProofFormatService | null {
    const formatService = this.proofFormats.find((proofFormats) => proofFormats.supportsFormat(format))

    return formatService ?? null
  }
}
