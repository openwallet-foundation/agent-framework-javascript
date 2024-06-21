import type { LegacyIndyProofFormatService } from '../../../formats'
import type {
  ProofProtocol,
  DependencyManager,
  FeatureRegistry,
  AgentContext,
  ProofProtocolOptions,
  InboundMessageContext,
  AgentMessage,
  ProblemReportMessage,
  GetProofFormatDataReturn,
  ProofFormat,
} from '@credo-ts/core'

import {
  ProofRole,
  BaseProofProtocol,
  Protocol,
  ProofRepository,
  DidCommMessageRepository,
  CredoError,
  MessageValidator,
  ProofExchangeRecord,
  ProofState,
  DidCommMessageRole,
  ConnectionService,
  Attachment,
  JsonTransformer,
  PresentationProblemReportReason,
  AckStatus,
  ProofsModuleConfig,
  AutoAcceptProof,
  JsonEncoder,
  utils,
} from '@credo-ts/core'

import { composeProofAutoAccept, createRequestFromPreview } from '../../../utils'

import { V1PresentationProblemReportError } from './errors'
import {
  V1PresentationAckHandler,
  V1PresentationHandler,
  V1PresentationProblemReportHandler,
  V1ProposePresentationHandler,
  V1RequestPresentationHandler,
} from './handlers'
import {
  INDY_PROOF_ATTACHMENT_ID,
  INDY_PROOF_REQUEST_ATTACHMENT_ID,
  V1PresentationAckMessage,
  V1PresentationMessage,
  V1ProposePresentationMessage,
  V1RequestPresentationMessage,
} from './messages'
import { V1PresentationProblemReportMessage } from './messages/V1PresentationProblemReportMessage'
import { V1PresentationPreview } from './models/V1PresentationPreview'

export interface V1ProofProtocolConfig {
  indyProofFormat: LegacyIndyProofFormatService
}

export class V1ProofProtocol extends BaseProofProtocol implements ProofProtocol<[LegacyIndyProofFormatService]> {
  private indyProofFormat: LegacyIndyProofFormatService

  public constructor({ indyProofFormat }: V1ProofProtocolConfig) {
    super()

    // TODO: just create a new instance of LegacyIndyProofFormatService here so it makes the setup easier
    this.indyProofFormat = indyProofFormat
  }

  /**
   * The version of the present proof protocol this protocol supports
   */
  public readonly version = 'v1' as const

  /**
   * Registers the protocol implementation (handlers, feature registry) on the agent.
   */
  public register(dependencyManager: DependencyManager, featureRegistry: FeatureRegistry) {
    // Register message handlers for the Issue Credential V1 Protocol
    dependencyManager.registerMessageHandlers([
      new V1ProposePresentationHandler(this),
      new V1RequestPresentationHandler(this),
      new V1PresentationHandler(this),
      new V1PresentationAckHandler(this),
      new V1PresentationProblemReportHandler(this),
    ])

    // Register Present Proof V1 in feature registry, with supported roles
    featureRegistry.register(
      new Protocol({
        id: 'https://didcomm.org/present-proof/1.0',
        roles: ['prover', 'verifier'],
      })
    )
  }

  public async createProposal(
    agentContext: AgentContext,
    {
      proofFormats,
      connectionRecord,
      comment,
      parentThreadId,
      autoAcceptProof,
    }: ProofProtocolOptions.CreateProofProposalOptions<[LegacyIndyProofFormatService]>
  ): Promise<ProofProtocolOptions.ProofProtocolMsgReturnType<V1ProposePresentationMessage>> {
    this.assertOnlyIndyFormat(proofFormats)

    const proofRepository = agentContext.dependencyManager.resolve(ProofRepository)
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    if (!proofFormats.indy) {
      throw new CredoError('Missing indy proof format in v1 create proposal call.')
    }

    const presentationProposal = new V1PresentationPreview({
      attributes: proofFormats.indy?.attributes,
      predicates: proofFormats.indy?.predicates,
    })

    // validate input data from user
    MessageValidator.validateSync(presentationProposal)

    // Create message
    const message = new V1ProposePresentationMessage({
      presentationProposal,
      comment,
    })

    if (parentThreadId)
      message.setThread({
        parentThreadId,
      })

    // Create record
    const proofRecord = new ProofExchangeRecord({
      connectionId: connectionRecord.id,
      threadId: message.threadId,
      parentThreadId: message.thread?.parentThreadId,
      state: ProofState.ProposalSent,
      role: ProofRole.Prover,
      autoAcceptProof,
      protocolVersion: 'v1',
    })

    await didCommMessageRepository.saveAgentMessage(agentContext, {
      agentMessage: message,
      associatedRecordId: proofRecord.id,
      role: DidCommMessageRole.Sender,
    })

    await proofRepository.save(agentContext, proofRecord)
    this.emitStateChangedEvent(agentContext, proofRecord, null)

    return { proofRecord, message }
  }

  public async processProposal(
    messageContext: InboundMessageContext<V1ProposePresentationMessage>
  ): Promise<ProofExchangeRecord> {
    const { message: proposalMessage, connection, agentContext } = messageContext

    const proofRepository = agentContext.dependencyManager.resolve(ProofRepository)
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    // TODO: with this method, we should update the credential protocol to use the ConnectionApi, so it
    // only depends on the public api, rather than the internal API (this helps with breaking changes)
    const connectionService = agentContext.dependencyManager.resolve(ConnectionService)

    agentContext.config.logger.debug(`Processing presentation proposal with message id ${proposalMessage.id}`)

    let proofRecord = await this.findByProperties(agentContext, {
      threadId: proposalMessage.threadId,
      role: ProofRole.Verifier,
      connectionId: connection?.id,
    })

    // Proof record already exists, this is a response to an earlier message sent by us
    if (proofRecord) {
      agentContext.config.logger.debug('Proof record already exists for incoming proposal')

      // Assert
      proofRecord.assertState(ProofState.RequestSent)
      proofRecord.assertProtocolVersion('v1')

      const lastReceivedMessage = await didCommMessageRepository.findAgentMessage(agentContext, {
        associatedRecordId: proofRecord.id,
        messageClass: V1ProposePresentationMessage,
        role: DidCommMessageRole.Receiver,
      })
      const lastSentMessage = await didCommMessageRepository.getAgentMessage(agentContext, {
        associatedRecordId: proofRecord.id,
        messageClass: V1RequestPresentationMessage,
        role: DidCommMessageRole.Sender,
      })
      await connectionService.assertConnectionOrOutOfBandExchange(messageContext, {
        lastReceivedMessage,
        lastSentMessage,
        expectedConnectionId: proofRecord.connectionId,
      })

      // Update record
      await didCommMessageRepository.saveOrUpdateAgentMessage(agentContext, {
        agentMessage: proposalMessage,
        associatedRecordId: proofRecord.id,
        role: DidCommMessageRole.Receiver,
      })
      await this.updateState(agentContext, proofRecord, ProofState.ProposalReceived)
    } else {
      agentContext.config.logger.debug('Proof record does not exist yet for incoming proposal')
      // Assert
      await connectionService.assertConnectionOrOutOfBandExchange(messageContext)

      // No proof record exists with thread id
      proofRecord = new ProofExchangeRecord({
        connectionId: connection?.id,
        threadId: proposalMessage.threadId,
        parentThreadId: proposalMessage.thread?.parentThreadId,
        state: ProofState.ProposalReceived,
        role: ProofRole.Verifier,
        protocolVersion: 'v1',
      })

      await didCommMessageRepository.saveOrUpdateAgentMessage(agentContext, {
        agentMessage: proposalMessage,
        associatedRecordId: proofRecord.id,
        role: DidCommMessageRole.Receiver,
      })

      // Save record
      await proofRepository.save(agentContext, proofRecord)
      this.emitStateChangedEvent(agentContext, proofRecord, null)
    }

    return proofRecord
  }

  public async acceptProposal(
    agentContext: AgentContext,
    {
      proofRecord,
      proofFormats,
      comment,
      autoAcceptProof,
    }: ProofProtocolOptions.AcceptProofProposalOptions<[LegacyIndyProofFormatService]>
  ): Promise<ProofProtocolOptions.ProofProtocolMsgReturnType<V1RequestPresentationMessage>> {
    // Assert
    proofRecord.assertProtocolVersion('v1')
    proofRecord.assertState(ProofState.ProposalReceived)
    if (proofFormats) this.assertOnlyIndyFormat(proofFormats)

    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    const proposalMessage = await didCommMessageRepository.getAgentMessage(agentContext, {
      associatedRecordId: proofRecord.id,
      messageClass: V1ProposePresentationMessage,
      role: DidCommMessageRole.Receiver,
    })

    const indyFormat = proofFormats?.indy

    // Create a proof request from the preview, so we can let the messages
    // be handled using the indy proof format which supports RFC0592
    const requestFromPreview = createRequestFromPreview({
      attributes: proposalMessage.presentationProposal.attributes,
      predicates: proposalMessage.presentationProposal.predicates,
      name: indyFormat?.name ?? 'Proof Request',
      version: indyFormat?.version ?? '1.0',
      nonce: await agentContext.wallet.generateNonce(),
    })

    const proposalAttachment = new Attachment({
      data: {
        json: JsonTransformer.toJSON(requestFromPreview),
      },
    })

    // Create message
    const { attachment } = await this.indyProofFormat.acceptProposal(agentContext, {
      attachmentId: INDY_PROOF_REQUEST_ATTACHMENT_ID,
      proofRecord,
      proposalAttachment,
    })

    const requestPresentationMessage = new V1RequestPresentationMessage({
      comment,
      requestAttachments: [attachment],
    })

    requestPresentationMessage.setThread({
      threadId: proofRecord.threadId,
      parentThreadId: proofRecord.parentThreadId,
    })

    await didCommMessageRepository.saveOrUpdateAgentMessage(agentContext, {
      agentMessage: requestPresentationMessage,
      associatedRecordId: proofRecord.id,
      role: DidCommMessageRole.Sender,
    })

    // Update record
    proofRecord.autoAcceptProof = autoAcceptProof ?? proofRecord.autoAcceptProof
    await this.updateState(agentContext, proofRecord, ProofState.RequestSent)

    return { message: requestPresentationMessage, proofRecord }
  }

  public async negotiateProposal(
    agentContext: AgentContext,
    {
      proofFormats,
      proofRecord,
      comment,
      autoAcceptProof,
    }: ProofProtocolOptions.NegotiateProofProposalOptions<[LegacyIndyProofFormatService]>
  ): Promise<ProofProtocolOptions.ProofProtocolMsgReturnType<AgentMessage>> {
    // Assert
    proofRecord.assertProtocolVersion('v1')
    proofRecord.assertState(ProofState.ProposalReceived)
    this.assertOnlyIndyFormat(proofFormats)

    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    // Create message
    const { attachment } = await this.indyProofFormat.createRequest(agentContext, {
      attachmentId: INDY_PROOF_REQUEST_ATTACHMENT_ID,
      proofFormats,
      proofRecord,
    })

    const requestPresentationMessage = new V1RequestPresentationMessage({
      comment,
      requestAttachments: [attachment],
    })
    requestPresentationMessage.setThread({
      threadId: proofRecord.threadId,
      parentThreadId: proofRecord.parentThreadId,
    })

    await didCommMessageRepository.saveOrUpdateAgentMessage(agentContext, {
      agentMessage: requestPresentationMessage,
      associatedRecordId: proofRecord.id,
      role: DidCommMessageRole.Sender,
    })

    proofRecord.autoAcceptProof = autoAcceptProof ?? proofRecord.autoAcceptProof
    await this.updateState(agentContext, proofRecord, ProofState.RequestSent)

    return { message: requestPresentationMessage, proofRecord }
  }

  public async createRequest(
    agentContext: AgentContext,
    {
      proofFormats,
      connectionRecord,
      comment,
      parentThreadId,
      autoAcceptProof,
    }: ProofProtocolOptions.CreateProofRequestOptions<[LegacyIndyProofFormatService]>
  ): Promise<ProofProtocolOptions.ProofProtocolMsgReturnType<AgentMessage>> {
    this.assertOnlyIndyFormat(proofFormats)

    const proofRepository = agentContext.dependencyManager.resolve(ProofRepository)
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    if (!proofFormats.indy) {
      throw new CredoError('Missing indy proof request data for v1 create request')
    }

    // Create record
    const proofRecord = new ProofExchangeRecord({
      connectionId: connectionRecord?.id,
      threadId: utils.uuid(),
      parentThreadId,
      state: ProofState.RequestSent,
      role: ProofRole.Verifier,
      autoAcceptProof,
      protocolVersion: 'v1',
    })

    // Create message
    const { attachment } = await this.indyProofFormat.createRequest(agentContext, {
      attachmentId: INDY_PROOF_REQUEST_ATTACHMENT_ID,
      proofFormats,
      proofRecord,
    })

    // Construct request message
    const message = new V1RequestPresentationMessage({
      id: proofRecord.threadId,
      comment,
      requestAttachments: [attachment],
    })

    message.setThread({
      threadId: proofRecord.threadId,
      parentThreadId: proofRecord.parentThreadId,
    })

    await didCommMessageRepository.saveAgentMessage(agentContext, {
      agentMessage: message,
      associatedRecordId: proofRecord.id,
      role: DidCommMessageRole.Sender,
    })

    await proofRepository.save(agentContext, proofRecord)
    this.emitStateChangedEvent(agentContext, proofRecord, null)

    return { message, proofRecord }
  }

  public async processRequest(
    messageContext: InboundMessageContext<V1RequestPresentationMessage>
  ): Promise<ProofExchangeRecord> {
    const { message: proofRequestMessage, connection, agentContext } = messageContext

    const proofRepository = agentContext.dependencyManager.resolve(ProofRepository)
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    // TODO: with this method, we should update the credential protocol to use the ConnectionApi, so it
    // only depends on the public api, rather than the internal API (this helps with breaking changes)
    const connectionService = agentContext.dependencyManager.resolve(ConnectionService)

    agentContext.config.logger.debug(`Processing presentation request with id ${proofRequestMessage.id}`)

    let proofRecord = await this.findByProperties(agentContext, {
      threadId: proofRequestMessage.threadId,
      role: ProofRole.Prover,
      connectionId: connection?.id,
    })

    const requestAttachment = proofRequestMessage.getRequestAttachmentById(INDY_PROOF_REQUEST_ATTACHMENT_ID)
    if (!requestAttachment) {
      throw new CredoError(`Indy attachment with id ${INDY_PROOF_REQUEST_ATTACHMENT_ID} not found in request message`)
    }

    // proof record already exists, this means we are the message is sent as reply to a proposal we sent
    if (proofRecord) {
      const lastReceivedMessage = await didCommMessageRepository.findAgentMessage(agentContext, {
        associatedRecordId: proofRecord.id,
        messageClass: V1RequestPresentationMessage,
        role: DidCommMessageRole.Receiver,
      })
      const lastSentMessage = await didCommMessageRepository.getAgentMessage(agentContext, {
        associatedRecordId: proofRecord.id,
        messageClass: V1ProposePresentationMessage,
        role: DidCommMessageRole.Sender,
      })

      // Assert
      proofRecord.assertProtocolVersion('v1')
      proofRecord.assertState(ProofState.ProposalSent)
      await connectionService.assertConnectionOrOutOfBandExchange(messageContext, {
        lastReceivedMessage,
        lastSentMessage,
        expectedConnectionId: proofRecord.connectionId,
      })

      await this.indyProofFormat.processRequest(agentContext, {
        attachment: requestAttachment,
        proofRecord,
      })

      await didCommMessageRepository.saveOrUpdateAgentMessage(agentContext, {
        agentMessage: proofRequestMessage,
        associatedRecordId: proofRecord.id,
        role: DidCommMessageRole.Receiver,
      })
      await this.updateState(agentContext, proofRecord, ProofState.RequestReceived)
    } else {
      // Assert
      await connectionService.assertConnectionOrOutOfBandExchange(messageContext)

      // No proof record exists with thread id
      proofRecord = new ProofExchangeRecord({
        connectionId: connection?.id,
        threadId: proofRequestMessage.threadId,
        parentThreadId: proofRequestMessage.thread?.parentThreadId,
        state: ProofState.RequestReceived,
        role: ProofRole.Prover,
        protocolVersion: 'v1',
      })

      await this.indyProofFormat.processRequest(agentContext, {
        attachment: requestAttachment,
        proofRecord,
      })

      await didCommMessageRepository.saveAgentMessage(agentContext, {
        agentMessage: proofRequestMessage,
        associatedRecordId: proofRecord.id,
        role: DidCommMessageRole.Receiver,
      })

      // Save in repository
      await proofRepository.save(agentContext, proofRecord)
      this.emitStateChangedEvent(agentContext, proofRecord, null)
    }

    return proofRecord
  }

  public async negotiateRequest(
    agentContext: AgentContext,
    {
      proofFormats,
      proofRecord,
      comment,
      autoAcceptProof,
    }: ProofProtocolOptions.NegotiateProofRequestOptions<[LegacyIndyProofFormatService]>
  ): Promise<ProofProtocolOptions.ProofProtocolMsgReturnType<AgentMessage>> {
    // Assert
    proofRecord.assertProtocolVersion('v1')
    proofRecord.assertState(ProofState.RequestReceived)
    this.assertOnlyIndyFormat(proofFormats)

    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    if (!proofRecord.connectionId) {
      throw new CredoError(
        `No connectionId found for proof record '${proofRecord.id}'. Connection-less verification does not support negotiation.`
      )
    }

    if (!proofFormats.indy) {
      throw new CredoError('Missing indy proof format in v1 negotiate request call.')
    }

    const presentationProposal = new V1PresentationPreview({
      attributes: proofFormats.indy?.attributes,
      predicates: proofFormats.indy?.predicates,
    })

    // validate input data from user
    MessageValidator.validateSync(presentationProposal)

    const message = new V1ProposePresentationMessage({
      comment,
      presentationProposal,
    })
    message.setThread({ threadId: proofRecord.threadId, parentThreadId: proofRecord.parentThreadId })

    await didCommMessageRepository.saveOrUpdateAgentMessage(agentContext, {
      agentMessage: message,
      associatedRecordId: proofRecord.id,
      role: DidCommMessageRole.Sender,
    })

    // Update record
    proofRecord.autoAcceptProof = autoAcceptProof ?? proofRecord.autoAcceptProof
    await this.updateState(agentContext, proofRecord, ProofState.ProposalSent)

    return { proofRecord, message: message }
  }

  public async acceptRequest(
    agentContext: AgentContext,
    {
      proofRecord,
      proofFormats,
      autoAcceptProof,
      comment,
    }: ProofProtocolOptions.AcceptProofRequestOptions<[LegacyIndyProofFormatService]>
  ): Promise<ProofProtocolOptions.ProofProtocolMsgReturnType<AgentMessage>> {
    // Assert
    proofRecord.assertProtocolVersion('v1')
    proofRecord.assertState(ProofState.RequestReceived)

    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    const requestMessage = await didCommMessageRepository.getAgentMessage(agentContext, {
      associatedRecordId: proofRecord.id,
      messageClass: V1RequestPresentationMessage,
      role: DidCommMessageRole.Receiver,
    })
    const proposalMessage = await didCommMessageRepository.findAgentMessage(agentContext, {
      associatedRecordId: proofRecord.id,
      messageClass: V1ProposePresentationMessage,
      role: DidCommMessageRole.Sender,
    })

    const requestAttachment = requestMessage.getRequestAttachmentById(INDY_PROOF_REQUEST_ATTACHMENT_ID)
    const indyProofRequest = requestMessage.indyProofRequest

    if (!requestAttachment || !indyProofRequest) {
      throw new V1PresentationProblemReportError(
        `Missing indy attachment in request message for presentation with thread id ${proofRecord.threadId}`,
        { problemCode: PresentationProblemReportReason.Abandoned }
      )
    }

    const proposalAttachment = proposalMessage
      ? new Attachment({
          data: {
            json: JsonTransformer.toJSON(
              createRequestFromPreview({
                attributes: proposalMessage.presentationProposal?.attributes,
                predicates: proposalMessage.presentationProposal?.predicates,
                name: indyProofRequest.name,
                nonce: indyProofRequest.nonce,
                version: indyProofRequest.nonce,
              })
            ),
          },
        })
      : undefined

    const { attachment } = await this.indyProofFormat.acceptRequest(agentContext, {
      attachmentId: INDY_PROOF_ATTACHMENT_ID,
      requestAttachment,
      proposalAttachment,
      proofFormats,
      proofRecord,
    })

    const message = new V1PresentationMessage({
      comment,
      presentationAttachments: [attachment],
    })
    message.setThread({ threadId: proofRecord.threadId, parentThreadId: proofRecord.parentThreadId })

    await didCommMessageRepository.saveAgentMessage(agentContext, {
      agentMessage: message,
      associatedRecordId: proofRecord.id,
      role: DidCommMessageRole.Sender,
    })

    // Update record
    proofRecord.autoAcceptProof = autoAcceptProof ?? proofRecord.autoAcceptProof
    await this.updateState(agentContext, proofRecord, ProofState.PresentationSent)

    return { message, proofRecord }
  }

  public async getCredentialsForRequest(
    agentContext: AgentContext,
    { proofRecord, proofFormats }: ProofProtocolOptions.GetCredentialsForRequestOptions<[LegacyIndyProofFormatService]>
  ): Promise<ProofProtocolOptions.GetCredentialsForRequestReturn<[LegacyIndyProofFormatService]>> {
    if (proofFormats) this.assertOnlyIndyFormat(proofFormats)

    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    const requestMessage = await didCommMessageRepository.getAgentMessage(agentContext, {
      associatedRecordId: proofRecord.id,
      messageClass: V1RequestPresentationMessage,
      role: DidCommMessageRole.Receiver,
    })

    const proposalMessage = await didCommMessageRepository.findAgentMessage(agentContext, {
      associatedRecordId: proofRecord.id,
      messageClass: V1ProposePresentationMessage,
      role: DidCommMessageRole.Sender,
    })

    const requestAttachment = requestMessage.getRequestAttachmentById(INDY_PROOF_REQUEST_ATTACHMENT_ID)
    const indyProofRequest = requestMessage.indyProofRequest

    if (!requestAttachment || !indyProofRequest) {
      throw new CredoError(
        `Missing indy attachment in request message for presentation with thread id ${proofRecord.threadId}`
      )
    }

    const proposalAttachment = proposalMessage
      ? new Attachment({
          data: {
            json: JsonTransformer.toJSON(
              createRequestFromPreview({
                attributes: proposalMessage.presentationProposal?.attributes,
                predicates: proposalMessage.presentationProposal?.predicates,
                name: indyProofRequest.name,
                nonce: indyProofRequest.nonce,
                version: indyProofRequest.nonce,
              })
            ),
          },
        })
      : undefined

    const credentialForRequest = await this.indyProofFormat.getCredentialsForRequest(agentContext, {
      proofRecord,
      requestAttachment,
      proofFormats,
      proposalAttachment,
    })

    return {
      proofFormats: {
        indy: credentialForRequest,
      },
    }
  }

  public async selectCredentialsForRequest(
    agentContext: AgentContext,
    {
      proofRecord,
      proofFormats,
    }: ProofProtocolOptions.SelectCredentialsForRequestOptions<[LegacyIndyProofFormatService]>
  ): Promise<ProofProtocolOptions.SelectCredentialsForRequestReturn<[LegacyIndyProofFormatService]>> {
    if (proofFormats) this.assertOnlyIndyFormat(proofFormats)

    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    const requestMessage = await didCommMessageRepository.getAgentMessage(agentContext, {
      associatedRecordId: proofRecord.id,
      messageClass: V1RequestPresentationMessage,
      role: DidCommMessageRole.Receiver,
    })

    const proposalMessage = await didCommMessageRepository.findAgentMessage(agentContext, {
      associatedRecordId: proofRecord.id,
      messageClass: V1ProposePresentationMessage,
      role: DidCommMessageRole.Sender,
    })

    const requestAttachment = requestMessage.getRequestAttachmentById(INDY_PROOF_REQUEST_ATTACHMENT_ID)
    const indyProofRequest = requestMessage.indyProofRequest

    if (!requestAttachment || !indyProofRequest) {
      throw new CredoError(
        `Missing indy attachment in request message for presentation with thread id ${proofRecord.threadId}`
      )
    }

    const proposalAttachment = proposalMessage
      ? new Attachment({
          data: {
            json: JsonTransformer.toJSON(
              createRequestFromPreview({
                attributes: proposalMessage.presentationProposal?.attributes,
                predicates: proposalMessage.presentationProposal?.predicates,
                name: indyProofRequest.name,
                nonce: indyProofRequest.nonce,
                version: indyProofRequest.nonce,
              })
            ),
          },
        })
      : undefined

    const selectedCredentials = await this.indyProofFormat.selectCredentialsForRequest(agentContext, {
      proofFormats,
      proofRecord,
      requestAttachment,
      proposalAttachment,
    })

    return {
      proofFormats: {
        indy: selectedCredentials,
      },
    }
  }

  public async processPresentation(
    messageContext: InboundMessageContext<V1PresentationMessage>
  ): Promise<ProofExchangeRecord> {
    const { message: presentationMessage, connection, agentContext } = messageContext

    agentContext.config.logger.debug(`Processing presentation with message id ${presentationMessage.id}`)

    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    // TODO: with this method, we should update the credential protocol to use the ConnectionApi, so it
    // only depends on the public api, rather than the internal API (this helps with breaking changes)
    const connectionService = agentContext.dependencyManager.resolve(ConnectionService)

    const proofRecord = await this.getByProperties(agentContext, {
      threadId: presentationMessage.threadId,
      role: ProofRole.Verifier,
    })

    const proposalMessage = await didCommMessageRepository.findAgentMessage(agentContext, {
      associatedRecordId: proofRecord.id,
      messageClass: V1ProposePresentationMessage,
      role: DidCommMessageRole.Receiver,
    })

    const requestMessage = await didCommMessageRepository.getAgentMessage(agentContext, {
      associatedRecordId: proofRecord.id,
      messageClass: V1RequestPresentationMessage,
      role: DidCommMessageRole.Sender,
    })

    // Assert
    proofRecord.assertState(ProofState.RequestSent)
    proofRecord.assertProtocolVersion('v1')
    await connectionService.assertConnectionOrOutOfBandExchange(messageContext, {
      lastReceivedMessage: proposalMessage,
      lastSentMessage: requestMessage,
      expectedConnectionId: proofRecord.connectionId,
    })

    // This makes sure that the sender of the incoming message is authorized to do so.
    if (!proofRecord.connectionId) {
      await connectionService.matchIncomingMessageToRequestMessageInOutOfBandExchange(messageContext, {
        expectedConnectionId: proofRecord.connectionId,
      })

      proofRecord.connectionId = connection?.id
    }

    const presentationAttachment = presentationMessage.getPresentationAttachmentById(INDY_PROOF_ATTACHMENT_ID)
    if (!presentationAttachment) {
      proofRecord.errorMessage = 'Missing indy proof attachment'
      await this.updateState(agentContext, proofRecord, ProofState.Abandoned)
      throw new V1PresentationProblemReportError(proofRecord.errorMessage, {
        problemCode: PresentationProblemReportReason.Abandoned,
      })
    }

    const requestAttachment = requestMessage.getRequestAttachmentById(INDY_PROOF_REQUEST_ATTACHMENT_ID)
    if (!requestAttachment) {
      proofRecord.errorMessage = 'Missing indy proof request attachment'
      await this.updateState(agentContext, proofRecord, ProofState.Abandoned)
      throw new V1PresentationProblemReportError(proofRecord.errorMessage, {
        problemCode: PresentationProblemReportReason.Abandoned,
      })
    }

    await didCommMessageRepository.saveAgentMessage(agentContext, {
      agentMessage: presentationMessage,
      associatedRecordId: proofRecord.id,
      role: DidCommMessageRole.Receiver,
    })

    let isValid: boolean
    try {
      isValid = await this.indyProofFormat.processPresentation(agentContext, {
        proofRecord,
        attachment: presentationAttachment,
        requestAttachment,
      })
    } catch (error) {
      proofRecord.errorMessage = error.message ?? 'Error verifying proof on presentation'
      proofRecord.isVerified = false
      await this.updateState(agentContext, proofRecord, ProofState.Abandoned)
      throw new V1PresentationProblemReportError('Error verifying proof on presentation', {
        problemCode: PresentationProblemReportReason.Abandoned,
      })
    }

    if (!isValid) {
      proofRecord.errorMessage = 'Invalid proof'
      proofRecord.isVerified = false
      await this.updateState(agentContext, proofRecord, ProofState.Abandoned)
      throw new V1PresentationProblemReportError('Invalid proof', {
        problemCode: PresentationProblemReportReason.Abandoned,
      })
    }

    // Update record
    proofRecord.isVerified = isValid
    await this.updateState(agentContext, proofRecord, ProofState.PresentationReceived)

    return proofRecord
  }

  public async acceptPresentation(
    agentContext: AgentContext,
    { proofRecord }: ProofProtocolOptions.AcceptPresentationOptions
  ): Promise<ProofProtocolOptions.ProofProtocolMsgReturnType<V1PresentationAckMessage>> {
    agentContext.config.logger.debug(`Creating presentation ack for proof record with id ${proofRecord.id}`)

    // Assert
    proofRecord.assertProtocolVersion('v1')
    proofRecord.assertState(ProofState.PresentationReceived)

    // Create message
    const ackMessage = new V1PresentationAckMessage({
      status: AckStatus.OK,
      threadId: proofRecord.threadId,
    })

    ackMessage.setThread({
      threadId: proofRecord.threadId,
      parentThreadId: proofRecord.parentThreadId,
    })

    // Update record
    await this.updateState(agentContext, proofRecord, ProofState.Done)

    return { message: ackMessage, proofRecord }
  }

  public async processAck(
    messageContext: InboundMessageContext<V1PresentationAckMessage>
  ): Promise<ProofExchangeRecord> {
    const { message: presentationAckMessage, connection, agentContext } = messageContext

    agentContext.config.logger.debug(`Processing presentation ack with message id ${presentationAckMessage.id}`)

    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    // TODO: with this method, we should update the credential protocol to use the ConnectionApi, so it
    // only depends on the public api, rather than the internal API (this helps with breaking changes)
    const connectionService = agentContext.dependencyManager.resolve(ConnectionService)

    const proofRecord = await this.getByProperties(agentContext, {
      threadId: presentationAckMessage.threadId,
      role: ProofRole.Prover,
      connectionId: connection?.id,
    })

    const lastReceivedMessage = await didCommMessageRepository.getAgentMessage(agentContext, {
      associatedRecordId: proofRecord.id,
      messageClass: V1RequestPresentationMessage,
      role: DidCommMessageRole.Receiver,
    })

    const lastSentMessage = await didCommMessageRepository.getAgentMessage(agentContext, {
      associatedRecordId: proofRecord.id,
      messageClass: V1PresentationMessage,
      role: DidCommMessageRole.Sender,
    })

    // Assert
    proofRecord.assertProtocolVersion('v1')
    proofRecord.assertState(ProofState.PresentationSent)
    await connectionService.assertConnectionOrOutOfBandExchange(messageContext, {
      lastReceivedMessage,
      lastSentMessage,
      expectedConnectionId: proofRecord.connectionId,
    })

    // Update record
    await this.updateState(agentContext, proofRecord, ProofState.Done)

    return proofRecord
  }

  public async createProblemReport(
    _agentContext: AgentContext,
    { proofRecord, description }: ProofProtocolOptions.CreateProofProblemReportOptions
  ): Promise<ProofProtocolOptions.ProofProtocolMsgReturnType<ProblemReportMessage>> {
    const message = new V1PresentationProblemReportMessage({
      description: {
        code: PresentationProblemReportReason.Abandoned,
        en: description,
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
      proposalMessage: V1ProposePresentationMessage
    }
  ): Promise<boolean> {
    const { proofRecord, proposalMessage } = options

    const proofsModuleConfig = agentContext.dependencyManager.resolve(ProofsModuleConfig)

    const autoAccept = composeProofAutoAccept(proofRecord.autoAcceptProof, proofsModuleConfig.autoAcceptProofs)

    // Handle always / never cases
    if (autoAccept === AutoAcceptProof.Always) return true
    if (autoAccept === AutoAcceptProof.Never) return false

    // We are in the ContentApproved case. We need to make sure we've sent a request, and it matches the proposal
    const requestMessage = await this.findRequestMessage(agentContext, proofRecord.id)
    const requestAttachment = requestMessage?.getRequestAttachmentById(INDY_PROOF_REQUEST_ATTACHMENT_ID)
    if (!requestAttachment) return false

    const rfc0592Proposal = JsonTransformer.toJSON(
      createRequestFromPreview({
        name: 'Proof Request',
        nonce: await agentContext.wallet.generateNonce(),
        version: '1.0',
        attributes: proposalMessage.presentationProposal.attributes,
        predicates: proposalMessage.presentationProposal.predicates,
      })
    )

    return this.indyProofFormat.shouldAutoRespondToProposal(agentContext, {
      proofRecord,
      proposalAttachment: new Attachment({
        data: {
          json: rfc0592Proposal,
        },
      }),
      requestAttachment,
    })
  }

  public async shouldAutoRespondToRequest(
    agentContext: AgentContext,
    options: {
      proofRecord: ProofExchangeRecord
      requestMessage: V1RequestPresentationMessage
    }
  ): Promise<boolean> {
    const { proofRecord, requestMessage } = options

    const proofsModuleConfig = agentContext.dependencyManager.resolve(ProofsModuleConfig)

    const autoAccept = composeProofAutoAccept(proofRecord.autoAcceptProof, proofsModuleConfig.autoAcceptProofs)

    // Handle always / never cases
    if (autoAccept === AutoAcceptProof.Always) return true
    if (autoAccept === AutoAcceptProof.Never) return false

    const requestAttachment = requestMessage.getRequestAttachmentById(INDY_PROOF_REQUEST_ATTACHMENT_ID)
    if (!requestAttachment) return false

    // We are in the ContentApproved case. We need to make sure we've sent a proposal, and it matches the request
    const proposalMessage = await this.findProposalMessage(agentContext, proofRecord.id)
    if (!proposalMessage) return false

    const rfc0592Proposal = createRequestFromPreview({
      name: 'Proof Request',
      nonce: await agentContext.wallet.generateNonce(),
      version: '1.0',
      attributes: proposalMessage.presentationProposal.attributes,
      predicates: proposalMessage.presentationProposal.predicates,
    })

    return this.indyProofFormat.shouldAutoRespondToRequest(agentContext, {
      proofRecord,
      proposalAttachment: new Attachment({
        data: {
          base64: JsonEncoder.toBase64(rfc0592Proposal),
        },
      }),
      requestAttachment,
    })
  }

  public async shouldAutoRespondToPresentation(
    agentContext: AgentContext,
    options: {
      proofRecord: ProofExchangeRecord
      presentationMessage: V1PresentationMessage
    }
  ): Promise<boolean> {
    const { proofRecord, presentationMessage } = options

    const proofsModuleConfig = agentContext.dependencyManager.resolve(ProofsModuleConfig)

    const autoAccept = composeProofAutoAccept(proofRecord.autoAcceptProof, proofsModuleConfig.autoAcceptProofs)

    // Handle always / never cases
    if (autoAccept === AutoAcceptProof.Always) return true
    if (autoAccept === AutoAcceptProof.Never) return false

    const presentationAttachment = presentationMessage.getPresentationAttachmentById(INDY_PROOF_ATTACHMENT_ID)
    if (!presentationAttachment) return false

    // We are in the ContentApproved case. We need to make sure we've sent a request, and it matches the presentation
    const requestMessage = await this.findRequestMessage(agentContext, proofRecord.id)
    const requestAttachment = requestMessage?.getRequestAttachmentById(INDY_PROOF_REQUEST_ATTACHMENT_ID)
    if (!requestAttachment) return false

    // We are in the ContentApproved case. We need to make sure we've sent a proposal, and it matches the request
    const proposalMessage = await this.findProposalMessage(agentContext, proofRecord.id)

    const rfc0592Proposal = proposalMessage
      ? JsonTransformer.toJSON(
          createRequestFromPreview({
            name: 'Proof Request',
            nonce: await agentContext.wallet.generateNonce(),
            version: '1.0',
            attributes: proposalMessage.presentationProposal.attributes,
            predicates: proposalMessage.presentationProposal.predicates,
          })
        )
      : undefined

    return this.indyProofFormat.shouldAutoRespondToPresentation(agentContext, {
      proofRecord,
      requestAttachment,
      presentationAttachment,
      proposalAttachment: new Attachment({
        data: {
          json: rfc0592Proposal,
        },
      }),
    })
  }

  public async findProposalMessage(
    agentContext: AgentContext,
    proofRecordId: string
  ): Promise<V1ProposePresentationMessage | null> {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)
    return await didCommMessageRepository.findAgentMessage(agentContext, {
      associatedRecordId: proofRecordId,
      messageClass: V1ProposePresentationMessage,
    })
  }

  public async findRequestMessage(
    agentContext: AgentContext,
    proofRecordId: string
  ): Promise<V1RequestPresentationMessage | null> {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)
    return await didCommMessageRepository.findAgentMessage(agentContext, {
      associatedRecordId: proofRecordId,
      messageClass: V1RequestPresentationMessage,
    })
  }

  public async findPresentationMessage(
    agentContext: AgentContext,
    proofRecordId: string
  ): Promise<V1PresentationMessage | null> {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)
    return await didCommMessageRepository.findAgentMessage(agentContext, {
      associatedRecordId: proofRecordId,
      messageClass: V1PresentationMessage,
    })
  }

  public async getFormatData(
    agentContext: AgentContext,
    proofRecordId: string
  ): Promise<GetProofFormatDataReturn<ProofFormat[]>> {
    // TODO: we could looking at fetching all record using a single query and then filtering based on the type of the message.
    const [proposalMessage, requestMessage, presentationMessage] = await Promise.all([
      this.findProposalMessage(agentContext, proofRecordId),
      this.findRequestMessage(agentContext, proofRecordId),
      this.findPresentationMessage(agentContext, proofRecordId),
    ])

    let indyProposeProof = undefined
    const indyRequestProof = requestMessage?.indyProofRequest ?? undefined
    const indyPresentProof = presentationMessage?.indyProof ?? undefined

    if (proposalMessage && indyRequestProof) {
      indyProposeProof = createRequestFromPreview({
        name: indyRequestProof.name,
        version: indyRequestProof.version,
        nonce: indyRequestProof.nonce,
        attributes: proposalMessage.presentationProposal.attributes,
        predicates: proposalMessage.presentationProposal.predicates,
      })
    } else if (proposalMessage) {
      indyProposeProof = createRequestFromPreview({
        name: 'Proof Request',
        version: '1.0',
        nonce: await agentContext.wallet.generateNonce(),
        attributes: proposalMessage.presentationProposal.attributes,
        predicates: proposalMessage.presentationProposal.predicates,
      })
    }

    return {
      proposal: proposalMessage
        ? {
            indy: indyProposeProof,
          }
        : undefined,
      request: requestMessage
        ? {
            indy: indyRequestProof,
          }
        : undefined,
      presentation: presentationMessage
        ? {
            indy: indyPresentProof,
          }
        : undefined,
    }
  }

  private assertOnlyIndyFormat(proofFormats: Record<string, unknown>) {
    const formatKeys = Object.keys(proofFormats)

    // It's fine to not have any formats in some cases, if indy is required the method that calls this should check for this
    if (formatKeys.length === 0) return

    if (formatKeys.length !== 1 || !formatKeys.includes('indy')) {
      throw new CredoError('Only indy proof format is supported for present proof v1 protocol')
    }
  }
}
