import type { LegacyIndyCredentialFormatService } from '../../../formats'
import type { AgentContext } from '@credo-ts/core'
import type {
  AgentMessage,
  CredentialProtocolOptions,
  InboundMessageContext,
  ProblemReportMessage,
  ExtractCredentialFormats,
  CredentialProtocol,
  FeatureRegistry,
  MessageHandlerRegistry,
} from '@credo-ts/didcomm'

import { CredoError, JsonTransformer, utils } from '@credo-ts/core'
import {
  CredentialRole,
  Protocol,
  CredentialRepository,
  CredentialExchangeRecord,
  CredentialState,
  ConnectionService,
  Attachment,
  AttachmentData,
  AckStatus,
  CredentialProblemReportReason,
  CredentialsModuleConfig,
  AutoAcceptCredential,
  DidCommMessageRepository,
  DidCommMessageRole,
  BaseCredentialProtocol,
  isLinkedAttachment,
} from '@credo-ts/didcomm'

import { AnonCredsCredentialProposal } from '../../../models/AnonCredsCredentialProposal'
import { composeCredentialAutoAccept, areCredentialPreviewAttributesEqual } from '../../../utils'

import {
  V1ProposeCredentialHandler,
  V1OfferCredentialHandler,
  V1RequestCredentialHandler,
  V1IssueCredentialHandler,
  V1CredentialAckHandler,
  V1CredentialProblemReportHandler,
} from './handlers'
import {
  V1CredentialPreview,
  V1ProposeCredentialMessage,
  V1OfferCredentialMessage,
  INDY_CREDENTIAL_OFFER_ATTACHMENT_ID,
  V1RequestCredentialMessage,
  INDY_CREDENTIAL_REQUEST_ATTACHMENT_ID,
  V1IssueCredentialMessage,
  INDY_CREDENTIAL_ATTACHMENT_ID,
  V1CredentialAckMessage,
  V1CredentialProblemReportMessage,
} from './messages'

export interface V1CredentialProtocolConfig {
  indyCredentialFormat: LegacyIndyCredentialFormatService
}

export class V1CredentialProtocol
  extends BaseCredentialProtocol<[LegacyIndyCredentialFormatService]>
  implements CredentialProtocol<[LegacyIndyCredentialFormatService]>
{
  private indyCredentialFormat: LegacyIndyCredentialFormatService

  public constructor({ indyCredentialFormat }: V1CredentialProtocolConfig) {
    super()

    // TODO: just create a new instance of LegacyIndyCredentialFormatService here so it makes the setup easier
    this.indyCredentialFormat = indyCredentialFormat
  }

  /**
   * The version of the issue credential protocol this protocol supports
   */
  public readonly version = 'v1'

  /**
   * Registers the protocol implementation (handlers, feature registry) on the agent.
   */
  public register(messageHandlerRegistry: MessageHandlerRegistry, featureRegistry: FeatureRegistry) {
    // Register message handlers for the Issue Credential V1 Protocol
    messageHandlerRegistry.registerMessageHandlers([
      new V1ProposeCredentialHandler(this),
      new V1OfferCredentialHandler(this),
      new V1RequestCredentialHandler(this),
      new V1IssueCredentialHandler(this),
      new V1CredentialAckHandler(this),
      new V1CredentialProblemReportHandler(this),
    ])

    // Register Issue Credential V1 in feature registry, with supported roles
    featureRegistry.register(
      new Protocol({
        id: 'https://didcomm.org/issue-credential/1.0',
        roles: ['holder', 'issuer'],
      })
    )
  }

  /**
   * Create a {@link ProposeCredentialMessage} not bound to an existing credential exchange.
   * To create a proposal as response to an existing credential exchange, use {@link createProposalAsResponse}.
   *
   * @param options The object containing config options
   * @returns Object containing proposal message and associated credential record
   *
   */
  public async createProposal(
    agentContext: AgentContext,
    {
      connectionRecord,
      credentialFormats,
      comment,
      autoAcceptCredential,
    }: CredentialProtocolOptions.CreateCredentialProposalOptions<[LegacyIndyCredentialFormatService]>
  ): Promise<CredentialProtocolOptions.CredentialProtocolMsgReturnType<AgentMessage>> {
    this.assertOnlyIndyFormat(credentialFormats)

    const credentialRepository = agentContext.dependencyManager.resolve(CredentialRepository)
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    if (!credentialFormats.indy) {
      throw new CredoError('Missing indy credential format in v1 create proposal call.')
    }

    // TODO: linked attachments are broken currently. We never include them in the messages.
    // The linking with previews does work, so it shouldn't be too much work to re-enable this.
    const { linkedAttachments } = credentialFormats.indy

    // Create record
    const credentialRecord = new CredentialExchangeRecord({
      connectionId: connectionRecord.id,
      threadId: utils.uuid(),
      state: CredentialState.ProposalSent,
      role: CredentialRole.Holder,
      linkedAttachments: linkedAttachments?.map((linkedAttachment) => linkedAttachment.attachment),
      autoAcceptCredential,
      protocolVersion: 'v1',
    })

    // call create proposal for validation of the proposal and addition of linked attachments
    const { previewAttributes, attachment } = await this.indyCredentialFormat.createProposal(agentContext, {
      credentialFormats,
      credentialRecord,
    })

    // Transform the attachment into the attachment payload and use that to construct the v1 message
    const indyCredentialProposal = JsonTransformer.fromJSON(attachment.getDataAsJson(), AnonCredsCredentialProposal)

    const credentialProposal = previewAttributes
      ? new V1CredentialPreview({
          attributes: previewAttributes,
        })
      : undefined

    // Create message
    const message = new V1ProposeCredentialMessage({
      ...indyCredentialProposal,
      id: credentialRecord.threadId,
      credentialPreview: credentialProposal,
      comment,
    })

    await didCommMessageRepository.saveAgentMessage(agentContext, {
      agentMessage: message,
      role: DidCommMessageRole.Sender,
      associatedRecordId: credentialRecord.id,
    })

    credentialRecord.credentialAttributes = credentialProposal?.attributes
    await credentialRepository.save(agentContext, credentialRecord)
    this.emitStateChangedEvent(agentContext, credentialRecord, null)

    return { credentialRecord, message }
  }

  /**
   * Process a received {@link ProposeCredentialMessage}. This will not accept the credential proposal
   * or send a credential offer. It will only create a new, or update the existing credential record with
   * the information from the credential proposal message. Use {@link createOfferAsResponse}
   * after calling this method to create a credential offer.
   *
   * @param messageContext The message context containing a credential proposal message
   * @returns credential record associated with the credential proposal message
   *
   */
  public async processProposal(
    messageContext: InboundMessageContext<V1ProposeCredentialMessage>
  ): Promise<CredentialExchangeRecord> {
    const { message: proposalMessage, connection, agentContext } = messageContext

    const credentialRepository = agentContext.dependencyManager.resolve(CredentialRepository)
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    // TODO: with this method, we should update the credential protocol to use the ConnectionApi, so it
    // only depends on the public api, rather than the internal API (this helps with breaking changes)
    const connectionService = agentContext.dependencyManager.resolve(ConnectionService)

    agentContext.config.logger.debug(`Processing credential proposal with message id ${proposalMessage.id}`)

    let credentialRecord = await this.findByProperties(messageContext.agentContext, {
      threadId: proposalMessage.threadId,
      role: CredentialRole.Issuer,
      connectionId: connection?.id,
    })

    // Credential record already exists, this is a response to an earlier message sent by us
    if (credentialRecord) {
      agentContext.config.logger.debug('Credential record already exists for incoming proposal')

      // Assert
      credentialRecord.assertProtocolVersion('v1')
      credentialRecord.assertState(CredentialState.OfferSent)

      const lastReceivedMessage = await didCommMessageRepository.findAgentMessage(messageContext.agentContext, {
        associatedRecordId: credentialRecord.id,
        messageClass: V1ProposeCredentialMessage,
        role: DidCommMessageRole.Receiver,
      })
      const lastSentMessage = await didCommMessageRepository.getAgentMessage(messageContext.agentContext, {
        associatedRecordId: credentialRecord.id,
        messageClass: V1OfferCredentialMessage,
        role: DidCommMessageRole.Sender,
      })

      await connectionService.assertConnectionOrOutOfBandExchange(messageContext, {
        lastReceivedMessage,
        lastSentMessage,
        expectedConnectionId: credentialRecord.connectionId,
      })

      await this.indyCredentialFormat.processProposal(messageContext.agentContext, {
        credentialRecord,
        attachment: new Attachment({
          data: new AttachmentData({
            json: JsonTransformer.toJSON(this.rfc0592ProposalFromV1ProposeMessage(proposalMessage)),
          }),
        }),
      })

      // Update record
      await this.updateState(messageContext.agentContext, credentialRecord, CredentialState.ProposalReceived)
      await didCommMessageRepository.saveOrUpdateAgentMessage(messageContext.agentContext, {
        agentMessage: proposalMessage,
        role: DidCommMessageRole.Receiver,
        associatedRecordId: credentialRecord.id,
      })
    } else {
      agentContext.config.logger.debug('Credential record does not exists yet for incoming proposal')
      // Assert
      await connectionService.assertConnectionOrOutOfBandExchange(messageContext)

      // No credential record exists with thread id
      credentialRecord = new CredentialExchangeRecord({
        connectionId: connection?.id,
        threadId: proposalMessage.threadId,
        state: CredentialState.ProposalReceived,
        role: CredentialRole.Issuer,
        protocolVersion: 'v1',
      })

      // Save record
      await credentialRepository.save(messageContext.agentContext, credentialRecord)
      this.emitStateChangedEvent(messageContext.agentContext, credentialRecord, null)

      await didCommMessageRepository.saveAgentMessage(messageContext.agentContext, {
        agentMessage: proposalMessage,
        role: DidCommMessageRole.Receiver,
        associatedRecordId: credentialRecord.id,
      })
    }
    return credentialRecord
  }

  /**
   * Processing an incoming credential message and create a credential offer as a response
   * @param options The object containing config options
   * @returns Object containing proposal message and associated credential record
   */
  public async acceptProposal(
    agentContext: AgentContext,
    {
      credentialRecord,
      credentialFormats,
      comment,
      autoAcceptCredential,
    }: CredentialProtocolOptions.AcceptCredentialProposalOptions<[LegacyIndyCredentialFormatService]>
  ): Promise<CredentialProtocolOptions.CredentialProtocolMsgReturnType<V1OfferCredentialMessage>> {
    // Assert
    credentialRecord.assertProtocolVersion('v1')
    credentialRecord.assertState(CredentialState.ProposalReceived)
    if (credentialFormats) this.assertOnlyIndyFormat(credentialFormats)

    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    const proposalMessage = await didCommMessageRepository.getAgentMessage(agentContext, {
      associatedRecordId: credentialRecord.id,
      messageClass: V1ProposeCredentialMessage,
      role: DidCommMessageRole.Receiver,
    })

    // NOTE: We set the credential attributes from the proposal on the record as we've 'accepted' them
    // and can now use them to create the offer in the format services. It may be overwritten later on
    // if the user provided other attributes in the credentialFormats array.
    credentialRecord.credentialAttributes = proposalMessage.credentialPreview?.attributes

    const { attachment, previewAttributes } = await this.indyCredentialFormat.acceptProposal(agentContext, {
      attachmentId: INDY_CREDENTIAL_OFFER_ATTACHMENT_ID,
      credentialFormats,
      credentialRecord,
      proposalAttachment: new Attachment({
        data: new AttachmentData({
          json: JsonTransformer.toJSON(this.rfc0592ProposalFromV1ProposeMessage(proposalMessage)),
        }),
      }),
    })

    if (!previewAttributes) {
      throw new CredoError('Missing required credential preview attributes from indy format service')
    }

    const message = new V1OfferCredentialMessage({
      comment,
      offerAttachments: [attachment],
      credentialPreview: new V1CredentialPreview({
        attributes: previewAttributes,
      }),
      attachments: credentialRecord.linkedAttachments,
    })

    message.setThread({ threadId: credentialRecord.threadId, parentThreadId: credentialRecord.parentThreadId })

    credentialRecord.credentialAttributes = message.credentialPreview.attributes
    credentialRecord.autoAcceptCredential = autoAcceptCredential ?? credentialRecord.autoAcceptCredential
    await this.updateState(agentContext, credentialRecord, CredentialState.OfferSent)

    await didCommMessageRepository.saveOrUpdateAgentMessage(agentContext, {
      agentMessage: message,
      role: DidCommMessageRole.Sender,
      associatedRecordId: credentialRecord.id,
    })

    return { credentialRecord, message }
  }

  /**
   * Negotiate a credential proposal as issuer (by sending a credential offer message) to the connection
   * associated with the credential record.
   *
   * @param options configuration for the offer see {@link NegotiateCredentialProposalOptions}
   * @returns Credential record associated with the credential offer and the corresponding new offer message
   *
   */
  public async negotiateProposal(
    agentContext: AgentContext,
    {
      credentialFormats,
      credentialRecord,
      comment,
      autoAcceptCredential,
    }: CredentialProtocolOptions.NegotiateCredentialProposalOptions<[LegacyIndyCredentialFormatService]>
  ): Promise<CredentialProtocolOptions.CredentialProtocolMsgReturnType<V1OfferCredentialMessage>> {
    // Assert
    credentialRecord.assertProtocolVersion('v1')
    credentialRecord.assertState(CredentialState.ProposalReceived)
    this.assertOnlyIndyFormat(credentialFormats)

    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    const { attachment, previewAttributes } = await this.indyCredentialFormat.createOffer(agentContext, {
      attachmentId: INDY_CREDENTIAL_OFFER_ATTACHMENT_ID,
      credentialFormats,
      credentialRecord,
    })

    if (!previewAttributes) {
      throw new CredoError('Missing required credential preview attributes from indy format service')
    }

    const message = new V1OfferCredentialMessage({
      comment,
      offerAttachments: [attachment],
      credentialPreview: new V1CredentialPreview({
        attributes: previewAttributes,
      }),
      attachments: credentialRecord.linkedAttachments,
    })
    message.setThread({ threadId: credentialRecord.threadId, parentThreadId: credentialRecord.parentThreadId })

    credentialRecord.credentialAttributes = message.credentialPreview.attributes
    credentialRecord.autoAcceptCredential = autoAcceptCredential ?? credentialRecord.autoAcceptCredential
    await this.updateState(agentContext, credentialRecord, CredentialState.OfferSent)

    await didCommMessageRepository.saveOrUpdateAgentMessage(agentContext, {
      agentMessage: message,
      role: DidCommMessageRole.Sender,
      associatedRecordId: credentialRecord.id,
    })

    return { credentialRecord, message }
  }

  /**
   * Create a {@link OfferCredentialMessage} not bound to an existing credential exchange.
   * To create an offer as response to an existing credential exchange, use {@link V1CredentialProtocol#createOfferAsResponse}.
   *
   * @param options The options containing config params for creating the credential offer
   * @returns Object containing offer message and associated credential record
   *
   */
  public async createOffer(
    agentContext: AgentContext,
    {
      credentialFormats,
      autoAcceptCredential,
      comment,
      connectionRecord,
    }: CredentialProtocolOptions.CreateCredentialOfferOptions<[LegacyIndyCredentialFormatService]>
  ): Promise<CredentialProtocolOptions.CredentialProtocolMsgReturnType<V1OfferCredentialMessage>> {
    // Assert
    this.assertOnlyIndyFormat(credentialFormats)

    const credentialRepository = agentContext.dependencyManager.resolve(CredentialRepository)
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    if (!credentialFormats.indy) {
      throw new CredoError('Missing indy credential format data for v1 create offer')
    }

    // Create record
    const credentialRecord = new CredentialExchangeRecord({
      connectionId: connectionRecord?.id,
      threadId: utils.uuid(),
      linkedAttachments: credentialFormats.indy.linkedAttachments?.map(
        (linkedAttachments) => linkedAttachments.attachment
      ),
      state: CredentialState.OfferSent,
      role: CredentialRole.Issuer,
      autoAcceptCredential,
      protocolVersion: 'v1',
    })

    const { attachment, previewAttributes } = await this.indyCredentialFormat.createOffer(agentContext, {
      attachmentId: INDY_CREDENTIAL_OFFER_ATTACHMENT_ID,
      credentialFormats,
      credentialRecord,
    })

    if (!previewAttributes) {
      throw new CredoError('Missing required credential preview from indy format service')
    }

    // Construct offer message
    const message = new V1OfferCredentialMessage({
      id: credentialRecord.threadId,
      credentialPreview: new V1CredentialPreview({
        attributes: previewAttributes,
      }),
      comment,
      offerAttachments: [attachment],
      attachments: credentialFormats.indy.linkedAttachments?.map((linkedAttachments) => linkedAttachments.attachment),
    })

    await didCommMessageRepository.saveAgentMessage(agentContext, {
      associatedRecordId: credentialRecord.id,
      agentMessage: message,
      role: DidCommMessageRole.Sender,
    })

    credentialRecord.credentialAttributes = message.credentialPreview.attributes
    await credentialRepository.save(agentContext, credentialRecord)
    this.emitStateChangedEvent(agentContext, credentialRecord, null)

    return { message, credentialRecord }
  }

  /**
   * Process a received {@link OfferCredentialMessage}. This will not accept the credential offer
   * or send a credential request. It will only create a new credential record with
   * the information from the credential offer message. Use {@link createRequest}
   * after calling this method to create a credential request.
   *
   * @param messageContext The message context containing a credential request message
   * @returns credential record associated with the credential offer message
   *
   */
  public async processOffer(
    messageContext: InboundMessageContext<V1OfferCredentialMessage>
  ): Promise<CredentialExchangeRecord> {
    const { message: offerMessage, connection, agentContext } = messageContext

    const credentialRepository = agentContext.dependencyManager.resolve(CredentialRepository)
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    // TODO: with this method, we should update the credential protocol to use the ConnectionApi, so it
    // only depends on the public api, rather than the internal API (this helps with breaking changes)
    const connectionService = agentContext.dependencyManager.resolve(ConnectionService)

    agentContext.config.logger.debug(`Processing credential offer with id ${offerMessage.id}`)

    let credentialRecord = await this.findByProperties(agentContext, {
      threadId: offerMessage.threadId,
      role: CredentialRole.Holder,
      connectionId: connection?.id,
    })

    const offerAttachment = offerMessage.getOfferAttachmentById(INDY_CREDENTIAL_OFFER_ATTACHMENT_ID)
    if (!offerAttachment) {
      throw new CredoError(`Indy attachment with id ${INDY_CREDENTIAL_OFFER_ATTACHMENT_ID} not found in offer message`)
    }

    if (credentialRecord) {
      const lastSentMessage = await didCommMessageRepository.getAgentMessage(messageContext.agentContext, {
        associatedRecordId: credentialRecord.id,
        messageClass: V1ProposeCredentialMessage,
        role: DidCommMessageRole.Sender,
      })
      const lastReceivedMessage = await didCommMessageRepository.findAgentMessage(messageContext.agentContext, {
        associatedRecordId: credentialRecord.id,
        messageClass: V1OfferCredentialMessage,
        role: DidCommMessageRole.Receiver,
      })

      // Assert
      credentialRecord.assertProtocolVersion('v1')
      credentialRecord.assertState(CredentialState.ProposalSent)
      await connectionService.assertConnectionOrOutOfBandExchange(messageContext, {
        lastReceivedMessage,
        lastSentMessage,
        expectedConnectionId: credentialRecord.connectionId,
      })

      await this.indyCredentialFormat.processOffer(messageContext.agentContext, {
        credentialRecord,
        attachment: offerAttachment,
      })

      await didCommMessageRepository.saveOrUpdateAgentMessage(messageContext.agentContext, {
        agentMessage: offerMessage,
        role: DidCommMessageRole.Receiver,
        associatedRecordId: credentialRecord.id,
      })
      await this.updateState(messageContext.agentContext, credentialRecord, CredentialState.OfferReceived)

      return credentialRecord
    } else {
      // Assert
      await connectionService.assertConnectionOrOutOfBandExchange(messageContext)

      // No credential record exists with thread id
      credentialRecord = new CredentialExchangeRecord({
        connectionId: connection?.id,
        threadId: offerMessage.threadId,
        parentThreadId: offerMessage.thread?.parentThreadId,
        state: CredentialState.OfferReceived,
        role: CredentialRole.Holder,
        protocolVersion: 'v1',
      })

      await this.indyCredentialFormat.processOffer(messageContext.agentContext, {
        credentialRecord,
        attachment: offerAttachment,
      })

      // Save in repository
      await didCommMessageRepository.saveAgentMessage(messageContext.agentContext, {
        agentMessage: offerMessage,
        role: DidCommMessageRole.Receiver,
        associatedRecordId: credentialRecord.id,
      })
      await credentialRepository.save(messageContext.agentContext, credentialRecord)
      this.emitStateChangedEvent(messageContext.agentContext, credentialRecord, null)

      return credentialRecord
    }
  }

  /**
   * Create a {@link RequestCredentialMessage} as response to a received credential offer.
   *
   * @param options configuration to use for the credential request
   * @returns Object containing request message and associated credential record
   *
   */
  public async acceptOffer(
    agentContext: AgentContext,
    {
      credentialRecord,
      credentialFormats,
      comment,
      autoAcceptCredential,
    }: CredentialProtocolOptions.AcceptCredentialOfferOptions<[LegacyIndyCredentialFormatService]>
  ): Promise<CredentialProtocolOptions.CredentialProtocolMsgReturnType<V1RequestCredentialMessage>> {
    // Assert credential
    credentialRecord.assertProtocolVersion('v1')
    credentialRecord.assertState(CredentialState.OfferReceived)

    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    const offerMessage = await didCommMessageRepository.getAgentMessage(agentContext, {
      associatedRecordId: credentialRecord.id,
      messageClass: V1OfferCredentialMessage,
      role: DidCommMessageRole.Receiver,
    })

    const offerAttachment = offerMessage.getOfferAttachmentById(INDY_CREDENTIAL_OFFER_ATTACHMENT_ID)
    if (!offerAttachment) {
      throw new CredoError(`Indy attachment with id ${INDY_CREDENTIAL_OFFER_ATTACHMENT_ID} not found in offer message`)
    }

    const { attachment } = await this.indyCredentialFormat.acceptOffer(agentContext, {
      credentialRecord,
      credentialFormats,
      attachmentId: INDY_CREDENTIAL_REQUEST_ATTACHMENT_ID,
      offerAttachment,
    })

    const requestMessage = new V1RequestCredentialMessage({
      comment,
      requestAttachments: [attachment],
      attachments: offerMessage.appendedAttachments?.filter((attachment) => isLinkedAttachment(attachment)),
    })
    requestMessage.setThread({ threadId: credentialRecord.threadId, parentThreadId: credentialRecord.parentThreadId })

    credentialRecord.credentialAttributes = offerMessage.credentialPreview.attributes
    credentialRecord.autoAcceptCredential = autoAcceptCredential ?? credentialRecord.autoAcceptCredential
    credentialRecord.linkedAttachments = offerMessage.appendedAttachments?.filter((attachment) =>
      isLinkedAttachment(attachment)
    )

    await didCommMessageRepository.saveOrUpdateAgentMessage(agentContext, {
      agentMessage: requestMessage,
      associatedRecordId: credentialRecord.id,
      role: DidCommMessageRole.Sender,
    })
    await this.updateState(agentContext, credentialRecord, CredentialState.RequestSent)

    return { message: requestMessage, credentialRecord }
  }

  /**
   * Process a received {@link RequestCredentialMessage}. This will not accept the credential request
   * or send a credential. It will only update the existing credential record with
   * the information from the credential request message. Use {@link createCredential}
   * after calling this method to create a credential.
   *
   * @param messageContext The message context containing a credential request message
   * @returns credential record associated with the credential request message
   *
   */
  public async negotiateOffer(
    agentContext: AgentContext,
    {
      credentialFormats,
      credentialRecord,
      autoAcceptCredential,
      comment,
    }: CredentialProtocolOptions.NegotiateCredentialOfferOptions<[LegacyIndyCredentialFormatService]>
  ): Promise<CredentialProtocolOptions.CredentialProtocolMsgReturnType<AgentMessage>> {
    // Assert
    credentialRecord.assertProtocolVersion('v1')
    credentialRecord.assertState(CredentialState.OfferReceived)
    this.assertOnlyIndyFormat(credentialFormats)

    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    if (!credentialRecord.connectionId) {
      throw new CredoError(
        `No connectionId found for credential record '${credentialRecord.id}'. Connection-less issuance does not support negotiation.`
      )
    }

    if (!credentialFormats.indy) {
      throw new CredoError('Missing indy credential format in v1 negotiate proposal call.')
    }

    const { linkedAttachments } = credentialFormats.indy

    // call create proposal for validation of the proposal and addition of linked attachments
    // As the format is different for v1 of the issue credential protocol we won't be using the attachment
    const { previewAttributes, attachment } = await this.indyCredentialFormat.createProposal(agentContext, {
      credentialFormats,
      credentialRecord,
    })

    // Transform the attachment into the attachment payload and use that to construct the v1 message
    const indyCredentialProposal = JsonTransformer.fromJSON(attachment.getDataAsJson(), AnonCredsCredentialProposal)

    const credentialProposal = previewAttributes
      ? new V1CredentialPreview({
          attributes: previewAttributes,
        })
      : undefined

    // Create message
    const message = new V1ProposeCredentialMessage({
      ...indyCredentialProposal,
      credentialPreview: credentialProposal,
      comment,
    })

    message.setThread({ threadId: credentialRecord.threadId, parentThreadId: credentialRecord.parentThreadId })

    await didCommMessageRepository.saveOrUpdateAgentMessage(agentContext, {
      agentMessage: message,
      role: DidCommMessageRole.Sender,
      associatedRecordId: credentialRecord.id,
    })

    // Update record
    credentialRecord.credentialAttributes = message.credentialPreview?.attributes
    credentialRecord.linkedAttachments = linkedAttachments?.map((attachment) => attachment.attachment)
    credentialRecord.autoAcceptCredential = autoAcceptCredential ?? credentialRecord.autoAcceptCredential
    await this.updateState(agentContext, credentialRecord, CredentialState.ProposalSent)

    return { credentialRecord, message }
  }

  /**
   * Starting from a request is not supported in v1 of the issue credential protocol
   * because indy doesn't allow to start from a request
   */
  public async createRequest(): Promise<
    CredentialProtocolOptions.CredentialProtocolMsgReturnType<V1RequestCredentialMessage>
  > {
    throw new CredoError('Starting from a request is not supported for v1 issue credential protocol')
  }

  public async processRequest(
    messageContext: InboundMessageContext<V1RequestCredentialMessage>
  ): Promise<CredentialExchangeRecord> {
    const { message: requestMessage, connection, agentContext } = messageContext

    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    // TODO: with this method, we should update the credential protocol to use the ConnectionApi, so it
    // only depends on the public api, rather than the internal API (this helps with breaking changes)
    const connectionService = agentContext.dependencyManager.resolve(ConnectionService)

    agentContext.config.logger.debug(`Processing credential request with id ${requestMessage.id}`)

    const credentialRecord = await this.getByProperties(messageContext.agentContext, {
      threadId: requestMessage.threadId,
      role: CredentialRole.Issuer,
    })

    agentContext.config.logger.trace('Credential record found when processing credential request', credentialRecord)

    const proposalMessage = await didCommMessageRepository.findAgentMessage(messageContext.agentContext, {
      associatedRecordId: credentialRecord.id,
      messageClass: V1ProposeCredentialMessage,
      role: DidCommMessageRole.Receiver,
    })
    const offerMessage = await didCommMessageRepository.findAgentMessage(messageContext.agentContext, {
      associatedRecordId: credentialRecord.id,
      messageClass: V1OfferCredentialMessage,
      role: DidCommMessageRole.Sender,
    })

    // Assert
    credentialRecord.assertProtocolVersion('v1')
    credentialRecord.assertState(CredentialState.OfferSent)
    await connectionService.assertConnectionOrOutOfBandExchange(messageContext, {
      lastReceivedMessage: proposalMessage ?? undefined,
      lastSentMessage: offerMessage ?? undefined,
      expectedConnectionId: credentialRecord.connectionId,
    })

    // This makes sure that the sender of the incoming message is authorized to do so.
    if (!credentialRecord.connectionId) {
      await connectionService.matchIncomingMessageToRequestMessageInOutOfBandExchange(messageContext, {
        expectedConnectionId: credentialRecord.connectionId,
      })
      credentialRecord.connectionId = connection?.id
    }

    const requestAttachment = requestMessage.getRequestAttachmentById(INDY_CREDENTIAL_REQUEST_ATTACHMENT_ID)

    if (!requestAttachment) {
      throw new CredoError(
        `Indy attachment with id ${INDY_CREDENTIAL_REQUEST_ATTACHMENT_ID} not found in request message`
      )
    }

    await this.indyCredentialFormat.processRequest(messageContext.agentContext, {
      credentialRecord,
      attachment: requestAttachment,
    })

    await didCommMessageRepository.saveAgentMessage(messageContext.agentContext, {
      agentMessage: requestMessage,
      role: DidCommMessageRole.Receiver,
      associatedRecordId: credentialRecord.id,
    })

    await this.updateState(messageContext.agentContext, credentialRecord, CredentialState.RequestReceived)

    return credentialRecord
  }

  /**
   * Create a {@link V1IssueCredentialMessage} as response to a received credential request.
   *
   * @returns Object containing issue credential message and associated credential record
   *
   */
  public async acceptRequest(
    agentContext: AgentContext,
    {
      credentialRecord,
      credentialFormats,
      comment,
      autoAcceptCredential,
    }: CredentialProtocolOptions.AcceptCredentialRequestOptions<[LegacyIndyCredentialFormatService]>
  ): Promise<CredentialProtocolOptions.CredentialProtocolMsgReturnType<V1IssueCredentialMessage>> {
    // Assert
    credentialRecord.assertProtocolVersion('v1')
    credentialRecord.assertState(CredentialState.RequestReceived)
    if (credentialFormats) this.assertOnlyIndyFormat(credentialFormats)

    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    const offerMessage = await didCommMessageRepository.getAgentMessage(agentContext, {
      associatedRecordId: credentialRecord.id,
      messageClass: V1OfferCredentialMessage,
      role: DidCommMessageRole.Sender,
    })
    const requestMessage = await didCommMessageRepository.getAgentMessage(agentContext, {
      associatedRecordId: credentialRecord.id,
      messageClass: V1RequestCredentialMessage,
      role: DidCommMessageRole.Receiver,
    })

    const offerAttachment = offerMessage.getOfferAttachmentById(INDY_CREDENTIAL_OFFER_ATTACHMENT_ID)
    const requestAttachment = requestMessage.getRequestAttachmentById(INDY_CREDENTIAL_REQUEST_ATTACHMENT_ID)

    if (!offerAttachment || !requestAttachment) {
      throw new CredoError(
        `Missing data payload in offer or request attachment in credential Record ${credentialRecord.id}`
      )
    }

    const { attachment } = await this.indyCredentialFormat.acceptRequest(agentContext, {
      credentialRecord,
      requestAttachment,
      offerAttachment,
      attachmentId: INDY_CREDENTIAL_ATTACHMENT_ID,
      credentialFormats,
    })

    const issueMessage = new V1IssueCredentialMessage({
      comment,
      credentialAttachments: [attachment],
      attachments: credentialRecord.linkedAttachments,
    })

    issueMessage.setThread({ threadId: credentialRecord.threadId, parentThreadId: credentialRecord.parentThreadId })
    issueMessage.setPleaseAck()

    await didCommMessageRepository.saveAgentMessage(agentContext, {
      agentMessage: issueMessage,
      associatedRecordId: credentialRecord.id,
      role: DidCommMessageRole.Sender,
    })

    credentialRecord.autoAcceptCredential = autoAcceptCredential ?? credentialRecord.autoAcceptCredential
    await this.updateState(agentContext, credentialRecord, CredentialState.CredentialIssued)

    return { message: issueMessage, credentialRecord }
  }

  /**
   * Process an incoming {@link V1IssueCredentialMessage}
   *
   * @param messageContext The message context containing a credential acknowledgement message
   * @returns credential record associated with the credential acknowledgement message
   *
   */
  public async processCredential(
    messageContext: InboundMessageContext<V1IssueCredentialMessage>
  ): Promise<CredentialExchangeRecord> {
    const { message: issueMessage, connection, agentContext } = messageContext

    agentContext.config.logger.debug(`Processing credential with id ${issueMessage.id}`)

    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    // TODO: with this method, we should update the credential protocol to use the ConnectionApi, so it
    // only depends on the public api, rather than the internal API (this helps with breaking changes)
    const connectionService = agentContext.dependencyManager.resolve(ConnectionService)

    const credentialRecord = await this.getByProperties(messageContext.agentContext, {
      threadId: issueMessage.threadId,
      role: CredentialRole.Holder,
      connectionId: connection?.id,
    })

    const requestCredentialMessage = await didCommMessageRepository.findAgentMessage(messageContext.agentContext, {
      associatedRecordId: credentialRecord.id,
      messageClass: V1RequestCredentialMessage,
      role: DidCommMessageRole.Sender,
    })
    const offerCredentialMessage = await didCommMessageRepository.findAgentMessage(messageContext.agentContext, {
      associatedRecordId: credentialRecord.id,
      messageClass: V1OfferCredentialMessage,
      role: DidCommMessageRole.Receiver,
    })

    // Assert
    credentialRecord.assertProtocolVersion('v1')
    credentialRecord.assertState(CredentialState.RequestSent)
    await connectionService.assertConnectionOrOutOfBandExchange(messageContext, {
      lastReceivedMessage: offerCredentialMessage,
      lastSentMessage: requestCredentialMessage,
      expectedConnectionId: credentialRecord.connectionId,
    })

    const issueAttachment = issueMessage.getCredentialAttachmentById(INDY_CREDENTIAL_ATTACHMENT_ID)
    if (!issueAttachment) {
      throw new CredoError('Missing indy credential attachment in processCredential')
    }

    const requestAttachment = requestCredentialMessage?.getRequestAttachmentById(INDY_CREDENTIAL_REQUEST_ATTACHMENT_ID)
    if (!requestAttachment) {
      throw new CredoError('Missing indy credential request attachment in processCredential')
    }

    const offerAttachment = offerCredentialMessage?.getOfferAttachmentById(INDY_CREDENTIAL_OFFER_ATTACHMENT_ID)
    if (!offerAttachment) {
      throw new CredoError('Missing indy credential request attachment in processCredential')
    }

    await this.indyCredentialFormat.processCredential(messageContext.agentContext, {
      offerAttachment,
      attachment: issueAttachment,
      credentialRecord,
      requestAttachment,
    })

    await didCommMessageRepository.saveAgentMessage(messageContext.agentContext, {
      agentMessage: issueMessage,
      role: DidCommMessageRole.Receiver,
      associatedRecordId: credentialRecord.id,
    })

    await this.updateState(messageContext.agentContext, credentialRecord, CredentialState.CredentialReceived)

    return credentialRecord
  }

  /**
   * Create a {@link CredentialAckMessage} as response to a received credential.
   *
   * @param credentialRecord The credential record for which to create the credential acknowledgement
   * @returns Object containing credential acknowledgement message and associated credential record
   *
   */
  public async acceptCredential(
    agentContext: AgentContext,
    { credentialRecord }: CredentialProtocolOptions.AcceptCredentialOptions
  ): Promise<CredentialProtocolOptions.CredentialProtocolMsgReturnType<V1CredentialAckMessage>> {
    credentialRecord.assertProtocolVersion('v1')
    credentialRecord.assertState(CredentialState.CredentialReceived)

    // Create message
    const ackMessage = new V1CredentialAckMessage({
      status: AckStatus.OK,
      threadId: credentialRecord.threadId,
    })

    ackMessage.setThread({ threadId: credentialRecord.threadId, parentThreadId: credentialRecord.parentThreadId })

    await this.updateState(agentContext, credentialRecord, CredentialState.Done)

    return { message: ackMessage, credentialRecord }
  }

  /**
   * Process a received {@link CredentialAckMessage}.
   *
   * @param messageContext The message context containing a credential acknowledgement message
   * @returns credential record associated with the credential acknowledgement message
   *
   */
  public async processAck(
    messageContext: InboundMessageContext<V1CredentialAckMessage>
  ): Promise<CredentialExchangeRecord> {
    const { message: ackMessage, connection, agentContext } = messageContext

    agentContext.config.logger.debug(`Processing credential ack with id ${ackMessage.id}`)

    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    // TODO: with this method, we should update the credential protocol to use the ConnectionApi, so it
    // only depends on the public api, rather than the internal API (this helps with breaking changes)
    const connectionService = agentContext.dependencyManager.resolve(ConnectionService)

    const credentialRecord = await this.getByProperties(messageContext.agentContext, {
      threadId: ackMessage.threadId,

      role: CredentialRole.Issuer,
      connectionId: connection?.id,
    })

    const requestCredentialMessage = await didCommMessageRepository.getAgentMessage(messageContext.agentContext, {
      associatedRecordId: credentialRecord.id,
      messageClass: V1RequestCredentialMessage,
      role: DidCommMessageRole.Receiver,
    })
    const issueCredentialMessage = await didCommMessageRepository.getAgentMessage(messageContext.agentContext, {
      associatedRecordId: credentialRecord.id,
      messageClass: V1IssueCredentialMessage,
      role: DidCommMessageRole.Sender,
    })

    // Assert
    credentialRecord.assertProtocolVersion('v1')
    credentialRecord.assertState(CredentialState.CredentialIssued)
    await connectionService.assertConnectionOrOutOfBandExchange(messageContext, {
      lastReceivedMessage: requestCredentialMessage,
      lastSentMessage: issueCredentialMessage,
      expectedConnectionId: credentialRecord.connectionId,
    })

    // Update record
    await this.updateState(messageContext.agentContext, credentialRecord, CredentialState.Done)

    return credentialRecord
  }

  /**
   * Create a {@link V1CredentialProblemReportMessage} to be sent.
   *
   * @param message message to send
   * @returns a {@link V1CredentialProblemReportMessage}
   *
   */
  public async createProblemReport(
    _agentContext: AgentContext,
    { credentialRecord, description }: CredentialProtocolOptions.CreateCredentialProblemReportOptions
  ): Promise<CredentialProtocolOptions.CredentialProtocolMsgReturnType<ProblemReportMessage>> {
    const message = new V1CredentialProblemReportMessage({
      description: {
        en: description,
        code: CredentialProblemReportReason.IssuanceAbandoned,
      },
    })

    return { message, credentialRecord }
  }

  // AUTO RESPOND METHODS
  public async shouldAutoRespondToProposal(
    agentContext: AgentContext,
    options: {
      credentialRecord: CredentialExchangeRecord
      proposalMessage: V1ProposeCredentialMessage
    }
  ) {
    const { credentialRecord, proposalMessage } = options

    const credentialsModuleConfig = agentContext.dependencyManager.resolve(CredentialsModuleConfig)

    const autoAccept = composeCredentialAutoAccept(
      credentialRecord.autoAcceptCredential,
      credentialsModuleConfig.autoAcceptCredentials
    )

    // Handle always / never cases
    if (autoAccept === AutoAcceptCredential.Always) return true
    if (autoAccept === AutoAcceptCredential.Never) return false

    const offerMessage = await this.findOfferMessage(agentContext, credentialRecord.id)

    // Do not auto accept if missing properties
    if (!offerMessage || !offerMessage.credentialPreview) return false
    if (!proposalMessage.credentialPreview || !proposalMessage.credentialDefinitionId) return false

    const credentialOfferJson = offerMessage.indyCredentialOffer

    // Check if credential definition id matches
    if (!credentialOfferJson) return false
    if (credentialOfferJson.cred_def_id !== proposalMessage.credentialDefinitionId) return false

    // Check if preview values match
    return areCredentialPreviewAttributesEqual(
      proposalMessage.credentialPreview.attributes,
      offerMessage.credentialPreview.attributes
    )
  }

  public async shouldAutoRespondToOffer(
    agentContext: AgentContext,
    options: {
      credentialRecord: CredentialExchangeRecord
      offerMessage: V1OfferCredentialMessage
    }
  ) {
    const { credentialRecord, offerMessage } = options

    const credentialsModuleConfig = agentContext.dependencyManager.resolve(CredentialsModuleConfig)

    const autoAccept = composeCredentialAutoAccept(
      credentialRecord.autoAcceptCredential,
      credentialsModuleConfig.autoAcceptCredentials
    )

    // Handle always / never cases
    if (autoAccept === AutoAcceptCredential.Always) return true
    if (autoAccept === AutoAcceptCredential.Never) return false

    const proposalMessage = await this.findProposalMessage(agentContext, credentialRecord.id)

    // Do not auto accept if missing properties
    if (!offerMessage.credentialPreview) return false
    if (!proposalMessage || !proposalMessage.credentialPreview || !proposalMessage.credentialDefinitionId) return false

    const credentialOfferJson = offerMessage.indyCredentialOffer

    // Check if credential definition id matches
    if (!credentialOfferJson) return false
    if (credentialOfferJson.cred_def_id !== proposalMessage.credentialDefinitionId) return false

    // Check if preview values match
    return areCredentialPreviewAttributesEqual(
      proposalMessage.credentialPreview.attributes,
      offerMessage.credentialPreview.attributes
    )
  }

  public async shouldAutoRespondToRequest(
    agentContext: AgentContext,
    options: {
      credentialRecord: CredentialExchangeRecord
      requestMessage: V1RequestCredentialMessage
    }
  ) {
    const { credentialRecord, requestMessage } = options

    const credentialsModuleConfig = agentContext.dependencyManager.resolve(CredentialsModuleConfig)

    const autoAccept = composeCredentialAutoAccept(
      credentialRecord.autoAcceptCredential,
      credentialsModuleConfig.autoAcceptCredentials
    )

    // Handle always / never cases
    if (autoAccept === AutoAcceptCredential.Always) return true
    if (autoAccept === AutoAcceptCredential.Never) return false

    const offerMessage = await this.findOfferMessage(agentContext, credentialRecord.id)
    if (!offerMessage) return false

    const offerAttachment = offerMessage.getOfferAttachmentById(INDY_CREDENTIAL_OFFER_ATTACHMENT_ID)
    const requestAttachment = requestMessage.getRequestAttachmentById(INDY_CREDENTIAL_REQUEST_ATTACHMENT_ID)

    if (!offerAttachment || !requestAttachment) return false

    return this.indyCredentialFormat.shouldAutoRespondToRequest(agentContext, {
      credentialRecord,
      offerAttachment,
      requestAttachment,
    })
  }

  public async shouldAutoRespondToCredential(
    agentContext: AgentContext,
    options: {
      credentialRecord: CredentialExchangeRecord
      credentialMessage: V1IssueCredentialMessage
    }
  ) {
    const { credentialRecord, credentialMessage } = options

    const credentialsModuleConfig = agentContext.dependencyManager.resolve(CredentialsModuleConfig)

    const autoAccept = composeCredentialAutoAccept(
      credentialRecord.autoAcceptCredential,
      credentialsModuleConfig.autoAcceptCredentials
    )

    // Handle always / never cases
    if (autoAccept === AutoAcceptCredential.Always) return true
    if (autoAccept === AutoAcceptCredential.Never) return false

    const requestMessage = await this.findRequestMessage(agentContext, credentialRecord.id)
    const offerMessage = await this.findOfferMessage(agentContext, credentialRecord.id)

    const credentialAttachment = credentialMessage.getCredentialAttachmentById(INDY_CREDENTIAL_ATTACHMENT_ID)
    if (!credentialAttachment) return false

    const requestAttachment = requestMessage?.getRequestAttachmentById(INDY_CREDENTIAL_REQUEST_ATTACHMENT_ID)
    if (!requestAttachment) return false

    const offerAttachment = offerMessage?.getOfferAttachmentById(INDY_CREDENTIAL_OFFER_ATTACHMENT_ID)

    return this.indyCredentialFormat.shouldAutoRespondToCredential(agentContext, {
      credentialRecord,
      credentialAttachment,
      requestAttachment,
      offerAttachment,
    })
  }

  public async findProposalMessage(agentContext: AgentContext, credentialExchangeId: string) {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    return await didCommMessageRepository.findAgentMessage(agentContext, {
      associatedRecordId: credentialExchangeId,
      messageClass: V1ProposeCredentialMessage,
    })
  }

  public async findOfferMessage(agentContext: AgentContext, credentialExchangeId: string) {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    return await didCommMessageRepository.findAgentMessage(agentContext, {
      associatedRecordId: credentialExchangeId,
      messageClass: V1OfferCredentialMessage,
    })
  }

  public async findRequestMessage(agentContext: AgentContext, credentialExchangeId: string) {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    return await didCommMessageRepository.findAgentMessage(agentContext, {
      associatedRecordId: credentialExchangeId,
      messageClass: V1RequestCredentialMessage,
    })
  }

  public async findCredentialMessage(agentContext: AgentContext, credentialExchangeId: string) {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    return await didCommMessageRepository.findAgentMessage(agentContext, {
      associatedRecordId: credentialExchangeId,
      messageClass: V1IssueCredentialMessage,
    })
  }

  public async getFormatData(
    agentContext: AgentContext,
    credentialExchangeId: string
  ): Promise<
    CredentialProtocolOptions.GetCredentialFormatDataReturn<
      ExtractCredentialFormats<[LegacyIndyCredentialFormatService]>
    >
  > {
    // TODO: we could looking at fetching all record using a single query and then filtering based on the type of the message.
    const [proposalMessage, offerMessage, requestMessage, credentialMessage] = await Promise.all([
      this.findProposalMessage(agentContext, credentialExchangeId),
      this.findOfferMessage(agentContext, credentialExchangeId),
      this.findRequestMessage(agentContext, credentialExchangeId),
      this.findCredentialMessage(agentContext, credentialExchangeId),
    ])

    const indyProposal = proposalMessage
      ? JsonTransformer.toJSON(this.rfc0592ProposalFromV1ProposeMessage(proposalMessage))
      : undefined

    const indyOffer = offerMessage?.indyCredentialOffer ?? undefined
    const indyRequest = requestMessage?.indyCredentialRequest ?? undefined
    const indyCredential = credentialMessage?.indyCredential ?? undefined

    return {
      proposalAttributes: proposalMessage?.credentialPreview?.attributes,
      proposal: proposalMessage
        ? {
            indy: indyProposal,
          }
        : undefined,
      offerAttributes: offerMessage?.credentialPreview?.attributes,
      offer: offerMessage
        ? {
            indy: indyOffer,
          }
        : undefined,
      request: requestMessage
        ? {
            indy: indyRequest,
          }
        : undefined,
      credential: credentialMessage
        ? {
            indy: indyCredential,
          }
        : undefined,
    }
  }

  private rfc0592ProposalFromV1ProposeMessage(proposalMessage: V1ProposeCredentialMessage) {
    const indyCredentialProposal = new AnonCredsCredentialProposal({
      credentialDefinitionId: proposalMessage.credentialDefinitionId,
      schemaId: proposalMessage.schemaId,
      issuerDid: proposalMessage.issuerDid,
      schemaIssuerDid: proposalMessage.schemaIssuerDid,
      schemaName: proposalMessage.schemaName,
      schemaVersion: proposalMessage.schemaVersion,
    })

    return indyCredentialProposal
  }

  private assertOnlyIndyFormat(credentialFormats: Record<string, unknown>) {
    const formatKeys = Object.keys(credentialFormats)

    // It's fine to not have any formats in some cases, if indy is required the method that calls this should check for this
    if (formatKeys.length === 0) return

    if (formatKeys.length !== 1 || !formatKeys.includes('indy')) {
      throw new CredoError('Only indy credential format is supported for issue credential v1 protocol')
    }
  }

  public getFormatServiceForRecordType(credentialRecordType: string) {
    if (credentialRecordType !== this.indyCredentialFormat.credentialRecordType) {
      throw new CredoError(
        `Unsupported credential record type ${credentialRecordType} for v1 issue credential protocol (need ${this.indyCredentialFormat.credentialRecordType})`
      )
    }

    return this.indyCredentialFormat
  }
}
