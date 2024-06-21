import type { AgentContext } from '../../../../agent'
import type { Attachment } from '../../../../decorators/attachment/Attachment'
import type {
  ExtractProofFormats,
  ProofFormatCredentialForRequestPayload,
  ProofFormatPayload,
  ProofFormatService,
} from '../../formats'
import type { ProofFormatSpec } from '../../models/ProofFormatSpec'
import type { ProofExchangeRecord } from '../../repository'

import { CredoError } from '../../../../error'
import { DidCommMessageRepository, DidCommMessageRole } from '../../../../storage/didcomm'

import { V2PresentationMessage, V2ProposePresentationMessage, V2RequestPresentationMessage } from './messages'

export class ProofFormatCoordinator<PFs extends ProofFormatService[]> {
  /**
   * Create a {@link V2ProposePresentationMessage}.
   *
   * @param options
   * @returns The created {@link V2ProposePresentationMessage}
   *
   */
  public async createProposal(
    agentContext: AgentContext,
    {
      proofFormats,
      formatServices,
      proofRecord,
      comment,
      goalCode,
      goal,
    }: {
      formatServices: ProofFormatService[]
      proofFormats: ProofFormatPayload<ExtractProofFormats<PFs>, 'createProposal'>
      proofRecord: ProofExchangeRecord
      comment?: string
      goalCode?: string
      goal?: string
    }
  ): Promise<V2ProposePresentationMessage> {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    // create message. there are two arrays in each message, one for formats the other for attachments
    const formats: ProofFormatSpec[] = []
    const proposalAttachments: Attachment[] = []

    for (const formatService of formatServices) {
      const { format, attachment } = await formatService.createProposal(agentContext, {
        proofFormats,
        proofRecord,
      })

      proposalAttachments.push(attachment)
      formats.push(format)
    }

    const message = new V2ProposePresentationMessage({
      id: proofRecord.threadId,
      formats,
      proposalAttachments,
      comment: comment,
      goalCode,
      goal,
    })

    message.setThread({ threadId: proofRecord.threadId, parentThreadId: proofRecord.parentThreadId })

    await didCommMessageRepository.saveOrUpdateAgentMessage(agentContext, {
      agentMessage: message,
      role: DidCommMessageRole.Sender,
      associatedRecordId: proofRecord.id,
    })

    return message
  }

  public async processProposal(
    agentContext: AgentContext,
    {
      proofRecord,
      message,
      formatServices,
    }: {
      proofRecord: ProofExchangeRecord
      message: V2ProposePresentationMessage
      formatServices: ProofFormatService[]
    }
  ) {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    for (const formatService of formatServices) {
      const attachment = this.getAttachmentForService(formatService, message.formats, message.proposalAttachments)

      await formatService.processProposal(agentContext, {
        attachment,
        proofRecord,
      })
    }

    await didCommMessageRepository.saveOrUpdateAgentMessage(agentContext, {
      agentMessage: message,
      role: DidCommMessageRole.Receiver,
      associatedRecordId: proofRecord.id,
    })
  }

  public async acceptProposal(
    agentContext: AgentContext,
    {
      proofRecord,
      proofFormats,
      formatServices,
      comment,
      goalCode,
      goal,
      presentMultiple,
      willConfirm,
    }: {
      proofRecord: ProofExchangeRecord
      proofFormats?: ProofFormatPayload<ExtractProofFormats<PFs>, 'acceptProposal'>
      formatServices: ProofFormatService[]
      comment?: string
      goalCode?: string
      goal?: string
      presentMultiple?: boolean
      willConfirm?: boolean
    }
  ) {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    // create message. there are two arrays in each message, one for formats the other for attachments
    const formats: ProofFormatSpec[] = []
    const requestAttachments: Attachment[] = []

    const proposalMessage = await didCommMessageRepository.getAgentMessage(agentContext, {
      associatedRecordId: proofRecord.id,
      messageClass: V2ProposePresentationMessage,
      role: DidCommMessageRole.Receiver,
    })

    for (const formatService of formatServices) {
      const proposalAttachment = this.getAttachmentForService(
        formatService,
        proposalMessage.formats,
        proposalMessage.proposalAttachments
      )

      const { attachment, format } = await formatService.acceptProposal(agentContext, {
        proofRecord,
        proofFormats,
        proposalAttachment,
      })

      requestAttachments.push(attachment)
      formats.push(format)
    }

    const message = new V2RequestPresentationMessage({
      formats,
      requestAttachments,
      comment,
      goalCode,
      goal,
      presentMultiple,
      willConfirm,
    })

    message.setThread({ threadId: proofRecord.threadId, parentThreadId: proofRecord.parentThreadId })

    await didCommMessageRepository.saveOrUpdateAgentMessage(agentContext, {
      agentMessage: message,
      associatedRecordId: proofRecord.id,
      role: DidCommMessageRole.Sender,
    })

    return message
  }

  /**
   * Create a {@link V2RequestPresentationMessage}.
   *
   * @param options
   * @returns The created {@link V2RequestPresentationMessage}
   *
   */
  public async createRequest(
    agentContext: AgentContext,
    {
      proofFormats,
      formatServices,
      proofRecord,
      comment,
      goalCode,
      goal,
      presentMultiple,
      willConfirm,
    }: {
      formatServices: ProofFormatService[]
      proofFormats: ProofFormatPayload<ExtractProofFormats<PFs>, 'createRequest'>
      proofRecord: ProofExchangeRecord
      comment?: string
      goalCode?: string
      goal?: string
      presentMultiple?: boolean
      willConfirm?: boolean
    }
  ): Promise<V2RequestPresentationMessage> {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    // create message. there are two arrays in each message, one for formats the other for attachments
    const formats: ProofFormatSpec[] = []
    const requestAttachments: Attachment[] = []

    for (const formatService of formatServices) {
      const { format, attachment } = await formatService.createRequest(agentContext, {
        proofFormats,
        proofRecord,
      })

      requestAttachments.push(attachment)
      formats.push(format)
    }

    const message = new V2RequestPresentationMessage({
      formats,
      comment,
      requestAttachments,
      goalCode,
      goal,
      presentMultiple,
      willConfirm,
    })

    message.setThread({ threadId: proofRecord.threadId, parentThreadId: proofRecord.parentThreadId })

    await didCommMessageRepository.saveOrUpdateAgentMessage(agentContext, {
      agentMessage: message,
      role: DidCommMessageRole.Sender,
      associatedRecordId: proofRecord.id,
    })

    return message
  }

  public async processRequest(
    agentContext: AgentContext,
    {
      proofRecord,
      message,
      formatServices,
    }: {
      proofRecord: ProofExchangeRecord
      message: V2RequestPresentationMessage
      formatServices: ProofFormatService[]
    }
  ) {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    for (const formatService of formatServices) {
      const attachment = this.getAttachmentForService(formatService, message.formats, message.requestAttachments)

      await formatService.processRequest(agentContext, {
        attachment,
        proofRecord,
      })
    }

    await didCommMessageRepository.saveOrUpdateAgentMessage(agentContext, {
      agentMessage: message,
      role: DidCommMessageRole.Receiver,
      associatedRecordId: proofRecord.id,
    })
  }

  public async acceptRequest(
    agentContext: AgentContext,
    {
      proofRecord,
      proofFormats,
      formatServices,
      comment,
      lastPresentation,
      goalCode,
      goal,
    }: {
      proofRecord: ProofExchangeRecord
      proofFormats?: ProofFormatPayload<ExtractProofFormats<PFs>, 'acceptRequest'>
      formatServices: ProofFormatService[]
      comment?: string
      lastPresentation?: boolean
      goalCode?: string
      goal?: string
    }
  ) {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    const requestMessage = await didCommMessageRepository.getAgentMessage(agentContext, {
      associatedRecordId: proofRecord.id,
      messageClass: V2RequestPresentationMessage,
      role: DidCommMessageRole.Receiver,
    })

    const proposalMessage = await didCommMessageRepository.findAgentMessage(agentContext, {
      associatedRecordId: proofRecord.id,
      messageClass: V2ProposePresentationMessage,
      role: DidCommMessageRole.Receiver,
    })

    // create message. there are two arrays in each message, one for formats the other for attachments
    const formats: ProofFormatSpec[] = []
    const presentationAttachments: Attachment[] = []

    for (const formatService of formatServices) {
      const requestAttachment = this.getAttachmentForService(
        formatService,
        requestMessage.formats,
        requestMessage.requestAttachments
      )

      const proposalAttachment = proposalMessage
        ? this.getAttachmentForService(formatService, proposalMessage.formats, proposalMessage.proposalAttachments)
        : undefined

      const { attachment, format } = await formatService.acceptRequest(agentContext, {
        requestAttachment,
        proposalAttachment,
        proofRecord,
        proofFormats,
      })

      presentationAttachments.push(attachment)
      formats.push(format)
    }

    const message = new V2PresentationMessage({
      formats,
      presentationAttachments,
      comment,
      lastPresentation,
      goalCode,
      goal,
    })

    message.setThread({ threadId: proofRecord.threadId, parentThreadId: proofRecord.parentThreadId })
    message.setPleaseAck()

    await didCommMessageRepository.saveOrUpdateAgentMessage(agentContext, {
      agentMessage: message,
      associatedRecordId: proofRecord.id,
      role: DidCommMessageRole.Sender,
    })

    return message
  }

  public async getCredentialsForRequest(
    agentContext: AgentContext,
    {
      proofRecord,
      proofFormats,
      formatServices,
    }: {
      proofRecord: ProofExchangeRecord
      proofFormats?: ProofFormatCredentialForRequestPayload<
        ExtractProofFormats<PFs>,
        'getCredentialsForRequest',
        'input'
      >
      formatServices: ProofFormatService[]
    }
  ): Promise<ProofFormatCredentialForRequestPayload<ExtractProofFormats<PFs>, 'getCredentialsForRequest', 'output'>> {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    const requestMessage = await didCommMessageRepository.getAgentMessage(agentContext, {
      associatedRecordId: proofRecord.id,
      messageClass: V2RequestPresentationMessage,
      role: DidCommMessageRole.Receiver,
    })

    const proposalMessage = await didCommMessageRepository.findAgentMessage(agentContext, {
      associatedRecordId: proofRecord.id,
      messageClass: V2ProposePresentationMessage,
      role: DidCommMessageRole.Receiver,
    })

    const credentialsForRequest: Record<string, unknown> = {}

    for (const formatService of formatServices) {
      const requestAttachment = this.getAttachmentForService(
        formatService,
        requestMessage.formats,
        requestMessage.requestAttachments
      )

      const proposalAttachment = proposalMessage
        ? this.getAttachmentForService(formatService, proposalMessage.formats, proposalMessage.proposalAttachments)
        : undefined

      const credentialsForFormat = await formatService.getCredentialsForRequest(agentContext, {
        requestAttachment,
        proposalAttachment,
        proofRecord,
        proofFormats,
      })

      credentialsForRequest[formatService.formatKey] = credentialsForFormat
    }

    return credentialsForRequest as ProofFormatCredentialForRequestPayload<
      ExtractProofFormats<PFs>,
      'getCredentialsForRequest',
      'output'
    >
  }

  public async selectCredentialsForRequest(
    agentContext: AgentContext,
    {
      proofRecord,
      proofFormats,
      formatServices,
    }: {
      proofRecord: ProofExchangeRecord
      proofFormats?: ProofFormatCredentialForRequestPayload<
        ExtractProofFormats<PFs>,
        'selectCredentialsForRequest',
        'input'
      >
      formatServices: ProofFormatService[]
    }
  ): Promise<
    ProofFormatCredentialForRequestPayload<ExtractProofFormats<PFs>, 'selectCredentialsForRequest', 'output'>
  > {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    const requestMessage = await didCommMessageRepository.getAgentMessage(agentContext, {
      associatedRecordId: proofRecord.id,
      messageClass: V2RequestPresentationMessage,
      role: DidCommMessageRole.Receiver,
    })

    const proposalMessage = await didCommMessageRepository.findAgentMessage(agentContext, {
      associatedRecordId: proofRecord.id,
      messageClass: V2ProposePresentationMessage,
      role: DidCommMessageRole.Receiver,
    })

    const credentialsForRequest: Record<string, unknown> = {}

    for (const formatService of formatServices) {
      const requestAttachment = this.getAttachmentForService(
        formatService,
        requestMessage.formats,
        requestMessage.requestAttachments
      )

      const proposalAttachment = proposalMessage
        ? this.getAttachmentForService(formatService, proposalMessage.formats, proposalMessage.proposalAttachments)
        : undefined

      const credentialsForFormat = await formatService.selectCredentialsForRequest(agentContext, {
        requestAttachment,
        proposalAttachment,
        proofRecord,
        proofFormats,
      })

      credentialsForRequest[formatService.formatKey] = credentialsForFormat
    }

    return credentialsForRequest as ProofFormatCredentialForRequestPayload<
      ExtractProofFormats<PFs>,
      'selectCredentialsForRequest',
      'output'
    >
  }

  public async processPresentation(
    agentContext: AgentContext,
    {
      proofRecord,
      message,
      requestMessage,
      formatServices,
    }: {
      proofRecord: ProofExchangeRecord
      message: V2PresentationMessage
      requestMessage: V2RequestPresentationMessage
      formatServices: ProofFormatService[]
    }
  ): Promise<{ isValid: true; message: undefined } | { isValid: false; message: string }> {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    const formatVerificationResults: boolean[] = []

    for (const formatService of formatServices) {
      const attachment = this.getAttachmentForService(formatService, message.formats, message.presentationAttachments)
      const requestAttachment = this.getAttachmentForService(
        formatService,
        requestMessage.formats,
        requestMessage.requestAttachments
      )

      try {
        // TODO: this should return a more complex object explaining why it is invalid
        const isValid = await formatService.processPresentation(agentContext, {
          attachment,
          requestAttachment,
          proofRecord,
        })

        formatVerificationResults.push(isValid)
      } catch (error) {
        return {
          message: error.message,
          isValid: false,
        }
      }
    }

    await didCommMessageRepository.saveOrUpdateAgentMessage(agentContext, {
      agentMessage: message,
      role: DidCommMessageRole.Receiver,
      associatedRecordId: proofRecord.id,
    })

    const isValid = formatVerificationResults.every((isValid) => isValid === true)

    if (isValid) {
      return {
        isValid,
        message: undefined,
      }
    } else {
      return {
        isValid,
        message: 'Not all presentations are valid',
      }
    }
  }

  public getAttachmentForService(
    credentialFormatService: ProofFormatService,
    formats: ProofFormatSpec[],
    attachments: Attachment[]
  ) {
    const attachmentId = this.getAttachmentIdForService(credentialFormatService, formats)
    const attachment = attachments.find((attachment) => attachment.id === attachmentId)

    if (!attachment) {
      throw new CredoError(`Attachment with id ${attachmentId} not found in attachments.`)
    }

    return attachment
  }

  private getAttachmentIdForService(credentialFormatService: ProofFormatService, formats: ProofFormatSpec[]) {
    const format = formats.find((format) => credentialFormatService.supportsFormat(format.format))

    if (!format) throw new CredoError(`No attachment found for service ${credentialFormatService.formatKey}`)

    return format.attachmentId
  }
}
