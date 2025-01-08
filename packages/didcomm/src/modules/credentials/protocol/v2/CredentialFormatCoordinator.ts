import type { AgentContext } from '@credo-ts/core'
import type { Attachment } from '../../../../decorators/attachment/Attachment'
import type { CredentialFormatPayload, CredentialFormatService, ExtractCredentialFormats } from '../../formats'
import type { CredentialFormatSpec } from '../../models'
import type { CredentialExchangeRecord } from '../../repository/CredentialExchangeRecord'

import { CredoError } from '@credo-ts/core'
import { DidCommMessageRepository, DidCommMessageRole } from '../../../../repository'

import {
  V2IssueCredentialMessage,
  V2OfferCredentialMessage,
  V2ProposeCredentialMessage,
  V2RequestCredentialMessage,
  V2CredentialPreview,
} from './messages'

export class CredentialFormatCoordinator<CFs extends CredentialFormatService[]> {
  /**
   * Create a {@link V2ProposeCredentialMessage}.
   *
   * @param options
   * @returns The created {@link V2ProposeCredentialMessage}
   *
   */
  public async createProposal(
    agentContext: AgentContext,
    {
      credentialFormats,
      formatServices,
      credentialRecord,
      comment,
      goalCode,
      goal,
    }: {
      formatServices: CredentialFormatService[]
      credentialFormats: CredentialFormatPayload<ExtractCredentialFormats<CFs>, 'createProposal'>
      credentialRecord: CredentialExchangeRecord
      comment?: string
      goalCode?: string
      goal?: string
    }
  ): Promise<V2ProposeCredentialMessage> {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    // create message. there are two arrays in each message, one for formats the other for attachments
    const formats: CredentialFormatSpec[] = []
    const proposalAttachments: Attachment[] = []
    let credentialPreview: V2CredentialPreview | undefined

    for (const formatService of formatServices) {
      const { format, attachment, previewAttributes } = await formatService.createProposal(agentContext, {
        credentialFormats,
        credentialRecord,
      })

      if (previewAttributes) {
        credentialPreview = new V2CredentialPreview({
          attributes: previewAttributes,
        })
      }

      proposalAttachments.push(attachment)
      formats.push(format)
    }

    credentialRecord.credentialAttributes = credentialPreview?.attributes

    const message = new V2ProposeCredentialMessage({
      id: credentialRecord.threadId,
      formats,
      proposalAttachments,
      comment,
      credentialPreview,
      goalCode,
      goal,
    })

    message.setThread({ threadId: credentialRecord.threadId, parentThreadId: credentialRecord.parentThreadId })

    await didCommMessageRepository.saveOrUpdateAgentMessage(agentContext, {
      agentMessage: message,
      role: DidCommMessageRole.Sender,
      associatedRecordId: credentialRecord.id,
    })

    return message
  }

  public async processProposal(
    agentContext: AgentContext,
    {
      credentialRecord,
      message,
      formatServices,
    }: {
      credentialRecord: CredentialExchangeRecord
      message: V2ProposeCredentialMessage
      formatServices: CredentialFormatService[]
    }
  ) {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    for (const formatService of formatServices) {
      const attachment = this.getAttachmentForService(formatService, message.formats, message.proposalAttachments)

      await formatService.processProposal(agentContext, {
        attachment,
        credentialRecord,
      })
    }

    await didCommMessageRepository.saveOrUpdateAgentMessage(agentContext, {
      agentMessage: message,
      role: DidCommMessageRole.Receiver,
      associatedRecordId: credentialRecord.id,
    })
  }

  public async acceptProposal(
    agentContext: AgentContext,
    {
      credentialRecord,
      credentialFormats,
      formatServices,
      comment,
      goalCode,
      goal,
    }: {
      credentialRecord: CredentialExchangeRecord
      credentialFormats?: CredentialFormatPayload<ExtractCredentialFormats<CFs>, 'acceptProposal'>
      formatServices: CredentialFormatService[]
      comment?: string
      goalCode?: string
      goal?: string
    }
  ) {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    // create message. there are two arrays in each message, one for formats the other for attachments
    const formats: CredentialFormatSpec[] = []
    const offerAttachments: Attachment[] = []
    let credentialPreview: V2CredentialPreview | undefined

    const proposalMessage = await didCommMessageRepository.getAgentMessage(agentContext, {
      associatedRecordId: credentialRecord.id,
      messageClass: V2ProposeCredentialMessage,
      role: DidCommMessageRole.Receiver,
    })

    // NOTE: We set the credential attributes from the proposal on the record as we've 'accepted' them
    // and can now use them to create the offer in the format services. It may be overwritten later on
    // if the user provided other attributes in the credentialFormats array.
    credentialRecord.credentialAttributes = proposalMessage.credentialPreview?.attributes

    for (const formatService of formatServices) {
      const proposalAttachment = this.getAttachmentForService(
        formatService,
        proposalMessage.formats,
        proposalMessage.proposalAttachments
      )

      const { attachment, format, previewAttributes } = await formatService.acceptProposal(agentContext, {
        credentialRecord,
        credentialFormats,
        proposalAttachment,
      })

      if (previewAttributes) {
        credentialPreview = new V2CredentialPreview({
          attributes: previewAttributes,
        })
      }

      offerAttachments.push(attachment)
      formats.push(format)
    }

    credentialRecord.credentialAttributes = credentialPreview?.attributes

    if (!credentialPreview) {
      // If no preview attributes were provided, use a blank preview. Not all formats use this object
      // but it is required by the protocol
      credentialPreview = new V2CredentialPreview({
        attributes: [],
      })
    }

    const message = new V2OfferCredentialMessage({
      formats,
      credentialPreview,
      offerAttachments,
      comment,
      goalCode,
      goal,
    })

    message.setThread({ threadId: credentialRecord.threadId, parentThreadId: credentialRecord.parentThreadId })

    await didCommMessageRepository.saveOrUpdateAgentMessage(agentContext, {
      agentMessage: message,
      associatedRecordId: credentialRecord.id,
      role: DidCommMessageRole.Sender,
    })

    return message
  }

  /**
   * Create a {@link V2OfferCredentialMessage}.
   *
   * @param options
   * @returns The created {@link V2OfferCredentialMessage}
   *
   */
  public async createOffer(
    agentContext: AgentContext,
    {
      credentialFormats,
      formatServices,
      credentialRecord,
      comment,
      goalCode,
      goal,
    }: {
      formatServices: CredentialFormatService[]
      credentialFormats: CredentialFormatPayload<ExtractCredentialFormats<CFs>, 'createOffer'>
      credentialRecord: CredentialExchangeRecord
      comment?: string
      goalCode?: string
      goal?: string
    }
  ): Promise<V2OfferCredentialMessage> {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    // create message. there are two arrays in each message, one for formats the other for attachments
    const formats: CredentialFormatSpec[] = []
    const offerAttachments: Attachment[] = []
    let credentialPreview: V2CredentialPreview | undefined

    for (const formatService of formatServices) {
      const { format, attachment, previewAttributes } = await formatService.createOffer(agentContext, {
        credentialFormats,
        credentialRecord,
      })

      if (previewAttributes) {
        credentialPreview = new V2CredentialPreview({
          attributes: previewAttributes,
        })
      }

      offerAttachments.push(attachment)
      formats.push(format)
    }

    credentialRecord.credentialAttributes = credentialPreview?.attributes

    if (!credentialPreview) {
      // If no preview attributes were provided, use a blank preview. Not all formats use this object
      // but it is required by the protocol
      credentialPreview = new V2CredentialPreview({
        attributes: [],
      })
    }

    const message = new V2OfferCredentialMessage({
      formats,
      comment,
      goalCode,
      goal,
      offerAttachments,
      credentialPreview,
    })

    message.setThread({ threadId: credentialRecord.threadId, parentThreadId: credentialRecord.parentThreadId })

    await didCommMessageRepository.saveOrUpdateAgentMessage(agentContext, {
      agentMessage: message,
      role: DidCommMessageRole.Sender,
      associatedRecordId: credentialRecord.id,
    })

    return message
  }

  public async processOffer(
    agentContext: AgentContext,
    {
      credentialRecord,
      message,
      formatServices,
    }: {
      credentialRecord: CredentialExchangeRecord
      message: V2OfferCredentialMessage
      formatServices: CredentialFormatService[]
    }
  ) {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    for (const formatService of formatServices) {
      const attachment = this.getAttachmentForService(formatService, message.formats, message.offerAttachments)

      await formatService.processOffer(agentContext, {
        attachment,
        credentialRecord,
      })
    }

    await didCommMessageRepository.saveOrUpdateAgentMessage(agentContext, {
      agentMessage: message,
      role: DidCommMessageRole.Receiver,
      associatedRecordId: credentialRecord.id,
    })
  }

  public async acceptOffer(
    agentContext: AgentContext,
    {
      credentialRecord,
      credentialFormats,
      formatServices,
      comment,
      goalCode,
      goal,
    }: {
      credentialRecord: CredentialExchangeRecord
      credentialFormats?: CredentialFormatPayload<ExtractCredentialFormats<CFs>, 'acceptOffer'>
      formatServices: CredentialFormatService[]
      comment?: string
      goalCode?: string
      goal?: string
    }
  ) {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    const offerMessage = await didCommMessageRepository.getAgentMessage(agentContext, {
      associatedRecordId: credentialRecord.id,
      messageClass: V2OfferCredentialMessage,
      role: DidCommMessageRole.Receiver,
    })

    // create message. there are two arrays in each message, one for formats the other for attachments
    const formats: CredentialFormatSpec[] = []
    const requestAttachments: Attachment[] = []
    const requestAppendAttachments: Attachment[] = []

    for (const formatService of formatServices) {
      const offerAttachment = this.getAttachmentForService(
        formatService,
        offerMessage.formats,
        offerMessage.offerAttachments
      )

      const { attachment, format, appendAttachments } = await formatService.acceptOffer(agentContext, {
        offerAttachment,
        credentialRecord,
        credentialFormats,
      })

      requestAttachments.push(attachment)
      formats.push(format)
      if (appendAttachments) requestAppendAttachments.push(...appendAttachments)
    }

    credentialRecord.credentialAttributes = offerMessage.credentialPreview?.attributes

    const message = new V2RequestCredentialMessage({
      formats,
      attachments: requestAppendAttachments,
      requestAttachments: requestAttachments,
      comment,
      goalCode,
      goal,
    })

    message.setThread({ threadId: credentialRecord.threadId, parentThreadId: credentialRecord.parentThreadId })

    await didCommMessageRepository.saveOrUpdateAgentMessage(agentContext, {
      agentMessage: message,
      associatedRecordId: credentialRecord.id,
      role: DidCommMessageRole.Sender,
    })

    return message
  }

  /**
   * Create a {@link V2RequestCredentialMessage}.
   *
   * @param options
   * @returns The created {@link V2RequestCredentialMessage}
   *
   */
  public async createRequest(
    agentContext: AgentContext,
    {
      credentialFormats,
      formatServices,
      credentialRecord,
      comment,
      goalCode,
      goal,
    }: {
      formatServices: CredentialFormatService[]
      credentialFormats: CredentialFormatPayload<ExtractCredentialFormats<CFs>, 'createRequest'>
      credentialRecord: CredentialExchangeRecord
      comment?: string
      goalCode?: string
      goal?: string
    }
  ): Promise<V2RequestCredentialMessage> {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    // create message. there are two arrays in each message, one for formats the other for attachments
    const formats: CredentialFormatSpec[] = []
    const requestAttachments: Attachment[] = []

    for (const formatService of formatServices) {
      const { format, attachment } = await formatService.createRequest(agentContext, {
        credentialFormats,
        credentialRecord,
      })

      requestAttachments.push(attachment)
      formats.push(format)
    }

    const message = new V2RequestCredentialMessage({
      formats,
      comment,
      goalCode,
      goal,
      requestAttachments: requestAttachments,
    })

    message.setThread({ threadId: credentialRecord.threadId, parentThreadId: credentialRecord.parentThreadId })

    await didCommMessageRepository.saveOrUpdateAgentMessage(agentContext, {
      agentMessage: message,
      role: DidCommMessageRole.Sender,
      associatedRecordId: credentialRecord.id,
    })

    return message
  }

  public async processRequest(
    agentContext: AgentContext,
    {
      credentialRecord,
      message,
      formatServices,
    }: {
      credentialRecord: CredentialExchangeRecord
      message: V2RequestCredentialMessage
      formatServices: CredentialFormatService[]
    }
  ) {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    for (const formatService of formatServices) {
      const attachment = this.getAttachmentForService(formatService, message.formats, message.requestAttachments)

      await formatService.processRequest(agentContext, {
        attachment,
        credentialRecord,
      })
    }

    await didCommMessageRepository.saveOrUpdateAgentMessage(agentContext, {
      agentMessage: message,
      role: DidCommMessageRole.Receiver,
      associatedRecordId: credentialRecord.id,
    })
  }

  public async acceptRequest(
    agentContext: AgentContext,
    {
      credentialRecord,
      credentialFormats,
      formatServices,
      comment,
      goalCode,
      goal,
    }: {
      credentialRecord: CredentialExchangeRecord
      credentialFormats?: CredentialFormatPayload<ExtractCredentialFormats<CFs>, 'acceptRequest'>
      formatServices: CredentialFormatService[]
      comment?: string
      goalCode?: string
      goal?: string
    }
  ) {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    const requestMessage = await didCommMessageRepository.getAgentMessage(agentContext, {
      associatedRecordId: credentialRecord.id,
      messageClass: V2RequestCredentialMessage,
      role: DidCommMessageRole.Receiver,
    })

    const offerMessage = await didCommMessageRepository.findAgentMessage(agentContext, {
      associatedRecordId: credentialRecord.id,
      messageClass: V2OfferCredentialMessage,
      role: DidCommMessageRole.Sender,
    })

    // create message. there are two arrays in each message, one for formats the other for attachments
    const formats: CredentialFormatSpec[] = []
    const credentialAttachments: Attachment[] = []

    for (const formatService of formatServices) {
      const requestAttachment = this.getAttachmentForService(
        formatService,
        requestMessage.formats,
        requestMessage.requestAttachments
      )

      const offerAttachment = offerMessage
        ? this.getAttachmentForService(formatService, offerMessage.formats, offerMessage.offerAttachments)
        : undefined

      const { attachment, format } = await formatService.acceptRequest(agentContext, {
        requestAttachment,
        offerAttachment,
        credentialRecord,
        credentialFormats,
        requestAppendAttachments: requestMessage.appendedAttachments,
      })

      credentialAttachments.push(attachment)
      formats.push(format)
    }

    const message = new V2IssueCredentialMessage({
      formats,
      credentialAttachments: credentialAttachments,
      comment,
      goalCode,
      goal,
    })

    message.setThread({ threadId: credentialRecord.threadId, parentThreadId: credentialRecord.parentThreadId })
    message.setPleaseAck()

    await didCommMessageRepository.saveOrUpdateAgentMessage(agentContext, {
      agentMessage: message,
      associatedRecordId: credentialRecord.id,
      role: DidCommMessageRole.Sender,
    })

    return message
  }

  public async processCredential(
    agentContext: AgentContext,
    {
      credentialRecord,
      message,
      requestMessage,
      formatServices,
    }: {
      credentialRecord: CredentialExchangeRecord
      message: V2IssueCredentialMessage
      requestMessage: V2RequestCredentialMessage
      formatServices: CredentialFormatService[]
    }
  ) {
    const didCommMessageRepository = agentContext.dependencyManager.resolve(DidCommMessageRepository)

    const offerMessage = await didCommMessageRepository.getAgentMessage(agentContext, {
      associatedRecordId: credentialRecord.id,
      messageClass: V2OfferCredentialMessage,
      role: DidCommMessageRole.Receiver,
    })

    for (const formatService of formatServices) {
      const offerAttachment = this.getAttachmentForService(
        formatService,
        offerMessage.formats,
        offerMessage.offerAttachments
      )

      const attachment = this.getAttachmentForService(formatService, message.formats, message.credentialAttachments)
      const requestAttachment = this.getAttachmentForService(
        formatService,
        requestMessage.formats,
        requestMessage.requestAttachments
      )

      await formatService.processCredential(agentContext, {
        attachment,
        offerAttachment,
        requestAttachment,
        credentialRecord,
        requestAppendAttachments: requestMessage.appendedAttachments,
      })
    }

    await didCommMessageRepository.saveOrUpdateAgentMessage(agentContext, {
      agentMessage: message,
      role: DidCommMessageRole.Receiver,
      associatedRecordId: credentialRecord.id,
    })
  }

  public getAttachmentForService(
    credentialFormatService: CredentialFormatService,
    formats: CredentialFormatSpec[],
    attachments: Attachment[]
  ) {
    const attachmentId = this.getAttachmentIdForService(credentialFormatService, formats)
    const attachment = attachments.find((attachment) => attachment.id === attachmentId)

    if (!attachment) {
      throw new CredoError(`Attachment with id ${attachmentId} not found in attachments.`)
    }

    return attachment
  }

  private getAttachmentIdForService(credentialFormatService: CredentialFormatService, formats: CredentialFormatSpec[]) {
    const format = formats.find((format) => credentialFormatService.supportsFormat(format.format))

    if (!format) throw new CredoError(`No attachment found for service ${credentialFormatService.formatKey}`)

    return format.attachmentId
  }
}
