import type { AnonCredsCredentialFormat, AnonCredsCredentialProposalFormat } from './AnonCredsCredentialFormat'
import type { AnonCredsCredential, AnonCredsCredentialOffer, AnonCredsCredentialRequest } from '../models'
import type { AnonCredsIssuerService, AnonCredsHolderService } from '../services'
import type { AnonCredsCredentialMetadata, AnonCredsCredentialRequestMetadata } from '../utils/metadata'
import type {
  CredentialFormatService,
  AgentContext,
  CredentialFormatCreateProposalOptions,
  CredentialFormatCreateProposalReturn,
  CredentialFormatProcessOptions,
  CredentialFormatAcceptProposalOptions,
  CredentialFormatCreateOfferReturn,
  CredentialFormatCreateOfferOptions,
  CredentialFormatAcceptOfferOptions,
  CredentialFormatCreateReturn,
  CredentialFormatAcceptRequestOptions,
  CredentialFormatProcessCredentialOptions,
  CredentialFormatAutoRespondProposalOptions,
  CredentialFormatAutoRespondOfferOptions,
  CredentialFormatAutoRespondRequestOptions,
  CredentialFormatAutoRespondCredentialOptions,
  CredentialExchangeRecord,
  CredentialPreviewAttributeOptions,
  LinkedAttachment,
} from '@credo-ts/core'

import {
  ProblemReportError,
  MessageValidator,
  CredentialFormatSpec,
  CredoError,
  Attachment,
  JsonEncoder,
  utils,
  CredentialProblemReportReason,
  JsonTransformer,
} from '@credo-ts/core'

import { AnonCredsCredentialProposal } from '../models/AnonCredsCredentialProposal'
import {
  AnonCredsCredentialDefinitionRepository,
  AnonCredsRevocationRegistryDefinitionPrivateRepository,
  AnonCredsRevocationRegistryState,
} from '../repository'
import { AnonCredsIssuerServiceSymbol, AnonCredsHolderServiceSymbol } from '../services'
import {
  dateToTimestamp,
  fetchCredentialDefinition,
  fetchRevocationRegistryDefinition,
  fetchRevocationStatusList,
  fetchSchema,
} from '../utils'
import {
  convertAttributesToCredentialValues,
  assertCredentialValuesMatch,
  checkCredentialValuesMatch,
  assertAttributesMatch,
  createAndLinkAttachmentsToPreview,
} from '../utils/credential'
import { AnonCredsCredentialMetadataKey, AnonCredsCredentialRequestMetadataKey } from '../utils/metadata'
import { getStoreCredentialOptions } from '../utils/w3cAnonCredsUtils'

const ANONCREDS_CREDENTIAL_OFFER = 'anoncreds/credential-offer@v1.0'
const ANONCREDS_CREDENTIAL_REQUEST = 'anoncreds/credential-request@v1.0'
const ANONCREDS_CREDENTIAL_FILTER = 'anoncreds/credential-filter@v1.0'
const ANONCREDS_CREDENTIAL = 'anoncreds/credential@v1.0'

export class AnonCredsCredentialFormatService implements CredentialFormatService<AnonCredsCredentialFormat> {
  /** formatKey is the key used when calling agent.credentials.xxx with credentialFormats.anoncreds */
  public readonly formatKey = 'anoncreds' as const

  /**
   * credentialRecordType is the type of record that stores the credential. It is stored in the credential
   * record binding in the credential exchange record.
   */
  public readonly credentialRecordType = 'w3c' as const

  /**
   * Create a {@link AttachmentFormats} object dependent on the message type.
   *
   * @param options The object containing all the options for the proposed credential
   * @returns object containing associated attachment, format and optionally the credential preview
   *
   */
  public async createProposal(
    agentContext: AgentContext,
    { credentialFormats, credentialRecord }: CredentialFormatCreateProposalOptions<AnonCredsCredentialFormat>
  ): Promise<CredentialFormatCreateProposalReturn> {
    const format = new CredentialFormatSpec({
      format: ANONCREDS_CREDENTIAL_FILTER,
    })

    const anoncredsFormat = credentialFormats.anoncreds

    if (!anoncredsFormat) {
      throw new CredoError('Missing anoncreds payload in createProposal')
    }

    // We want all properties except for `attributes` and `linkedAttachments` attributes.
    // The easiest way is to destructure and use the spread operator. But that leaves the other properties unused
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { attributes, linkedAttachments, ...anoncredsCredentialProposal } = anoncredsFormat
    const proposal = new AnonCredsCredentialProposal(anoncredsCredentialProposal)

    try {
      MessageValidator.validateSync(proposal)
    } catch (error) {
      throw new CredoError(`Invalid proposal supplied: ${anoncredsCredentialProposal} in AnonCredsFormatService`)
    }

    const attachment = this.getFormatData(JsonTransformer.toJSON(proposal), format.attachmentId)

    const { previewAttributes } = this.getCredentialLinkedAttachments(
      anoncredsFormat.attributes,
      anoncredsFormat.linkedAttachments
    )

    // Set the metadata
    credentialRecord.metadata.set<AnonCredsCredentialMetadata>(AnonCredsCredentialMetadataKey, {
      schemaId: proposal.schemaId,
      credentialDefinitionId: proposal.credentialDefinitionId,
    })

    return { format, attachment, previewAttributes }
  }

  public async processProposal(
    agentContext: AgentContext,
    { attachment }: CredentialFormatProcessOptions
  ): Promise<void> {
    const proposalJson = attachment.getDataAsJson()

    JsonTransformer.fromJSON(proposalJson, AnonCredsCredentialProposal)
  }

  public async acceptProposal(
    agentContext: AgentContext,
    {
      attachmentId,
      credentialFormats,
      credentialRecord,
      proposalAttachment,
    }: CredentialFormatAcceptProposalOptions<AnonCredsCredentialFormat>
  ): Promise<CredentialFormatCreateOfferReturn> {
    const anoncredsFormat = credentialFormats?.anoncreds

    const proposalJson = proposalAttachment.getDataAsJson<AnonCredsCredentialProposalFormat>()
    const credentialDefinitionId = anoncredsFormat?.credentialDefinitionId ?? proposalJson.cred_def_id

    const attributes = anoncredsFormat?.attributes ?? credentialRecord.credentialAttributes

    if (!credentialDefinitionId) {
      throw new CredoError('No credential definition id in proposal or provided as input to accept proposal method.')
    }

    if (!attributes) {
      throw new CredoError('No attributes in proposal or provided as input to accept proposal method.')
    }

    const { format, attachment, previewAttributes } = await this.createAnonCredsOffer(agentContext, {
      credentialRecord,
      attachmentId,
      attributes,
      credentialDefinitionId,
      revocationRegistryDefinitionId: anoncredsFormat?.revocationRegistryDefinitionId,
      revocationRegistryIndex: anoncredsFormat?.revocationRegistryIndex,
      linkedAttachments: anoncredsFormat?.linkedAttachments,
    })

    return { format, attachment, previewAttributes }
  }

  /**
   * Create a credential attachment format for a credential request.
   *
   * @param options The object containing all the options for the credential offer
   * @returns object containing associated attachment, formats and offersAttach elements
   *
   */
  public async createOffer(
    agentContext: AgentContext,
    { credentialFormats, credentialRecord, attachmentId }: CredentialFormatCreateOfferOptions<AnonCredsCredentialFormat>
  ): Promise<CredentialFormatCreateOfferReturn> {
    const anoncredsFormat = credentialFormats.anoncreds

    if (!anoncredsFormat) {
      throw new CredoError('Missing anoncreds credential format data')
    }

    const { format, attachment, previewAttributes } = await this.createAnonCredsOffer(agentContext, {
      credentialRecord,
      attachmentId,
      attributes: anoncredsFormat.attributes,
      credentialDefinitionId: anoncredsFormat.credentialDefinitionId,
      revocationRegistryDefinitionId: anoncredsFormat.revocationRegistryDefinitionId,
      revocationRegistryIndex: anoncredsFormat.revocationRegistryIndex,
      linkedAttachments: anoncredsFormat.linkedAttachments,
    })

    return { format, attachment, previewAttributes }
  }

  public async processOffer(
    agentContext: AgentContext,
    { attachment, credentialRecord }: CredentialFormatProcessOptions
  ) {
    agentContext.config.logger.debug(
      `Processing anoncreds credential offer for credential record ${credentialRecord.id}`
    )

    const credOffer = attachment.getDataAsJson<AnonCredsCredentialOffer>()

    if (!credOffer.schema_id || !credOffer.cred_def_id) {
      throw new ProblemReportError('Invalid credential offer', {
        problemCode: CredentialProblemReportReason.IssuanceAbandoned,
      })
    }
  }

  public async acceptOffer(
    agentContext: AgentContext,
    {
      credentialRecord,
      attachmentId,
      offerAttachment,
      credentialFormats,
    }: CredentialFormatAcceptOfferOptions<AnonCredsCredentialFormat>
  ): Promise<CredentialFormatCreateReturn> {
    const holderService = agentContext.dependencyManager.resolve<AnonCredsHolderService>(AnonCredsHolderServiceSymbol)

    const credentialOffer = offerAttachment.getDataAsJson<AnonCredsCredentialOffer>()

    // Get credential definition
    const { credentialDefinition } = await fetchCredentialDefinition(agentContext, credentialOffer.cred_def_id)

    const { credentialRequest, credentialRequestMetadata } = await holderService.createCredentialRequest(agentContext, {
      credentialOffer,
      credentialDefinition,
      linkSecretId: credentialFormats?.anoncreds?.linkSecretId,
    })

    credentialRecord.metadata.set<AnonCredsCredentialRequestMetadata>(
      AnonCredsCredentialRequestMetadataKey,
      credentialRequestMetadata
    )
    credentialRecord.metadata.set<AnonCredsCredentialMetadata>(AnonCredsCredentialMetadataKey, {
      credentialDefinitionId: credentialOffer.cred_def_id,
      schemaId: credentialOffer.schema_id,
    })

    const format = new CredentialFormatSpec({
      attachmentId,
      format: ANONCREDS_CREDENTIAL_REQUEST,
    })

    const attachment = this.getFormatData(credentialRequest, format.attachmentId)
    return { format, attachment }
  }

  /**
   * Starting from a request is not supported for anoncreds credentials, this method only throws an error.
   */
  public async createRequest(): Promise<CredentialFormatCreateReturn> {
    throw new CredoError('Starting from a request is not supported for anoncreds credentials')
  }

  /**
   * We don't have any models to validate an anoncreds request object, for now this method does nothing
   */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  public async processRequest(agentContext: AgentContext, options: CredentialFormatProcessOptions): Promise<void> {
    // not needed for anoncreds
  }

  public async acceptRequest(
    agentContext: AgentContext,
    {
      credentialRecord,
      attachmentId,
      offerAttachment,
      requestAttachment,
    }: CredentialFormatAcceptRequestOptions<AnonCredsCredentialFormat>
  ): Promise<CredentialFormatCreateReturn> {
    // Assert credential attributes
    const credentialAttributes = credentialRecord.credentialAttributes
    if (!credentialAttributes) {
      throw new CredoError(
        `Missing required credential attribute values on credential record with id ${credentialRecord.id}`
      )
    }

    const anonCredsIssuerService =
      agentContext.dependencyManager.resolve<AnonCredsIssuerService>(AnonCredsIssuerServiceSymbol)

    const credentialOffer = offerAttachment?.getDataAsJson<AnonCredsCredentialOffer>()
    if (!credentialOffer) throw new CredoError('Missing anoncreds credential offer in createCredential')

    const credentialRequest = requestAttachment.getDataAsJson<AnonCredsCredentialRequest>()
    if (!credentialRequest) throw new CredoError('Missing anoncreds credential request in createCredential')

    // We check locally for credential definition info. If it supports revocation, we need to search locally for
    // an active revocation registry
    const credentialDefinition = (
      await agentContext.dependencyManager
        .resolve(AnonCredsCredentialDefinitionRepository)
        .getByCredentialDefinitionId(agentContext, credentialRequest.cred_def_id)
    ).credentialDefinition.value

    let revocationRegistryDefinitionId
    let revocationRegistryIndex
    let revocationStatusList

    if (credentialDefinition.revocation) {
      const credentialMetadata =
        credentialRecord.metadata.get<AnonCredsCredentialMetadata>(AnonCredsCredentialMetadataKey)
      revocationRegistryDefinitionId = credentialMetadata?.revocationRegistryId
      if (credentialMetadata?.credentialRevocationId) {
        revocationRegistryIndex = Number(credentialMetadata.credentialRevocationId)
      }

      if (!revocationRegistryDefinitionId || !revocationRegistryIndex) {
        throw new CredoError(
          'Revocation registry definition id and revocation index are mandatory to issue AnonCreds revocable credentials'
        )
      }
      const revocationRegistryDefinitionPrivateRecord = await agentContext.dependencyManager
        .resolve(AnonCredsRevocationRegistryDefinitionPrivateRepository)
        .getByRevocationRegistryDefinitionId(agentContext, revocationRegistryDefinitionId)

      if (revocationRegistryDefinitionPrivateRecord.state !== AnonCredsRevocationRegistryState.Active) {
        throw new CredoError(
          `Revocation registry ${revocationRegistryDefinitionId} is in ${revocationRegistryDefinitionPrivateRecord.state} state`
        )
      }

      const revocationStatusListResult = await fetchRevocationStatusList(
        agentContext,
        revocationRegistryDefinitionId,
        dateToTimestamp(new Date())
      )
      revocationStatusList = revocationStatusListResult.revocationStatusList
    }

    const { credential, credentialRevocationId } = await anonCredsIssuerService.createCredential(agentContext, {
      credentialOffer,
      credentialRequest,
      credentialValues: convertAttributesToCredentialValues(credentialAttributes),
      revocationRegistryDefinitionId,
      revocationRegistryIndex,
      revocationStatusList,
    })

    // If the credential is revocable, store the revocation identifiers in the credential record
    if (credential.rev_reg_id) {
      credentialRecord.metadata.add<AnonCredsCredentialMetadata>(AnonCredsCredentialMetadataKey, {
        revocationRegistryId: revocationRegistryDefinitionId ?? undefined,
        credentialRevocationId: credentialRevocationId ?? undefined,
      })
      credentialRecord.setTags({
        anonCredsRevocationRegistryId: revocationRegistryDefinitionId,
        anonCredsCredentialRevocationId: credentialRevocationId,
      })
    }

    const format = new CredentialFormatSpec({
      attachmentId,
      format: ANONCREDS_CREDENTIAL,
    })

    const attachment = this.getFormatData(credential, format.attachmentId)
    return { format, attachment }
  }

  /**
   * Processes an incoming credential - retrieve metadata, retrieve payload and store it in wallet
   * @param options the issue credential message wrapped inside this object
   * @param credentialRecord the credential exchange record for this credential
   */
  public async processCredential(
    agentContext: AgentContext,
    { credentialRecord, attachment }: CredentialFormatProcessCredentialOptions
  ): Promise<void> {
    const credentialRequestMetadata = credentialRecord.metadata.get<AnonCredsCredentialRequestMetadata>(
      AnonCredsCredentialRequestMetadataKey
    )

    const anonCredsHolderService =
      agentContext.dependencyManager.resolve<AnonCredsHolderService>(AnonCredsHolderServiceSymbol)

    if (!credentialRequestMetadata) {
      throw new CredoError(
        `Missing required request metadata for credential exchange with thread id with id ${credentialRecord.id}`
      )
    }

    if (!credentialRecord.credentialAttributes) {
      throw new CredoError('Missing credential attributes on credential record. Unable to check credential attributes')
    }

    const anonCredsCredential = attachment.getDataAsJson<AnonCredsCredential>()

    const { credentialDefinition, credentialDefinitionId } = await fetchCredentialDefinition(
      agentContext,
      anonCredsCredential.cred_def_id
    )
    const { schema, indyNamespace } = await fetchSchema(agentContext, anonCredsCredential.schema_id)

    // Resolve revocation registry if credential is revocable
    const revocationRegistryResult = anonCredsCredential.rev_reg_id
      ? await fetchRevocationRegistryDefinition(agentContext, anonCredsCredential.rev_reg_id)
      : undefined

    // assert the credential values match the offer values
    const recordCredentialValues = convertAttributesToCredentialValues(credentialRecord.credentialAttributes)
    assertCredentialValuesMatch(anonCredsCredential.values, recordCredentialValues)

    const storeCredentialOptions = getStoreCredentialOptions(
      {
        credentialId: utils.uuid(),
        credentialRequestMetadata,
        credential: anonCredsCredential,
        credentialDefinitionId,
        credentialDefinition,
        schema,
        revocationRegistry: revocationRegistryResult?.revocationRegistryDefinition
          ? {
              definition: revocationRegistryResult.revocationRegistryDefinition,
              id: revocationRegistryResult.revocationRegistryDefinitionId,
            }
          : undefined,
      },
      indyNamespace
    )

    const credentialId = await anonCredsHolderService.storeCredential(agentContext, storeCredentialOptions)

    // If the credential is revocable, store the revocation identifiers in the credential record
    if (anonCredsCredential.rev_reg_id) {
      const credential = await anonCredsHolderService.getCredential(agentContext, { id: credentialId })

      credentialRecord.metadata.add<AnonCredsCredentialMetadata>(AnonCredsCredentialMetadataKey, {
        credentialRevocationId: credential.credentialRevocationId ?? undefined,
        revocationRegistryId: credential.revocationRegistryId ?? undefined,
      })
      credentialRecord.setTags({
        anonCredsRevocationRegistryId: credential.revocationRegistryId,
        anonCredsCredentialRevocationId: credential.credentialRevocationId,
      })
    }

    credentialRecord.credentials.push({
      credentialRecordType: this.credentialRecordType,
      credentialRecordId: credentialId,
    })
  }

  public supportsFormat(format: string): boolean {
    const supportedFormats = [
      ANONCREDS_CREDENTIAL_REQUEST,
      ANONCREDS_CREDENTIAL_OFFER,
      ANONCREDS_CREDENTIAL_FILTER,
      ANONCREDS_CREDENTIAL,
    ]

    return supportedFormats.includes(format)
  }

  /**
   * Gets the attachment object for a given attachmentId. We need to get out the correct attachmentId for
   * anoncreds and then find the corresponding attachment (if there is one)
   * @param formats the formats object containing the attachmentId
   * @param messageAttachments the attachments containing the payload
   * @returns The Attachment if found or undefined
   *
   */
  public getAttachment(formats: CredentialFormatSpec[], messageAttachments: Attachment[]): Attachment | undefined {
    const supportedAttachmentIds = formats.filter((f) => this.supportsFormat(f.format)).map((f) => f.attachmentId)
    const supportedAttachment = messageAttachments.find((attachment) => supportedAttachmentIds.includes(attachment.id))

    return supportedAttachment
  }

  public async deleteCredentialById(agentContext: AgentContext, credentialRecordId: string): Promise<void> {
    const anonCredsHolderService =
      agentContext.dependencyManager.resolve<AnonCredsHolderService>(AnonCredsHolderServiceSymbol)

    await anonCredsHolderService.deleteCredential(agentContext, credentialRecordId)
  }

  public async shouldAutoRespondToProposal(
    agentContext: AgentContext,
    { offerAttachment, proposalAttachment }: CredentialFormatAutoRespondProposalOptions
  ) {
    const proposalJson = proposalAttachment.getDataAsJson<AnonCredsCredentialProposalFormat>()
    const offerJson = offerAttachment.getDataAsJson<AnonCredsCredentialOffer>()

    // We want to make sure the credential definition matches.
    // TODO: If no credential definition is present on the proposal, we could check whether the other fields
    // of the proposal match with the credential definition id.
    return proposalJson.cred_def_id === offerJson.cred_def_id
  }

  public async shouldAutoRespondToOffer(
    agentContext: AgentContext,
    { offerAttachment, proposalAttachment }: CredentialFormatAutoRespondOfferOptions
  ) {
    const proposalJson = proposalAttachment.getDataAsJson<AnonCredsCredentialProposalFormat>()
    const offerJson = offerAttachment.getDataAsJson<AnonCredsCredentialOffer>()

    // We want to make sure the credential definition matches.
    // TODO: If no credential definition is present on the proposal, we could check whether the other fields
    // of the proposal match with the credential definition id.
    return proposalJson.cred_def_id === offerJson.cred_def_id
  }

  public async shouldAutoRespondToRequest(
    agentContext: AgentContext,
    { offerAttachment, requestAttachment }: CredentialFormatAutoRespondRequestOptions
  ) {
    const credentialOfferJson = offerAttachment.getDataAsJson<AnonCredsCredentialOffer>()
    const credentialRequestJson = requestAttachment.getDataAsJson<AnonCredsCredentialRequest>()

    return credentialOfferJson.cred_def_id === credentialRequestJson.cred_def_id
  }

  public async shouldAutoRespondToCredential(
    agentContext: AgentContext,
    { credentialRecord, requestAttachment, credentialAttachment }: CredentialFormatAutoRespondCredentialOptions
  ) {
    const credentialJson = credentialAttachment.getDataAsJson<AnonCredsCredential>()
    const credentialRequestJson = requestAttachment.getDataAsJson<AnonCredsCredentialRequest>()

    // make sure the credential definition matches
    if (credentialJson.cred_def_id !== credentialRequestJson.cred_def_id) return false

    // If we don't have any attributes stored we can't compare so always return false.
    if (!credentialRecord.credentialAttributes) return false
    const attributeValues = convertAttributesToCredentialValues(credentialRecord.credentialAttributes)

    // check whether the values match the values in the record
    return checkCredentialValuesMatch(attributeValues, credentialJson.values)
  }

  private async createAnonCredsOffer(
    agentContext: AgentContext,
    {
      credentialRecord,
      attachmentId,
      credentialDefinitionId,
      revocationRegistryDefinitionId,
      revocationRegistryIndex,
      attributes,
      linkedAttachments,
    }: {
      credentialDefinitionId: string
      revocationRegistryDefinitionId?: string
      revocationRegistryIndex?: number
      credentialRecord: CredentialExchangeRecord
      attachmentId?: string
      attributes: CredentialPreviewAttributeOptions[]
      linkedAttachments?: LinkedAttachment[]
    }
  ): Promise<CredentialFormatCreateOfferReturn> {
    const anonCredsIssuerService =
      agentContext.dependencyManager.resolve<AnonCredsIssuerService>(AnonCredsIssuerServiceSymbol)

    // if the proposal has an attachment Id use that, otherwise the generated id of the formats object
    const format = new CredentialFormatSpec({
      attachmentId: attachmentId,
      format: ANONCREDS_CREDENTIAL,
    })

    const offer = await anonCredsIssuerService.createCredentialOffer(agentContext, {
      credentialDefinitionId,
    })

    const { previewAttributes } = this.getCredentialLinkedAttachments(attributes, linkedAttachments)
    if (!previewAttributes) {
      throw new CredoError('Missing required preview attributes for anoncreds offer')
    }

    await this.assertPreviewAttributesMatchSchemaAttributes(agentContext, offer, previewAttributes)

    // We check locally for credential definition info. If it supports revocation, revocationRegistryIndex
    // and revocationRegistryDefinitionId are mandatory
    const credentialDefinition = (
      await agentContext.dependencyManager
        .resolve(AnonCredsCredentialDefinitionRepository)
        .getByCredentialDefinitionId(agentContext, offer.cred_def_id)
    ).credentialDefinition.value

    if (credentialDefinition.revocation) {
      if (!revocationRegistryDefinitionId || revocationRegistryIndex === undefined) {
        throw new CredoError(
          'AnonCreds revocable credentials require revocationRegistryDefinitionId and revocationRegistryIndex'
        )
      }

      // Set revocation tags
      credentialRecord.setTags({
        anonCredsRevocationRegistryId: revocationRegistryDefinitionId,
        anonCredsCredentialRevocationId: revocationRegistryIndex.toString(),
      })
    }

    // Set the metadata
    credentialRecord.metadata.set<AnonCredsCredentialMetadata>(AnonCredsCredentialMetadataKey, {
      schemaId: offer.schema_id,
      credentialDefinitionId: offer.cred_def_id,
      credentialRevocationId: revocationRegistryIndex?.toString(),
      revocationRegistryId: revocationRegistryDefinitionId,
    })

    const attachment = this.getFormatData(offer, format.attachmentId)

    return { format, attachment, previewAttributes }
  }

  private async assertPreviewAttributesMatchSchemaAttributes(
    agentContext: AgentContext,
    offer: AnonCredsCredentialOffer,
    attributes: CredentialPreviewAttributeOptions[]
  ): Promise<void> {
    const { schema } = await fetchSchema(agentContext, offer.schema_id)

    assertAttributesMatch(schema, attributes)
  }

  /**
   * Get linked attachments for anoncreds format from a proposal message. This allows attachments
   * to be copied across to old style credential records
   *
   * @param options ProposeCredentialOptions object containing (optionally) the linked attachments
   * @return array of linked attachments or undefined if none present
   */
  private getCredentialLinkedAttachments(
    attributes?: CredentialPreviewAttributeOptions[],
    linkedAttachments?: LinkedAttachment[]
  ): {
    attachments?: Attachment[]
    previewAttributes?: CredentialPreviewAttributeOptions[]
  } {
    if (!linkedAttachments && !attributes) {
      return {}
    }

    let previewAttributes = attributes ?? []
    let attachments: Attachment[] | undefined

    if (linkedAttachments) {
      // there are linked attachments so transform into the attribute field of the CredentialPreview object for
      // this proposal
      previewAttributes = createAndLinkAttachmentsToPreview(linkedAttachments, previewAttributes)
      attachments = linkedAttachments.map((linkedAttachment) => linkedAttachment.attachment)
    }

    return { attachments, previewAttributes }
  }

  /**
   * Returns an object of type {@link Attachment} for use in credential exchange messages.
   * It looks up the correct format identifier and encodes the data as a base64 attachment.
   *
   * @param data The data to include in the attach object
   * @param id the attach id from the formats component of the message
   */
  public getFormatData(data: unknown, id: string): Attachment {
    const attachment = new Attachment({
      id,
      mimeType: 'application/json',
      data: {
        base64: JsonEncoder.toBase64(data),
      },
    })

    return attachment
  }
}
