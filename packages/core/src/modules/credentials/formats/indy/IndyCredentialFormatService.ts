import type { IndyCredentialFormat } from './IndyCredentialFormat'
import type { AgentContext } from '../../../../agent'
import type { LinkedAttachment } from '../../../../utils/LinkedAttachment'
import type { CredentialPreviewAttributeOptions } from '../../models/CredentialPreviewAttribute'
import type { CredentialExchangeRecord } from '../../repository/CredentialExchangeRecord'
import type { CredentialFormatService } from '../CredentialFormatService'
import type {
  CredentialFormatAcceptOfferOptions,
  CredentialFormatAcceptProposalOptions,
  CredentialFormatAcceptRequestOptions,
  CredentialFormatAutoRespondCredentialOptions,
  CredentialFormatAutoRespondOfferOptions,
  CredentialFormatAutoRespondProposalOptions,
  CredentialFormatAutoRespondRequestOptions,
  CredentialFormatCreateOfferOptions,
  CredentialFormatCreateOfferReturn,
  CredentialFormatCreateProposalOptions,
  CredentialFormatCreateProposalReturn,
  CredentialFormatCreateReturn,
  CredentialFormatProcessOptions,
  CredentialFormatProcessCredentialOptions,
} from '../CredentialFormatServiceOptions'
import type * as Indy from 'indy-sdk'

import { KeyType } from '../../../../crypto'
import { Attachment, AttachmentData } from '../../../../decorators/attachment/Attachment'
import { AriesFrameworkError } from '../../../../error'
import { JsonEncoder } from '../../../../utils/JsonEncoder'
import { JsonTransformer } from '../../../../utils/JsonTransformer'
import { MessageValidator } from '../../../../utils/MessageValidator'
import { TypedArrayEncoder } from '../../../../utils/TypedArrayEncoder'
import { getIndyDidFromVerificationMethod } from '../../../../utils/did'
import { uuid } from '../../../../utils/uuid'
import { ConnectionService } from '../../../connections'
import { DidResolverService, findVerificationMethodByKeyType } from '../../../dids'
import { IndyHolderService } from '../../../indy/services/IndyHolderService'
import { IndyIssuerService } from '../../../indy/services/IndyIssuerService'
import { IndyLedgerService } from '../../../ledger'
import { CredentialProblemReportError, CredentialProblemReportReason } from '../../errors'
import { CredentialFormatSpec } from '../../models/CredentialFormatSpec'
import { CredentialPreviewAttribute } from '../../models/CredentialPreviewAttribute'
import { CredentialMetadataKeys } from '../../repository/CredentialMetadataTypes'

import { IndyCredentialUtils } from './IndyCredentialUtils'
import { IndyCredPropose } from './models/IndyCredPropose'

const INDY_CRED_ABSTRACT = 'hlindy/cred-abstract@v2.0'
const INDY_CRED_REQUEST = 'hlindy/cred-req@v2.0'
const INDY_CRED_FILTER = 'hlindy/cred-filter@v2.0'
const INDY_CRED = 'hlindy/cred@v2.0'

export class IndyCredentialFormatService implements CredentialFormatService<IndyCredentialFormat> {
  public readonly formatKey = 'indy' as const
  public readonly credentialRecordType = 'indy' as const

  /**
   * Create a {@link AttachmentFormats} object dependent on the message type.
   *
   * @param options The object containing all the options for the proposed credential
   * @returns object containing associated attachment, format and optionally the credential preview
   *
   */
  public async createProposal(
    agentContext: AgentContext,
    { credentialFormats, credentialRecord, attachmentId }: CredentialFormatCreateProposalOptions<IndyCredentialFormat>
  ): Promise<CredentialFormatCreateProposalReturn> {
    const format = new CredentialFormatSpec({
      format: INDY_CRED_FILTER,
      attachmentId,
    })

    const indyFormat = credentialFormats.indy

    if (!indyFormat) {
      throw new AriesFrameworkError('Missing indy payload in createProposal')
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { attributes, linkedAttachments, ...indyCredentialProposal } = indyFormat

    const proposal = new IndyCredPropose(indyCredentialProposal)

    try {
      MessageValidator.validateSync(proposal)
    } catch (error) {
      throw new AriesFrameworkError(`Invalid proposal supplied: ${indyCredentialProposal} in Indy Format Service`)
    }

    const proposalJson = JsonTransformer.toJSON(proposal)
    const attachment = this.getFormatData(proposalJson, format.attachmentId)

    const { previewAttributes } = this.getCredentialLinkedAttachments(
      indyFormat.attributes,
      indyFormat.linkedAttachments
    )

    // Set the metadata
    credentialRecord.metadata.set(CredentialMetadataKeys.IndyCredential, {
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

    // fromJSON also validates
    JsonTransformer.fromJSON(proposalJson, IndyCredPropose)
  }

  public async acceptProposal(
    agentContext: AgentContext,
    {
      attachmentId,
      credentialFormats,
      credentialRecord,
      proposalAttachment,
    }: CredentialFormatAcceptProposalOptions<IndyCredentialFormat>
  ): Promise<CredentialFormatCreateOfferReturn> {
    const indyFormat = credentialFormats?.indy

    const credentialProposal = JsonTransformer.fromJSON(proposalAttachment.getDataAsJson(), IndyCredPropose)

    const credentialDefinitionId = indyFormat?.credentialDefinitionId ?? credentialProposal.credentialDefinitionId
    const attributes = indyFormat?.attributes ?? credentialRecord.credentialAttributes

    if (!credentialDefinitionId) {
      throw new AriesFrameworkError(
        'No credentialDefinitionId in proposal or provided as input to accept proposal method.'
      )
    }

    if (!attributes) {
      throw new AriesFrameworkError('No attributes in proposal or provided as input to accept proposal method.')
    }

    const { format, attachment, previewAttributes } = await this.createIndyOffer(agentContext, {
      credentialRecord,
      attachmentId,
      attributes,
      credentialDefinitionId: credentialDefinitionId,
      linkedAttachments: indyFormat?.linkedAttachments,
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
    { credentialFormats, credentialRecord, attachmentId }: CredentialFormatCreateOfferOptions<IndyCredentialFormat>
  ): Promise<CredentialFormatCreateOfferReturn> {
    const indyFormat = credentialFormats.indy

    if (!indyFormat) {
      throw new AriesFrameworkError('Missing indy credentialFormat data')
    }

    const { format, attachment, previewAttributes } = await this.createIndyOffer(agentContext, {
      credentialRecord,
      attachmentId,
      attributes: indyFormat.attributes,
      credentialDefinitionId: indyFormat.credentialDefinitionId,
      linkedAttachments: indyFormat.linkedAttachments,
    })

    return { format, attachment, previewAttributes }
  }

  public async processOffer(
    agentContext: AgentContext,
    { attachment, credentialRecord }: CredentialFormatProcessOptions
  ) {
    agentContext.config.logger.debug(`Processing indy credential offer for credential record ${credentialRecord.id}`)

    const credOffer = attachment.getDataAsJson<Indy.CredOffer>()

    if (!credOffer.schema_id || !credOffer.cred_def_id) {
      throw new CredentialProblemReportError('Invalid credential offer', {
        problemCode: CredentialProblemReportReason.IssuanceAbandoned,
      })
    }
  }

  public async acceptOffer(
    agentContext: AgentContext,
    {
      credentialFormats,
      credentialRecord,
      attachmentId,
      offerAttachment,
    }: CredentialFormatAcceptOfferOptions<IndyCredentialFormat>
  ): Promise<CredentialFormatCreateReturn> {
    const indyFormat = credentialFormats?.indy

    const indyLedgerService = agentContext.dependencyManager.resolve(IndyLedgerService)
    const indyHolderService = agentContext.dependencyManager.resolve(IndyHolderService)

    const holderDid = indyFormat?.holderDid ?? (await this.getIndyHolderDid(agentContext, credentialRecord))

    const credentialOffer = offerAttachment.getDataAsJson<Indy.CredOffer>()
    const credentialDefinition = await indyLedgerService.getCredentialDefinition(
      agentContext,
      credentialOffer.cred_def_id
    )

    const [credentialRequest, credentialRequestMetadata] = await indyHolderService.createCredentialRequest(
      agentContext,
      {
        holderDid,
        credentialOffer,
        credentialDefinition,
      }
    )

    credentialRecord.metadata.set(CredentialMetadataKeys.IndyRequest, credentialRequestMetadata)
    credentialRecord.metadata.set(CredentialMetadataKeys.IndyCredential, {
      credentialDefinitionId: credentialOffer.cred_def_id,
      schemaId: credentialOffer.schema_id,
    })

    const format = new CredentialFormatSpec({
      attachmentId,
      format: INDY_CRED_REQUEST,
    })

    const attachment = this.getFormatData(credentialRequest, format.attachmentId)
    return { format, attachment }
  }

  /**
   * Starting from a request is not supported for indy credentials, this method only throws an error.
   */
  public async createRequest(): Promise<CredentialFormatCreateReturn> {
    throw new AriesFrameworkError('Starting from a request is not supported for indy credentials')
  }

  /**
   * We don't have any models to validate an indy request object, for now this method does nothing
   */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  public async processRequest(agentContext: AgentContext, options: CredentialFormatProcessOptions): Promise<void> {
    // not needed for Indy
  }

  public async acceptRequest(
    agentContext: AgentContext,
    {
      credentialRecord,
      attachmentId,
      offerAttachment,
      requestAttachment,
    }: CredentialFormatAcceptRequestOptions<IndyCredentialFormat>
  ): Promise<CredentialFormatCreateReturn> {
    // Assert credential attributes
    const credentialAttributes = credentialRecord.credentialAttributes
    if (!credentialAttributes) {
      throw new CredentialProblemReportError(
        `Missing required credential attribute values on credential record with id ${credentialRecord.id}`,
        { problemCode: CredentialProblemReportReason.IssuanceAbandoned }
      )
    }

    const indyIssuerService = agentContext.dependencyManager.resolve(IndyIssuerService)

    const credentialOffer = offerAttachment?.getDataAsJson<Indy.CredOffer>()
    const credentialRequest = requestAttachment.getDataAsJson<Indy.CredReq>()

    if (!credentialOffer || !credentialRequest) {
      throw new AriesFrameworkError('Missing indy credential offer or credential request in createCredential')
    }

    const [credential, credentialRevocationId] = await indyIssuerService.createCredential(agentContext, {
      credentialOffer,
      credentialRequest,
      credentialValues: IndyCredentialUtils.convertAttributesToValues(credentialAttributes),
    })

    if (credential.rev_reg_id) {
      credentialRecord.metadata.add(CredentialMetadataKeys.IndyCredential, {
        indyCredentialRevocationId: credentialRevocationId,
        indyRevocationRegistryId: credential.rev_reg_id,
      })
    }

    const format = new CredentialFormatSpec({
      attachmentId,
      format: INDY_CRED,
    })

    const attachment = this.getFormatData(credential, format.attachmentId)
    return { format, attachment }
  }

  /**
   * Processes an incoming credential - retrieve metadata, retrieve payload and store it in the Indy wallet
   * @param options the issue credential message wrapped inside this object
   * @param credentialRecord the credential exchange record for this credential
   */
  public async processCredential(
    agentContext: AgentContext,
    { credentialRecord, attachment }: CredentialFormatProcessCredentialOptions
  ): Promise<void> {
    const credentialRequestMetadata = credentialRecord.metadata.get(CredentialMetadataKeys.IndyRequest)

    const indyLedgerService = agentContext.dependencyManager.resolve(IndyLedgerService)
    const indyHolderService = agentContext.dependencyManager.resolve(IndyHolderService)

    if (!credentialRequestMetadata) {
      throw new CredentialProblemReportError(
        `Missing required request metadata for credential with id ${credentialRecord.id}`,
        { problemCode: CredentialProblemReportReason.IssuanceAbandoned }
      )
    }

    const indyCredential = attachment.getDataAsJson<Indy.Cred>()
    const credentialDefinition = await indyLedgerService.getCredentialDefinition(
      agentContext,
      indyCredential.cred_def_id
    )
    const revocationRegistry = indyCredential.rev_reg_id
      ? await indyLedgerService.getRevocationRegistryDefinition(agentContext, indyCredential.rev_reg_id)
      : null

    if (!credentialRecord.credentialAttributes) {
      throw new AriesFrameworkError(
        'Missing credential attributes on credential record. Unable to check credential attributes'
      )
    }

    // assert the credential values match the offer values
    const recordCredentialValues = IndyCredentialUtils.convertAttributesToValues(credentialRecord.credentialAttributes)
    IndyCredentialUtils.assertValuesMatch(indyCredential.values, recordCredentialValues)

    const credentialId = await indyHolderService.storeCredential(agentContext, {
      credentialId: uuid(),
      credentialRequestMetadata,
      credential: indyCredential,
      credentialDefinition,
      revocationRegistryDefinition: revocationRegistry?.revocationRegistryDefinition,
    })

    // If the credential is revocable, store the revocation identifiers in the credential record
    if (indyCredential.rev_reg_id) {
      const credential = await indyHolderService.getCredential(agentContext, credentialId)

      credentialRecord.metadata.add(CredentialMetadataKeys.IndyCredential, {
        indyCredentialRevocationId: credential.cred_rev_id,
        indyRevocationRegistryId: indyCredential.rev_reg_id,
      })
    }

    credentialRecord.credentials.push({
      credentialRecordType: this.credentialRecordType,
      credentialRecordId: credentialId,
    })
  }

  public supportsFormat(format: string): boolean {
    const supportedFormats = [INDY_CRED_ABSTRACT, INDY_CRED_REQUEST, INDY_CRED_FILTER, INDY_CRED]

    return supportedFormats.includes(format)
  }

  /**
   * Gets the attachment object for a given attachmentId. We need to get out the correct attachmentId for
   * indy and then find the corresponding attachment (if there is one)
   * @param formats the formats object containing the attachmentId
   * @param messageAttachments the attachments containing the payload
   * @returns The Attachment if found or undefined
   *
   */
  public getAttachment(formats: CredentialFormatSpec[], messageAttachments: Attachment[]): Attachment | undefined {
    const supportedAttachmentIds = formats.filter((f) => this.supportsFormat(f.format)).map((f) => f.attachmentId)
    const supportedAttachments = messageAttachments.filter((attachment) =>
      supportedAttachmentIds.includes(attachment.id)
    )

    return supportedAttachments[0]
  }

  public async deleteCredentialById(agentContext: AgentContext, credentialRecordId: string): Promise<void> {
    const indyHolderService = agentContext.dependencyManager.resolve(IndyHolderService)

    await indyHolderService.deleteCredential(agentContext, credentialRecordId)
  }

  public async shouldAutoRespondToProposal(
    agentContext: AgentContext,
    { offerAttachment, proposalAttachment }: CredentialFormatAutoRespondProposalOptions
  ) {
    const credentialProposalJson = proposalAttachment.getDataAsJson()
    const credentialProposal = JsonTransformer.fromJSON(credentialProposalJson, IndyCredPropose)

    const credentialOfferJson = offerAttachment.getDataAsJson<Indy.CredOffer>()

    // We want to make sure the credential definition matches.
    // TODO: If no credential definition is present on the proposal, we could check whether the other fields
    // of the proposal match with the credential definition id.
    return credentialProposal.credentialDefinitionId === credentialOfferJson.cred_def_id
  }

  public async shouldAutoRespondToOffer(
    agentContext: AgentContext,
    { offerAttachment, proposalAttachment }: CredentialFormatAutoRespondOfferOptions
  ) {
    const credentialProposalJson = proposalAttachment.getDataAsJson()
    const credentialProposal = JsonTransformer.fromJSON(credentialProposalJson, IndyCredPropose)

    const credentialOfferJson = offerAttachment.getDataAsJson<Indy.CredOffer>()

    // We want to make sure the credential definition matches.
    // TODO: If no credential definition is present on the proposal, we could check whether the other fields
    // of the proposal match with the credential definition id.
    return credentialProposal.credentialDefinitionId === credentialOfferJson.cred_def_id
  }

  public async shouldAutoRespondToRequest(
    agentContext: AgentContext,
    { offerAttachment, requestAttachment }: CredentialFormatAutoRespondRequestOptions
  ) {
    const credentialOfferJson = offerAttachment.getDataAsJson<Indy.CredOffer>()
    const credentialRequestJson = requestAttachment.getDataAsJson<Indy.CredReq>()

    return credentialOfferJson.cred_def_id == credentialRequestJson.cred_def_id
  }

  public async shouldAutoRespondToCredential(
    agentContext: AgentContext,
    { credentialRecord, requestAttachment, credentialAttachment }: CredentialFormatAutoRespondCredentialOptions
  ) {
    const credentialJson = credentialAttachment.getDataAsJson<Indy.Cred>()
    const credentialRequestJson = requestAttachment.getDataAsJson<Indy.CredReq>()

    // make sure the credential definition matches
    if (credentialJson.cred_def_id !== credentialRequestJson.cred_def_id) return false

    // If we don't have any attributes stored we can't compare so always return false.
    if (!credentialRecord.credentialAttributes) return false
    const attributeValues = IndyCredentialUtils.convertAttributesToValues(credentialRecord.credentialAttributes)

    // check whether the values match the values in the record
    return IndyCredentialUtils.checkValuesMatch(attributeValues, credentialJson.values)
  }

  private async createIndyOffer(
    agentContext: AgentContext,
    {
      credentialRecord,
      attachmentId,
      credentialDefinitionId,
      attributes,
      linkedAttachments,
    }: {
      credentialDefinitionId: string
      credentialRecord: CredentialExchangeRecord
      attachmentId?: string
      attributes: CredentialPreviewAttributeOptions[]
      linkedAttachments?: LinkedAttachment[]
    }
  ): Promise<CredentialFormatCreateOfferReturn> {
    const indyIssuerService = agentContext.dependencyManager.resolve(IndyIssuerService)

    // if the proposal has an attachment Id use that, otherwise the generated id of the formats object
    const format = new CredentialFormatSpec({
      attachmentId,
      format: INDY_CRED_ABSTRACT,
    })

    const offer = await indyIssuerService.createCredentialOffer(agentContext, credentialDefinitionId)

    const { previewAttributes } = this.getCredentialLinkedAttachments(attributes, linkedAttachments)
    if (!previewAttributes) {
      throw new AriesFrameworkError('Missing required preview attributes for indy offer')
    }

    await this.assertPreviewAttributesMatchSchemaAttributes(agentContext, offer, previewAttributes)

    credentialRecord.metadata.set(CredentialMetadataKeys.IndyCredential, {
      schemaId: offer.schema_id,
      credentialDefinitionId: offer.cred_def_id,
    })

    const attachment = this.getFormatData(offer, format.attachmentId)

    return { format, attachment, previewAttributes }
  }

  private async assertPreviewAttributesMatchSchemaAttributes(
    agentContext: AgentContext,
    offer: Indy.CredOffer,
    attributes: CredentialPreviewAttribute[]
  ): Promise<void> {
    const indyLedgerService = agentContext.dependencyManager.resolve(IndyLedgerService)

    const schema = await indyLedgerService.getSchema(agentContext, offer.schema_id)

    IndyCredentialUtils.checkAttributesMatch(schema, attributes)
  }

  private async getIndyHolderDid(agentContext: AgentContext, credentialRecord: CredentialExchangeRecord) {
    const connectionService = agentContext.dependencyManager.resolve(ConnectionService)
    const didResolver = agentContext.dependencyManager.resolve(DidResolverService)

    // If we have a connection id we try to extract the did from the connection did document.
    if (credentialRecord.connectionId) {
      const connection = await connectionService.getById(agentContext, credentialRecord.connectionId)
      if (!connection.did) {
        throw new AriesFrameworkError(`Connection record ${connection.id} has no 'did'`)
      }
      const resolved = await didResolver.resolve(agentContext, connection.did)

      if (resolved.didDocument) {
        const verificationMethod = await findVerificationMethodByKeyType(
          'Ed25519VerificationKey2018',
          resolved.didDocument
        )

        if (verificationMethod) {
          return getIndyDidFromVerificationMethod(verificationMethod)
        }
      }
    }

    // If it wasn't successful to extract the did from the connection, we'll create a new key (e.g. if using connection-less)
    // FIXME: we already create a did for the exchange when using connection-less, but this is on a higher level. We should look at
    // a way to reuse this key, but for now this is easier.
    const key = await agentContext.wallet.createKey({ keyType: KeyType.Ed25519 })
    const did = TypedArrayEncoder.toBase58(key.publicKey.slice(0, 16))

    return did
  }

  /**
   * Get linked attachments for indy format from a proposal message. This allows attachments
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
    previewAttributes?: CredentialPreviewAttribute[]
  } {
    if (!linkedAttachments && !attributes) {
      return {}
    }

    let previewAttributes = attributes?.map((attribute) => new CredentialPreviewAttribute(attribute)) ?? []
    let attachments: Attachment[] | undefined

    if (linkedAttachments) {
      // there are linked attachments so transform into the attribute field of the CredentialPreview object for
      // this proposal
      previewAttributes = IndyCredentialUtils.createAndLinkAttachmentsToPreview(linkedAttachments, previewAttributes)
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
  private getFormatData(data: unknown, id: string): Attachment {
    const attachment = new Attachment({
      id,
      mimeType: 'application/json',
      data: new AttachmentData({
        base64: JsonEncoder.toBase64(data),
      }),
    })

    return attachment
  }
}
