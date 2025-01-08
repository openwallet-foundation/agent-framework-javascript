import type { CredentialFormat, CredentialFormatPayload } from './CredentialFormat'
import type { CredentialFormatService } from './CredentialFormatService'
import type { Attachment } from '../../../decorators/attachment/Attachment'
import type { CredentialFormatSpec } from '../models/CredentialFormatSpec'
import type { CredentialPreviewAttributeOptions } from '../models/CredentialPreviewAttribute'
import type { CredentialExchangeRecord } from '../repository/CredentialExchangeRecord'

/**
 * Infer the {@link CredentialFormat} based on a {@link CredentialFormatService}.
 *
 * It does this by extracting the `CredentialFormat` generic from the `CredentialFormatService`.
 *
 * @example
 * ```
 * // TheCredentialFormat is now equal to IndyCredentialFormat
 * type TheCredentialFormat = ExtractCredentialFormat<IndyCredentialFormatService>
 * ```
 *
 * Because the `IndyCredentialFormatService` is defined as follows:
 * ```
 * class IndyCredentialFormatService implements CredentialFormatService<IndyCredentialFormat> {
 * }
 * ```
 */
export type ExtractCredentialFormat<Type> = Type extends CredentialFormatService<infer CredentialFormat>
  ? CredentialFormat
  : never

/**
 * Infer an array of {@link CredentialFormat} types based on an array of {@link CredentialFormatService} types.
 *
 * This is based on {@link ExtractCredentialFormat}, but allows to handle arrays.
 */
export type ExtractCredentialFormats<CFs extends CredentialFormatService[]> = {
  [CF in keyof CFs]: ExtractCredentialFormat<CFs[CF]>
}

/**
 * Base return type for all methods that create an attachment format.
 *
 * It requires an attachment and a format to be returned.
 */
export interface CredentialFormatCreateReturn {
  format: CredentialFormatSpec
  attachment: Attachment
  appendAttachments?: Attachment[]
}

/**
 * Base return type for all credential process methods.
 */
export interface CredentialFormatProcessOptions {
  attachment: Attachment
  credentialRecord: CredentialExchangeRecord
}

export interface CredentialFormatProcessCredentialOptions extends CredentialFormatProcessOptions {
  offerAttachment: Attachment
  requestAttachment: Attachment
  requestAppendAttachments?: Attachment[]
}

export interface CredentialFormatCreateProposalOptions<CF extends CredentialFormat> {
  credentialRecord: CredentialExchangeRecord
  credentialFormats: CredentialFormatPayload<[CF], 'createProposal'>
  attachmentId?: string
}

export interface CredentialFormatAcceptProposalOptions<CF extends CredentialFormat> {
  credentialRecord: CredentialExchangeRecord
  credentialFormats?: CredentialFormatPayload<[CF], 'acceptProposal'>
  attachmentId?: string

  proposalAttachment: Attachment
}

export interface CredentialFormatCreateProposalReturn extends CredentialFormatCreateReturn {
  previewAttributes?: CredentialPreviewAttributeOptions[]
}

export interface CredentialFormatCreateOfferOptions<CF extends CredentialFormat> {
  credentialRecord: CredentialExchangeRecord
  credentialFormats: CredentialFormatPayload<[CF], 'createOffer'>
  attachmentId?: string
}

export interface CredentialFormatAcceptOfferOptions<CF extends CredentialFormat> {
  credentialRecord: CredentialExchangeRecord
  credentialFormats?: CredentialFormatPayload<[CF], 'acceptOffer'>
  attachmentId?: string
  offerAttachment: Attachment
}

export interface CredentialFormatCreateOfferReturn extends CredentialFormatCreateReturn {
  previewAttributes?: CredentialPreviewAttributeOptions[]
}

export interface CredentialFormatCreateRequestOptions<CF extends CredentialFormat> {
  credentialRecord: CredentialExchangeRecord
  credentialFormats: CredentialFormatPayload<[CF], 'createRequest'>
}

export interface CredentialFormatAcceptRequestOptions<CF extends CredentialFormat> {
  credentialRecord: CredentialExchangeRecord
  credentialFormats?: CredentialFormatPayload<[CF], 'acceptRequest'>
  attachmentId?: string
  offerAttachment?: Attachment
  requestAttachment: Attachment
  requestAppendAttachments?: Attachment[]
}

// Auto accept method interfaces
export interface CredentialFormatAutoRespondProposalOptions {
  credentialRecord: CredentialExchangeRecord
  proposalAttachment: Attachment
  offerAttachment: Attachment
}

export interface CredentialFormatAutoRespondOfferOptions {
  credentialRecord: CredentialExchangeRecord
  proposalAttachment: Attachment
  offerAttachment: Attachment
}

export interface CredentialFormatAutoRespondRequestOptions {
  credentialRecord: CredentialExchangeRecord
  proposalAttachment?: Attachment
  offerAttachment: Attachment
  requestAttachment: Attachment
}

export interface CredentialFormatAutoRespondCredentialOptions {
  credentialRecord: CredentialExchangeRecord
  proposalAttachment?: Attachment
  offerAttachment?: Attachment
  requestAttachment: Attachment
  credentialAttachment: Attachment
}
