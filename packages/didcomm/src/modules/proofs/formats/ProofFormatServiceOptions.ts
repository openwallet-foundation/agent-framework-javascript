import type { ProofFormat, ProofFormatCredentialForRequestPayload, ProofFormatPayload } from './ProofFormat'
import type { ProofFormatService } from './ProofFormatService'
import type { Attachment } from '../../../decorators/attachment/Attachment'
import type { ProofFormatSpec } from '../models/ProofFormatSpec'
import type { ProofExchangeRecord } from '../repository/ProofExchangeRecord'

/**
 * Infer the {@link ProofFormat} based on a {@link ProofFormatService}.
 *
 * It does this by extracting the `ProofFormat` generic from the `ProofFormatService`.
 *
 * @example
 * ```
 * // TheProofFormat is now equal to IndyProofFormat
 * type TheProofFormat = ExtractProofFormat<IndyProofFormatService>
 * ```
 *
 * Because the `IndyProofFormatService` is defined as follows:
 * ```
 * class IndyProofFormatService implements ProofFormatService<IndyProofFormat> {
 * }
 * ```
 */
export type ExtractProofFormat<Type> = Type extends ProofFormatService<infer ProofFormat> ? ProofFormat : never

/**
 * Infer an array of {@link ProofFormat} types based on an array of {@link ProofFormatService} types.
 *
 * This is based on {@link ExtractProofFormat}, but allows to handle arrays.
 */
export type ExtractProofFormats<PFs extends ProofFormatService[]> = {
  [PF in keyof PFs]: ExtractProofFormat<PFs[PF]>
}

/**
 * Base return type for all methods that create an attachment format.
 *
 * It requires an attachment and a format to be returned.
 */
export interface ProofFormatCreateReturn {
  format: ProofFormatSpec
  attachment: Attachment
}

/**
 * Base type for all proof process methods.
 */
export interface ProofFormatProcessOptions {
  attachment: Attachment
  proofRecord: ProofExchangeRecord
}

export interface ProofFormatProcessPresentationOptions extends ProofFormatProcessOptions {
  requestAttachment: Attachment
}

export interface ProofFormatCreateProposalOptions<PF extends ProofFormat> {
  proofRecord: ProofExchangeRecord
  proofFormats: ProofFormatPayload<[PF], 'createProposal'>
  attachmentId?: string
}

export interface ProofFormatAcceptProposalOptions<PF extends ProofFormat> {
  proofRecord: ProofExchangeRecord
  proofFormats?: ProofFormatPayload<[PF], 'acceptProposal'>
  attachmentId?: string

  proposalAttachment: Attachment
}

export interface FormatCreateRequestOptions<PF extends ProofFormat> {
  proofRecord: ProofExchangeRecord
  proofFormats: ProofFormatPayload<[PF], 'createRequest'>
  attachmentId?: string
}

export interface ProofFormatAcceptRequestOptions<PF extends ProofFormat> {
  proofRecord: ProofExchangeRecord
  proofFormats?: ProofFormatPayload<[PF], 'acceptRequest'>
  attachmentId?: string

  requestAttachment: Attachment
  proposalAttachment?: Attachment
}

export interface ProofFormatGetCredentialsForRequestOptions<PF extends ProofFormat> {
  proofRecord: ProofExchangeRecord
  proofFormats?: ProofFormatCredentialForRequestPayload<[PF], 'getCredentialsForRequest', 'input'>

  requestAttachment: Attachment
  proposalAttachment?: Attachment
}

export type ProofFormatGetCredentialsForRequestReturn<PF extends ProofFormat> =
  PF['proofFormats']['getCredentialsForRequest']['output']

export interface ProofFormatSelectCredentialsForRequestOptions<PF extends ProofFormat> {
  proofRecord: ProofExchangeRecord
  proofFormats?: ProofFormatCredentialForRequestPayload<[PF], 'selectCredentialsForRequest', 'input'>

  requestAttachment: Attachment
  proposalAttachment?: Attachment
}

export type ProofFormatSelectCredentialsForRequestReturn<PF extends ProofFormat> =
  PF['proofFormats']['selectCredentialsForRequest']['output']

export interface ProofFormatAutoRespondProposalOptions {
  proofRecord: ProofExchangeRecord
  proposalAttachment: Attachment
  requestAttachment: Attachment
}

export interface ProofFormatAutoRespondRequestOptions {
  proofRecord: ProofExchangeRecord
  requestAttachment: Attachment
  proposalAttachment: Attachment
}

export interface ProofFormatAutoRespondPresentationOptions {
  proofRecord: ProofExchangeRecord
  proposalAttachment?: Attachment
  requestAttachment: Attachment
  presentationAttachment: Attachment
}
