import type { CredentialProtocol } from './CredentialProtocol'
import type { AgentMessage } from '../../../AgentMessage'
import type { ConnectionRecord } from '../../connections'
import type {
  CredentialFormat,
  CredentialFormatPayload,
  CredentialFormatService,
  ExtractCredentialFormats,
} from '../formats'
import type { CredentialPreviewAttributeOptions } from '../models'
import type { AutoAcceptCredential } from '../models/CredentialAutoAcceptType'
import type { CredentialExchangeRecord } from '../repository/CredentialExchangeRecord'

/**
 * Get the format data payload for a specific message from a list of CredentialFormat interfaces and a message
 *
 * For an indy offer, this resolves to the cred abstract format as defined here:
 * https://github.com/hyperledger/aries-rfcs/tree/b3a3942ef052039e73cd23d847f42947f8287da2/features/0592-indy-attachments#cred-abstract-format
 *
 * @example
 * ```
 *
 * type OfferFormatData = CredentialFormatDataMessagePayload<[IndyCredentialFormat, JsonLdCredentialFormat], 'createOffer'>
 *
 * // equal to
 * type OfferFormatData = {
 *  indy: {
 *   // ... payload for indy offer attachment as defined in RFC 0592 ...
 *  },
 *  jsonld: {
 *   // ... payload for jsonld offer attachment as defined in RFC 0593 ...
 *  }
 * }
 * ```
 */
export type CredentialFormatDataMessagePayload<
  CFs extends CredentialFormat[] = CredentialFormat[],
  M extends keyof CredentialFormat['formatData'] = keyof CredentialFormat['formatData']
> = {
  [Service in CFs[number] as Service['formatKey']]?: Service['formatData'][M]
}

/**
 * Infer the {@link CredentialFormat} types based on an array of {@link CredentialProtocol} types.
 *
 * It does this by extracting the `CredentialFormatServices` generic from the `CredentialProtocol`, and
 * then extracting the `CredentialFormat` generic from each of the `CredentialFormatService` types.
 *
 * @example
 * ```
 * // TheCredentialFormatServices is now equal to [IndyCredentialFormatService]
 * type TheCredentialFormatServices = CredentialFormatsFromProtocols<[V1CredentialProtocol]>
 * ```
 *
 * Because the `V1CredentialProtocol` is defined as follows:
 * ```
 * class V1CredentialProtocol implements CredentialProtocol<[IndyCredentialFormatService]> {
 * }
 * ```
 */
export type CredentialFormatsFromProtocols<Type extends CredentialProtocol[]> = Type[number] extends CredentialProtocol<
  infer CredentialFormatServices
>
  ? CredentialFormatServices extends CredentialFormatService[]
    ? ExtractCredentialFormats<CredentialFormatServices>
    : never
  : never

/**
 * Get format data return value. Each key holds a mapping of credential format key to format data.
 *
 * @example
 * ```
 * {
 *   proposal: {
 *     indy: {
 *       cred_def_id: string
 *     }
 *   }
 * }
 * ```
 */
export type GetCredentialFormatDataReturn<CFs extends CredentialFormat[] = CredentialFormat[]> = {
  proposalAttributes?: CredentialPreviewAttributeOptions[]
  proposal?: CredentialFormatDataMessagePayload<CFs, 'proposal'>
  offer?: CredentialFormatDataMessagePayload<CFs, 'offer'>
  offerAttributes?: CredentialPreviewAttributeOptions[]
  request?: CredentialFormatDataMessagePayload<CFs, 'request'>
  credential?: CredentialFormatDataMessagePayload<CFs, 'credential'>
}

interface BaseOptions {
  comment?: string
  autoAcceptCredential?: AutoAcceptCredential

  /**
   * Will be ignored for v1 protocol as it is not supported
   */
  goalCode?: string

  /**
   * Will be ignored for v1 protocol as it is not supported
   */
  goal?: string
}

export interface CreateCredentialProposalOptions<CFs extends CredentialFormatService[]> extends BaseOptions {
  connectionRecord: ConnectionRecord
  credentialFormats: CredentialFormatPayload<ExtractCredentialFormats<CFs>, 'createProposal'>
}

export interface AcceptCredentialProposalOptions<CFs extends CredentialFormatService[]> extends BaseOptions {
  credentialRecord: CredentialExchangeRecord
  credentialFormats?: CredentialFormatPayload<ExtractCredentialFormats<CFs>, 'acceptProposal'>
}

export interface NegotiateCredentialProposalOptions<CFs extends CredentialFormatService[]> {
  credentialRecord: CredentialExchangeRecord
  credentialFormats: CredentialFormatPayload<ExtractCredentialFormats<CFs>, 'createOffer'>
  autoAcceptCredential?: AutoAcceptCredential
  comment?: string

  /**
   * Will be ignored for v1 protocol as it is not supported
   */
  goalCode?: string

  /**
   * Will be ignored for v1 protocol as it is not supported
   */
  goal?: string
}

export interface CreateCredentialOfferOptions<CFs extends CredentialFormatService[]> extends BaseOptions {
  // Create offer can also be used for connection-less, so connection is optional
  connectionRecord?: ConnectionRecord
  credentialFormats: CredentialFormatPayload<ExtractCredentialFormats<CFs>, 'createOffer'>
}

export interface AcceptCredentialOfferOptions<CFs extends CredentialFormatService[]> extends BaseOptions {
  credentialRecord: CredentialExchangeRecord
  credentialFormats?: CredentialFormatPayload<ExtractCredentialFormats<CFs>, 'acceptOffer'>
}

export interface NegotiateCredentialOfferOptions<CFs extends CredentialFormatService[]> extends BaseOptions {
  credentialRecord: CredentialExchangeRecord
  credentialFormats: CredentialFormatPayload<ExtractCredentialFormats<CFs>, 'createProposal'>
}

export interface CreateCredentialRequestOptions<CFs extends CredentialFormatService[]> extends BaseOptions {
  connectionRecord: ConnectionRecord
  credentialFormats: CredentialFormatPayload<ExtractCredentialFormats<CFs>, 'createRequest'>
}

export interface AcceptCredentialRequestOptions<CFs extends CredentialFormatService[]> extends BaseOptions {
  credentialRecord: CredentialExchangeRecord
  credentialFormats?: CredentialFormatPayload<ExtractCredentialFormats<CFs>, 'acceptRequest'>
}

export interface AcceptCredentialOptions {
  credentialRecord: CredentialExchangeRecord
}

export interface CreateCredentialProblemReportOptions {
  credentialRecord: CredentialExchangeRecord
  description: string
}

export interface CredentialProtocolMsgReturnType<MessageType extends AgentMessage> {
  message: MessageType
  credentialRecord: CredentialExchangeRecord
}

export interface DeleteCredentialOptions {
  deleteAssociatedCredentials?: boolean
  deleteAssociatedDidCommMessages?: boolean
}
