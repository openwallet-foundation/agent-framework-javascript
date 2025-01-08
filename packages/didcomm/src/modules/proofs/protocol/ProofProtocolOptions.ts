import type { ProofProtocol } from './ProofProtocol'
import type { AgentMessage } from '../../../AgentMessage'
import type { ConnectionRecord } from '../../connections'
import type {
  ExtractProofFormats,
  ProofFormat,
  ProofFormatCredentialForRequestPayload,
  ProofFormatPayload,
  ProofFormatService,
} from '../formats'
import type { AutoAcceptProof } from '../models'
import type { ProofExchangeRecord } from '../repository'

/**
 * Get the format data payload for a specific message from a list of ProofFormat interfaces and a message
 *
 * For an indy offer, this resolves to the proof request format as defined here:
 * https://github.com/hyperledger/aries-rfcs/tree/b3a3942ef052039e73cd23d847f42947f8287da2/features/0592-indy-attachments#proof-request-format
 *
 * @example
 * ```
 *
 * type RequestFormatData = ProofFormatDataMessagePayload<[IndyProofFormat, PresentationExchangeProofFormat], 'createRequest'>
 *
 * // equal to
 * type RequestFormatData = {
 *  indy: {
 *   // ... payload for indy proof request attachment as defined in RFC 0592 ...
 *  },
 *  presentationExchange: {
 *   // ... payload for presentation exchange request attachment as defined in RFC 0510 ...
 *  }
 * }
 * ```
 */
export type ProofFormatDataMessagePayload<
  CFs extends ProofFormat[] = ProofFormat[],
  M extends keyof ProofFormat['formatData'] = keyof ProofFormat['formatData']
> = {
  [ProofFormat in CFs[number] as ProofFormat['formatKey']]?: ProofFormat['formatData'][M]
}

/**
 * Infer the {@link ProofFormat} types based on an array of {@link ProofProtocol} types.
 *
 * It does this by extracting the `ProofFormatServices` generic from the `ProofProtocol`, and
 * then extracting the `ProofFormat` generic from each of the `ProofFormatService` types.
 *
 * @example
 * ```
 * // TheProofFormatServices is now equal to [IndyProofFormatService]
 * type TheProofFormatServices = ProofFormatsFromProtocols<[V1ProofProtocol]>
 * ```
 *
 * Because the `V1ProofProtocol` is defined as follows:
 * ```
 * class V1ProofProtocol implements ProofProtocol<[IndyProofFormatService]> {
 * }
 * ```
 */
export type ProofFormatsFromProtocols<Type extends ProofProtocol[]> = Type[number] extends ProofProtocol<
  infer ProofFormatServices
>
  ? ProofFormatServices extends ProofFormatService[]
    ? ExtractProofFormats<ProofFormatServices>
    : never
  : never

export type GetProofFormatDataReturn<PFs extends ProofFormat[] = ProofFormat[]> = {
  proposal?: ProofFormatDataMessagePayload<PFs, 'proposal'>
  request?: ProofFormatDataMessagePayload<PFs, 'request'>
  presentation?: ProofFormatDataMessagePayload<PFs, 'presentation'>
}

interface BaseOptions {
  comment?: string
  autoAcceptProof?: AutoAcceptProof

  /**
   * Will be ignored for v1 protocol as it is not supported
   */
  goalCode?: string

  /**
   * Will be ignored for v1 protocol as it is not supported
   */
  goal?: string
}

export interface CreateProofProposalOptions<PFs extends ProofFormatService[]> extends BaseOptions {
  connectionRecord: ConnectionRecord
  proofFormats: ProofFormatPayload<ExtractProofFormats<PFs>, 'createProposal'>
  parentThreadId?: string
}

export interface AcceptProofProposalOptions<PFs extends ProofFormatService[]> extends BaseOptions {
  proofRecord: ProofExchangeRecord
  proofFormats?: ProofFormatPayload<ExtractProofFormats<PFs>, 'acceptProposal'>

  /** @default true */
  willConfirm?: boolean
}

export interface NegotiateProofProposalOptions<PFs extends ProofFormatService[]> extends BaseOptions {
  proofRecord: ProofExchangeRecord
  proofFormats: ProofFormatPayload<ExtractProofFormats<PFs>, 'createRequest'>

  /** @default true */
  willConfirm?: boolean
}

export interface CreateProofRequestOptions<PFs extends ProofFormatService[]> extends BaseOptions {
  // Create request can also be used for connection-less, so connection is optional
  connectionRecord?: ConnectionRecord
  proofFormats: ProofFormatPayload<ExtractProofFormats<PFs>, 'createRequest'>
  parentThreadId?: string

  /** @default true */
  willConfirm?: boolean
}

export interface AcceptProofRequestOptions<PFs extends ProofFormatService[]> extends BaseOptions {
  proofRecord: ProofExchangeRecord
  proofFormats?: ProofFormatPayload<ExtractProofFormats<PFs>, 'acceptRequest'>
}

export interface NegotiateProofRequestOptions<PFs extends ProofFormatService[]> extends BaseOptions {
  proofRecord: ProofExchangeRecord
  proofFormats: ProofFormatPayload<ExtractProofFormats<PFs>, 'createProposal'>
}

export interface GetCredentialsForRequestOptions<PFs extends ProofFormatService[]> {
  proofRecord: ProofExchangeRecord
  proofFormats?: ProofFormatCredentialForRequestPayload<ExtractProofFormats<PFs>, 'getCredentialsForRequest', 'input'>
}

export interface GetCredentialsForRequestReturn<PFs extends ProofFormatService[]> {
  proofFormats: ProofFormatCredentialForRequestPayload<ExtractProofFormats<PFs>, 'getCredentialsForRequest', 'output'>
}

export interface SelectCredentialsForRequestOptions<PFs extends ProofFormatService[]> {
  proofRecord: ProofExchangeRecord
  proofFormats?: ProofFormatCredentialForRequestPayload<
    ExtractProofFormats<PFs>,
    'selectCredentialsForRequest',
    'input'
  >
}

export interface SelectCredentialsForRequestReturn<PFs extends ProofFormatService[]> {
  proofFormats: ProofFormatCredentialForRequestPayload<
    ExtractProofFormats<PFs>,
    'selectCredentialsForRequest',
    'output'
  >
}

export interface AcceptPresentationOptions {
  proofRecord: ProofExchangeRecord
}

export interface CreateProofProblemReportOptions {
  proofRecord: ProofExchangeRecord
  description: string
}

export interface ProofProtocolMsgReturnType<MessageType extends AgentMessage> {
  message: MessageType
  proofRecord: ProofExchangeRecord
}

export interface DeleteProofOptions {
  deleteAssociatedDidCommMessages?: boolean
}
