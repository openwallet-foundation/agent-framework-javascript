import type { ProofFormatCredentialForRequestPayload, ProofFormatPayload } from './formats'
import type { AutoAcceptProof } from './models'
import type { ProofProtocol } from './protocol/ProofProtocol'
import type {
  DeleteProofOptions,
  GetProofFormatDataReturn,
  ProofFormatsFromProtocols,
} from './protocol/ProofProtocolOptions'

// re-export GetFormatDataReturn type from protocol, as it is also used in the api
export type { GetProofFormatDataReturn, DeleteProofOptions }

export type FindProofProposalMessageReturn<PPs extends ProofProtocol[]> = ReturnType<PPs[number]['findProposalMessage']>
export type FindProofRequestMessageReturn<PPs extends ProofProtocol[]> = ReturnType<PPs[number]['findRequestMessage']>
export type FindProofPresentationMessageReturn<PPs extends ProofProtocol[]> = ReturnType<
  PPs[number]['findPresentationMessage']
>

/**
 * Get the supported protocol versions based on the provided proof protocols.
 */
export type ProofsProtocolVersionType<PPs extends ProofProtocol[]> = PPs[number]['version']

interface BaseOptions {
  autoAcceptProof?: AutoAcceptProof
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

/**
 * Interface for ProofsApi.proposeProof. Will send a proposal.
 */
export interface ProposeProofOptions<PPs extends ProofProtocol[] = ProofProtocol[]> extends BaseOptions {
  connectionId: string
  protocolVersion: ProofsProtocolVersionType<PPs>
  proofFormats: ProofFormatPayload<ProofFormatsFromProtocols<PPs>, 'createProposal'>

  parentThreadId?: string
}

/**
 * Interface for ProofsApi.acceptProposal. Will send a request
 *
 * proofFormats is optional because this is an accept method
 */
export interface AcceptProofProposalOptions<PPs extends ProofProtocol[] = ProofProtocol[]> extends BaseOptions {
  proofRecordId: string
  proofFormats?: ProofFormatPayload<ProofFormatsFromProtocols<PPs>, 'acceptProposal'>

  /** @default true */
  willConfirm?: boolean
}

/**
 * Interface for ProofsApi.negotiateProposal. Will send a request
 */
export interface NegotiateProofProposalOptions<PPs extends ProofProtocol[] = ProofProtocol[]> extends BaseOptions {
  proofRecordId: string
  proofFormats: ProofFormatPayload<ProofFormatsFromProtocols<PPs>, 'createRequest'>

  /** @default true */
  willConfirm?: boolean
}

/**
 * Interface for ProofsApi.createRequest. Will create an out of band request
 */
export interface CreateProofRequestOptions<PPs extends ProofProtocol[] = ProofProtocol[]> extends BaseOptions {
  protocolVersion: ProofsProtocolVersionType<PPs>
  proofFormats: ProofFormatPayload<ProofFormatsFromProtocols<PPs>, 'createRequest'>

  parentThreadId?: string

  /** @default true */
  willConfirm?: boolean
}

/**
 * Interface for ProofsApi.requestCredential. Extends CreateProofRequestOptions, will send a request
 */
export interface RequestProofOptions<PPs extends ProofProtocol[] = ProofProtocol[]>
  extends BaseOptions,
    CreateProofRequestOptions<PPs> {
  connectionId: string
}

/**
 * Interface for ProofsApi.acceptRequest. Will send a presentation
 */
export interface AcceptProofRequestOptions<PPs extends ProofProtocol[] = ProofProtocol[]> extends BaseOptions {
  proofRecordId: string

  /**
   * whether to enable return routing on the send presentation message. This value only
   * has an effect for connectionless exchanges.
   */
  useReturnRoute?: boolean
  proofFormats?: ProofFormatPayload<ProofFormatsFromProtocols<PPs>, 'acceptRequest'>

  /** @default true */
  willConfirm?: boolean
}

/**
 * Interface for ProofsApi.negotiateRequest. Will send a proposal
 */
export interface NegotiateProofRequestOptions<PPs extends ProofProtocol[] = ProofProtocol[]> extends BaseOptions {
  proofRecordId: string
  proofFormats: ProofFormatPayload<ProofFormatsFromProtocols<PPs>, 'createProposal'>
}

/**
 * Interface for ProofsApi.acceptPresentation. Will send an ack message
 */
export interface AcceptProofOptions {
  proofRecordId: string
}

/**
 * Interface for ProofsApi.getCredentialsForRequest. Will return the credentials that match the proof request
 */
export interface GetCredentialsForProofRequestOptions<PPs extends ProofProtocol[] = ProofProtocol[]> {
  proofRecordId: string
  proofFormats?: ProofFormatCredentialForRequestPayload<
    ProofFormatsFromProtocols<PPs>,
    'getCredentialsForRequest',
    'input'
  >
}

export interface GetCredentialsForProofRequestReturn<PPs extends ProofProtocol[] = ProofProtocol[]> {
  proofFormats: ProofFormatCredentialForRequestPayload<
    ProofFormatsFromProtocols<PPs>,
    'getCredentialsForRequest',
    'output'
  >
}

/**
 * Interface for ProofsApi.selectCredentialsForRequest. Will automatically select return the first/best
 * credentials that match the proof request
 */
export interface SelectCredentialsForProofRequestOptions<PPs extends ProofProtocol[] = ProofProtocol[]> {
  proofRecordId: string
  proofFormats?: ProofFormatCredentialForRequestPayload<
    ProofFormatsFromProtocols<PPs>,
    'getCredentialsForRequest',
    'input'
  >
}

export interface SelectCredentialsForProofRequestReturn<PPs extends ProofProtocol[] = ProofProtocol[]> {
  proofFormats: ProofFormatCredentialForRequestPayload<
    ProofFormatsFromProtocols<PPs>,
    'selectCredentialsForRequest',
    'output'
  >
}

/**
 * Interface for ProofsApi.sendProblemReport. Will send a problem-report message
 */
export interface SendProofProblemReportOptions {
  proofRecordId: string
  description: string
}

/**
 * Interface for ProofsApi.declineRequest. Decline a received proof request and optionally send a problem-report message to Verifier
 */
export interface DeclineProofRequestOptions {
  proofRecordId: string

  /**
   * Whether to send a problem-report message to the verifier as part
   * of declining the proof request
   */
  sendProblemReport?: boolean

  /**
   * Description to include in the problem-report message
   * Only used if `sendProblemReport` is set to `true`.
   * @default "Request declined"
   */
  problemReportDescription?: string
}
