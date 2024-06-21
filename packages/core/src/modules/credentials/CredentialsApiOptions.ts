import type { CredentialFormatPayload } from './formats'
import type { AutoAcceptCredential } from './models'
import type { CredentialProtocol } from './protocol/CredentialProtocol'
import type {
  CredentialFormatsFromProtocols,
  DeleteCredentialOptions,
  GetCredentialFormatDataReturn,
} from './protocol/CredentialProtocolOptions'

// re-export GetCredentialFormatDataReturn type from protocol, as it is also used in the api
export type { GetCredentialFormatDataReturn, DeleteCredentialOptions }

export type FindCredentialProposalMessageReturn<CPs extends CredentialProtocol[] = CredentialProtocol[]> = ReturnType<
  CPs[number]['findProposalMessage']
>
export type FindCredentialOfferMessageReturn<CPs extends CredentialProtocol[] = CredentialProtocol[]> = ReturnType<
  CPs[number]['findOfferMessage']
>
export type FindCredentialRequestMessageReturn<CPs extends CredentialProtocol[] = CredentialProtocol[]> = ReturnType<
  CPs[number]['findRequestMessage']
>
export type FindCredentialMessageReturn<CPs extends CredentialProtocol[] = CredentialProtocol[]> = ReturnType<
  CPs[number]['findCredentialMessage']
>

/**
 * Get the supported protocol versions based on the provided credential protocols.
 */
export type CredentialProtocolVersionType<CPs extends CredentialProtocol[] = CredentialProtocol[]> =
  CPs[number]['version']

interface BaseOptions {
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

/**
 * Interface for CredentialsApi.proposeCredential. Will send a proposal.
 */
export interface ProposeCredentialOptions<CPs extends CredentialProtocol[] = CredentialProtocol[]> extends BaseOptions {
  connectionId: string
  protocolVersion: CredentialProtocolVersionType<CPs>
  credentialFormats: CredentialFormatPayload<CredentialFormatsFromProtocols<CPs>, 'createProposal'>
}

/**
 * Interface for CredentialsApi.acceptProposal. Will send an offer
 *
 * credentialFormats is optional because this is an accept method
 */
export interface AcceptCredentialProposalOptions<CPs extends CredentialProtocol[] = CredentialProtocol[]>
  extends BaseOptions {
  credentialRecordId: string
  credentialFormats?: CredentialFormatPayload<CredentialFormatsFromProtocols<CPs>, 'acceptProposal'>
}

/**
 * Interface for CredentialsApi.negotiateProposal. Will send an offer
 */
export interface NegotiateCredentialProposalOptions<CPs extends CredentialProtocol[] = CredentialProtocol[]>
  extends BaseOptions {
  credentialRecordId: string
  credentialFormats: CredentialFormatPayload<CredentialFormatsFromProtocols<CPs>, 'createOffer'>
}

/**
 * Interface for CredentialsApi.createOffer. Will create an out of band offer
 */
export interface CreateCredentialOfferOptions<CPs extends CredentialProtocol[] = CredentialProtocol[]>
  extends BaseOptions {
  protocolVersion: CredentialProtocolVersionType<CPs>
  credentialFormats: CredentialFormatPayload<CredentialFormatsFromProtocols<CPs>, 'createOffer'>
}

/**
 * Interface for CredentialsApi.offerCredential. Extends CreateCredentialOfferOptions, will send an offer
 */
export interface OfferCredentialOptions<CPs extends CredentialProtocol[] = CredentialProtocol[]>
  extends BaseOptions,
    CreateCredentialOfferOptions<CPs> {
  connectionId: string
}

/**
 * Interface for CredentialsApi.acceptOffer. Will send a request
 *
 * credentialFormats is optional because this is an accept method
 */
export interface AcceptCredentialOfferOptions<CPs extends CredentialProtocol[] = CredentialProtocol[]>
  extends BaseOptions {
  credentialRecordId: string
  credentialFormats?: CredentialFormatPayload<CredentialFormatsFromProtocols<CPs>, 'acceptOffer'>
}

/**
 * Interface for CredentialsApi.negotiateOffer. Will send a proposal.
 */
export interface NegotiateCredentialOfferOptions<CPs extends CredentialProtocol[] = CredentialProtocol[]>
  extends BaseOptions {
  credentialRecordId: string
  credentialFormats: CredentialFormatPayload<CredentialFormatsFromProtocols<CPs>, 'createProposal'>
}

/**
 * Interface for CredentialsApi.acceptRequest. Will send a credential
 *
 * credentialFormats is optional because this is an accept method
 */
export interface AcceptCredentialRequestOptions<CPs extends CredentialProtocol[] = CredentialProtocol[]>
  extends BaseOptions {
  credentialRecordId: string
  credentialFormats?: CredentialFormatPayload<CredentialFormatsFromProtocols<CPs>, 'acceptRequest'>
  autoAcceptCredential?: AutoAcceptCredential
  comment?: string
}

/**
 * Interface for CredentialsApi.acceptCredential. Will send an ack message
 */
export interface AcceptCredentialOptions {
  credentialRecordId: string
}

/**
 * Interface for CredentialsApi.sendRevocationNotification. Will send a revoke message
 */
export interface SendRevocationNotificationOptions {
  credentialRecordId: string
  revocationId: string // TODO: Get from record?
  revocationFormat: string // TODO: Get from record?
  comment?: string
  requestAck?: boolean
}

/**
 * Interface for CredentialsApi.sendProblemReport. Will send a problem-report message
 */
export interface SendCredentialProblemReportOptions {
  credentialRecordId: string
  description: string
}

/**
 * Interface for CredentialsApi.declineOffer. Decline a received credential offer and optionally send a problem-report message to Issuer.
 */
export interface DeclineCredentialOfferOptions {
  // TODO: in next major release, move the id to this object as well
  // for consistency with the proofs api
  // credentialRecordId: string

  /**
   * Whether to send a problem-report message to the issuer as part
   * of declining the credential offer
   */
  sendProblemReport?: boolean

  /**
   * Description to include in the problem-report message
   * Only used if `sendProblemReport` is set to `true`.
   * @default "Offer declined"
   */
  problemReportDescription?: string
}
