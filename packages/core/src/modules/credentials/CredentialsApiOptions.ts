import type { GetFormatDataReturn } from './CredentialServiceOptions'
import type { CredentialFormat, CredentialFormatPayload } from './formats'
import type { AutoAcceptCredential } from './models/CredentialAutoAcceptType'
import type { CredentialService } from './services'

// re-export GetFormatDataReturn type from service, as it is also used in the module
export type { GetFormatDataReturn }

export type FindCredentialProposalMessageReturn<CSs extends CredentialService[]> = ReturnType<
  CSs[number]['findProposalMessage']
>
export type FindCredentialOfferMessageReturn<CSs extends CredentialService[]> = ReturnType<
  CSs[number]['findOfferMessage']
>
export type FindCredentialRequestMessageReturn<CSs extends CredentialService[]> = ReturnType<
  CSs[number]['findRequestMessage']
>
export type FindCredentialMessageReturn<CSs extends CredentialService[]> = ReturnType<
  CSs[number]['findCredentialMessage']
>

/**
 * Get the supported protocol versions based on the provided credential services.
 */
export type CredentialProtocolVersionType<CSs extends CredentialService[]> = CSs[number]['version']

/**
 * Get the service map for usage in the credentials module. Will return a type mapping of protocol version to service.
 *
 * @example
 * ```
 * type ServiceMap = CredentialServiceMap<[IndyCredentialFormat], [V1CredentialService]>
 *
 * // equal to
 * type ServiceMap = {
 *   v1: V1CredentialService
 * }
 * ```
 */
export type CredentialServiceMap<CFs extends CredentialFormat[], CSs extends CredentialService<CFs>[]> = {
  [CS in CSs[number] as CS['version']]: CredentialService<CFs>
}

interface BaseOptions {
  autoAcceptCredential?: AutoAcceptCredential
  comment?: string
}

/**
 * Interface for CredentialsApi.proposeCredential. Will send a proposal.
 */
export interface ProposeCredentialOptions<
  CFs extends CredentialFormat[] = CredentialFormat[],
  CSs extends CredentialService[] = CredentialService[]
> extends BaseOptions {
  connectionId: string
  protocolVersion: CredentialProtocolVersionType<CSs>
  credentialFormats: CredentialFormatPayload<CFs, 'createProposal'>
}

/**
 * Interface for CredentialsApi.acceptProposal. Will send an offer
 *
 * credentialFormats is optional because this is an accept method
 */
export interface AcceptCredentialProposalOptions<CFs extends CredentialFormat[] = CredentialFormat[]>
  extends BaseOptions {
  credentialRecordId: string
  credentialFormats?: CredentialFormatPayload<CFs, 'acceptProposal'>
}

/**
 * Interface for CredentialsApi.negotiateProposal. Will send an offer
 */
export interface NegotiateCredentialProposalOptions<CFs extends CredentialFormat[] = CredentialFormat[]>
  extends BaseOptions {
  credentialRecordId: string
  credentialFormats: CredentialFormatPayload<CFs, 'createOffer'>
}

/**
 * Interface for CredentialsApi.createOffer. Will create an out of band offer
 */
export interface CreateOfferOptions<
  CFs extends CredentialFormat[] = CredentialFormat[],
  CSs extends CredentialService[] = CredentialService[]
> extends BaseOptions {
  protocolVersion: CredentialProtocolVersionType<CSs>
  credentialFormats: CredentialFormatPayload<CFs, 'createOffer'>
}

/**
 * Interface for CredentialsApi.offerCredentials. Extends CreateOfferOptions, will send an offer
 */
export interface OfferCredentialOptions<
  CFs extends CredentialFormat[] = CredentialFormat[],
  CSs extends CredentialService[] = CredentialService[]
> extends BaseOptions,
    CreateOfferOptions<CFs, CSs> {
  connectionId: string
}

/**
 * Interface for CredentialsApi.acceptOffer. Will send a request
 *
 * credentialFormats is optional because this is an accept method
 */
export interface AcceptCredentialOfferOptions<CFs extends CredentialFormat[] = CredentialFormat[]> extends BaseOptions {
  credentialRecordId: string
  credentialFormats?: CredentialFormatPayload<CFs, 'acceptOffer'>
}

/**
 * Interface for CredentialsApi.negotiateOffer. Will send a proposal.
 */
export interface NegotiateCredentialOfferOptions<CFs extends CredentialFormat[] = CredentialFormat[]>
  extends BaseOptions {
  credentialRecordId: string
  credentialFormats: CredentialFormatPayload<CFs, 'createProposal'>
}

/**
 * Interface for CredentialsApi.acceptRequest. Will send a credential
 *
 * credentialFormats is optional because this is an accept method
 */
export interface AcceptCredentialRequestOptions<CFs extends CredentialFormat[] = CredentialFormat[]>
  extends BaseOptions {
  credentialRecordId: string
  credentialFormats?: CredentialFormatPayload<CFs, 'acceptRequest'>
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
 * Interface for CredentialsApi.sendProblemReport. Will send a problem-report message
 */
export interface SendCredentialProblemReportOptions {
  credentialRecordId: string
  message: string
}
