import type { IndyRequestProofFormat, IndyVerifyProofFormat } from '../formats/IndyProofFormatsServiceOptions'
import type { PresentationExchangeProposalFormat } from '../formats/PresentationExchangeFormatsServiceOptions'
import type { IndyProposeProofFormat } from '../formats/indy/IndyProofFormat'
import type { ProofRequest } from '../formats/indy/models/ProofRequest'
import type { IndyRequestedCredentialsOptions, RequestedCredentials } from '../formats/indy/models/RequestedCredentials'
import type { RetrievedCredentials } from '../formats/indy/models/RetrievedCredentials'
import type { RequestPresentationExchangeOptions } from '../formats/presentation-exchange/models/RequestPresentation'
import type { RequestPresentationOptions } from '../protocol/v1/messages'
import type { GetRequestedCredentialsConfig } from './GetRequestedCredentialsConfig'
import type { SelectResults } from '@sphereon/pex'
import type { IVerifiableCredential } from '@sphereon/ssi-types'

export interface ProposeProofFormats {
  // If you want to propose an indy proof without attributes or
  // any of the other properties you should pass an empty object
  indy?: IndyProposeProofFormat
  presentationExchange?: PresentationExchangeProposalFormat
}

export interface RequestProofFormats {
  indy?: IndyRequestProofFormat
  presentationExchange?: RequestPresentationOptions
}

export interface CreatePresentationFormats {
  indy?: IndyRequestedCredentialsOptions
  presentationExchange?: IVerifiableCredential
}

export interface AcceptProposalFormats {
  indy?: IndyAcceptProposalOptions
  presentationExchange?: never
}

export interface VerifyProofFormats {
  indy?: IndyVerifyProofFormat
  presentationExchange?: never
}

export interface RequestedCredentialConfigOptions {
  indy?: GetRequestedCredentialsConfig
  presentationExchange?: never
}

export interface RetrievedCredentialOptions {
  indy?: RetrievedCredentials
  presentationExchange?: SelectResults
}

export interface ProofRequestFormats {
  indy?: ProofRequest
  presentationExchange?: RequestPresentationExchangeOptions
}

export interface RequestedCredentialsFormats {
  indy?: RequestedCredentials
  presentationExchange?: IVerifiableCredential
}

interface IndyAcceptProposalOptions {
  request: ProofRequest
}

export interface AutoSelectCredentialOptions {
  indy?: RetrievedCredentials
  presentationExchange?: SelectResults
}
