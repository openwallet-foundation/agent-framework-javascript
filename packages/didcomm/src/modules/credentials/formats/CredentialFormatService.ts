import type { CredentialFormat } from './CredentialFormat'
import type {
  CredentialFormatCreateProposalOptions,
  CredentialFormatCreateProposalReturn,
  CredentialFormatProcessOptions,
  CredentialFormatCreateOfferOptions,
  CredentialFormatCreateOfferReturn,
  CredentialFormatCreateRequestOptions,
  CredentialFormatCreateReturn,
  CredentialFormatAcceptRequestOptions,
  CredentialFormatAcceptOfferOptions,
  CredentialFormatAcceptProposalOptions,
  CredentialFormatAutoRespondCredentialOptions,
  CredentialFormatAutoRespondOfferOptions,
  CredentialFormatAutoRespondProposalOptions,
  CredentialFormatAutoRespondRequestOptions,
  CredentialFormatProcessCredentialOptions,
} from './CredentialFormatServiceOptions'
import type { AgentContext } from '@credo-ts/core'

export interface CredentialFormatService<CF extends CredentialFormat = CredentialFormat> {
  formatKey: CF['formatKey']
  credentialRecordType: CF['credentialRecordType']

  // proposal methods
  createProposal(
    agentContext: AgentContext,
    options: CredentialFormatCreateProposalOptions<CF>
  ): Promise<CredentialFormatCreateProposalReturn>
  processProposal(agentContext: AgentContext, options: CredentialFormatProcessOptions): Promise<void>
  acceptProposal(
    agentContext: AgentContext,
    options: CredentialFormatAcceptProposalOptions<CF>
  ): Promise<CredentialFormatCreateOfferReturn>

  // offer methods
  createOffer(
    agentContext: AgentContext,
    options: CredentialFormatCreateOfferOptions<CF>
  ): Promise<CredentialFormatCreateOfferReturn>
  processOffer(agentContext: AgentContext, options: CredentialFormatProcessOptions): Promise<void>
  acceptOffer(
    agentContext: AgentContext,
    options: CredentialFormatAcceptOfferOptions<CF>
  ): Promise<CredentialFormatCreateReturn>

  // request methods
  createRequest(
    agentContext: AgentContext,
    options: CredentialFormatCreateRequestOptions<CF>
  ): Promise<CredentialFormatCreateReturn>
  processRequest(agentContext: AgentContext, options: CredentialFormatProcessOptions): Promise<void>
  acceptRequest(
    agentContext: AgentContext,
    options: CredentialFormatAcceptRequestOptions<CF>
  ): Promise<CredentialFormatCreateReturn>

  // credential methods
  processCredential(agentContext: AgentContext, options: CredentialFormatProcessCredentialOptions): Promise<void>

  // auto accept methods
  shouldAutoRespondToProposal(
    agentContext: AgentContext,
    options: CredentialFormatAutoRespondProposalOptions
  ): Promise<boolean>
  shouldAutoRespondToOffer(
    agentContext: AgentContext,
    options: CredentialFormatAutoRespondOfferOptions
  ): Promise<boolean>
  shouldAutoRespondToRequest(
    agentContext: AgentContext,
    options: CredentialFormatAutoRespondRequestOptions
  ): Promise<boolean>
  shouldAutoRespondToCredential(
    agentContext: AgentContext,
    options: CredentialFormatAutoRespondCredentialOptions
  ): Promise<boolean>

  deleteCredentialById(agentContext: AgentContext, credentialId: string): Promise<void>

  supportsFormat(formatIdentifier: string): boolean
}
