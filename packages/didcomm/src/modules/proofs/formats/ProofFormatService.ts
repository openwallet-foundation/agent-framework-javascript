import type { ProofFormat } from './ProofFormat'
import type {
  ProofFormatAcceptProposalOptions,
  ProofFormatAcceptRequestOptions,
  ProofFormatCreateProposalOptions,
  FormatCreateRequestOptions,
  ProofFormatProcessPresentationOptions,
  ProofFormatCreateReturn,
  ProofFormatProcessOptions,
  ProofFormatGetCredentialsForRequestOptions,
  ProofFormatGetCredentialsForRequestReturn,
  ProofFormatSelectCredentialsForRequestOptions,
  ProofFormatSelectCredentialsForRequestReturn,
  ProofFormatAutoRespondProposalOptions,
  ProofFormatAutoRespondRequestOptions,
  ProofFormatAutoRespondPresentationOptions,
} from './ProofFormatServiceOptions'
import type { AgentContext } from '@credo-ts/core'

export interface ProofFormatService<PF extends ProofFormat = ProofFormat> {
  formatKey: PF['formatKey']

  // proposal methods
  createProposal(
    agentContext: AgentContext,
    options: ProofFormatCreateProposalOptions<PF>
  ): Promise<ProofFormatCreateReturn>
  processProposal(agentContext: AgentContext, options: ProofFormatProcessOptions): Promise<void>
  acceptProposal(
    agentContext: AgentContext,
    options: ProofFormatAcceptProposalOptions<PF>
  ): Promise<ProofFormatCreateReturn>

  // request methods
  createRequest(agentContext: AgentContext, options: FormatCreateRequestOptions<PF>): Promise<ProofFormatCreateReturn>
  processRequest(agentContext: AgentContext, options: ProofFormatProcessOptions): Promise<void>
  acceptRequest(
    agentContext: AgentContext,
    options: ProofFormatAcceptRequestOptions<PF>
  ): Promise<ProofFormatCreateReturn>

  // presentation methods
  processPresentation(agentContext: AgentContext, options: ProofFormatProcessPresentationOptions): Promise<boolean>

  // credentials for request
  getCredentialsForRequest(
    agentContext: AgentContext,
    options: ProofFormatGetCredentialsForRequestOptions<PF>
  ): Promise<ProofFormatGetCredentialsForRequestReturn<PF>>
  selectCredentialsForRequest(
    agentContext: AgentContext,
    options: ProofFormatSelectCredentialsForRequestOptions<PF>
  ): Promise<ProofFormatSelectCredentialsForRequestReturn<PF>>

  // auto accept methods
  shouldAutoRespondToProposal(
    agentContext: AgentContext,
    options: ProofFormatAutoRespondProposalOptions
  ): Promise<boolean>
  shouldAutoRespondToRequest(
    agentContext: AgentContext,
    options: ProofFormatAutoRespondRequestOptions
  ): Promise<boolean>
  shouldAutoRespondToPresentation(
    agentContext: AgentContext,
    options: ProofFormatAutoRespondPresentationOptions
  ): Promise<boolean>

  supportsFormat(formatIdentifier: string): boolean
}
