import type { AgentContext } from '../../../agent'
import type { AgentConfig } from '../../../agent/AgentConfig'
import type { DidCommMessageRepository } from '../../../storage'
import type {
  CreateRequestAsResponseOptions,
  RequestedCredentialReturn,
  RetrievedCredentialOptions,
} from '../ProofServiceOptions'
import type { ProofAttachmentFormat } from './ProofAttachmentFormat'
import type { ProofFormat } from './ProofFormat'
import type {
  FormatPresentationAttachment,
  FormatCreateProofRequestOptions,
  FormatCreatePresentationOptions,
  FormatCreateProofProposalOptions,
  FormatGetRequestedCredentials,
  FormatProcessPresentationOptions,
  FormatProcessProposalOptions,
  FormatProcessRequestOptions,
  FormatProofRequestOptions,
} from './ProofFormatServiceOptions'

/**
 * This abstract class is the base class for any proof format
 * specific service.
 *
 * @export
 * @abstract
 * @class ProofFormatService
 */
export abstract class ProofFormatService<PF extends ProofFormat = ProofFormat> {
  protected didCommMessageRepository: DidCommMessageRepository
  protected agentConfig: AgentConfig

  abstract readonly formatKey: PF['formatKey']

  public constructor(didCommMessageRepository: DidCommMessageRepository, agentConfig: AgentConfig) {
    this.didCommMessageRepository = didCommMessageRepository
    this.agentConfig = agentConfig
  }

  abstract createProposal(options: FormatCreateProofProposalOptions): Promise<ProofAttachmentFormat>

  abstract processProposal(options: FormatProcessProposalOptions): Promise<void>

  abstract createRequest(options: FormatCreateProofRequestOptions): Promise<ProofAttachmentFormat>

  abstract processRequest(options: FormatProcessRequestOptions): Promise<void>

  abstract createPresentation(
    agentContext: AgentContext,
    options: FormatCreatePresentationOptions<PF>
  ): Promise<ProofAttachmentFormat>

  abstract processPresentation(agentContext: AgentContext, options: FormatProcessPresentationOptions): Promise<boolean>

  abstract createProofRequestFromProposal(options: FormatPresentationAttachment): Promise<FormatProofRequestOptions>

  public abstract getRequestedCredentialsForProofRequest(
    agentContext: AgentContext,
    options: FormatGetRequestedCredentials
  ): Promise<RetrievedCredentialOptions<[PF]>>

  public abstract autoSelectCredentialsForProofRequest(
    options: RetrievedCredentialOptions<[PF]>
  ): Promise<RequestedCredentialReturn<[PF]>>

  abstract proposalAndRequestAreEqual(
    proposalAttachments: ProofAttachmentFormat[],
    requestAttachments: ProofAttachmentFormat[]
  ): boolean

  abstract supportsFormat(formatIdentifier: string): boolean

  abstract createRequestAsResponse(options: CreateRequestAsResponseOptions<[PF]>): Promise<ProofAttachmentFormat>
}
