import type {
  CreateProofProposalOptions,
  CreateProofRequestOptions,
  DeleteProofOptions,
  GetProofFormatDataReturn,
  CreateProofProblemReportOptions,
  ProofProtocolMsgReturnType,
  AcceptProofProposalOptions,
  NegotiateProofProposalOptions,
  AcceptProofRequestOptions,
  NegotiateProofRequestOptions,
  AcceptPresentationOptions,
  GetCredentialsForRequestOptions,
  GetCredentialsForRequestReturn,
  SelectCredentialsForRequestOptions,
  SelectCredentialsForRequestReturn,
} from './ProofProtocolOptions'
import type { AgentMessage } from '../../../agent/AgentMessage'
import type { FeatureRegistry } from '../../../agent/FeatureRegistry'
import type { AgentContext } from '../../../agent/context/AgentContext'
import type { InboundMessageContext } from '../../../agent/models/InboundMessageContext'
import type { DependencyManager } from '../../../plugins'
import type { Query, QueryOptions } from '../../../storage/StorageService'
import type { ProblemReportMessage } from '../../problem-reports'
import type { ExtractProofFormats, ProofFormatService } from '../formats'
import type { ProofRole } from '../models'
import type { ProofState } from '../models/ProofState'
import type { ProofExchangeRecord } from '../repository'

export interface ProofProtocol<PFs extends ProofFormatService[] = ProofFormatService[]> {
  readonly version: string

  // methods for proposal
  createProposal(
    agentContext: AgentContext,
    options: CreateProofProposalOptions<PFs>
  ): Promise<ProofProtocolMsgReturnType<AgentMessage>>
  processProposal(messageContext: InboundMessageContext<AgentMessage>): Promise<ProofExchangeRecord>
  acceptProposal(
    agentContext: AgentContext,
    options: AcceptProofProposalOptions<PFs>
  ): Promise<ProofProtocolMsgReturnType<AgentMessage>>
  negotiateProposal(
    agentContext: AgentContext,
    options: NegotiateProofProposalOptions<PFs>
  ): Promise<ProofProtocolMsgReturnType<AgentMessage>>

  // methods for request
  createRequest(
    agentContext: AgentContext,
    options: CreateProofRequestOptions<PFs>
  ): Promise<ProofProtocolMsgReturnType<AgentMessage>>
  processRequest(messageContext: InboundMessageContext<AgentMessage>): Promise<ProofExchangeRecord>
  acceptRequest(
    agentContext: AgentContext,
    options: AcceptProofRequestOptions<PFs>
  ): Promise<ProofProtocolMsgReturnType<AgentMessage>>
  negotiateRequest(
    agentContext: AgentContext,
    options: NegotiateProofRequestOptions<PFs>
  ): Promise<ProofProtocolMsgReturnType<AgentMessage>>

  // retrieving credentials for request
  getCredentialsForRequest(
    agentContext: AgentContext,
    options: GetCredentialsForRequestOptions<PFs>
  ): Promise<GetCredentialsForRequestReturn<PFs>>
  selectCredentialsForRequest(
    agentContext: AgentContext,
    options: SelectCredentialsForRequestOptions<PFs>
  ): Promise<SelectCredentialsForRequestReturn<PFs>>

  // methods for presentation
  processPresentation(messageContext: InboundMessageContext<AgentMessage>): Promise<ProofExchangeRecord>
  acceptPresentation(
    agentContext: AgentContext,
    options: AcceptPresentationOptions
  ): Promise<ProofProtocolMsgReturnType<AgentMessage>>

  // methods for ack
  processAck(messageContext: InboundMessageContext<AgentMessage>): Promise<ProofExchangeRecord>

  // method for problem report
  createProblemReport(
    agentContext: AgentContext,
    options: CreateProofProblemReportOptions
  ): Promise<ProofProtocolMsgReturnType<ProblemReportMessage>>
  processProblemReport(messageContext: InboundMessageContext<ProblemReportMessage>): Promise<ProofExchangeRecord>

  findProposalMessage(agentContext: AgentContext, proofExchangeId: string): Promise<AgentMessage | null>
  findRequestMessage(agentContext: AgentContext, proofExchangeId: string): Promise<AgentMessage | null>
  findPresentationMessage(agentContext: AgentContext, proofExchangeId: string): Promise<AgentMessage | null>
  getFormatData(
    agentContext: AgentContext,
    proofExchangeId: string
  ): Promise<GetProofFormatDataReturn<ExtractProofFormats<PFs>>>

  // repository methods
  updateState(agentContext: AgentContext, proofRecord: ProofExchangeRecord, newState: ProofState): Promise<void>
  getById(agentContext: AgentContext, proofExchangeId: string): Promise<ProofExchangeRecord>
  getAll(agentContext: AgentContext): Promise<ProofExchangeRecord[]>
  findAllByQuery(
    agentContext: AgentContext,
    query: Query<ProofExchangeRecord>,
    queryOptions?: QueryOptions
  ): Promise<ProofExchangeRecord[]>
  findById(agentContext: AgentContext, proofExchangeId: string): Promise<ProofExchangeRecord | null>
  delete(agentContext: AgentContext, proofRecord: ProofExchangeRecord, options?: DeleteProofOptions): Promise<void>
  getByProperties(
    agentContext: AgentContext,
    properties: {
      threadId: string
      connectionId?: string
      role?: ProofRole
    }
  ): Promise<ProofExchangeRecord>
  findByProperties(
    agentContext: AgentContext,
    properties: {
      threadId: string
      connectionId?: string
      role?: ProofRole
    }
  ): Promise<ProofExchangeRecord | null>
  update(agentContext: AgentContext, proofRecord: ProofExchangeRecord): Promise<void>

  register(dependencyManager: DependencyManager, featureRegistry: FeatureRegistry): void
}
