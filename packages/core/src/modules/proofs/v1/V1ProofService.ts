import type { AgentMessage } from '../../../agent/AgentMessage'
import type { HandlerInboundMessage } from '../../../agent/Handler'
import type { AutoAcceptProof } from '../ProofAutoAcceptType'
import type { ProofRecord } from '../repository/ProofRecord'
import type { V2ProposePresentationHandler } from '../v2/handlers/V2ProposePresentationHandler'
import type {
  AcceptProposalOptions,
  CreateRequestOptions,
  PresentationConfig,
  ProofRequestAsResponse,
  ProofRequestConfigOptions,
  ProposeProofOptions,
  RequestProofOptions,
} from '../v2/interface'
import type { ProofRequestOptions, RetrievedCredentials } from './models'

import { Lifecycle, scoped } from 'tsyringe'

import { ConsoleLogger, LogLevel } from '../../../logger'
import { ConnectionService } from '../../connections'
import { PresentationPreview } from '../PresentationPreview'
import { ProofProtocolVersion } from '../ProofProtocolVersion'
import { ProofService } from '../ProofService'

import { V1LegacyProofService } from './V1LegacyProofService'
import { ProofRequest } from './models'

const logger = new ConsoleLogger(LogLevel.debug)

/**
 * @todo add method to check if request matches proposal. Useful to see if a request I received is the same as the proposal I sent.
 * @todo add method to reject / revoke messages
 * @todo validate attachments / messages
 */
@scoped(Lifecycle.ContainerScoped)
export class V1ProofService extends ProofService {
  createRequest(
    createRequestOptions: CreateRequestOptions
  ): Promise<{ proofRecord: ProofRecord; message: AgentMessage }> {
    throw new Error('Method not implemented.')
  }

  public createProofRequestFromProposal(acceptProposalOptions: AcceptProposalOptions): Promise<ProofRequest> {
    let presentationProposal: PresentationPreview | undefined
    let proofRequestOptions: ProofRequestConfigOptions | undefined

    if (acceptProposalOptions.proofFormats.indy) {
      presentationProposal = new PresentationPreview({
        attributes: acceptProposalOptions.proofFormats.indy?.presentationProposal?.attributes,
        predicates: acceptProposalOptions.proofFormats.indy?.presentationProposal?.predicates,
      })
      proofRequestOptions = acceptProposalOptions.proofFormats.indy?.proofRequestOptions
    } else {
      presentationProposal = new PresentationPreview({
        attributes: [],
        predicates: [],
      })
      proofRequestOptions = {
        name: '',
        version: '',
        nonce: '',
      }
    }
    return this.legacyProofService.createProofRequestFromProposal(presentationProposal, proofRequestOptions)
  }

  public processProposal(messageContext: HandlerInboundMessage<V2ProposePresentationHandler>): Promise<ProofRecord> {
    logger.debug(messageContext.message.id) // temp used to avoid lint errors
    throw new Error('Method not implemented.')
  }

  private legacyProofService: V1LegacyProofService

  private connectionService: ConnectionService

  public constructor(proofService: V1LegacyProofService, connectionService: ConnectionService) {
    super()
    this.legacyProofService = proofService
    this.connectionService = connectionService
  }

  public registerHandlers() {
    throw new Error('Method not implemented.')
  }

  public getVersion(): ProofProtocolVersion {
    return ProofProtocolVersion.V1_0
  }

  /**
   * Create a {@link ProposePresentationMessage} not bound to an existing presentation exchange.
   * To create a proposal as response to an existing presentation exchange, use {@link ProofService.createProposalAsResponse}.
   *
   * @param connectionRecord The connection for which to create the presentation proposal
   * @param presentationProposal The presentation proposal to include in the message
   * @param config Additional configuration to use for the proposal
   * @returns Object containing proposal message and associated proof record
   *
   */
  public async createProposal(
    proposal: ProposeProofOptions
  ): Promise<{ proofRecord: ProofRecord; message: AgentMessage }> {
    // Assert
    const connection = await this.connectionService.getById(proposal.connectionId)

    let presentationProposal: PresentationPreview | undefined
    if (proposal?.proofFormats?.indy?.proofPreview?.attributes) {
      presentationProposal = new PresentationPreview({
        attributes: proposal?.proofFormats.indy?.proofPreview?.attributes,
        predicates: proposal?.proofFormats.indy?.proofPreview?.predicates,
      })
    } else {
      presentationProposal = new PresentationPreview({
        attributes: [],
        predicates: [],
      })
    }

    const proposalConfig: PresentationConfig = {
      comment: proposal?.comment,
      autoAcceptProof: proposal?.autoAcceptProof,
    }

    const { message, proofRecord } = await this.legacyProofService.createProposal(
      connection,
      presentationProposal,
      proposalConfig
    )

    return { proofRecord, message }
  }

  public getRequestedCredentialsForProofRequest(
    proofRequest: ProofRequest,
    presentationProposal?: PresentationPreview
  ): Promise<RetrievedCredentials> {
    return this.legacyProofService.getRequestedCredentialsForProofRequest(proofRequest, presentationProposal)
  }

  public async createRequestAsResponse(
    proofRequestAsResponse: ProofRequestAsResponse
  ): Promise<{ message: AgentMessage; proofRecord: ProofRecord }> {
    // const { proofRecord, proofRequest } = proofRequestAsResponse
    const { message, proofRecord } = await this.legacyProofService.createRequestAsResponse(
      proofRequestAsResponse.proofRecord,
      proofRequestAsResponse.proofRequest
    )

    return { proofRecord, message }
  }

  public async requestProof(
    requestProofOptions: RequestProofOptions
  ): Promise<{ proofRecord: ProofRecord; message: AgentMessage }> {
    const { connectionId, proofRequestOptions, comment, autoAcceptProof } = requestProofOptions

    const connection = await this.connectionService.getById(connectionId)

    const nonce = proofRequestOptions.nonce ?? (await this.legacyProofService.generateProofRequestNonce())

    const proofRequest = new ProofRequest({
      name: proofRequestOptions.name ?? 'proof-request',
      version: proofRequestOptions.name ?? '1.0',
      nonce,
      requestedAttributes: proofRequestOptions.requestedAttributes,
      requestedPredicates: proofRequestOptions.requestedPredicates,
    })

    const proposalConfig: PresentationConfig = {
      comment: comment,
      autoAcceptProof: autoAcceptProof,
    }

    const { message, proofRecord } = await this.legacyProofService.createRequest(
      proofRequest,
      connection,
      proposalConfig
    )

    return { proofRecord, message }
  }

  public async generateProofRequestNonce() {
    return this.legacyProofService.generateProofRequestNonce()
  }

  public async getById(proofRecordId: string): Promise<ProofRecord> {
    return this.legacyProofService.getById(proofRecordId)
  }
}
