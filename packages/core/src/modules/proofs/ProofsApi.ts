import type {
  AcceptProofOptions,
  AcceptProofProposalOptions,
  AcceptProofRequestOptions,
  CreateProofRequestOptions,
  DeleteProofOptions,
  FindProofPresentationMessageReturn,
  FindProofProposalMessageReturn,
  FindProofRequestMessageReturn,
  GetCredentialsForProofRequestOptions,
  GetCredentialsForProofRequestReturn,
  GetProofFormatDataReturn,
  NegotiateProofProposalOptions,
  NegotiateProofRequestOptions,
  ProposeProofOptions,
  RequestProofOptions,
  SelectCredentialsForProofRequestOptions,
  SelectCredentialsForProofRequestReturn,
  SendProofProblemReportOptions,
  DeclineProofRequestOptions,
} from './ProofsApiOptions'
import type { ProofProtocol } from './protocol/ProofProtocol'
import type { ProofFormatsFromProtocols } from './protocol/ProofProtocolOptions'
import type { ProofExchangeRecord } from './repository/ProofExchangeRecord'
import type { AgentMessage } from '../../agent/AgentMessage'
import type { Query } from '../../storage/StorageService'

import { injectable } from 'tsyringe'

import { MessageSender } from '../../agent/MessageSender'
import { AgentContext } from '../../agent/context/AgentContext'
import { OutboundMessageContext } from '../../agent/models'
import { ServiceDecorator } from '../../decorators/service/ServiceDecorator'
import { AriesFrameworkError } from '../../error'
import { DidCommMessageRepository } from '../../storage'
import { DidCommMessageRole } from '../../storage/didcomm/DidCommMessageRole'
import { ConnectionService } from '../connections/services/ConnectionService'
import { RoutingService } from '../routing/services/RoutingService'

import { ProofsModuleConfig } from './ProofsModuleConfig'
import { ProofState } from './models/ProofState'
import { ProofRepository } from './repository/ProofRepository'

export interface ProofsApi<PPs extends ProofProtocol[]> {
  // Proposal methods
  proposeProof(options: ProposeProofOptions<PPs>): Promise<ProofExchangeRecord>
  acceptProposal(options: AcceptProofProposalOptions<PPs>): Promise<ProofExchangeRecord>
  negotiateProposal(options: NegotiateProofProposalOptions<PPs>): Promise<ProofExchangeRecord>

  // Request methods
  requestProof(options: RequestProofOptions<PPs>): Promise<ProofExchangeRecord>
  acceptRequest(options: AcceptProofRequestOptions<PPs>): Promise<ProofExchangeRecord>
  declineRequest(options: DeclineProofRequestOptions): Promise<ProofExchangeRecord>
  negotiateRequest(options: NegotiateProofRequestOptions<PPs>): Promise<ProofExchangeRecord>

  // Present
  acceptPresentation(options: AcceptProofOptions): Promise<ProofExchangeRecord>

  // out of band
  createRequest(options: CreateProofRequestOptions<PPs>): Promise<{
    message: AgentMessage
    proofRecord: ProofExchangeRecord
  }>

  // Auto Select
  selectCredentialsForRequest(
    options: SelectCredentialsForProofRequestOptions<PPs>
  ): Promise<SelectCredentialsForProofRequestReturn<PPs>>

  // Get credentials for request
  getCredentialsForRequest(
    options: GetCredentialsForProofRequestOptions<PPs>
  ): Promise<GetCredentialsForProofRequestReturn<PPs>>

  sendProblemReport(options: SendProofProblemReportOptions): Promise<ProofExchangeRecord>

  // Record Methods
  getAll(): Promise<ProofExchangeRecord[]>
  findAllByQuery(query: Query<ProofExchangeRecord>): Promise<ProofExchangeRecord[]>
  getById(proofRecordId: string): Promise<ProofExchangeRecord>
  findById(proofRecordId: string): Promise<ProofExchangeRecord | null>
  deleteById(proofId: string, options?: DeleteProofOptions): Promise<void>
  update(proofRecord: ProofExchangeRecord): Promise<void>
  getFormatData(proofRecordId: string): Promise<GetProofFormatDataReturn<ProofFormatsFromProtocols<PPs>>>

  // DidComm Message Records
  findProposalMessage(proofRecordId: string): Promise<FindProofProposalMessageReturn<PPs>>
  findRequestMessage(proofRecordId: string): Promise<FindProofRequestMessageReturn<PPs>>
  findPresentationMessage(proofRecordId: string): Promise<FindProofPresentationMessageReturn<PPs>>
}

@injectable()
export class ProofsApi<PPs extends ProofProtocol[]> implements ProofsApi<PPs> {
  /**
   * Configuration for the proofs module
   */
  public readonly config: ProofsModuleConfig<PPs>

  private connectionService: ConnectionService
  private messageSender: MessageSender
  private routingService: RoutingService
  private proofRepository: ProofRepository
  private didCommMessageRepository: DidCommMessageRepository
  private agentContext: AgentContext

  public constructor(
    messageSender: MessageSender,
    connectionService: ConnectionService,
    agentContext: AgentContext,
    proofRepository: ProofRepository,
    routingService: RoutingService,
    didCommMessageRepository: DidCommMessageRepository,
    config: ProofsModuleConfig<PPs>
  ) {
    this.messageSender = messageSender
    this.connectionService = connectionService
    this.proofRepository = proofRepository
    this.agentContext = agentContext
    this.routingService = routingService
    this.didCommMessageRepository = didCommMessageRepository
    this.config = config
  }

  private getProtocol<PVT extends PPs[number]['version']>(protocolVersion: PVT): ProofProtocol {
    const proofProtocol = this.config.proofProtocols.find((protocol) => protocol.version === protocolVersion)

    if (!proofProtocol) {
      throw new AriesFrameworkError(`No proof protocol registered for protocol version ${protocolVersion}`)
    }

    return proofProtocol
  }

  /**
   * Initiate a new presentation exchange as prover by sending a presentation proposal message
   * to the connection with the specified connection id.
   *
   * @param options configuration to use for the proposal
   * @returns Proof exchange record associated with the sent proposal message
   */
  public async proposeProof(options: ProposeProofOptions<PPs>): Promise<ProofExchangeRecord> {
    const protocol = this.getProtocol(options.protocolVersion)

    const connectionRecord = await this.connectionService.getById(this.agentContext, options.connectionId)

    // Assert
    connectionRecord.assertReady()

    const { message, proofRecord } = await protocol.createProposal(this.agentContext, {
      connectionRecord,
      proofFormats: options.proofFormats,
      autoAcceptProof: options.autoAcceptProof,
      goalCode: options.goalCode,
      comment: options.comment,
      parentThreadId: options.parentThreadId,
    })

    const outboundMessageContext = new OutboundMessageContext(message, {
      agentContext: this.agentContext,
      connection: connectionRecord,
      associatedRecord: proofRecord,
    })

    await this.messageSender.sendMessage(outboundMessageContext)
    return proofRecord
  }

  /**
   * Accept a presentation proposal as verifier (by sending a presentation request message) to the connection
   * associated with the proof record.
   *
   * @param options config object for accepting the proposal
   * @returns Proof exchange record associated with the presentation request
   */
  public async acceptProposal(options: AcceptProofProposalOptions<PPs>): Promise<ProofExchangeRecord> {
    const proofRecord = await this.getById(options.proofRecordId)

    if (!proofRecord.connectionId) {
      throw new AriesFrameworkError(
        `No connectionId found for proof record '${proofRecord.id}'. Connection-less verification does not support presentation proposal or negotiation.`
      )
    }

    // with version we can get the protocol
    const protocol = this.getProtocol(proofRecord.protocolVersion)
    const connectionRecord = await this.connectionService.getById(this.agentContext, proofRecord.connectionId)

    // Assert
    connectionRecord.assertReady()

    const { message } = await protocol.acceptProposal(this.agentContext, {
      proofRecord,
      proofFormats: options.proofFormats,
      goalCode: options.goalCode,
      willConfirm: options.willConfirm,
      comment: options.comment,
      autoAcceptProof: options.autoAcceptProof,
    })

    // send the message
    const outboundMessageContext = new OutboundMessageContext(message, {
      agentContext: this.agentContext,
      connection: connectionRecord,
      associatedRecord: proofRecord,
    })

    await this.messageSender.sendMessage(outboundMessageContext)
    return proofRecord
  }

  /**
   * Answer with a new presentation request in response to received presentation proposal message
   * to the connection associated with the proof record.
   *
   * @param options multiple properties like proof record id, proof formats to accept requested credentials object
   * specifying which credentials to use for the proof
   * @returns Proof record associated with the sent request message
   */
  public async negotiateProposal(options: NegotiateProofProposalOptions<PPs>): Promise<ProofExchangeRecord> {
    const proofRecord = await this.getById(options.proofRecordId)

    if (!proofRecord.connectionId) {
      throw new AriesFrameworkError(
        `No connectionId found for proof record '${proofRecord.id}'. Connection-less verification does not support negotiation.`
      )
    }

    const protocol = this.getProtocol(proofRecord.protocolVersion)
    const connectionRecord = await this.connectionService.getById(this.agentContext, proofRecord.connectionId)

    // Assert
    connectionRecord.assertReady()

    const { message } = await protocol.negotiateProposal(this.agentContext, {
      proofRecord,
      proofFormats: options.proofFormats,
      autoAcceptProof: options.autoAcceptProof,
      comment: options.comment,
      goalCode: options.goalCode,
      willConfirm: options.willConfirm,
    })

    const outboundMessageContext = new OutboundMessageContext(message, {
      agentContext: this.agentContext,
      connection: connectionRecord,
      associatedRecord: proofRecord,
    })
    await this.messageSender.sendMessage(outboundMessageContext)

    return proofRecord
  }

  /**
   * Initiate a new presentation exchange as verifier by sending a presentation request message
   * to the connection with the specified connection id
   *
   * @param options multiple properties like connection id, protocol version, proof Formats to build the proof request
   * @returns Proof record associated with the sent request message
   */
  public async requestProof(options: RequestProofOptions<PPs>): Promise<ProofExchangeRecord> {
    const connectionRecord = await this.connectionService.getById(this.agentContext, options.connectionId)
    const protocol = this.getProtocol(options.protocolVersion)

    // Assert
    connectionRecord.assertReady()

    const { message, proofRecord } = await protocol.createRequest(this.agentContext, {
      connectionRecord,
      proofFormats: options.proofFormats,
      autoAcceptProof: options.autoAcceptProof,
      parentThreadId: options.parentThreadId,
      comment: options.comment,
      goalCode: options.goalCode,
      willConfirm: options.willConfirm,
    })

    const outboundMessageContext = new OutboundMessageContext(message, {
      agentContext: this.agentContext,
      connection: connectionRecord,
      associatedRecord: proofRecord,
    })

    await this.messageSender.sendMessage(outboundMessageContext)
    return proofRecord
  }

  /**
   * Accept a presentation request as prover (by sending a presentation message) to the connection
   * associated with the proof record.
   *
   * @param options multiple properties like proof record id, proof formats to accept requested credentials object
   * specifying which credentials to use for the proof
   * @returns Proof record associated with the sent presentation message
   */
  public async acceptRequest(options: AcceptProofRequestOptions<PPs>): Promise<ProofExchangeRecord> {
    const proofRecord = await this.getById(options.proofRecordId)

    const protocol = this.getProtocol(proofRecord.protocolVersion)

    const requestMessage = await protocol.findRequestMessage(this.agentContext, proofRecord.id)

    // Use connection if present
    if (proofRecord.connectionId) {
      const connectionRecord = await this.connectionService.getById(this.agentContext, proofRecord.connectionId)

      // Assert
      connectionRecord.assertReady()

      const { message } = await protocol.acceptRequest(this.agentContext, {
        proofFormats: options.proofFormats,
        proofRecord,
        comment: options.comment,
        autoAcceptProof: options.autoAcceptProof,
        goalCode: options.goalCode,
      })

      const outboundMessageContext = new OutboundMessageContext(message, {
        agentContext: this.agentContext,
        connection: connectionRecord,
        associatedRecord: proofRecord,
      })
      await this.messageSender.sendMessage(outboundMessageContext)

      return proofRecord
    }

    // Use ~service decorator otherwise
    else if (requestMessage?.service) {
      // Create ~service decorator
      const routing = await this.routingService.getRouting(this.agentContext)
      const ourService = new ServiceDecorator({
        serviceEndpoint: routing.endpoints[0],
        recipientKeys: [routing.recipientKey.publicKeyBase58],
        routingKeys: routing.routingKeys.map((key) => key.publicKeyBase58),
      })
      const recipientService = requestMessage.service

      const { message } = await protocol.acceptRequest(this.agentContext, {
        proofFormats: options.proofFormats,
        proofRecord,
        comment: options.comment,
        autoAcceptProof: options.autoAcceptProof,
        goalCode: options.goalCode,
      })
      // Set and save ~service decorator to record (to remember our verkey)
      message.service = ourService
      await this.didCommMessageRepository.saveOrUpdateAgentMessage(this.agentContext, {
        agentMessage: message,
        role: DidCommMessageRole.Sender,
        associatedRecordId: proofRecord.id,
      })
      await this.messageSender.sendMessageToService(
        new OutboundMessageContext(message, {
          agentContext: this.agentContext,
          serviceParams: {
            service: recipientService.resolvedDidCommService,
            senderKey: ourService.resolvedDidCommService.recipientKeys[0],
            returnRoute: options.useReturnRoute ?? true, // defaults to true if missing
          },
        })
      )
      return proofRecord
    }
    // Cannot send message without connectionId or ~service decorator
    else {
      throw new AriesFrameworkError(
        `Cannot accept presentation request without connectionId or ~service decorator on presentation request.`
      )
    }
  }

  public async declineRequest(options: DeclineProofRequestOptions): Promise<ProofExchangeRecord> {
    const proofRecord = await this.getById(options.proofRecordId)
    proofRecord.assertState(ProofState.RequestReceived)

    const protocol = this.getProtocol(proofRecord.protocolVersion)
    if (options.sendProblemReport) {
      await this.sendProblemReport({ proofRecordId: options.proofRecordId, description: 'Request declined' })
    }

    await protocol.updateState(this.agentContext, proofRecord, ProofState.Declined)

    return proofRecord
  }

  /**
   * Answer with a new presentation proposal in response to received presentation request message
   * to the connection associated with the proof record.
   *
   * @param options multiple properties like proof record id, proof format (indy/ presentation exchange)
   * to include in the message
   * @returns Proof record associated with the sent proposal message
   */
  public async negotiateRequest(options: NegotiateProofRequestOptions<PPs>): Promise<ProofExchangeRecord> {
    const proofRecord = await this.getById(options.proofRecordId)

    if (!proofRecord.connectionId) {
      throw new AriesFrameworkError(
        `No connectionId found for proof record '${proofRecord.id}'. Connection-less verification does not support presentation proposal or negotiation.`
      )
    }

    const connectionRecord = await this.connectionService.getById(this.agentContext, proofRecord.connectionId)

    // Assert
    connectionRecord.assertReady()

    const protocol = this.getProtocol(proofRecord.protocolVersion)
    const { message } = await protocol.negotiateRequest(this.agentContext, {
      proofRecord,
      proofFormats: options.proofFormats,
      autoAcceptProof: options.autoAcceptProof,
      goalCode: options.goalCode,
      comment: options.comment,
    })

    const outboundMessageContext = new OutboundMessageContext(message, {
      agentContext: this.agentContext,
      connection: connectionRecord,
      associatedRecord: proofRecord,
    })

    await this.messageSender.sendMessage(outboundMessageContext)
    return proofRecord
  }

  /**
   * Initiate a new presentation exchange as verifier by sending an out of band presentation
   * request message
   *
   * @param options multiple properties like protocol version, proof Formats to build the proof request
   * @returns the message itself and the proof record associated with the sent request message
   */
  public async createRequest(options: CreateProofRequestOptions<PPs>): Promise<{
    message: AgentMessage
    proofRecord: ProofExchangeRecord
  }> {
    const protocol = this.getProtocol(options.protocolVersion)

    return await protocol.createRequest(this.agentContext, {
      proofFormats: options.proofFormats,
      autoAcceptProof: options.autoAcceptProof,
      comment: options.comment,
      parentThreadId: options.parentThreadId,
      goalCode: options.goalCode,
      willConfirm: options.willConfirm,
    })
  }

  /**
   * Accept a presentation as prover (by sending a presentation acknowledgement message) to the connection
   * associated with the proof record.
   *
   * @param proofRecordId The id of the proof exchange record for which to accept the presentation
   * @returns Proof record associated with the sent presentation acknowledgement message
   *
   */
  public async acceptPresentation(options: AcceptProofOptions): Promise<ProofExchangeRecord> {
    const proofRecord = await this.getById(options.proofRecordId)
    const protocol = this.getProtocol(proofRecord.protocolVersion)

    const requestMessage = await protocol.findRequestMessage(this.agentContext, proofRecord.id)
    const presentationMessage = await protocol.findPresentationMessage(this.agentContext, proofRecord.id)

    // Use connection if present
    if (proofRecord.connectionId) {
      const connectionRecord = await this.connectionService.getById(this.agentContext, proofRecord.connectionId)

      // Assert
      connectionRecord.assertReady()

      const { message } = await protocol.acceptPresentation(this.agentContext, {
        proofRecord,
      })

      const outboundMessageContext = new OutboundMessageContext(message, {
        agentContext: this.agentContext,
        connection: connectionRecord,
        associatedRecord: proofRecord,
      })
      await this.messageSender.sendMessage(outboundMessageContext)

      return proofRecord
    }
    // Use ~service decorator otherwise
    else if (requestMessage?.service && presentationMessage?.service) {
      const recipientService = presentationMessage.service
      const ourService = requestMessage.service

      const { message } = await protocol.acceptPresentation(this.agentContext, {
        proofRecord,
      })

      await this.messageSender.sendMessageToService(
        new OutboundMessageContext(message, {
          agentContext: this.agentContext,
          serviceParams: {
            service: recipientService.resolvedDidCommService,
            senderKey: ourService.resolvedDidCommService.recipientKeys[0],
            returnRoute: false, // hard wire to be false since it's the end of the protocol so not needed here
          },
        })
      )

      return proofRecord
    }
    // Cannot send message without credentialId or ~service decorator
    else {
      throw new AriesFrameworkError(
        `Cannot accept presentation without connectionId or ~service decorator on presentation message.`
      )
    }
  }

  /**
   * Create a {@link RetrievedCredentials} object. Given input proof request and presentation proposal,
   * use credentials in the wallet to build indy requested credentials object for input to proof creation.
   * If restrictions allow, self attested attributes will be used.
   *
   * @param options multiple properties like proof record id and optional configuration
   * @returns RequestedCredentials
   */
  public async selectCredentialsForRequest(
    options: SelectCredentialsForProofRequestOptions<PPs>
  ): Promise<SelectCredentialsForProofRequestReturn<PPs>> {
    const proofRecord = await this.getById(options.proofRecordId)

    const protocol = this.getProtocol(proofRecord.protocolVersion)

    return protocol.selectCredentialsForRequest(this.agentContext, {
      proofFormats: options.proofFormats,
      proofRecord,
    })
  }

  /**
   * Get credentials in the wallet for a received proof request.
   *
   * @param options multiple properties like proof record id and optional configuration
   */
  public async getCredentialsForRequest(
    options: GetCredentialsForProofRequestOptions<PPs>
  ): Promise<GetCredentialsForProofRequestReturn<PPs>> {
    const proofRecord = await this.getById(options.proofRecordId)

    const protocol = this.getProtocol(proofRecord.protocolVersion)

    return protocol.getCredentialsForRequest(this.agentContext, {
      proofRecord,
      proofFormats: options.proofFormats,
    })
  }

  /**
   * Send problem report message for a proof record
   *
   * @param proofRecordId  The id of the proof record for which to send problem report
   * @param message message to send
   * @returns proof record associated with the proof problem report message
   */
  public async sendProblemReport(options: SendProofProblemReportOptions): Promise<ProofExchangeRecord> {
    const proofRecord = await this.getById(options.proofRecordId)

    const protocol = this.getProtocol(proofRecord.protocolVersion)

    const requestMessage = await protocol.findRequestMessage(this.agentContext, proofRecord.id)

    const { message: problemReport } = await protocol.createProblemReport(this.agentContext, {
      proofRecord,
      description: options.description,
    })

    if (proofRecord.connectionId) {
      const connectionRecord = await this.connectionService.getById(this.agentContext, proofRecord.connectionId)

      // Assert
      connectionRecord.assertReady()

      const outboundMessageContext = new OutboundMessageContext(problemReport, {
        agentContext: this.agentContext,
        connection: connectionRecord,
        associatedRecord: proofRecord,
      })

      await this.messageSender.sendMessage(outboundMessageContext)
      return proofRecord
    } else if (requestMessage?.service) {
      proofRecord.assertState(ProofState.RequestReceived)

      // Create ~service decorator
      const routing = await this.routingService.getRouting(this.agentContext)
      const ourService = new ServiceDecorator({
        serviceEndpoint: routing.endpoints[0],
        recipientKeys: [routing.recipientKey.publicKeyBase58],
        routingKeys: routing.routingKeys.map((key) => key.publicKeyBase58),
      })
      const recipientService = requestMessage.service

      await this.messageSender.sendMessageToService(
        new OutboundMessageContext(problemReport, {
          agentContext: this.agentContext,
          serviceParams: {
            service: recipientService.resolvedDidCommService,
            senderKey: ourService.resolvedDidCommService.recipientKeys[0],
          },
        })
      )

      return proofRecord
    }
    // Cannot send message without connectionId or ~service decorator
    else {
      throw new AriesFrameworkError(
        `Cannot send problem report without connectionId or ~service decorator on presentation request.`
      )
    }
  }

  public async getFormatData(proofRecordId: string): Promise<GetProofFormatDataReturn<ProofFormatsFromProtocols<PPs>>> {
    const proofRecord = await this.getById(proofRecordId)
    const protocol = this.getProtocol(proofRecord.protocolVersion)

    return protocol.getFormatData(this.agentContext, proofRecordId)
  }

  /**
   * Retrieve all proof records
   *
   * @returns List containing all proof records
   */
  public async getAll(): Promise<ProofExchangeRecord[]> {
    return this.proofRepository.getAll(this.agentContext)
  }

  /**
   * Retrieve all proof records by specified query params
   *
   * @returns List containing all proof records matching specified params
   */
  public findAllByQuery(query: Query<ProofExchangeRecord>): Promise<ProofExchangeRecord[]> {
    return this.proofRepository.findByQuery(this.agentContext, query)
  }

  /**
   * Retrieve a proof record by id
   *
   * @param proofRecordId The proof record id
   * @throws {RecordNotFoundError} If no record is found
   * @return The proof record
   *
   */
  public async getById(proofRecordId: string): Promise<ProofExchangeRecord> {
    return await this.proofRepository.getById(this.agentContext, proofRecordId)
  }

  /**
   * Retrieve a proof record by id
   *
   * @param proofRecordId The proof record id
   * @return The proof record or null if not found
   *
   */
  public async findById(proofRecordId: string): Promise<ProofExchangeRecord | null> {
    return await this.proofRepository.findById(this.agentContext, proofRecordId)
  }

  /**
   * Delete a proof record by id
   *
   * @param proofId the proof record id
   */
  public async deleteById(proofId: string, options?: DeleteProofOptions) {
    const proofRecord = await this.getById(proofId)
    const protocol = this.getProtocol(proofRecord.protocolVersion)
    return protocol.delete(this.agentContext, proofRecord, options)
  }

  /**
   * Retrieve a proof record by connection id and thread id
   *
   * @param connectionId The connection id
   * @param threadId The thread id
   * @throws {RecordNotFoundError} If no record is found
   * @throws {RecordDuplicateError} If multiple records are found
   * @returns The proof record
   */
  public async getByThreadAndConnectionId(threadId: string, connectionId?: string): Promise<ProofExchangeRecord> {
    return this.proofRepository.getByThreadAndConnectionId(this.agentContext, threadId, connectionId)
  }

  /**
   * Retrieve proof records by connection id and parent thread id
   *
   * @param connectionId The connection id
   * @param parentThreadId The parent thread id
   * @returns List containing all proof records matching the given query
   */
  public async getByParentThreadAndConnectionId(
    parentThreadId: string,
    connectionId?: string
  ): Promise<ProofExchangeRecord[]> {
    return this.proofRepository.getByParentThreadAndConnectionId(this.agentContext, parentThreadId, connectionId)
  }

  /**
   * Update a proof record by
   *
   * @param proofRecord the proof record
   */
  public async update(proofRecord: ProofExchangeRecord): Promise<void> {
    await this.proofRepository.update(this.agentContext, proofRecord)
  }

  public async findProposalMessage(proofRecordId: string): Promise<FindProofProposalMessageReturn<PPs>> {
    const record = await this.getById(proofRecordId)
    const protocol = this.getProtocol(record.protocolVersion)
    return protocol.findProposalMessage(this.agentContext, proofRecordId) as FindProofProposalMessageReturn<PPs>
  }

  public async findRequestMessage(proofRecordId: string): Promise<FindProofRequestMessageReturn<PPs>> {
    const record = await this.getById(proofRecordId)
    const protocol = this.getProtocol(record.protocolVersion)
    return protocol.findRequestMessage(this.agentContext, proofRecordId) as FindProofRequestMessageReturn<PPs>
  }

  public async findPresentationMessage(proofRecordId: string): Promise<FindProofPresentationMessageReturn<PPs>> {
    const record = await this.getById(proofRecordId)
    const protocol = this.getProtocol(record.protocolVersion)
    return protocol.findPresentationMessage(this.agentContext, proofRecordId) as FindProofPresentationMessageReturn<PPs>
  }
}
