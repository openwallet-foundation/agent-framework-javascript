<<<<<<< HEAD
import type { AgentMessage } from '../../agent/AgentMessage'
import type { ProofService } from './ProofService'
import type {
  AcceptPresentationOptions,
  AcceptProposalOptions,
  AutoSelectCredentialsForProofRequestOptions,
  OutOfBandRequestOptions,
  ProposeProofOptions,
  RequestProofOptions,
} from './models/ModuleOptions'
import type { AutoAcceptProof } from './models/ProofAutoAcceptType'
import type {
  CreateOutOfBandRequestOptions,
  CreatePresentationOptions,
  CreateProposalOptions,
  CreateRequestOptions,
  ProofRequestFromProposalOptions,
} from './models/ProofServiceOptions'
import type { RequestedCredentialsFormats } from './models/SharedOptions'
import type { ProofRecord } from './repository/ProofRecord'

import { Lifecycle, scoped } from 'tsyringe'

import { AgentConfig } from '../../agent/AgentConfig'
import { Dispatcher } from '../../agent/Dispatcher'
import { MessageSender } from '../../agent/MessageSender'
import { createOutboundMessage } from '../../agent/helpers'
import { ServiceDecorator } from '../../decorators/service/ServiceDecorator'
import { AriesFrameworkError } from '../../error'
import { DidCommMessageRole } from '../../storage'
import { ConnectionService } from '../connections/services/ConnectionService'
import { MediationRecipientService } from '../routing/services/MediationRecipientService'

import { ProofResponseCoordinator } from './ProofResponseCoordinator'
import { ProofProtocolVersion } from './models/ProofProtocolVersion'
import { ProofState } from './models/ProofState'
import { V1ProofService } from './protocol/v1/V1ProofService'
import { V2ProofService } from './protocol/v2/V2ProofService'
import { ProofRepository } from './repository/ProofRepository'

@scoped(Lifecycle.ContainerScoped)
export class ProofsModule {
  private connectionService: ConnectionService
  private messageSender: MessageSender
  private agentConfig: AgentConfig
  private mediationRecipientService: MediationRecipientService
  private serviceMap: { [key in ProofProtocolVersion]: ProofService }
  private proofRepository: ProofRepository

  public constructor(
    dispatcher: Dispatcher,
    connectionService: ConnectionService,
    messageSender: MessageSender,
    agentConfig: AgentConfig,
    mediationRecipientService: MediationRecipientService,
    v1ProofService: V1ProofService,
    v2ProofService: V2ProofService,
    proofRepository: ProofRepository
  ) {
    this.connectionService = connectionService
    this.messageSender = messageSender
    this.agentConfig = agentConfig
    this.mediationRecipientService = mediationRecipientService
    this.proofRepository = proofRepository

    this.serviceMap = {
      [ProofProtocolVersion.V1]: v1ProofService,
      [ProofProtocolVersion.V2]: v2ProofService,
    }

    this.registerHandlers(dispatcher, mediationRecipientService)
  }

  private getService(protocolVersion: ProofProtocolVersion) {
    return this.serviceMap[protocolVersion]
  }

  //1  DONE
  /**
   * Initiate a new presentation exchange as prover by sending a presentation proposal message
   * to the connection with the specified connection id.
   *
   * @param options multiple properties like protocol version, connection id, proof format (indy/ presentation exchange)
   * to include in the message
   * @returns Proof record associated with the sent proposal message
   */
  public async proposeProof(options: ProposeProofOptions): Promise<ProofRecord> {
    const version: ProofProtocolVersion = options.protocolVersion

    const service = this.getService(version)

    const { connectionId } = options

    const connection = await this.connectionService.getById(connectionId)

    // Assert
    connection.assertReady()

    const proposalOptions: CreateProposalOptions = {
      connectionRecord: connection,
      protocolVersion: version,
      proofFormats: options.proofFormats,
      autoAcceptProof: options.autoAcceptProof,
      goalCode: options.goalCode,
      comment: options.comment,
    }

    const { message, proofRecord } = await service.createProposal(proposalOptions)

    const outbound = createOutboundMessage(connection, message)
    await this.messageSender.sendMessage(outbound)

    return proofRecord
  }

  // 2
  /**
   * Accept a presentation proposal as verifier (by sending a presentation request message) to the connection
   * associated with the proof record.
   *
   * @param options multiple properties like proof record id, additional configuration for creating the request
   * @returns Proof record associated with the presentation request
   */
  public async acceptProposal(options: AcceptProposalOptions): Promise<ProofRecord> {
    const { proofRecordId } = options
    const proofRecord = await this.getById(proofRecordId)

    const service = this.getService(proofRecord.protocolVersion)

    if (!proofRecord.connectionId) {
      throw new AriesFrameworkError(
        `No connectionId found for credential record '${proofRecord.id}'. Connection-less issuance does not support presentation proposal or negotiation.`
      )
    }

    const connection = await this.connectionService.getById(proofRecord.connectionId)

    // Assert
    connection.assertReady()

    const proofRequestFromProposalOptions: ProofRequestFromProposalOptions = {
      proofRecord,
    }

    const proofRequest = await service.createProofRequestFromProposal(proofRequestFromProposalOptions)

    const { message } = await service.createRequestAsResponse({
      proofRecord: proofRecord,
      proofFormats: proofRequest,
      goalCode: options.goalCode,
      willConfirm: options.willConfirm ?? true,
      comment: options.comment,
    })

    const outboundMessage = createOutboundMessage(connection, message)
    await this.messageSender.sendMessage(outboundMessage)

    return proofRecord
  }

  // 3
  /**
   * Initiate a new presentation exchange as verifier by sending a presentation request message
   * to the connection with the specified connection id
   *
   * @param options multiple properties like connection id, protocol version, proof Formats to build the proof request
   * @returns Proof record associated with the sent request message
   */
  public async requestProof(options: RequestProofOptions): Promise<ProofRecord> {
    const version: ProofProtocolVersion = options.protocolVersion
    const service = this.getService(options.protocolVersion)

    const connection = await this.connectionService.getById(options.connectionId)

    // Assert
    connection.assertReady()

    const createProofRequest: CreateRequestOptions = {
      connectionRecord: connection,
      proofFormats: options.proofFormats,
      protocolVersion: version,
      autoAcceptProof: options.autoAcceptProof,
      comment: options.comment,
    }
    const { message, proofRecord } = await service.createRequest(createProofRequest)

    const outboundMessage = createOutboundMessage(connection, message)
    await this.messageSender.sendMessage(outboundMessage)
=======
import type { DependencyManager, Module } from '../../plugins'
import type { ProofsModuleConfigOptions } from './ProofsModuleConfig'

import { ProofsApi } from './ProofsApi'
import { ProofsModuleConfig } from './ProofsModuleConfig'
import { ProofRepository } from './repository'
import { ProofService } from './services'

export class ProofsModule implements Module {
  public readonly config: ProofsModuleConfig
>>>>>>> d2fe29e094b07fcfcf9d55fb65539ca2297fa3cb

  public constructor(config?: ProofsModuleConfigOptions) {
    this.config = new ProofsModuleConfig(config)
  }

  /**
<<<<<<< HEAD
   * Initiate a new presentation exchange as verifier by creating a presentation request
   * not bound to any connection. The request must be delivered out-of-band to the holder
   *
   * @param options multiple properties like protocol version and proof formats to build the proof request
   * @returns The proof record and proof request message
   */
  public async createOutOfBandRequest(options: OutOfBandRequestOptions): Promise<{
    message: AgentMessage
    proofRecord: ProofRecord
  }> {
    const version: ProofProtocolVersion = options.protocolVersion

    const service = this.getService(version)

    const createProofRequest: CreateOutOfBandRequestOptions = {
      proofFormats: options.proofFormats,
      protocolVersion: version,
      autoAcceptProof: options.autoAcceptProof,
      comment: options.comment,
    }

    const { message, proofRecord } = await service.createRequest(createProofRequest)

    // Create and set ~service decorator
    const routing = await this.mediationRecipientService.getRouting()
    message.service = new ServiceDecorator({
      serviceEndpoint: routing.endpoints[0],
      recipientKeys: [routing.recipientKey.publicKeyBase58],
      routingKeys: routing.routingKeys.map((key) => key.publicKeyBase58),
    })

    // Save ~service decorator to record (to remember our verkey)

    await service.saveOrUpdatePresentationMessage({
      message,
      proofRecord: proofRecord,
      role: DidCommMessageRole.Sender,
    })

    await service.update(proofRecord)

    return { proofRecord, message }
  }

  /**
   * Accept a presentation request as prover (by sending a presentation message) to the connection
   * associated with the proof record.
   *
   * @param options multiple properties like proof record id, proof formats to accept requested credentials object
   * specifying which credentials to use for the proof
   * @returns Proof record associated with the sent presentation message
   */
  public async acceptRequest(options: AcceptPresentationOptions): Promise<ProofRecord> {
    const { proofRecordId, proofFormats, comment } = options

    const record = await this.getById(proofRecordId)

    const version: ProofProtocolVersion = record.protocolVersion
    const service = this.getService(version)

    const presentationOptions: CreatePresentationOptions = {
      proofFormats,
      proofRecord: record,
      comment,
    }
    const { message, proofRecord } = await service.createPresentation(presentationOptions)

    const requestMessage = await service.findRequestMessage(proofRecord.id)

    // Use connection if present
    if (proofRecord.connectionId) {
      const connection = await this.connectionService.getById(proofRecord.connectionId)

      // Assert
      connection.assertReady()

      const outboundMessage = createOutboundMessage(connection, message)
      await this.messageSender.sendMessage(outboundMessage)

      return proofRecord
    }

    // Use ~service decorator otherwise
    else if (requestMessage?.service) {
      // Create ~service decorator
      const routing = await this.mediationRecipientService.getRouting()
      const ourService = new ServiceDecorator({
        serviceEndpoint: routing.endpoints[0],
        recipientKeys: [routing.recipientKey.publicKeyBase58],
        routingKeys: routing.routingKeys.map((key) => key.publicKeyBase58),
      })

      const recipientService = requestMessage.service

      // Set and save ~service decorator to record (to remember our verkey)
      message.service = ourService

      await service.saveOrUpdatePresentationMessage({
        proofRecord: proofRecord,
        message: message,
        role: DidCommMessageRole.Sender,
      })

      await this.messageSender.sendMessageToService({
        message,
        service: recipientService.resolvedDidCommService,
        senderKey: ourService.resolvedDidCommService.recipientKeys[0],
        returnRoute: true,
      })

      return proofRecord
    }
    // Cannot send message without connectionId or ~service decorator
    else {
      throw new AriesFrameworkError(
        `Cannot accept presentation request without connectionId or ~service decorator on presentation request.`
      )
    }
  }

  /**
   * Declines a proof request as holder
   * @param proofRecordId the id of the proof request to be declined
   * @returns proof record that was declined
   */
  public async declineRequest(proofRecordId: string): Promise<ProofRecord> {
    const proofRecord = await this.getById(proofRecordId)
    const service = this.getService(proofRecord.protocolVersion)

    proofRecord.assertState(ProofState.RequestReceived)

    await service.updateState(proofRecord, ProofState.Declined)

    return proofRecord
  }

  /**
   * Accept a presentation as prover (by sending a presentation acknowledgement message) to the connection
   * associated with the proof record.
   *
   * @param proofRecordId The id of the proof record for which to accept the presentation
   * @returns Proof record associated with the sent presentation acknowledgement message
   *
   */
  public async acceptPresentation(proofRecordId: string): Promise<ProofRecord> {
    const record = await this.getById(proofRecordId)
    const service = this.getService(record.protocolVersion)

    const { message, proofRecord } = await service.createAck({
      proofRecord: record,
    })

    const requestMessage = await service.findRequestMessage(record.id)

    const presentationMessage = await service.findPresentationMessage(record.id)

    // Use connection if present
    if (proofRecord.connectionId) {
      const connection = await this.connectionService.getById(proofRecord.connectionId)

      // Assert
      connection.assertReady()

      const outboundMessage = createOutboundMessage(connection, message)
      await this.messageSender.sendMessage(outboundMessage)
    }
    // Use ~service decorator otherwise
    else if (requestMessage?.service && presentationMessage?.service) {
      const recipientService = presentationMessage?.service
      const ourService = requestMessage.service

      await this.messageSender.sendMessageToService({
        message,
        service: recipientService.resolvedDidCommService,
        senderKey: ourService.resolvedDidCommService.recipientKeys[0],
        returnRoute: true,
      })
    }
    // Cannot send message without credentialId or ~service decorator
    else {
      throw new AriesFrameworkError(
        `Cannot accept presentation without connectionId or ~service decorator on presentation message.`
      )
    }

    return record
  }

  /**
   * Create a {@link RetrievedCredentials} object. Given input proof request and presentation proposal,
   * use credentials in the wallet to build indy requested credentials object for input to proof creation.
   * If restrictions allow, self attested attributes will be used.
   *
   * @param options multiple properties like proof record id and optional configuration
   * @returns RequestedCredentials
   */
  public async autoSelectCredentialsForProofRequest(
    options: AutoSelectCredentialsForProofRequestOptions
  ): Promise<RequestedCredentialsFormats> {
    const proofRecord = await this.getById(options.proofRecordId)

    const service = this.getService(proofRecord.protocolVersion)

    const retrievedCredentials = await service.getRequestedCredentialsForProofRequest({
      proofRecord: proofRecord,
      config: options.config,
    })

    return await service.autoSelectCredentialsForProofRequest(retrievedCredentials)
  }

  /**
   * Send problem report message for a proof record
   *
   * @param proofRecordId  The id of the proof record for which to send problem report
   * @param message message to send
   * @returns proof record associated with the proof problem report message
   */
  public async sendProblemReport(proofRecordId: string, message: string) {
    const record = await this.getById(proofRecordId)
    const service = this.getService(record.protocolVersion)
    if (!record.connectionId) {
      throw new AriesFrameworkError(`No connectionId found for proof record '${record.id}'.`)
    }
    const connection = await this.connectionService.getById(record.connectionId)

    // Assert
    connection.assertReady()

    const { message: problemReport } = await service.createProblemReport({
      proofRecord: record,
      description: message,
    })

    const outboundMessage = createOutboundMessage(connection, problemReport)
    await this.messageSender.sendMessage(outboundMessage)

    return record
  }

  /**
   * Retrieve all proof records
   *
   * @returns List containing all proof records
   */
  public getAll(): Promise<ProofRecord[]> {
    return this.proofRepository.getAll()
  }

  /**
   * Retrieve a proof record by id
   *
   * @param proofRecordId The proof record id
   * @throws {RecordNotFoundError} If no record is found
   * @throws {RecordDuplicateError} If multiple records are found
   * @return The proof record
   *
   */
  public async getById(proofRecordId: string): Promise<ProofRecord> {
    return this.proofRepository.getById(proofRecordId)
  }

  /**
   * Retrieve a proof record by id
   *
   * @param proofRecordId The proof record id
   * @return The proof record or null if not found
   *
   */
  public async findById(proofRecordId: string): Promise<ProofRecord | null> {
    return this.proofRepository.findById(proofRecordId)
  }

  /**
   * Delete a proof record by id
   *
   * @param proofId the proof record id
   */
  public async deleteById(proofId: string) {
    const proofRecord = await this.getById(proofId)
    return this.proofRepository.delete(proofRecord)
  }

  private registerHandlers(dispatcher: Dispatcher, mediationRecipientService: MediationRecipientService) {
    for (const service of Object.values(this.serviceMap)) {
      service.registerHandlers(
        dispatcher,
        this.agentConfig,
        new ProofResponseCoordinator(this.agentConfig, service),
        mediationRecipientService
      )
    }
  }
}

export interface ProofRequestConfig {
  comment?: string
  autoAcceptProof?: AutoAcceptProof
=======
   * Registers the dependencies of the proofs module on the dependency manager.
   */
  public register(dependencyManager: DependencyManager) {
    // Api
    dependencyManager.registerContextScoped(ProofsApi)

    // Config
    dependencyManager.registerInstance(ProofsModuleConfig, this.config)

    // Services
    dependencyManager.registerSingleton(ProofService)

    // Repositories
    dependencyManager.registerSingleton(ProofRepository)
  }
>>>>>>> d2fe29e094b07fcfcf9d55fb65539ca2297fa3cb
}
