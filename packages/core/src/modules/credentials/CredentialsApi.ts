import type {
  AcceptCredentialOptions,
  AcceptCredentialOfferOptions,
  AcceptCredentialProposalOptions,
  AcceptCredentialRequestOptions,
  CreateCredentialOfferOptions,
  FindCredentialMessageReturn,
  FindCredentialOfferMessageReturn,
  FindCredentialProposalMessageReturn,
  FindCredentialRequestMessageReturn,
  GetCredentialFormatDataReturn,
  NegotiateCredentialOfferOptions,
  NegotiateCredentialProposalOptions,
  OfferCredentialOptions,
  ProposeCredentialOptions,
  SendCredentialProblemReportOptions,
  DeleteCredentialOptions,
  SendRevocationNotificationOptions,
  DeclineCredentialOfferOptions,
} from './CredentialsApiOptions'
import type { CredentialProtocol } from './protocol/CredentialProtocol'
import type { CredentialFormatsFromProtocols } from './protocol/CredentialProtocolOptions'
import type { CredentialExchangeRecord } from './repository/CredentialExchangeRecord'
import type { AgentMessage } from '../../agent/AgentMessage'
import type { Query, QueryOptions } from '../../storage/StorageService'

import { AgentContext } from '../../agent'
import { MessageSender } from '../../agent/MessageSender'
import { getOutboundMessageContext } from '../../agent/getOutboundMessageContext'
import { InjectionSymbols } from '../../constants'
import { CredoError } from '../../error'
import { Logger } from '../../logger'
import { inject, injectable } from '../../plugins'
import { DidCommMessageRepository } from '../../storage/didcomm/DidCommMessageRepository'
import { ConnectionService } from '../connections/services'
import { RoutingService } from '../routing/services/RoutingService'

import { CredentialsModuleConfig } from './CredentialsModuleConfig'
import { CredentialState } from './models/CredentialState'
import { RevocationNotificationService } from './protocol/revocation-notification/services'
import { CredentialRepository } from './repository/CredentialRepository'

export interface CredentialsApi<CPs extends CredentialProtocol[]> {
  // Propose Credential methods
  proposeCredential(options: ProposeCredentialOptions<CPs>): Promise<CredentialExchangeRecord>
  acceptProposal(options: AcceptCredentialProposalOptions<CPs>): Promise<CredentialExchangeRecord>
  negotiateProposal(options: NegotiateCredentialProposalOptions<CPs>): Promise<CredentialExchangeRecord>

  // Offer Credential Methods
  offerCredential(options: OfferCredentialOptions<CPs>): Promise<CredentialExchangeRecord>
  acceptOffer(options: AcceptCredentialOfferOptions<CPs>): Promise<CredentialExchangeRecord>
  declineOffer(credentialRecordId: string, options?: DeclineCredentialOfferOptions): Promise<CredentialExchangeRecord>
  negotiateOffer(options: NegotiateCredentialOfferOptions<CPs>): Promise<CredentialExchangeRecord>

  // Request Credential Methods
  // This is for beginning the exchange with a request (no proposal or offer). Only possible
  // (currently) with W3C. We will not implement this in phase I

  // when the issuer accepts the request he issues the credential to the holder
  acceptRequest(options: AcceptCredentialRequestOptions<CPs>): Promise<CredentialExchangeRecord>

  // Issue Credential Methods
  acceptCredential(options: AcceptCredentialOptions): Promise<CredentialExchangeRecord>

  // Revoke Credential Methods
  sendRevocationNotification(options: SendRevocationNotificationOptions): Promise<void>

  // out of band
  createOffer(options: CreateCredentialOfferOptions<CPs>): Promise<{
    message: AgentMessage
    credentialRecord: CredentialExchangeRecord
  }>

  sendProblemReport(options: SendCredentialProblemReportOptions): Promise<CredentialExchangeRecord>

  // Record Methods
  getAll(): Promise<CredentialExchangeRecord[]>
  findAllByQuery(
    query: Query<CredentialExchangeRecord>,
    queryOptions?: QueryOptions
  ): Promise<CredentialExchangeRecord[]>
  getById(credentialRecordId: string): Promise<CredentialExchangeRecord>
  findById(credentialRecordId: string): Promise<CredentialExchangeRecord | null>
  deleteById(credentialRecordId: string, options?: DeleteCredentialOptions): Promise<void>
  update(credentialRecord: CredentialExchangeRecord): Promise<void>
  getFormatData(credentialRecordId: string): Promise<GetCredentialFormatDataReturn<CredentialFormatsFromProtocols<CPs>>>

  // DidComm Message Records
  findProposalMessage(credentialExchangeId: string): Promise<FindCredentialProposalMessageReturn<CPs>>
  findOfferMessage(credentialExchangeId: string): Promise<FindCredentialOfferMessageReturn<CPs>>
  findRequestMessage(credentialExchangeId: string): Promise<FindCredentialRequestMessageReturn<CPs>>
  findCredentialMessage(credentialExchangeId: string): Promise<FindCredentialMessageReturn<CPs>>
}

@injectable()
export class CredentialsApi<CPs extends CredentialProtocol[]> implements CredentialsApi<CPs> {
  /**
   * Configuration for the credentials module
   */
  public readonly config: CredentialsModuleConfig<CPs>

  private connectionService: ConnectionService
  private messageSender: MessageSender
  private credentialRepository: CredentialRepository
  private agentContext: AgentContext
  private didCommMessageRepository: DidCommMessageRepository
  private revocationNotificationService: RevocationNotificationService
  private routingService: RoutingService
  private logger: Logger

  public constructor(
    messageSender: MessageSender,
    connectionService: ConnectionService,
    agentContext: AgentContext,
    @inject(InjectionSymbols.Logger) logger: Logger,
    credentialRepository: CredentialRepository,
    mediationRecipientService: RoutingService,
    didCommMessageRepository: DidCommMessageRepository,
    revocationNotificationService: RevocationNotificationService,
    config: CredentialsModuleConfig<CPs>
  ) {
    this.messageSender = messageSender
    this.connectionService = connectionService
    this.credentialRepository = credentialRepository
    this.routingService = mediationRecipientService
    this.agentContext = agentContext
    this.didCommMessageRepository = didCommMessageRepository
    this.revocationNotificationService = revocationNotificationService
    this.logger = logger
    this.config = config
  }

  private getProtocol<PVT extends CPs[number]['version']>(protocolVersion: PVT): CredentialProtocol {
    const credentialProtocol = this.config.credentialProtocols.find((protocol) => protocol.version === protocolVersion)

    if (!credentialProtocol) {
      throw new CredoError(`No credential protocol registered for protocol version ${protocolVersion}`)
    }

    return credentialProtocol
  }

  /**
   * Initiate a new credential exchange as holder by sending a credential proposal message
   * to the connection with the specified connection id.
   *
   * @param options configuration to use for the proposal
   * @returns Credential exchange record associated with the sent proposal message
   */

  public async proposeCredential(options: ProposeCredentialOptions<CPs>): Promise<CredentialExchangeRecord> {
    const protocol = this.getProtocol(options.protocolVersion)

    const connectionRecord = await this.connectionService.getById(this.agentContext, options.connectionId)

    // Assert
    connectionRecord.assertReady()

    // will get back a credential record -> map to Credential Exchange Record
    const { credentialRecord, message } = await protocol.createProposal(this.agentContext, {
      connectionRecord,
      credentialFormats: options.credentialFormats,
      comment: options.comment,
      autoAcceptCredential: options.autoAcceptCredential,
      goalCode: options.goalCode,
      goal: options.goal,
    })

    const outboundMessageContext = await getOutboundMessageContext(this.agentContext, {
      message,
      associatedRecord: credentialRecord,
      connectionRecord,
    })

    await this.messageSender.sendMessage(outboundMessageContext)
    return credentialRecord
  }

  /**
   * Accept a credential proposal as issuer (by sending a credential offer message) to the connection
   * associated with the credential record.
   *
   * @param options config object for accepting the proposal
   * @returns Credential exchange record associated with the credential offer
   *
   */
  public async acceptProposal(options: AcceptCredentialProposalOptions<CPs>): Promise<CredentialExchangeRecord> {
    const credentialRecord = await this.getById(options.credentialRecordId)

    if (!credentialRecord.connectionId) {
      throw new CredoError(
        `No connectionId found for credential record '${credentialRecord.id}'. Connection-less issuance does not support credential proposal or negotiation.`
      )
    }

    // with version we can get the protocol
    const protocol = this.getProtocol(credentialRecord.protocolVersion)
    const connectionRecord = await this.connectionService.getById(this.agentContext, credentialRecord.connectionId)

    // Assert
    connectionRecord.assertReady()

    // will get back a credential record -> map to Credential Exchange Record
    const { message } = await protocol.acceptProposal(this.agentContext, {
      credentialRecord,
      credentialFormats: options.credentialFormats,
      comment: options.comment,
      autoAcceptCredential: options.autoAcceptCredential,
      goalCode: options.goalCode,
      goal: options.goal,
    })

    // send the message
    const outboundMessageContext = await getOutboundMessageContext(this.agentContext, {
      message,
      associatedRecord: credentialRecord,
      connectionRecord,
    })
    await this.messageSender.sendMessage(outboundMessageContext)

    return credentialRecord
  }

  /**
   * Negotiate a credential proposal as issuer (by sending a credential offer message) to the connection
   * associated with the credential record.
   *
   * @param options configuration for the offer see {@link NegotiateCredentialProposalOptions}
   * @returns Credential exchange record associated with the credential offer
   *
   */
  public async negotiateProposal(options: NegotiateCredentialProposalOptions<CPs>): Promise<CredentialExchangeRecord> {
    const credentialRecord = await this.getById(options.credentialRecordId)

    if (!credentialRecord.connectionId) {
      throw new CredoError(
        `No connection id for credential record ${credentialRecord.id} not found. Connection-less issuance does not support negotiation`
      )
    }

    // with version we can get the Service
    const protocol = this.getProtocol(credentialRecord.protocolVersion)

    const { message } = await protocol.negotiateProposal(this.agentContext, {
      credentialRecord,
      credentialFormats: options.credentialFormats,
      comment: options.comment,
      autoAcceptCredential: options.autoAcceptCredential,
      goalCode: options.goalCode,
      goal: options.goal,
    })

    const connectionRecord = await this.connectionService.getById(this.agentContext, credentialRecord.connectionId)
    const outboundMessageContext = await getOutboundMessageContext(this.agentContext, {
      message,
      associatedRecord: credentialRecord,
      connectionRecord,
    })
    await this.messageSender.sendMessage(outboundMessageContext)

    return credentialRecord
  }

  /**
   * Initiate a new credential exchange as issuer by sending a credential offer message
   * to the connection with the specified connection id.
   *
   * @param options config options for the credential offer
   * @returns Credential exchange record associated with the sent credential offer message
   */
  public async offerCredential(options: OfferCredentialOptions<CPs>): Promise<CredentialExchangeRecord> {
    const connectionRecord = await this.connectionService.getById(this.agentContext, options.connectionId)
    const protocol = this.getProtocol(options.protocolVersion)

    this.logger.debug(`Got a credentialProtocol object for version ${options.protocolVersion}`)

    const { message, credentialRecord } = await protocol.createOffer(this.agentContext, {
      credentialFormats: options.credentialFormats,
      autoAcceptCredential: options.autoAcceptCredential,
      comment: options.comment,
      connectionRecord,
      goalCode: options.goalCode,
      goal: options.goal,
    })

    this.logger.debug('Offer Message successfully created; message= ', message)
    const outboundMessageContext = await getOutboundMessageContext(this.agentContext, {
      message,
      associatedRecord: credentialRecord,
      connectionRecord,
    })
    await this.messageSender.sendMessage(outboundMessageContext)

    return credentialRecord
  }

  /**
   * Accept a credential offer as holder (by sending a credential request message) to the connection
   * associated with the credential record.
   *
   * @param options The object containing config options of the offer to be accepted
   * @returns Object containing offer associated credential record
   */
  public async acceptOffer(options: AcceptCredentialOfferOptions<CPs>): Promise<CredentialExchangeRecord> {
    const credentialRecord = await this.getById(options.credentialRecordId)

    const protocol = this.getProtocol(credentialRecord.protocolVersion)

    this.logger.debug(`Got a credentialProtocol object for this version; version = ${protocol.version}`)
    const offerMessage = await protocol.findOfferMessage(this.agentContext, credentialRecord.id)
    if (!offerMessage) {
      throw new CredoError(`No offer message found for credential record with id '${credentialRecord.id}'`)
    }

    // Use connection if present
    const connectionRecord = credentialRecord.connectionId
      ? await this.connectionService.getById(this.agentContext, credentialRecord.connectionId)
      : undefined
    connectionRecord?.assertReady()

    const { message } = await protocol.acceptOffer(this.agentContext, {
      credentialRecord,
      credentialFormats: options.credentialFormats,
      comment: options.comment,
      autoAcceptCredential: options.autoAcceptCredential,
      goalCode: options.goalCode,
      goal: options.goal,
    })

    const outboundMessageContext = await getOutboundMessageContext(this.agentContext, {
      message,
      connectionRecord,
      associatedRecord: credentialRecord,
      lastReceivedMessage: offerMessage,
    })
    await this.messageSender.sendMessage(outboundMessageContext)

    return credentialRecord
  }

  public async declineOffer(
    credentialRecordId: string,
    options?: DeclineCredentialOfferOptions
  ): Promise<CredentialExchangeRecord> {
    const credentialRecord = await this.getById(credentialRecordId)
    credentialRecord.assertState(CredentialState.OfferReceived)

    // with version we can get the Service
    const protocol = this.getProtocol(credentialRecord.protocolVersion)
    if (options?.sendProblemReport) {
      await this.sendProblemReport({
        credentialRecordId,
        description: options.problemReportDescription ?? 'Offer declined',
      })
    }

    await protocol.updateState(this.agentContext, credentialRecord, CredentialState.Declined)

    return credentialRecord
  }

  public async negotiateOffer(options: NegotiateCredentialOfferOptions<CPs>): Promise<CredentialExchangeRecord> {
    const credentialRecord = await this.getById(options.credentialRecordId)

    if (!credentialRecord.connectionId) {
      throw new CredoError(
        `No connection id for credential record ${credentialRecord.id} not found. Connection-less issuance does not support negotiation`
      )
    }

    const connectionRecord = await this.connectionService.getById(this.agentContext, credentialRecord.connectionId)

    // Assert
    connectionRecord.assertReady()

    const protocol = this.getProtocol(credentialRecord.protocolVersion)
    const { message } = await protocol.negotiateOffer(this.agentContext, {
      credentialFormats: options.credentialFormats,
      credentialRecord,
      comment: options.comment,
      autoAcceptCredential: options.autoAcceptCredential,
      goalCode: options.goalCode,
      goal: options.goal,
    })

    const outboundMessageContext = await getOutboundMessageContext(this.agentContext, {
      message,
      associatedRecord: credentialRecord,
      connectionRecord,
    })
    await this.messageSender.sendMessage(outboundMessageContext)

    return credentialRecord
  }

  /**
   * Initiate a new credential exchange as issuer by creating a credential offer
   * not bound to any connection. The offer must be delivered out-of-band to the holder
   * @param options The credential options to use for the offer
   * @returns The credential record and credential offer message
   */
  public async createOffer(options: CreateCredentialOfferOptions<CPs>): Promise<{
    message: AgentMessage
    credentialRecord: CredentialExchangeRecord
  }> {
    const protocol = this.getProtocol(options.protocolVersion)

    this.logger.debug(`Got a credentialProtocol object for version ${options.protocolVersion}`)
    const { message, credentialRecord } = await protocol.createOffer(this.agentContext, {
      credentialFormats: options.credentialFormats,
      comment: options.comment,
      autoAcceptCredential: options.autoAcceptCredential,
      goalCode: options.goalCode,
      goal: options.goal,
    })

    this.logger.debug('Offer Message successfully created', { message })

    return { message, credentialRecord }
  }

  /**
   * Accept a credential request as holder (by sending a credential request message) to the connection
   * associated with the credential record.
   *
   * @param options The object containing config options of the request
   * @returns CredentialExchangeRecord updated with information pertaining to this request
   */
  public async acceptRequest(options: AcceptCredentialRequestOptions<CPs>): Promise<CredentialExchangeRecord> {
    const credentialRecord = await this.getById(options.credentialRecordId)

    // with version we can get the Service
    const protocol = this.getProtocol(credentialRecord.protocolVersion)

    this.logger.debug(`Got a credentialProtocol object for version ${credentialRecord.protocolVersion}`)

    // Use connection if present
    const connectionRecord = credentialRecord.connectionId
      ? await this.connectionService.getById(this.agentContext, credentialRecord.connectionId)
      : undefined
    connectionRecord?.assertReady()

    const requestMessage = await protocol.findRequestMessage(this.agentContext, credentialRecord.id)
    if (!requestMessage) {
      throw new CredoError(`No request message found for credential record with id '${credentialRecord.id}'`)
    }
    const offerMessage = await protocol.findOfferMessage(this.agentContext, credentialRecord.id)
    if (!offerMessage) {
      throw new CredoError(`No offer message found for credential record with id '${credentialRecord.id}'`)
    }

    const { message } = await protocol.acceptRequest(this.agentContext, {
      credentialRecord,
      credentialFormats: options.credentialFormats,
      comment: options.comment,
      autoAcceptCredential: options.autoAcceptCredential,
    })
    this.logger.debug('We have a credential message (sending outbound): ', message)

    const outboundMessageContext = await getOutboundMessageContext(this.agentContext, {
      message,
      connectionRecord,
      associatedRecord: credentialRecord,
      lastReceivedMessage: requestMessage,
      lastSentMessage: offerMessage,
    })
    await this.messageSender.sendMessage(outboundMessageContext)

    return credentialRecord
  }

  /**
   * Accept a credential as holder (by sending a credential acknowledgement message) to the connection
   * associated with the credential record.
   *
   * @param credentialRecordId The id of the credential record for which to accept the credential
   * @returns credential exchange record associated with the sent credential acknowledgement message
   *
   */
  public async acceptCredential(options: AcceptCredentialOptions): Promise<CredentialExchangeRecord> {
    const credentialRecord = await this.getById(options.credentialRecordId)

    // with version we can get the Service
    const protocol = this.getProtocol(credentialRecord.protocolVersion)

    this.logger.debug(`Got a credentialProtocol object for version ${credentialRecord.protocolVersion}`)

    // Use connection if present
    const connectionRecord = credentialRecord.connectionId
      ? await this.connectionService.getById(this.agentContext, credentialRecord.connectionId)
      : undefined
    connectionRecord?.assertReady()

    const requestMessage = await protocol.findRequestMessage(this.agentContext, credentialRecord.id)
    if (!requestMessage) {
      throw new CredoError(`No request message found for credential record with id '${credentialRecord.id}'`)
    }
    const credentialMessage = await protocol.findCredentialMessage(this.agentContext, credentialRecord.id)
    if (!credentialMessage) {
      throw new CredoError(`No credential message found for credential record with id '${credentialRecord.id}'`)
    }

    const { message } = await protocol.acceptCredential(this.agentContext, {
      credentialRecord,
    })

    const outboundMessageContext = await getOutboundMessageContext(this.agentContext, {
      message,
      connectionRecord,
      associatedRecord: credentialRecord,
      lastReceivedMessage: credentialMessage,
    })
    await this.messageSender.sendMessage(outboundMessageContext)

    return credentialRecord
  }

  /**
   * Send a revocation notification for a credential exchange record. Currently Revocation Notification V2 protocol is supported
   *
   * @param credentialRecordId The id of the credential record for which to send revocation notification
   */
  public async sendRevocationNotification(options: SendRevocationNotificationOptions): Promise<void> {
    const { credentialRecordId, revocationId, revocationFormat, comment, requestAck } = options

    const credentialRecord = await this.getById(credentialRecordId)

    const { message } = await this.revocationNotificationService.v2CreateRevocationNotification({
      credentialId: revocationId,
      revocationFormat,
      comment,
      requestAck,
    })
    const protocol = this.getProtocol(credentialRecord.protocolVersion)

    const requestMessage = await protocol.findRequestMessage(this.agentContext, credentialRecord.id)
    if (!requestMessage) {
      throw new CredoError(`No request message found for credential record with id '${credentialRecord.id}'`)
    }

    const offerMessage = await protocol.findOfferMessage(this.agentContext, credentialRecord.id)
    if (!offerMessage) {
      throw new CredoError(`No offer message found for credential record with id '${credentialRecord.id}'`)
    }

    // Use connection if present
    const connectionRecord = credentialRecord.connectionId
      ? await this.connectionService.getById(this.agentContext, credentialRecord.connectionId)
      : undefined
    connectionRecord?.assertReady()

    const outboundMessageContext = await getOutboundMessageContext(this.agentContext, {
      message,
      connectionRecord,
      associatedRecord: credentialRecord,
    })
    await this.messageSender.sendMessage(outboundMessageContext)
  }

  /**
   * Send problem report message for a credential record
   * @param credentialRecordId The id of the credential record for which to send problem report
   * @returns credential record associated with the credential problem report message
   */
  public async sendProblemReport(options: SendCredentialProblemReportOptions) {
    const credentialRecord = await this.getById(options.credentialRecordId)

    const protocol = this.getProtocol(credentialRecord.protocolVersion)

    const offerMessage = await protocol.findOfferMessage(this.agentContext, credentialRecord.id)

    const { message: problemReport } = await protocol.createProblemReport(this.agentContext, {
      description: options.description,
      credentialRecord,
    })

    // Use connection if present
    const connectionRecord = credentialRecord.connectionId
      ? await this.connectionService.getById(this.agentContext, credentialRecord.connectionId)
      : undefined
    connectionRecord?.assertReady()

    // If there's no connection (so connection-less, we require the state to be offer received)
    if (!connectionRecord) {
      credentialRecord.assertState(CredentialState.OfferReceived)

      if (!offerMessage) {
        throw new CredoError(`No offer message found for credential record with id '${credentialRecord.id}'`)
      }
    }

    const outboundMessageContext = await getOutboundMessageContext(this.agentContext, {
      message: problemReport,
      connectionRecord,
      associatedRecord: credentialRecord,
      lastReceivedMessage: offerMessage ?? undefined,
    })
    await this.messageSender.sendMessage(outboundMessageContext)

    return credentialRecord
  }

  public async getFormatData(
    credentialRecordId: string
  ): Promise<GetCredentialFormatDataReturn<CredentialFormatsFromProtocols<CPs>>> {
    const credentialRecord = await this.getById(credentialRecordId)
    const protocol = this.getProtocol(credentialRecord.protocolVersion)

    return protocol.getFormatData(this.agentContext, credentialRecordId)
  }

  /**
   * Retrieve a credential record by id
   *
   * @param credentialRecordId The credential record id
   * @throws {RecordNotFoundError} If no record is found
   * @return The credential record
   *
   */
  public getById(credentialRecordId: string): Promise<CredentialExchangeRecord> {
    return this.credentialRepository.getById(this.agentContext, credentialRecordId)
  }

  /**
   * Retrieve all credential records
   *
   * @returns List containing all credential records
   */
  public getAll(): Promise<CredentialExchangeRecord[]> {
    return this.credentialRepository.getAll(this.agentContext)
  }

  /**
   * Retrieve all credential records by specified query params
   *
   * @returns List containing all credential records matching specified query paramaters
   */
  public findAllByQuery(query: Query<CredentialExchangeRecord>) {
    return this.credentialRepository.findByQuery(this.agentContext, query)
  }

  /**
   * Find a credential record by id
   *
   * @param credentialRecordId the credential record id
   * @returns The credential record or null if not found
   */
  public findById(credentialRecordId: string): Promise<CredentialExchangeRecord | null> {
    return this.credentialRepository.findById(this.agentContext, credentialRecordId)
  }

  /**
   * Delete a credential record by id, also calls service to delete from wallet
   *
   * @param credentialId the credential record id
   * @param options the delete credential options for the delete operation
   */
  public async deleteById(credentialId: string, options?: DeleteCredentialOptions) {
    const credentialRecord = await this.getById(credentialId)
    const protocol = this.getProtocol(credentialRecord.protocolVersion)
    return protocol.delete(this.agentContext, credentialRecord, options)
  }

  /**
   * Update a credential exchange record
   *
   * @param credentialRecord the credential exchange record
   */
  public async update(credentialRecord: CredentialExchangeRecord): Promise<void> {
    await this.credentialRepository.update(this.agentContext, credentialRecord)
  }

  public async findProposalMessage(credentialExchangeId: string): Promise<FindCredentialProposalMessageReturn<CPs>> {
    const protocol = await this.getServiceForCredentialExchangeId(credentialExchangeId)

    return protocol.findProposalMessage(
      this.agentContext,
      credentialExchangeId
    ) as FindCredentialProposalMessageReturn<CPs>
  }

  public async findOfferMessage(credentialExchangeId: string): Promise<FindCredentialOfferMessageReturn<CPs>> {
    const protocol = await this.getServiceForCredentialExchangeId(credentialExchangeId)

    return protocol.findOfferMessage(this.agentContext, credentialExchangeId) as FindCredentialOfferMessageReturn<CPs>
  }

  public async findRequestMessage(credentialExchangeId: string): Promise<FindCredentialRequestMessageReturn<CPs>> {
    const protocol = await this.getServiceForCredentialExchangeId(credentialExchangeId)

    return protocol.findRequestMessage(
      this.agentContext,
      credentialExchangeId
    ) as FindCredentialRequestMessageReturn<CPs>
  }

  public async findCredentialMessage(credentialExchangeId: string): Promise<FindCredentialMessageReturn<CPs>> {
    const protocol = await this.getServiceForCredentialExchangeId(credentialExchangeId)

    return protocol.findCredentialMessage(this.agentContext, credentialExchangeId) as FindCredentialMessageReturn<CPs>
  }

  private async getServiceForCredentialExchangeId(credentialExchangeId: string) {
    const credentialExchangeRecord = await this.getById(credentialExchangeId)

    return this.getProtocol(credentialExchangeRecord.protocolVersion)
  }
}
