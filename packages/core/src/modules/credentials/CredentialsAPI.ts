import type { AgentMessage } from '../../agent/AgentMessage'
import type { CredentialService, CredentialServiceType } from './CredentialService'
import type { CredentialRecord } from './repository'
import type { CredentialRecordBinding, CredentialExchangeRecordProps } from './v2/CredentialExchangeRecord'
import type {
  AcceptOfferOptions,
  AcceptProposalOptions,
  NegotiateProposalOptions,
  OfferCredentialOptions,
  ProposeCredentialOptions,
  RequestCredentialOptions,
} from './v2/interfaces'

import { Lifecycle, scoped } from 'tsyringe'

import { AgentConfig } from '../../agent/AgentConfig'
import { Dispatcher } from '../../agent/Dispatcher'
import { EventEmitter } from '../../agent/EventEmitter'
import { MessageSender } from '../../agent/MessageSender'
import { createOutboundMessage } from '../../agent/helpers'
import { ServiceDecorator } from '../../decorators/service/ServiceDecorator'
import { AriesFrameworkError } from '../../error'
import { unitTestLogger } from '../../logger'
import { ConnectionService } from '../connections/services/ConnectionService'
import { IndyHolderService, IndyIssuerService } from '../indy'
import { IndyLedgerService } from '../ledger'
import { MediationRecipientService } from '../routing'

import { CredentialProtocolVersion } from './CredentialProtocolVersion'
import { CredentialResponseCoordinator } from './CredentialResponseCoordinator'
import { CredentialState } from './CredentialState'
import { CredentialsModule } from './CredentialsModule'
import { CredentialRepository } from './repository'
import { V1CredentialService } from './v1/V1CredentialService'
import { V1LegacyCredentialService } from './v1/V1LegacyCredentialService'
import { CredentialRecordType, CredentialExchangeRecord } from './v2/CredentialExchangeRecord'
import { CredentialRole } from './v2/CredentialRole'
import { V2CredentialService } from './v2/V2CredentialService'

export interface CredentialsAPI {
  // Proposal methods

  proposeCredential(credentialOptions: ProposeCredentialOptions): Promise<CredentialExchangeRecord>
  acceptCredentialProposal(credentialOptions: AcceptProposalOptions): Promise<CredentialExchangeRecord>
  negotiateCredentialProposal(credentialOptions: NegotiateProposalOptions): Promise<CredentialExchangeRecord>

  // Offer methods

  offerCredential(credentialOptions: OfferCredentialOptions): Promise<CredentialExchangeRecord>
  acceptCredentialOffer(credentialOptions: AcceptOfferOptions): Promise<CredentialExchangeRecord>
  // declineOffer(credentialRecordId: string): Promise<CredentialExchangeRecord>
  // negotiateOffer(credentialOptions: NegotiateOfferOptions): Promise<CredentialExchangeRecord>

  // // Request
  // requestCredential(credentialOptions: RequestCredentialOptions): Promise<CredentialExchangeRecord>

  // when the issuer accepts the request he issues the credential to the holder
  // acceptRequest(credentialOptions: AcceptRequestOptions): Promise<CredentialExchangeRecord>

  // // Credential
  // acceptCredential(credentialRecordId: string): Promise<CredentialExchangeRecord>

  // // Record Methods
  // getAll(): Promise<CredentialExchangeRecord[]>
  getById(credentialRecordId: string): Promise<CredentialRecord>
  // findById(credentialRecordId: string): Promise<CredentialExchangeRecord | null>
  // deleteById(credentialRecordId: string): Promise<void>
  // findByQuery(query: Record<string, Tag | string[]>): Promise<CredentialExchangeRecord[]>
}

@scoped(Lifecycle.ContainerScoped)
export class CredentialsAPI extends CredentialsModule implements CredentialsAPI {
  private connService: ConnectionService
  private msgSender: MessageSender
  private v1CredentialService: V1LegacyCredentialService
  private credentialRepository: CredentialRepository
  private eventEmitter: EventEmitter
  private dispatcher: Dispatcher
  private agConfig: AgentConfig
  private credentialResponseCoord: CredentialResponseCoordinator
  private v1Service: V1CredentialService
  private v2Service: V2CredentialService
  private indyIssuerService: IndyIssuerService
  private mediatorRecipientService: MediationRecipientService
  private indyLedgerService: IndyLedgerService
  private indyHolderService: IndyHolderService
  private serviceMap: { '1.0': V1CredentialService; '2.0': V2CredentialService }

  // note some of the parameters passed in here are temporary, as we intend
  // to eventually remove CredentialsModule
  public constructor(
    dispatcher: Dispatcher,
    messageSender: MessageSender,
    connectionService: ConnectionService,
    agentConfig: AgentConfig,
    credentialResponseCoordinator: CredentialResponseCoordinator,
    v1CredentialService: V1LegacyCredentialService,
    credentialRepository: CredentialRepository,
    eventEmitter: EventEmitter,
    indyIssuerService: IndyIssuerService,
    mediationRecipientService: MediationRecipientService,
    indyLedgerService: IndyLedgerService,
    indyHolderService: IndyHolderService
  ) {
    super(
      dispatcher,
      connectionService,
      v1CredentialService,
      messageSender,
      agentConfig,
      credentialResponseCoordinator,
      mediationRecipientService
    )
    this.msgSender = messageSender
    this.v1CredentialService = v1CredentialService
    this.connService = connectionService
    this.credentialRepository = credentialRepository
    this.eventEmitter = eventEmitter
    this.dispatcher = dispatcher
    this.agConfig = agentConfig
    this.credentialResponseCoord = credentialResponseCoordinator
    this.indyIssuerService = indyIssuerService
    this.mediatorRecipientService = mediationRecipientService
    this.indyLedgerService = indyLedgerService
    this.indyHolderService = indyHolderService

    this.v1Service = new V1CredentialService(this.connService, this.v1CredentialService)

    this.v2Service = new V2CredentialService(
      this.connService,
      this.v1CredentialService,
      this.credentialRepository,
      this.eventEmitter,
      this.msgSender,
      this.dispatcher,
      this.agConfig,
      this.credentialResponseCoord,
      this.indyIssuerService,
      this.mediatorRecipientService,
      this.indyLedgerService,
      this.indyHolderService
    )

    this.serviceMap = {
      [CredentialProtocolVersion.V1_0]: this.v1Service,
      [CredentialProtocolVersion.V2_0]: this.v2Service,
    }
    unitTestLogger(
      `+++++++++++++++++++++ CREATE CREDENTIALS API (AIP2.0) FOR ${this.agConfig.label} +++++++++++++++++++++++++++`
    )

    // register handlers here
    // this.v1Service.registerHandlers() // MJR - TODO
    this.v2Service.registerHandlers()
  }

  public getService(protocolVersion: CredentialProtocolVersion): CredentialServiceType {
    return this.serviceMap[protocolVersion]
  }

  /**
   * Initiate a new credential exchange as holder by sending a credential proposal message
   * to the connection with the specified credential options
   *
   * @param credentialOptions configuration to use for the proposal
   * @returns Credential exchange record associated with the sent proposal message
   */

  public async proposeCredential(credentialOptions: ProposeCredentialOptions): Promise<CredentialExchangeRecord> {
    unitTestLogger('>> IN CREDENTIAL API => proposeCredential')

    // get the version
    const version: CredentialProtocolVersion = credentialOptions.protocolVersion

    unitTestLogger(`version =${version}`)

    // with version we can get the Service
    const service: CredentialService = this.getService(version)

    unitTestLogger('Got a CredentialService object for this version')

    const connection = await this.connService.getById(credentialOptions.connectionId)

    // will get back a credential record -> map to Credential Exchange Record
    const { credentialRecord, message } = await service.createProposal(credentialOptions)

    unitTestLogger('We have a message (sending outbound): ', message)

    // send the message here
    const outbound = createOutboundMessage(connection, message)

    unitTestLogger('Send Proposal to Issuer')
    await this.msgSender.sendMessage(outbound)

    const recordBinding: CredentialRecordBinding = {
      credentialRecordType: credentialOptions.credentialFormats.indy
        ? CredentialRecordType.INDY
        : CredentialRecordType.W3C,
      credentialRecordId: credentialRecord.id,
    }

    const bindings: CredentialRecordBinding[] = []
    bindings.push(recordBinding)

    // MJR-TODO get credential exchange record from the getById call??

    const props: CredentialExchangeRecordProps = {
      connectionId: credentialRecord.connectionId,
      threadId: credentialRecord.threadId,
      protocolVersion: version,
      state: CredentialState.ProposalSent,
      role: CredentialRole.Holder,
      credentials: bindings,
    }
    const credentialExchangeRecord = new CredentialExchangeRecord(props)

    // MJR-TODO: do we need to implement this?
    // await this.credentialRepository.save(credentialExchangeRecord)

    return credentialExchangeRecord
  }

  /**
   * Accept a credential proposal as issuer (by sending a credential offer message) to the connection
   * associated with the credential record.
   *
   * @param credentialOptions config object for the proposal (and subsequent offer) which replaces previous named parameters
   * @returns Credential exchange record associated with the credential offer
   *
   */
  public async acceptCredentialProposal(credentialOptions: AcceptProposalOptions): Promise<CredentialExchangeRecord> {
    // get the version
    const version: CredentialProtocolVersion = credentialOptions.protocolVersion

    // with version we can get the Service
    const service: CredentialService = this.getService(version)

    // will get back a credential record -> map to Credential Exchange Record
    const { credentialRecord, message } = await service.acceptProposal(credentialOptions)

    const recordBinding: CredentialRecordBinding = {
      credentialRecordType: credentialOptions.credentialFormats.indy
        ? CredentialRecordType.INDY
        : CredentialRecordType.W3C,
      credentialRecordId: credentialRecord.id,
    }

    const connection = await this.connService.getById(credentialOptions.connectionId)

    unitTestLogger('We have an offer message (sending outbound): ', message)

    // send the message here
    const outbound = createOutboundMessage(connection, message)

    unitTestLogger('Send Proposal to Issuer')
    await this.msgSender.sendMessage(outbound)
    const bindings: CredentialRecordBinding[] = []
    bindings.push(recordBinding)

    const props: CredentialExchangeRecordProps = {
      connectionId: credentialRecord.connectionId,
      threadId: credentialRecord.threadId,
      protocolVersion: version,
      state: CredentialState.ProposalSent,
      role: CredentialRole.Holder,
      credentials: bindings,
    }

    const credentialExchangeRecord = new CredentialExchangeRecord(props)

    // MJR-TODO: do we need to implement this?
    // await this.credentialRepository.save(credentialExchangeRecord)

    return credentialExchangeRecord
  }

  /**
   * Accept a credential offer as holder (by sending a credential request message) to the connection
   * associated with the credential record.
   *
   * @param credentialRecordId The id of the credential record for which to accept the offer
   * @param config Additional configuration to use for the request
   * @returns Credential record associated with the sent credential request message
   *
   */
  public async acceptCredentialOffer(credentialOptions: AcceptOfferOptions): Promise<CredentialExchangeRecord> {
    // get the version
    const version: CredentialProtocolVersion = credentialOptions.protocolVersion

    // will get back a credential record -> map to Credential Exchange Record
    const { credentialRecord } = await this.acceptOffer(credentialOptions)

    const recordBinding: CredentialRecordBinding = {
      credentialRecordType: credentialOptions.credentialRecordType
        ? CredentialRecordType.INDY
        : CredentialRecordType.W3C,
      credentialRecordId: credentialRecord.id,
    }

    const bindings: CredentialRecordBinding[] = []
    bindings.push(recordBinding)

    const props: CredentialExchangeRecordProps = {
      connectionId: credentialRecord.connectionId,
      threadId: credentialRecord.threadId,
      protocolVersion: version,
      state: CredentialState.RequestSent,
      role: CredentialRole.Holder,
      credentials: bindings,
    }

    const credentialExchangeRecord = new CredentialExchangeRecord(props)

    // MJR-TODO: do we need to implement this?
    // await this.credentialRepository.save(credentialExchangeRecord)

    return credentialExchangeRecord
  }
  /**
   * Accept a credential offer as holder (by sending a credential request message) to the connection
   * associated with the credential record.
   *
   * @param offer The object containing config options of the offer to be accepted
   * @returns Object containing offer associated credential record
   */
  private async acceptOffer(
    offer: AcceptOfferOptions
  ): Promise<{ credentialRecord: CredentialRecord; message: AgentMessage }> {
    unitTestLogger('>> IN CREDENTIAL API => acceptOffer')

    const service: CredentialService = this.getService(offer.protocolVersion)

    unitTestLogger(`Got a CredentialService object for this version; version = ${service.getVersion()}`)

    const record: CredentialRecord = await this.getById(offer.credentialRecordId)

    // Use connection if present
    if (record.connectionId) {
      const connection = await this.connService.getById(record.connectionId)

      const requestOptions: RequestCredentialOptions = {
        holderDid: connection.did,
        comment: offer.comment,
        credentialRecordType: offer.credentialRecordType,
        autoAcceptCredential: offer.autoAcceptCredential,
        credentialFormats: {}, // this gets filled in later
      }
      const { message, credentialRecord } = await service.createRequest(record, requestOptions)

      unitTestLogger('We have sent a credential request')
      const outboundMessage = createOutboundMessage(connection, message)

      await this.msgSender.sendMessage(outboundMessage)

      unitTestLogger('Outbound [Request] Message Sent')

      return { credentialRecord, message }
    }
    // Use ~service decorator otherwise
    else if (record.offerMessage?.service) {
      // Create ~service decorator
      const routing = await this.mediatorRecipientService.getRouting()
      const ourService = new ServiceDecorator({
        serviceEndpoint: routing.endpoints[0],
        recipientKeys: [routing.verkey],
        routingKeys: routing.routingKeys,
      })
      const recipientService = record.offerMessage.service

      const requestOptions: RequestCredentialOptions = {
        holderDid: ourService.recipientKeys[0],
        comment: offer.comment,
        credentialRecordType: offer.credentialRecordType,
        autoAcceptCredential: offer.autoAcceptCredential,
        credentialFormats: {}, // this gets filled in later
      }
      const { message, credentialRecord } = await service.createRequest(record, requestOptions)

      // Set and save ~service decorator to record (to remember our verkey)
      message.service = ourService
      await this.credentialRepository.update(credentialRecord)

      await this,
        this.msgSender.sendMessageToService({
          message,
          service: recipientService.toDidCommService(),
          senderKey: ourService.recipientKeys[0],
          returnRoute: true,
        })

      return { credentialRecord, message }
    }
    // Cannot send message without connectionId or ~service decorator
    else {
      throw new AriesFrameworkError(
        `Cannot accept offer for credential record without connectionId or ~service decorator on credential offer.`
      )
    }
  }

  /**
   * Negotiate a credential proposal as issuer (by sending a credential offer message) to the connection
   * associated with the credential record.
   *
   * @param credentialOptions configuration for the offer see {@link NegotiateProposalOptions}
   * @returns Credential exchange record associated with the credential offer
   *
   */
  public async negotiateCredentialProposal(
    credentialOptions: NegotiateProposalOptions
  ): Promise<CredentialExchangeRecord> {
    unitTestLogger('>> IN CREDENTIAL API => negotiateCredentialProposal')

    // get the version
    const version: CredentialProtocolVersion = credentialOptions.protocolVersion

    unitTestLogger(`version =${version}`)

    // with version we can get the Service
    const service: CredentialService = this.getService(version)

    const { credentialRecord, message } = await service.negotiateProposal(credentialOptions)

    if (!credentialRecord.connectionId) {
      throw new AriesFrameworkError(`Connection id for credential record ${credentialRecord.credentialId} not found!`)
    }
    const connection = await this.connService.getById(credentialRecord.connectionId)
    if (!connection) {
      throw new AriesFrameworkError(`Connection for ${credentialRecord.connectionId} not found!`)
    }
    // use record connection id to get the connection

    const outboundMessage = createOutboundMessage(connection, message)

    await this.msgSender.sendMessage(outboundMessage)

    const recordBinding: CredentialRecordBinding = {
      credentialRecordType: credentialOptions.credentialFormats.indy
        ? CredentialRecordType.INDY
        : CredentialRecordType.W3C,
      credentialRecordId: credentialRecord.id,
    }

    const bindings: CredentialRecordBinding[] = []
    bindings.push(recordBinding)

    const props: CredentialExchangeRecordProps = {
      connectionId: credentialRecord.connectionId,
      threadId: credentialRecord.threadId,
      protocolVersion: version,
      state: CredentialState.ProposalSent,
      role: CredentialRole.Holder,
      credentials: bindings,
    }
    const credentialExchangeRecord = new CredentialExchangeRecord(props)

    return credentialExchangeRecord
  }

  /**
   * Initiate a new credential exchange as issuer by sending a credential offer message
   * to the connection with the specified connection id.
   *
   * @param credentialOptions config options for the credential offer
   * @returns Credential exchange record associated with the sent credential offer message
   */
  public async offerCredential(credentialOptions: OfferCredentialOptions): Promise<CredentialExchangeRecord> {
    const connection = await this.connService.getById(credentialOptions.connectionId)

    // with version we can get the Service
    const service: CredentialService = this.getService(credentialOptions.protocolVersion)

    unitTestLogger('Got a CredentialService object for this version')
    const { message, credentialRecord } = await service.createOffer(credentialOptions)

    unitTestLogger('V2 Offer Message successfully created; message= ', message)
    const outboundMessage = createOutboundMessage(connection, message)
    await this.msgSender.sendMessage(outboundMessage)

    const recordBinding: CredentialRecordBinding = {
      credentialRecordType: credentialOptions.credentialFormats.indy
        ? CredentialRecordType.INDY
        : CredentialRecordType.W3C,
      credentialRecordId: credentialRecord.id,
    }

    const bindings: CredentialRecordBinding[] = []
    bindings.push(recordBinding)

    const props: CredentialExchangeRecordProps = {
      connectionId: credentialRecord.connectionId,
      threadId: credentialRecord.threadId,
      protocolVersion: credentialOptions.protocolVersion,
      state: CredentialState.ProposalSent,
      role: CredentialRole.Holder,
      credentials: bindings,
    }
    const credentialExchangeRecord = new CredentialExchangeRecord(props)

    return credentialExchangeRecord
  }
}
