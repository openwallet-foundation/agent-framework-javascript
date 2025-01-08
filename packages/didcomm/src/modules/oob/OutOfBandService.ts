import type { OutOfBandDidCommService } from './domain'
import type { HandshakeReusedEvent, OutOfBandStateChangedEvent } from './domain/OutOfBandEvents'
import type { InboundMessageContext } from '../../models'
import type { ConnectionRecord, HandshakeProtocol } from '../connections'
import type { AgentContext, Key, Query, QueryOptions } from '@credo-ts/core'

import { EventEmitter, CredoError, injectable, DidsApi, parseDid } from '@credo-ts/core'

import { DidCommDocumentService } from '../../services'

import { OutOfBandEventTypes } from './domain/OutOfBandEvents'
import { OutOfBandRole } from './domain/OutOfBandRole'
import { OutOfBandState } from './domain/OutOfBandState'
import { HandshakeReuseMessage, OutOfBandInvitation } from './messages'
import { HandshakeReuseAcceptedMessage } from './messages/HandshakeReuseAcceptedMessage'
import { OutOfBandRecord, OutOfBandRepository } from './repository'

export interface CreateFromImplicitInvitationConfig {
  did: string
  threadId: string
  handshakeProtocols: HandshakeProtocol[]
  autoAcceptConnection?: boolean
  recipientKey: Key
}

@injectable()
export class OutOfBandService {
  private outOfBandRepository: OutOfBandRepository
  private eventEmitter: EventEmitter
  private didCommDocumentService: DidCommDocumentService

  public constructor(
    outOfBandRepository: OutOfBandRepository,
    eventEmitter: EventEmitter,
    didCommDocumentService: DidCommDocumentService
  ) {
    this.outOfBandRepository = outOfBandRepository
    this.eventEmitter = eventEmitter
    this.didCommDocumentService = didCommDocumentService
  }

  /**
   * Creates an Out of Band record from a Connection/DIDExchange request started by using
   * a publicly resolvable DID this agent can control
   */
  public async createFromImplicitInvitation(
    agentContext: AgentContext,
    config: CreateFromImplicitInvitationConfig
  ): Promise<OutOfBandRecord> {
    const { did, threadId, handshakeProtocols, autoAcceptConnection, recipientKey } = config

    // Verify it is a valid did and it is present in the wallet
    const publicDid = parseDid(did)
    const didsApi = agentContext.dependencyManager.resolve(DidsApi)
    const [createdDid] = await didsApi.getCreatedDids({ did: publicDid.did })
    if (!createdDid) {
      throw new CredoError(`Referenced public did ${did} not found.`)
    }

    // Recreate an 'implicit invitation' matching the parameters used by the invitee when
    // initiating the flow
    const outOfBandInvitation = new OutOfBandInvitation({
      id: did,
      services: [did],
      handshakeProtocols,
    })

    outOfBandInvitation.setThread({ threadId })

    const outOfBandRecord = new OutOfBandRecord({
      role: OutOfBandRole.Sender,
      state: OutOfBandState.AwaitResponse,
      reusable: true,
      autoAcceptConnection: autoAcceptConnection ?? false,
      outOfBandInvitation,
      tags: {
        recipientKeyFingerprints: [recipientKey.fingerprint],
      },
    })

    await this.save(agentContext, outOfBandRecord)
    this.emitStateChangedEvent(agentContext, outOfBandRecord, null)
    return outOfBandRecord
  }

  public async processHandshakeReuse(messageContext: InboundMessageContext<HandshakeReuseMessage>) {
    const reuseMessage = messageContext.message
    const parentThreadId = reuseMessage.thread?.parentThreadId

    if (!parentThreadId) {
      throw new CredoError('handshake-reuse message must have a parent thread id')
    }

    const outOfBandRecord = await this.findByCreatedInvitationId(messageContext.agentContext, parentThreadId)
    if (!outOfBandRecord) {
      throw new CredoError('No out of band record found for handshake-reuse message')
    }

    // Assert
    outOfBandRecord.assertRole(OutOfBandRole.Sender)
    outOfBandRecord.assertState(OutOfBandState.AwaitResponse)

    const requestLength = outOfBandRecord.outOfBandInvitation.getRequests()?.length ?? 0
    if (requestLength > 0) {
      throw new CredoError('Handshake reuse should only be used when no requests are present')
    }

    const reusedConnection = messageContext.assertReadyConnection()
    this.eventEmitter.emit<HandshakeReusedEvent>(messageContext.agentContext, {
      type: OutOfBandEventTypes.HandshakeReused,
      payload: {
        reuseThreadId: reuseMessage.threadId,
        connectionRecord: reusedConnection,
        outOfBandRecord,
      },
    })

    // If the out of band record is not reusable we can set the state to done
    if (!outOfBandRecord.reusable) {
      await this.updateState(messageContext.agentContext, outOfBandRecord, OutOfBandState.Done)
    }

    const reuseAcceptedMessage = new HandshakeReuseAcceptedMessage({
      threadId: reuseMessage.threadId,
      parentThreadId,
    })

    return reuseAcceptedMessage
  }

  public async processHandshakeReuseAccepted(messageContext: InboundMessageContext<HandshakeReuseAcceptedMessage>) {
    const reuseAcceptedMessage = messageContext.message
    const parentThreadId = reuseAcceptedMessage.thread?.parentThreadId

    if (!parentThreadId) {
      throw new CredoError('handshake-reuse-accepted message must have a parent thread id')
    }

    const outOfBandRecord = await this.findByReceivedInvitationId(messageContext.agentContext, parentThreadId)
    if (!outOfBandRecord) {
      throw new CredoError('No out of band record found for handshake-reuse-accepted message')
    }

    // Assert
    outOfBandRecord.assertRole(OutOfBandRole.Receiver)
    outOfBandRecord.assertState(OutOfBandState.PrepareResponse)

    const reusedConnection = messageContext.assertReadyConnection()

    // Checks whether the connection associated with reuse accepted message matches with the connection
    // associated with the reuse message.
    // FIXME: not really a fan of the reuseConnectionId, but it's the only way I can think of now to get the connection
    // associated with the reuse message. Maybe we can at least move it to the metadata and remove it directly afterwards?
    // But this is an issue in general that has also come up for ACA-Py. How do I find the connection associated with an oob record?
    // Because it doesn't work really well with connection reuse.
    if (outOfBandRecord.reuseConnectionId !== reusedConnection.id) {
      throw new CredoError('handshake-reuse-accepted is not in response to a handshake-reuse message.')
    }

    this.eventEmitter.emit<HandshakeReusedEvent>(messageContext.agentContext, {
      type: OutOfBandEventTypes.HandshakeReused,
      payload: {
        reuseThreadId: reuseAcceptedMessage.threadId,
        connectionRecord: reusedConnection,
        outOfBandRecord,
      },
    })

    // receiver role is never reusable, so we can set the state to done
    await this.updateState(messageContext.agentContext, outOfBandRecord, OutOfBandState.Done)
  }

  public async createHandShakeReuse(
    agentContext: AgentContext,
    outOfBandRecord: OutOfBandRecord,
    connectionRecord: ConnectionRecord
  ) {
    const reuseMessage = new HandshakeReuseMessage({ parentThreadId: outOfBandRecord.outOfBandInvitation.id })

    // Store the reuse connection id
    outOfBandRecord.reuseConnectionId = connectionRecord.id
    await this.outOfBandRepository.update(agentContext, outOfBandRecord)

    return reuseMessage
  }

  public async save(agentContext: AgentContext, outOfBandRecord: OutOfBandRecord) {
    return this.outOfBandRepository.save(agentContext, outOfBandRecord)
  }

  public async updateState(agentContext: AgentContext, outOfBandRecord: OutOfBandRecord, newState: OutOfBandState) {
    const previousState = outOfBandRecord.state
    outOfBandRecord.state = newState
    await this.outOfBandRepository.update(agentContext, outOfBandRecord)

    this.emitStateChangedEvent(agentContext, outOfBandRecord, previousState)
  }

  public emitStateChangedEvent(
    agentContext: AgentContext,
    outOfBandRecord: OutOfBandRecord,
    previousState: OutOfBandState | null
  ) {
    this.eventEmitter.emit<OutOfBandStateChangedEvent>(agentContext, {
      type: OutOfBandEventTypes.OutOfBandStateChanged,
      payload: {
        outOfBandRecord: outOfBandRecord.clone(),
        previousState,
      },
    })
  }

  public async findById(agentContext: AgentContext, outOfBandRecordId: string) {
    return this.outOfBandRepository.findById(agentContext, outOfBandRecordId)
  }

  public async getById(agentContext: AgentContext, outOfBandRecordId: string) {
    return this.outOfBandRepository.getById(agentContext, outOfBandRecordId)
  }

  public async findByReceivedInvitationId(agentContext: AgentContext, receivedInvitationId: string) {
    return this.outOfBandRepository.findSingleByQuery(agentContext, {
      invitationId: receivedInvitationId,
      role: OutOfBandRole.Receiver,
    })
  }

  public async findByCreatedInvitationId(agentContext: AgentContext, createdInvitationId: string, threadId?: string) {
    return this.outOfBandRepository.findSingleByQuery(agentContext, {
      invitationId: createdInvitationId,
      role: OutOfBandRole.Sender,
      threadId,
    })
  }

  public async findCreatedByRecipientKey(agentContext: AgentContext, recipientKey: Key) {
    return this.outOfBandRepository.findSingleByQuery(agentContext, {
      recipientKeyFingerprints: [recipientKey.fingerprint],
      role: OutOfBandRole.Sender,
    })
  }

  public async getAll(agentContext: AgentContext) {
    return this.outOfBandRepository.getAll(agentContext)
  }

  public async findAllByQuery(agentContext: AgentContext, query: Query<OutOfBandRecord>, queryOptions?: QueryOptions) {
    return this.outOfBandRepository.findByQuery(agentContext, query, queryOptions)
  }

  public async deleteById(agentContext: AgentContext, outOfBandId: string) {
    const outOfBandRecord = await this.getById(agentContext, outOfBandId)
    return this.outOfBandRepository.delete(agentContext, outOfBandRecord)
  }

  /**
   * Extract a resolved didcomm service from an out of band invitation.
   *
   * Currently the first service that can be resolved is returned.
   */
  public async getResolvedServiceForOutOfBandServices(
    agentContext: AgentContext,
    services: Array<string | OutOfBandDidCommService>
  ) {
    for (const service of services) {
      if (typeof service === 'string') {
        const [didService] = await this.didCommDocumentService.resolveServicesFromDid(agentContext, service)

        if (didService) return didService
      } else {
        return service.resolvedDidCommService
      }
    }

    throw new CredoError('Could not extract a service from the out of band invitation.')
  }
}
