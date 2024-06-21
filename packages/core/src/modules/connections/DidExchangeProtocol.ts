import type { ConnectionRecord } from './repository'
import type { Routing } from './services/ConnectionService'
import type { AgentContext } from '../../agent'
import type { InboundMessageContext } from '../../agent/models/InboundMessageContext'
import type { ParsedMessageType } from '../../utils/messageType'
import type { ResolvedDidCommService } from '../didcomm'
import type { OutOfBandRecord } from '../oob/repository'

import { InjectionSymbols } from '../../constants'
import { Key, KeyType } from '../../crypto'
import { JwsService } from '../../crypto/JwsService'
import { JwaSignatureAlgorithm } from '../../crypto/jose/jwa'
import { getJwkFromKey } from '../../crypto/jose/jwk'
import { Attachment, AttachmentData } from '../../decorators/attachment/Attachment'
import { CredoError } from '../../error'
import { Logger } from '../../logger'
import { inject, injectable } from '../../plugins'
import { TypedArrayEncoder, isDid, Buffer } from '../../utils'
import { JsonEncoder } from '../../utils/JsonEncoder'
import { JsonTransformer } from '../../utils/JsonTransformer'
import { base64ToBase64URL } from '../../utils/base64'
import {
  DidDocument,
  DidKey,
  getNumAlgoFromPeerDid,
  PeerDidNumAlgo,
  DidsApi,
  isValidPeerDid,
  getAlternativeDidsForPeerDid,
} from '../dids'
import { getKeyFromVerificationMethod } from '../dids/domain/key-type'
import { tryParseDid } from '../dids/domain/parse'
import { didKeyToInstanceOfKey } from '../dids/helpers'
import { DidRepository } from '../dids/repository'
import { OutOfBandRole } from '../oob/domain/OutOfBandRole'
import { OutOfBandState } from '../oob/domain/OutOfBandState'
import { getMediationRecordForDidDocument } from '../routing/services/helpers'

import { ConnectionsModuleConfig } from './ConnectionsModuleConfig'
import { DidExchangeStateMachine } from './DidExchangeStateMachine'
import { DidExchangeProblemReportError, DidExchangeProblemReportReason } from './errors'
import { DidExchangeRequestMessage, DidExchangeResponseMessage, DidExchangeCompleteMessage } from './messages'
import { DidExchangeRole, DidExchangeState, HandshakeProtocol } from './models'
import { ConnectionService } from './services'
import { createPeerDidFromServices, getDidDocumentForCreatedDid, routingToServices } from './services/helpers'

interface DidExchangeRequestParams {
  label?: string
  alias?: string
  goal?: string
  goalCode?: string
  routing?: Routing
  autoAcceptConnection?: boolean
  ourDid?: string
}

@injectable()
export class DidExchangeProtocol {
  private connectionService: ConnectionService
  private jwsService: JwsService
  private didRepository: DidRepository
  private logger: Logger

  public constructor(
    connectionService: ConnectionService,
    didRepository: DidRepository,
    jwsService: JwsService,
    @inject(InjectionSymbols.Logger) logger: Logger
  ) {
    this.connectionService = connectionService
    this.didRepository = didRepository
    this.jwsService = jwsService
    this.logger = logger
  }

  public async createRequest(
    agentContext: AgentContext,
    outOfBandRecord: OutOfBandRecord,
    params: DidExchangeRequestParams
  ): Promise<{ message: DidExchangeRequestMessage; connectionRecord: ConnectionRecord }> {
    this.logger.debug(`Create message ${DidExchangeRequestMessage.type.messageTypeUri} start`, {
      outOfBandRecord,
      params,
    })
    const config = agentContext.dependencyManager.resolve(ConnectionsModuleConfig)

    const { outOfBandInvitation } = outOfBandRecord
    const { alias, goal, goalCode, routing, autoAcceptConnection, ourDid: did } = params
    // TODO: We should store only one did that we'll use to send the request message with success.
    // We take just the first one for now.
    const [invitationDid] = outOfBandInvitation.invitationDids

    // Create message
    const label = params.label ?? agentContext.config.label

    let didDocument, mediatorId

    // If our did is specified, make sure we have all key material for it
    if (did) {
      didDocument = await getDidDocumentForCreatedDid(agentContext, did)
      mediatorId = (await getMediationRecordForDidDocument(agentContext, didDocument))?.id
      // Otherwise, create a did:peer based on the provided routing
    } else {
      if (!routing) throw new CredoError(`'routing' must be defined if 'ourDid' is not specified`)

      didDocument = await createPeerDidFromServices(
        agentContext,
        routingToServices(routing),
        config.peerNumAlgoForDidExchangeRequests
      )
      mediatorId = routing.mediatorId
    }

    const parentThreadId = outOfBandRecord.outOfBandInvitation.id

    const message = new DidExchangeRequestMessage({ label, parentThreadId, did: didDocument.id, goal, goalCode })

    // Create sign attachment containing didDoc
    if (isValidPeerDid(didDocument.id) && getNumAlgoFromPeerDid(didDocument.id) === PeerDidNumAlgo.GenesisDoc) {
      const didDocAttach = await this.createSignedAttachment(
        agentContext,
        didDocument.toJSON(),
        didDocument.recipientKeys.map((key) => key.publicKeyBase58)
      )
      message.didDoc = didDocAttach
    }

    const connectionRecord = await this.connectionService.createConnection(agentContext, {
      protocol: HandshakeProtocol.DidExchange,
      role: DidExchangeRole.Requester,
      alias,
      state: DidExchangeState.InvitationReceived,
      theirLabel: outOfBandInvitation.label,
      mediatorId,
      autoAcceptConnection: outOfBandRecord.autoAcceptConnection,
      outOfBandId: outOfBandRecord.id,
      invitationDid,
      imageUrl: outOfBandInvitation.imageUrl,
    })

    DidExchangeStateMachine.assertCreateMessageState(DidExchangeRequestMessage.type, connectionRecord)

    connectionRecord.did = didDocument.id
    connectionRecord.threadId = message.id

    if (autoAcceptConnection !== undefined || autoAcceptConnection !== null) {
      connectionRecord.autoAcceptConnection = autoAcceptConnection
    }

    await this.updateState(agentContext, DidExchangeRequestMessage.type, connectionRecord)
    this.logger.debug(`Create message ${DidExchangeRequestMessage.type.messageTypeUri} end`, {
      connectionRecord,
      message,
    })
    return { message, connectionRecord }
  }

  public async processRequest(
    messageContext: InboundMessageContext<DidExchangeRequestMessage>,
    outOfBandRecord: OutOfBandRecord
  ): Promise<ConnectionRecord> {
    this.logger.debug(`Process message ${messageContext.message.type} start`, {
      message: messageContext.message,
    })

    outOfBandRecord.assertRole(OutOfBandRole.Sender)
    outOfBandRecord.assertState(OutOfBandState.AwaitResponse)

    // TODO check there is no connection record for particular oob record

    const { message, agentContext } = messageContext

    // Check corresponding invitation ID is the request's ~thread.pthid or pthid is a public did
    // TODO Maybe we can do it in handler, but that actually does not make sense because we try to find oob by parent thread ID there.
    const parentThreadId = message.thread?.parentThreadId
    if (
      !parentThreadId ||
      (!tryParseDid(parentThreadId) && parentThreadId !== outOfBandRecord.getTags().invitationId)
    ) {
      throw new DidExchangeProblemReportError('Missing reference to invitation.', {
        problemCode: DidExchangeProblemReportReason.RequestNotAccepted,
      })
    }

    // If the responder wishes to continue the exchange, they will persist the received information in their wallet.

    // Get DID Document either from message (if it is a supported did:peer) or resolve it externally
    const didDocument = await this.resolveDidDocument(agentContext, message)

    // A DID Record must be stored in order to allow for searching for its recipient keys when receiving a message
    const didRecord = await this.didRepository.storeReceivedDid(messageContext.agentContext, {
      did: didDocument.id,
      // It is important to take the did document from the PeerDid class
      // as it will have the id property
      didDocument:
        !isValidPeerDid(didDocument.id) || getNumAlgoFromPeerDid(message.did) === PeerDidNumAlgo.GenesisDoc
          ? didDocument
          : undefined,
      tags: {
        // We need to save the recipientKeys, so we can find the associated did
        // of a key when we receive a message from another connection.
        recipientKeyFingerprints: didDocument.recipientKeys.map((key) => key.fingerprint),

        // For did:peer, store any alternative dids (like short form did:peer:4),
        // it may have in order to relate any message referencing it
        alternativeDids: isValidPeerDid(didDocument.id) ? getAlternativeDidsForPeerDid(didDocument.id) : undefined,
      },
    })

    this.logger.debug('Saved DID record', {
      id: didRecord.id,
      did: didRecord.did,
      role: didRecord.role,
      tags: didRecord.getTags(),
      didDocument: 'omitted...',
    })

    const connectionRecord = await this.connectionService.createConnection(messageContext.agentContext, {
      protocol: HandshakeProtocol.DidExchange,
      role: DidExchangeRole.Responder,
      state: DidExchangeState.RequestReceived,
      alias: outOfBandRecord.alias,
      theirDid: message.did,
      theirLabel: message.label,
      threadId: message.threadId,
      mediatorId: outOfBandRecord.mediatorId,
      autoAcceptConnection: outOfBandRecord.autoAcceptConnection,
      outOfBandId: outOfBandRecord.id,
    })

    await this.updateState(messageContext.agentContext, DidExchangeRequestMessage.type, connectionRecord)
    this.logger.debug(`Process message ${DidExchangeRequestMessage.type.messageTypeUri} end`, connectionRecord)
    return connectionRecord
  }

  public async createResponse(
    agentContext: AgentContext,
    connectionRecord: ConnectionRecord,
    outOfBandRecord: OutOfBandRecord,
    routing?: Routing
  ): Promise<DidExchangeResponseMessage> {
    this.logger.debug(`Create message ${DidExchangeResponseMessage.type.messageTypeUri} start`, connectionRecord)
    DidExchangeStateMachine.assertCreateMessageState(DidExchangeResponseMessage.type, connectionRecord)

    const { threadId, theirDid } = connectionRecord

    const config = agentContext.dependencyManager.resolve(ConnectionsModuleConfig)

    if (!threadId) {
      throw new CredoError('Missing threadId on connection record.')
    }

    if (!theirDid) {
      throw new CredoError('Missing theirDid on connection record.')
    }

    let services: ResolvedDidCommService[] = []
    if (routing) {
      services = routingToServices(routing)
    } else if (outOfBandRecord.outOfBandInvitation.getInlineServices().length > 0) {
      const inlineServices = outOfBandRecord.outOfBandInvitation.getInlineServices()
      services = inlineServices.map((service) => ({
        id: service.id,
        serviceEndpoint: service.serviceEndpoint,
        recipientKeys: service.recipientKeys.map(didKeyToInstanceOfKey),
        routingKeys: service.routingKeys?.map(didKeyToInstanceOfKey) ?? [],
      }))
    } else {
      // We don't support using a did from the OOB invitation services currently, in this case we always pass routing to this method
      throw new CredoError(
        'No routing provided, and no inline services found in out of band invitation. When using did services in out of band invitation, make sure to provide routing information for rotation.'
      )
    }

    // Use the same num algo for response as received in request
    const numAlgo = isValidPeerDid(theirDid)
      ? getNumAlgoFromPeerDid(theirDid)
      : config.peerNumAlgoForDidExchangeRequests

    const didDocument = await createPeerDidFromServices(agentContext, services, numAlgo)
    const message = new DidExchangeResponseMessage({ did: didDocument.id, threadId })

    if (numAlgo === PeerDidNumAlgo.GenesisDoc) {
      message.didDoc = await this.createSignedAttachment(
        agentContext,
        didDocument.toJSON(),
        Array.from(
          new Set(
            services
              .map((s) => s.recipientKeys)
              .reduce((acc, curr) => acc.concat(curr), [])
              .map((key) => key.publicKeyBase58)
          )
        )
      )
    } else {
      // We assume any other case is a resolvable did (e.g. did:peer:2 or did:peer:4)
      message.didRotate = await this.createSignedAttachment(
        agentContext,
        didDocument.id,
        Array.from(
          new Set(
            services
              .map((s) => s.recipientKeys)
              .reduce((acc, curr) => acc.concat(curr), [])
              .map((key) => key.publicKeyBase58)
          )
        )
      )
    }

    connectionRecord.did = didDocument.id

    await this.updateState(agentContext, DidExchangeResponseMessage.type, connectionRecord)
    this.logger.debug(`Create message ${DidExchangeResponseMessage.type.messageTypeUri} end`, {
      connectionRecord,
      message,
    })
    return message
  }

  public async processResponse(
    messageContext: InboundMessageContext<DidExchangeResponseMessage>,
    outOfBandRecord: OutOfBandRecord
  ): Promise<ConnectionRecord> {
    this.logger.debug(`Process message ${DidExchangeResponseMessage.type.messageTypeUri} start`, {
      message: messageContext.message,
    })

    const { connection: connectionRecord, message, agentContext } = messageContext

    if (!connectionRecord) {
      throw new CredoError('No connection record in message context.')
    }

    DidExchangeStateMachine.assertProcessMessageState(DidExchangeResponseMessage.type, connectionRecord)

    if (!message.thread?.threadId || message.thread?.threadId !== connectionRecord.threadId) {
      throw new DidExchangeProblemReportError('Invalid or missing thread ID.', {
        problemCode: DidExchangeProblemReportReason.ResponseNotAccepted,
      })
    }

    // Get DID Document either from message (if it is a did:peer) or resolve it externally
    const didDocument = await this.resolveDidDocument(
      agentContext,
      message,
      outOfBandRecord
        .getTags()
        .recipientKeyFingerprints.map((fingerprint) => Key.fromFingerprint(fingerprint).publicKeyBase58)
    )

    if (isValidPeerDid(didDocument.id)) {
      const didRecord = await this.didRepository.storeReceivedDid(messageContext.agentContext, {
        did: didDocument.id,
        didDocument: getNumAlgoFromPeerDid(message.did) === PeerDidNumAlgo.GenesisDoc ? didDocument : undefined,
        tags: {
          // We need to save the recipientKeys, so we can find the associated did
          // of a key when we receive a message from another connection.
          recipientKeyFingerprints: didDocument.recipientKeys.map((key) => key.fingerprint),

          // For did:peer, store any alternative dids (like short form did:peer:4),
          // it may have in order to relate any message referencing it
          alternativeDids: getAlternativeDidsForPeerDid(didDocument.id),
        },
      })

      this.logger.debug('Saved DID record', {
        id: didRecord.id,
        did: didRecord.did,
        role: didRecord.role,
        tags: didRecord.getTags(),
        didDocument: 'omitted...',
      })
    }

    connectionRecord.theirDid = message.did

    await this.updateState(messageContext.agentContext, DidExchangeResponseMessage.type, connectionRecord)
    this.logger.debug(`Process message ${DidExchangeResponseMessage.type.messageTypeUri} end`, connectionRecord)
    return connectionRecord
  }

  public async createComplete(
    agentContext: AgentContext,
    connectionRecord: ConnectionRecord,
    outOfBandRecord: OutOfBandRecord
  ): Promise<DidExchangeCompleteMessage> {
    this.logger.debug(`Create message ${DidExchangeCompleteMessage.type.messageTypeUri} start`, connectionRecord)
    DidExchangeStateMachine.assertCreateMessageState(DidExchangeCompleteMessage.type, connectionRecord)

    const threadId = connectionRecord.threadId
    const parentThreadId = outOfBandRecord.outOfBandInvitation.id

    if (!threadId) {
      throw new CredoError(`Connection record ${connectionRecord.id} does not have 'threadId' attribute.`)
    }

    if (!parentThreadId) {
      throw new CredoError(`Connection record ${connectionRecord.id} does not have 'parentThreadId' attribute.`)
    }

    const message = new DidExchangeCompleteMessage({ threadId, parentThreadId })

    await this.updateState(agentContext, DidExchangeCompleteMessage.type, connectionRecord)
    this.logger.debug(`Create message ${DidExchangeCompleteMessage.type.messageTypeUri} end`, {
      connectionRecord,
      message,
    })
    return message
  }

  public async processComplete(
    messageContext: InboundMessageContext<DidExchangeCompleteMessage>,
    outOfBandRecord: OutOfBandRecord
  ): Promise<ConnectionRecord> {
    this.logger.debug(`Process message ${DidExchangeCompleteMessage.type.messageTypeUri} start`, {
      message: messageContext.message,
    })

    const { connection: connectionRecord, message } = messageContext

    if (!connectionRecord) {
      throw new CredoError('No connection record in message context.')
    }

    DidExchangeStateMachine.assertProcessMessageState(DidExchangeCompleteMessage.type, connectionRecord)

    if (message.threadId !== connectionRecord.threadId) {
      throw new DidExchangeProblemReportError('Invalid or missing thread ID.', {
        problemCode: DidExchangeProblemReportReason.CompleteRejected,
      })
    }
    const pthid = message.thread?.parentThreadId
    if (!pthid || pthid !== outOfBandRecord.outOfBandInvitation.id) {
      throw new DidExchangeProblemReportError('Invalid or missing parent thread ID referencing to the invitation.', {
        problemCode: DidExchangeProblemReportReason.CompleteRejected,
      })
    }

    await this.updateState(messageContext.agentContext, DidExchangeCompleteMessage.type, connectionRecord)
    this.logger.debug(`Process message ${DidExchangeCompleteMessage.type.messageTypeUri} end`, { connectionRecord })
    return connectionRecord
  }

  private async updateState(
    agentContext: AgentContext,
    messageType: ParsedMessageType,
    connectionRecord: ConnectionRecord
  ) {
    this.logger.debug(`Updating state`, { connectionRecord })
    const nextState = DidExchangeStateMachine.nextState(messageType, connectionRecord)
    return this.connectionService.updateState(agentContext, connectionRecord, nextState)
  }

  private async createSignedAttachment(
    agentContext: AgentContext,
    data: string | Record<string, unknown>,
    verkeys: string[]
  ) {
    const signedAttach = new Attachment({
      mimeType: typeof data === 'string' ? undefined : 'application/json',
      data: new AttachmentData({
        base64:
          typeof data === 'string' ? TypedArrayEncoder.toBase64URL(Buffer.from(data)) : JsonEncoder.toBase64(data),
      }),
    })

    await Promise.all(
      verkeys.map(async (verkey) => {
        const key = Key.fromPublicKeyBase58(verkey, KeyType.Ed25519)
        const kid = new DidKey(key).did
        const payload = typeof data === 'string' ? TypedArrayEncoder.fromString(data) : JsonEncoder.toBuffer(data)

        const jws = await this.jwsService.createJws(agentContext, {
          payload,
          key,
          header: {
            kid,
          },
          protectedHeaderOptions: {
            alg: JwaSignatureAlgorithm.EdDSA,
            jwk: getJwkFromKey(key),
          },
        })
        signedAttach.addJws(jws)
      })
    )

    return signedAttach
  }

  /**
   * Resolves a did document from a given `request` or `response` message, verifying its signature or did rotate
   * signature in case it is taken from message attachment.
   *
   * @param message DID request or DID response message
   * @param invitationKeys array containing keys from connection invitation that could be used for signing of DID document
   * @returns verified DID document content from message attachment
   */

  private async resolveDidDocument(
    agentContext: AgentContext,
    message: DidExchangeRequestMessage | DidExchangeResponseMessage,
    invitationKeysBase58: string[] = []
  ) {
    // The only supported case where we expect to receive a did-document attachment is did:peer algo 1
    return isDid(message.did, 'peer') && getNumAlgoFromPeerDid(message.did) === PeerDidNumAlgo.GenesisDoc
      ? this.extractAttachedDidDocument(agentContext, message, invitationKeysBase58)
      : this.extractResolvableDidDocument(agentContext, message, invitationKeysBase58)
  }

  /**
   * Extracts DID document from message (resolving it externally if required) and verifies did-rotate attachment signature
   * if applicable
   */
  private async extractResolvableDidDocument(
    agentContext: AgentContext,
    message: DidExchangeRequestMessage | DidExchangeResponseMessage,
    invitationKeysBase58?: string[]
  ) {
    // Validate did-rotate attachment in case of DID Exchange response
    if (message instanceof DidExchangeResponseMessage) {
      const didRotateAttachment = message.didRotate

      if (!didRotateAttachment) {
        throw new DidExchangeProblemReportError('DID Rotate attachment is missing.', {
          problemCode: DidExchangeProblemReportReason.ResponseNotAccepted,
        })
      }

      const jws = didRotateAttachment.data.jws

      if (!jws) {
        throw new DidExchangeProblemReportError('DID Rotate signature is missing.', {
          problemCode: DidExchangeProblemReportReason.ResponseNotAccepted,
        })
      }

      if (!didRotateAttachment.data.base64) {
        throw new CredoError('DID Rotate attachment is missing base64 property for signed did.')
      }

      // JWS payload must be base64url encoded
      const base64UrlPayload = base64ToBase64URL(didRotateAttachment.data.base64)
      const signedDid = TypedArrayEncoder.fromBase64(base64UrlPayload).toString()

      if (signedDid !== message.did) {
        throw new CredoError(
          `DID Rotate attachment's did ${message.did} does not correspond to message did ${message.did}`
        )
      }

      const { isValid, signerKeys } = await this.jwsService.verifyJws(agentContext, {
        jws: {
          ...jws,
          payload: base64UrlPayload,
        },
        jwkResolver: ({ jws: { header } }) => {
          if (typeof header.kid !== 'string' || !isDid(header.kid, 'key')) {
            throw new CredoError('JWS header kid must be a did:key DID.')
          }

          const didKey = DidKey.fromDid(header.kid)
          return getJwkFromKey(didKey.key)
        },
      })

      if (!isValid || !signerKeys.every((key) => invitationKeysBase58?.includes(key.publicKeyBase58))) {
        throw new DidExchangeProblemReportError(
          `DID Rotate signature is invalid. isValid: ${isValid} signerKeys: ${JSON.stringify(
            signerKeys
          )} invitationKeys:${JSON.stringify(invitationKeysBase58)}`,
          {
            problemCode: DidExchangeProblemReportReason.ResponseNotAccepted,
          }
        )
      }
    }

    // Now resolve the document related to the did (which can be either a public did or an inline did)
    try {
      return await agentContext.dependencyManager.resolve(DidsApi).resolveDidDocument(message.did)
    } catch (error) {
      const problemCode =
        message instanceof DidExchangeRequestMessage
          ? DidExchangeProblemReportReason.RequestNotAccepted
          : DidExchangeProblemReportReason.ResponseNotAccepted

      throw new DidExchangeProblemReportError(error, {
        problemCode,
      })
    }
  }

  /**
   * Extracts DID document as is from request or response message attachment and verifies its signature.
   *
   * @param message DID request or DID response message
   * @param invitationKeys array containing keys from connection invitation that could be used for signing of DID document
   * @returns verified DID document content from message attachment
   */
  private async extractAttachedDidDocument(
    agentContext: AgentContext,
    message: DidExchangeRequestMessage | DidExchangeResponseMessage,
    invitationKeysBase58: string[] = []
  ): Promise<DidDocument> {
    if (!message.didDoc) {
      const problemCode =
        message instanceof DidExchangeRequestMessage
          ? DidExchangeProblemReportReason.RequestNotAccepted
          : DidExchangeProblemReportReason.ResponseNotAccepted
      throw new DidExchangeProblemReportError('DID Document attachment is missing.', { problemCode })
    }
    const didDocumentAttachment = message.didDoc
    const jws = didDocumentAttachment.data.jws

    if (!jws) {
      const problemCode =
        message instanceof DidExchangeRequestMessage
          ? DidExchangeProblemReportReason.RequestNotAccepted
          : DidExchangeProblemReportReason.ResponseNotAccepted
      throw new DidExchangeProblemReportError('DID Document signature is missing.', { problemCode })
    }

    if (!didDocumentAttachment.data.base64) {
      throw new CredoError('DID Document attachment is missing base64 property for signed did document.')
    }

    // JWS payload must be base64url encoded
    const base64UrlPayload = base64ToBase64URL(didDocumentAttachment.data.base64)

    const { isValid, signerKeys } = await this.jwsService.verifyJws(agentContext, {
      jws: {
        ...jws,
        payload: base64UrlPayload,
      },
      jwkResolver: ({ jws: { header } }) => {
        if (typeof header.kid !== 'string' || !isDid(header.kid, 'key')) {
          throw new CredoError('JWS header kid must be a did:key DID.')
        }

        const didKey = DidKey.fromDid(header.kid)
        return getJwkFromKey(didKey.key)
      },
    })

    const json = JsonEncoder.fromBase64(didDocumentAttachment.data.base64)
    const didDocument = JsonTransformer.fromJSON(json, DidDocument)
    const didDocumentKeysBase58 = didDocument.authentication
      ?.map((authentication) => {
        const verificationMethod =
          typeof authentication === 'string'
            ? didDocument.dereferenceVerificationMethod(authentication)
            : authentication
        const key = getKeyFromVerificationMethod(verificationMethod)
        return key.publicKeyBase58
      })
      .concat(invitationKeysBase58)

    this.logger.trace('JWS verification result', { isValid, signerKeys, didDocumentKeysBase58 })

    if (!isValid || !signerKeys.every((key) => didDocumentKeysBase58?.includes(key.publicKeyBase58))) {
      const problemCode =
        message instanceof DidExchangeRequestMessage
          ? DidExchangeProblemReportReason.RequestNotAccepted
          : DidExchangeProblemReportReason.ResponseNotAccepted
      throw new DidExchangeProblemReportError('DID Document signature is invalid.', { problemCode })
    }

    return didDocument
  }
}
