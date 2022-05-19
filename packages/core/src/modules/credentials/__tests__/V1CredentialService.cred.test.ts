import type { Logger } from '../../../../src/logger'
import type { AgentConfig } from '../../../agent/AgentConfig'
import type { ConnectionRecord } from '../../connections'
import type { ConnectionService } from '../../connections/services/ConnectionService'
import type { StoreCredentialOptions } from '../../indy/services/IndyHolderService'
import type { RevocationNotificationReceivedEvent, CredentialStateChangedEvent } from '../CredentialEvents'
import type { ServiceAcceptRequestOptions } from '../CredentialServiceOptions'
import type { RequestCredentialOptions } from '../CredentialsModuleOptions'
import type { CredentialPreviewAttribute } from '../models/CredentialPreviewAttributes'
import type { IndyCredentialMetadata } from '../protocol/v1/models/CredentialInfo'
import type { CustomCredentialTags } from '../repository/CredentialExchangeRecord'

import { getAgentConfig, getMockConnection, mockFunction } from '../../../../tests/helpers'
import { Dispatcher } from '../../../agent/Dispatcher'
import { EventEmitter } from '../../../agent/EventEmitter'
import { MessageSender } from '../../../agent/MessageSender'
import { InboundMessageContext } from '../../../agent/models/InboundMessageContext'
import { Attachment, AttachmentData } from '../../../decorators/attachment/Attachment'
import { AriesFrameworkError, RecordNotFoundError } from '../../../error'
import { DidCommMessageRepository } from '../../../storage'
import { JsonEncoder } from '../../../utils/JsonEncoder'
import { AckStatus } from '../../common'
import { DidExchangeState } from '../../connections'
import { IndyHolderService } from '../../indy/services/IndyHolderService'
import { IndyIssuerService } from '../../indy/services/IndyIssuerService'
import { IndyLedgerService } from '../../ledger/services'
import { MediationRecipientService } from '../../routing/services/MediationRecipientService'
import { CredentialEventTypes } from '../CredentialEvents'
import { CredentialProtocolVersion } from '../CredentialProtocolVersion'
import { CredentialState } from '../CredentialState'
import { CredentialUtils } from '../CredentialUtils'
import { CredentialFormatType } from '../CredentialsModuleOptions'
import { CredentialProblemReportReason } from '../errors/CredentialProblemReportReason'
import { IndyCredentialFormatService } from '../formats/indy/IndyCredentialFormatService'
import { V1CredentialPreview } from '../protocol/v1/V1CredentialPreview'
import { V1CredentialService } from '../protocol/v1/V1CredentialService'
import {
  V1RequestCredentialMessage,
  V1CredentialAckMessage,
  INDY_CREDENTIAL_ATTACHMENT_ID,
  INDY_CREDENTIAL_OFFER_ATTACHMENT_ID,
  INDY_CREDENTIAL_REQUEST_ATTACHMENT_ID,
  V1OfferCredentialMessage,
  V1IssueCredentialMessage,
  V1CredentialProblemReportMessage,
} from '../protocol/v1/messages'
import { V1RevocationNotificationMessage } from '../protocol/v1/messages/V1RevocationNotificationMessage'
import { V2RevocationNotificationMessage } from '../protocol/v2/messages/V2RevocationNotificationMessage'
import { CredentialExchangeRecord } from '../repository/CredentialExchangeRecord'
import { CredentialMetadataKeys } from '../repository/CredentialMetadataTypes'
import { CredentialRepository } from '../repository/CredentialRepository'
import { RevocationService } from '../services'

import { credDef, credReq, credOffer, schema } from './fixtures'

// Mock classes
jest.mock('../repository/CredentialRepository')
jest.mock('../../../modules/ledger/services/IndyLedgerService')
jest.mock('../../indy/services/IndyHolderService')
jest.mock('../../indy/services/IndyIssuerService')
jest.mock('../../../../src/storage/didcomm/DidCommMessageRepository')
jest.mock('../../routing/services/MediationRecipientService')

// Mock typed object
const CredentialRepositoryMock = CredentialRepository as jest.Mock<CredentialRepository>
const IndyLedgerServiceMock = IndyLedgerService as jest.Mock<IndyLedgerService>
const IndyHolderServiceMock = IndyHolderService as jest.Mock<IndyHolderService>
const IndyIssuerServiceMock = IndyIssuerService as jest.Mock<IndyIssuerService>
const DidCommMessageRepositoryMock = DidCommMessageRepository as jest.Mock<DidCommMessageRepository>
const MessageSenderMock = MessageSender as jest.Mock<MessageSender>
const MediationRecipientServiceMock = MediationRecipientService as jest.Mock<MediationRecipientService>

const connection = getMockConnection({
  id: '123',
  state: DidExchangeState.Completed,
})

const credentialPreview = V1CredentialPreview.fromRecord({
  name: 'John',
  age: '99',
})

const offerAttachment = new Attachment({
  id: INDY_CREDENTIAL_OFFER_ATTACHMENT_ID,
  mimeType: 'application/json',
  data: new AttachmentData({
    base64:
      'eyJzY2hlbWFfaWQiOiJhYWEiLCJjcmVkX2RlZl9pZCI6IlRoN01wVGFSWlZSWW5QaWFiZHM4MVk6MzpDTDoxNzpUQUciLCJub25jZSI6Im5vbmNlIiwia2V5X2NvcnJlY3RuZXNzX3Byb29mIjp7fX0',
  }),
})

const requestAttachment = new Attachment({
  id: INDY_CREDENTIAL_REQUEST_ATTACHMENT_ID,
  mimeType: 'application/json',
  data: new AttachmentData({
    base64: JsonEncoder.toBase64(credReq),
  }),
})

const credentialAttachment = new Attachment({
  id: INDY_CREDENTIAL_ATTACHMENT_ID,
  mimeType: 'application/json',
  data: new AttachmentData({
    base64: JsonEncoder.toBase64({
      values: CredentialUtils.convertAttributesToValues(credentialPreview.attributes),
    }),
  }),
})

const acceptRequestOptions: ServiceAcceptRequestOptions = {
  attachId: INDY_CREDENTIAL_ATTACHMENT_ID,
  comment: 'credential response comment',
  credentialRecordId: undefined,
}

// A record is deserialized to JSON when it's stored into the storage. We want to simulate this behaviour for `offer`
// object to test our service would behave correctly. We use type assertion for `offer` attribute to `any`.
const mockCredentialRecord = ({
  state,
  metadata,
  threadId,
  connectionId,
  tags,
  id,
  credentialAttributes,
  indyRevocationRegistryId,
  indyCredentialRevocationId,
}: {
  state?: CredentialState
  requestMessage?: V1RequestCredentialMessage
  metadata?: IndyCredentialMetadata & { indyRequest: Record<string, unknown> }
  tags?: CustomCredentialTags
  threadId?: string
  connectionId?: string
  credentialId?: string
  id?: string
  credentialAttributes?: CredentialPreviewAttribute[]
  indyRevocationRegistryId?: string
  indyCredentialRevocationId?: string
} = {}) => {
  const offerMessage = new V1OfferCredentialMessage({
    comment: 'some comment',
    credentialPreview: credentialPreview,
    offerAttachments: [offerAttachment],
  })

  const credentialRecord = new CredentialExchangeRecord({
    id,
    credentialAttributes: credentialAttributes || credentialPreview.attributes,
    state: state || CredentialState.OfferSent,
    threadId: threadId ?? offerMessage.id,
    connectionId: connectionId ?? '123',
    credentials: [
      {
        credentialRecordType: CredentialFormatType.Indy,
        credentialRecordId: '123456',
      },
    ],
    tags,
    protocolVersion: CredentialProtocolVersion.V1,
  })

  if (metadata?.indyRequest) {
    credentialRecord.metadata.set(CredentialMetadataKeys.IndyRequest, { ...metadata.indyRequest })
  }

  if (metadata?.schemaId) {
    credentialRecord.metadata.add(CredentialMetadataKeys.IndyCredential, {
      schemaId: metadata.schemaId,
    })
  }

  if (metadata?.credentialDefinitionId) {
    credentialRecord.metadata.add(CredentialMetadataKeys.IndyCredential, {
      credentialDefinitionId: metadata.credentialDefinitionId,
    })
  }

  credentialRecord.metadata.add(CredentialMetadataKeys.IndyCredential, {
    indyCredentialRevocationId,
    indyRevocationRegistryId,
  })

  return credentialRecord
}

let credentialRequestMessage: V1RequestCredentialMessage
let credentialOfferMessage: V1OfferCredentialMessage
let credentialIssueMessage: V1IssueCredentialMessage
let revocationService: RevocationService
let logger: Logger

describe('CredentialService', () => {
  let credentialRepository: CredentialRepository
  let indyLedgerService: IndyLedgerService
  let indyIssuerService: IndyIssuerService
  let indyHolderService: IndyHolderService
  let eventEmitter: EventEmitter
  let didCommMessageRepository: DidCommMessageRepository
  let mediationRecipientService: MediationRecipientService
  let messageSender: MessageSender
  let agentConfig: AgentConfig

  let dispatcher: Dispatcher
  let credentialService: V1CredentialService

  const initMessages = () => {
    credentialRequestMessage = new V1RequestCredentialMessage({
      comment: 'abcd',
      requestAttachments: [requestAttachment],
    })
    credentialOfferMessage = new V1OfferCredentialMessage({
      comment: 'some comment',
      credentialPreview: credentialPreview,
      offerAttachments: [offerAttachment],
    })
    credentialIssueMessage = new V1IssueCredentialMessage({
      comment: 'some comment',
      credentialAttachments: [offerAttachment],
    })

    mockFunction(didCommMessageRepository.findAgentMessage).mockImplementation(async (options) => {
      if (options.messageClass === V1OfferCredentialMessage) {
        return credentialOfferMessage
      }
      if (options.messageClass === V1RequestCredentialMessage) {
        return credentialRequestMessage
      }
      if (options.messageClass === V1IssueCredentialMessage) {
        return credentialIssueMessage
      }
      return null
    })
  }

  beforeEach(async () => {
    credentialRepository = new CredentialRepositoryMock()
    indyIssuerService = new IndyIssuerServiceMock()
    didCommMessageRepository = new DidCommMessageRepositoryMock()
    messageSender = new MessageSenderMock()
    agentConfig = getAgentConfig('CredentialServiceTest')
    mediationRecipientService = new MediationRecipientServiceMock()
    indyHolderService = new IndyHolderServiceMock()
    indyLedgerService = new IndyLedgerServiceMock()
    mockFunction(indyLedgerService.getCredentialDefinition).mockReturnValue(Promise.resolve(credDef))

    eventEmitter = new EventEmitter(agentConfig)

    dispatcher = new Dispatcher(messageSender, eventEmitter, agentConfig)
    revocationService = new RevocationService(credentialRepository, eventEmitter, agentConfig)
    logger = agentConfig.logger

    credentialService = new V1CredentialService(
      {
        getById: () => Promise.resolve(connection),
        assertConnectionOrServiceDecorator: () => true,
      } as unknown as ConnectionService,
      didCommMessageRepository,
      agentConfig,
      mediationRecipientService,
      dispatcher,
      eventEmitter,
      credentialRepository,
      new IndyCredentialFormatService(
        credentialRepository,
        eventEmitter,
        indyIssuerService,
        indyLedgerService,
        indyHolderService,
        agentConfig
      ),
      revocationService
    )
    mockFunction(indyLedgerService.getCredentialDefinition).mockReturnValue(Promise.resolve(credDef))
    mockFunction(indyLedgerService.getSchema).mockReturnValue(Promise.resolve(schema))
  })

  describe('createCredentialRequest', () => {
    let credentialRecord: CredentialExchangeRecord
    beforeEach(() => {
      credentialRecord = mockCredentialRecord({
        state: CredentialState.OfferReceived,
        threadId: 'fd9c5ddb-ec11-4acd-bc32-540736249746',
        connectionId: 'b1e2f039-aa39-40be-8643-6ce2797b5190',
      })
      initMessages()
    })

    test(`updates state to ${CredentialState.RequestSent}, set request metadata`, async () => {
      const repositoryUpdateSpy = jest.spyOn(credentialRepository, 'update')

      // mock offer so that the request works

      // when
      const options: RequestCredentialOptions = {}
      await credentialService.createRequest(credentialRecord, options, 'holderDid')

      // then
      expect(repositoryUpdateSpy).toHaveBeenCalledTimes(1)
      const [[updatedCredentialRecord]] = repositoryUpdateSpy.mock.calls
      expect(updatedCredentialRecord.toJSON()).toMatchObject({
        metadata: { '_internal/indyRequest': { cred_req: 'meta-data' } },
        state: CredentialState.RequestSent,
      })
    })

    test('returns credential request message base on existing credential offer message', async () => {
      // given
      const comment = 'credential request comment'
      const options: RequestCredentialOptions = {
        connectionId: credentialRecord.connectionId,
        comment: 'credential request comment',
      }

      // when
      const { message: credentialRequest } = await credentialService.createRequest(
        credentialRecord,
        options,
        'holderDid'
      )

      // then
      expect(credentialRequest.toJSON()).toMatchObject({
        '@id': expect.any(String),
        '@type': 'https://didcomm.org/issue-credential/1.0/request-credential',
        '~thread': {
          thid: credentialRecord.threadId,
        },
        comment,
        'requests~attach': [
          {
            '@id': expect.any(String),
            'mime-type': 'application/json',
            data: {
              base64: expect.any(String),
            },
          },
        ],
      })
    })

    const validState = CredentialState.OfferReceived
    const invalidCredentialStates = Object.values(CredentialState).filter((state) => state !== validState)
    test(`throws an error when state transition is invalid`, async () => {
      await Promise.all(
        invalidCredentialStates.map(async (state) => {
          await expect(
            credentialService.createRequest(mockCredentialRecord({ state }), {}, 'holderDid')
          ).rejects.toThrowError(`Credential record is in invalid state ${state}. Valid states are: ${validState}.`)
        })
      )
    })
  })

  describe('processCredentialRequest', () => {
    let credential: CredentialExchangeRecord
    let messageContext: InboundMessageContext<V1RequestCredentialMessage>
    beforeEach(() => {
      credential = mockCredentialRecord({ state: CredentialState.OfferSent })

      const credentialRequest = new V1RequestCredentialMessage({
        comment: 'abcd',
        requestAttachments: [requestAttachment],
      })
      credentialRequest.setThread({ threadId: 'somethreadid' })
      messageContext = new InboundMessageContext(credentialRequest, {
        connection,
      })
      initMessages()
    })

    test(`updates state to ${CredentialState.RequestReceived}, set request and returns credential record`, async () => {
      const repositoryUpdateSpy = jest.spyOn(credentialRepository, 'update')

      // given
      mockFunction(credentialRepository.getSingleByQuery).mockReturnValue(Promise.resolve(credential))

      // when
      const returnedCredentialRecord = await credentialService.processRequest(messageContext)

      // then
      expect(credentialRepository.getSingleByQuery).toHaveBeenNthCalledWith(1, {
        threadId: 'somethreadid',
        connectionId: connection.id,
      })
      expect(repositoryUpdateSpy).toHaveBeenCalledTimes(1)
      expect(returnedCredentialRecord.state).toEqual(CredentialState.RequestReceived)
    })

    test(`emits stateChange event from ${CredentialState.OfferSent} to ${CredentialState.RequestReceived}`, async () => {
      const eventListenerMock = jest.fn()
      eventEmitter.on<CredentialStateChangedEvent>(CredentialEventTypes.CredentialStateChanged, eventListenerMock)
      mockFunction(credentialRepository.getSingleByQuery).mockReturnValue(Promise.resolve(credential))

      // mock offer so that the request works
      const returnedCredentialRecord = await credentialService.processRequest(messageContext)

      // then
      expect(credentialRepository.getSingleByQuery).toHaveBeenNthCalledWith(1, {
        threadId: 'somethreadid',
        connectionId: connection.id,
      })
      expect(returnedCredentialRecord.state).toEqual(CredentialState.RequestReceived)
    })

    const validState = CredentialState.OfferSent
    const invalidCredentialStates = Object.values(CredentialState).filter((state) => state !== validState)
    test(`throws an error when state transition is invalid`, async () => {
      await Promise.all(
        invalidCredentialStates.map(async (state) => {
          mockFunction(credentialRepository.getSingleByQuery).mockReturnValue(
            Promise.resolve(mockCredentialRecord({ state }))
          )
          await expect(credentialService.processRequest(messageContext)).rejects.toThrowError(
            `Credential record is in invalid state ${state}. Valid states are: ${validState}.`
          )
        })
      )
    })
  })

  describe('createCredential', () => {
    const threadId = 'fd9c5ddb-ec11-4acd-bc32-540736249746'
    let credential: CredentialExchangeRecord
    beforeEach(() => {
      credential = mockCredentialRecord({
        state: CredentialState.RequestReceived,
        requestMessage: new V1RequestCredentialMessage({
          comment: 'abcd',
          requestAttachments: [requestAttachment],
        }),
        threadId,
        connectionId: 'b1e2f039-aa39-40be-8643-6ce2797b5190',
      })
      initMessages()
    })
    test(`updates state to ${CredentialState.CredentialIssued}`, async () => {
      const repositoryUpdateSpy = jest.spyOn(credentialRepository, 'update')

      // when
      await credentialService.createCredential(credential, acceptRequestOptions)

      // then
      expect(repositoryUpdateSpy).toHaveBeenCalledTimes(1)
      const [[updatedCredentialRecord]] = repositoryUpdateSpy.mock.calls
      expect(updatedCredentialRecord).toMatchObject({
        state: CredentialState.CredentialIssued,
      })
    })

    test(`emits stateChange event from ${CredentialState.RequestReceived} to ${CredentialState.CredentialIssued}`, async () => {
      const eventListenerMock = jest.fn()

      // given
      mockFunction(credentialRepository.getById).mockReturnValue(Promise.resolve(credential))
      eventEmitter.on<CredentialStateChangedEvent>(CredentialEventTypes.CredentialStateChanged, eventListenerMock)

      // when
      await credentialService.createCredential(credential, acceptRequestOptions)

      // then
      expect(eventListenerMock).toHaveBeenCalledWith({
        type: 'CredentialStateChanged',
        payload: {
          previousState: CredentialState.RequestReceived,
          credentialRecord: expect.objectContaining({
            state: CredentialState.CredentialIssued,
          }),
        },
      })
    })

    test('returns credential response message base on credential request message', async () => {
      // given
      mockFunction(credentialRepository.getById).mockReturnValue(Promise.resolve(credential))
      const comment = 'credential response comment'

      // when

      const { message: credentialResponse } = await credentialService.createCredential(credential, acceptRequestOptions)
      // then
      expect(credentialResponse.toJSON()).toMatchObject({
        '@id': expect.any(String),
        '@type': 'https://didcomm.org/issue-credential/1.0/issue-credential',
        '~thread': {
          thid: credential.threadId,
        },
        comment,
        'credentials~attach': [
          {
            '@id': expect.any(String),
            'mime-type': 'application/json',
            data: {
              base64: expect.any(String),
            },
          },
        ],
        '~please_ack': expect.any(Object),
      })

      // Value of `cred` should be as same as in the credential response message.
      const [cred] = await indyIssuerService.createCredential({
        credentialOffer: credOffer,
        credentialRequest: credReq,
        credentialValues: {},
      })
      const [responseAttachment] = credentialResponse.credentialAttachments
      expect(responseAttachment.getDataAsJson()).toEqual(cred)
    })
  })

  describe('processCredential', () => {
    let credential: CredentialExchangeRecord
    let messageContext: InboundMessageContext<V1IssueCredentialMessage>
    beforeEach(() => {
      credential = mockCredentialRecord({
        state: CredentialState.RequestSent,
        requestMessage: new V1RequestCredentialMessage({
          requestAttachments: [requestAttachment],
        }),
        metadata: { indyRequest: { cred_req: 'meta-data' } },
      })

      const credentialResponse = new V1IssueCredentialMessage({
        comment: 'abcd',
        credentialAttachments: [credentialAttachment],
      })
      credentialResponse.setThread({ threadId: 'somethreadid' })
      messageContext = new InboundMessageContext(credentialResponse, {
        connection,
      })
      initMessages()
    })

    test('finds credential record by thread ID and saves credential attachment into the wallet', async () => {
      const storeCredentialMock = indyHolderService.storeCredential as jest.Mock<
        Promise<string>,
        [StoreCredentialOptions]
      >
      // given
      mockFunction(credentialRepository.getSingleByQuery).mockReturnValue(Promise.resolve(credential))
      // when
      await credentialService.processCredential(messageContext)

      // then
      expect(credentialRepository.getSingleByQuery).toHaveBeenNthCalledWith(1, {
        threadId: 'somethreadid',
        connectionId: connection.id,
      })

      expect(storeCredentialMock).toHaveBeenNthCalledWith(1, {
        credentialId: expect.any(String),
        credentialRequestMetadata: { cred_req: 'meta-data' },
        credential: messageContext.message.indyCredential,
        credentialDefinition: credDef,
      })
    })
  })

  describe('createAck', () => {
    const threadId = 'fd9c5ddb-ec11-4acd-bc32-540736249746'
    let credential: CredentialExchangeRecord

    beforeEach(() => {
      credential = mockCredentialRecord({
        state: CredentialState.CredentialReceived,
        threadId,
        connectionId: 'b1e2f039-aa39-40be-8643-6ce2797b5190',
      })
    })

    test(`updates state to ${CredentialState.Done}`, async () => {
      // given
      const repositoryUpdateSpy = jest.spyOn(credentialRepository, 'update')

      // when
      await credentialService.createAck(credential)

      // then
      expect(repositoryUpdateSpy).toHaveBeenCalledTimes(1)
      const [[updatedCredentialRecord]] = repositoryUpdateSpy.mock.calls
      expect(updatedCredentialRecord).toMatchObject({
        state: CredentialState.Done,
      })
    })

    test(`emits stateChange event from ${CredentialState.CredentialReceived} to ${CredentialState.Done}`, async () => {
      const eventListenerMock = jest.fn()
      eventEmitter.on<CredentialStateChangedEvent>(CredentialEventTypes.CredentialStateChanged, eventListenerMock)

      // when
      await credentialService.createAck(credential)

      // then
      expect(eventListenerMock).toHaveBeenCalledWith({
        type: 'CredentialStateChanged',
        payload: {
          previousState: CredentialState.CredentialReceived,
          credentialRecord: expect.objectContaining({
            state: CredentialState.Done,
          }),
        },
      })
    })

    test('returns credential response message base on credential request message', async () => {
      // given
      mockFunction(credentialRepository.getById).mockReturnValue(Promise.resolve(credential))

      // when
      const { message: ackMessage } = await credentialService.createAck(credential)

      // then
      expect(ackMessage.toJSON()).toMatchObject({
        '@id': expect.any(String),
        '@type': 'https://didcomm.org/issue-credential/1.0/ack',
        '~thread': {
          thid: 'fd9c5ddb-ec11-4acd-bc32-540736249746',
        },
      })
    })

    const validState = CredentialState.CredentialReceived
    const invalidCredentialStates = Object.values(CredentialState).filter((state) => state !== validState)
    test(`throws an error when state transition is invalid`, async () => {
      await Promise.all(
        invalidCredentialStates.map(async (state) => {
          await expect(
            credentialService.createAck(
              mockCredentialRecord({ state, threadId, connectionId: 'b1e2f039-aa39-40be-8643-6ce2797b5190' })
            )
          ).rejects.toThrowError(`Credential record is in invalid state ${state}. Valid states are: ${validState}.`)
        })
      )
    })
  })

  describe('processAck', () => {
    let credential: CredentialExchangeRecord
    let messageContext: InboundMessageContext<V1CredentialAckMessage>

    beforeEach(() => {
      credential = mockCredentialRecord({
        state: CredentialState.CredentialIssued,
      })

      const credentialRequest = new V1CredentialAckMessage({
        status: AckStatus.OK,
        threadId: 'somethreadid',
      })
      messageContext = new InboundMessageContext(credentialRequest, {
        connection,
      })
      initMessages()
    })

    test(`updates state to ${CredentialState.Done} and returns credential record`, async () => {
      const repositoryUpdateSpy = jest.spyOn(credentialRepository, 'update')

      // given
      mockFunction(credentialRepository.getSingleByQuery).mockReturnValue(Promise.resolve(credential))

      // when
      const returnedCredentialRecord = await credentialService.processAck(messageContext)

      // then
      const expectedCredentialRecord = {
        state: CredentialState.Done,
      }
      expect(credentialRepository.getSingleByQuery).toHaveBeenNthCalledWith(1, {
        threadId: 'somethreadid',
        connectionId: connection.id,
      })
      expect(repositoryUpdateSpy).toHaveBeenCalledTimes(1)
      const [[updatedCredentialRecord]] = repositoryUpdateSpy.mock.calls
      expect(updatedCredentialRecord).toMatchObject(expectedCredentialRecord)
      expect(returnedCredentialRecord).toMatchObject(expectedCredentialRecord)
    })
  })

  describe('createProblemReport', () => {
    const threadId = 'fd9c5ddb-ec11-4acd-bc32-540736249746'
    let credential: CredentialExchangeRecord

    beforeEach(() => {
      credential = mockCredentialRecord({
        state: CredentialState.OfferReceived,
        threadId,
        connectionId: 'b1e2f039-aa39-40be-8643-6ce2797b5190',
      })
    })

    test('returns problem report message base once get error', async () => {
      // given
      mockFunction(credentialRepository.getById).mockReturnValue(Promise.resolve(credential))

      // when
      const credentialProblemReportMessage = new V1CredentialProblemReportMessage({
        description: {
          en: 'Indy error',
          code: CredentialProblemReportReason.IssuanceAbandoned,
        },
      })

      credentialProblemReportMessage.setThread({ threadId })
      // then
      expect(credentialProblemReportMessage.toJSON()).toMatchObject({
        '@id': expect.any(String),
        '@type': 'https://didcomm.org/issue-credential/1.0/problem-report',
        '~thread': {
          thid: 'fd9c5ddb-ec11-4acd-bc32-540736249746',
        },
      })
    })
  })

  describe('processProblemReport', () => {
    let credential: CredentialExchangeRecord
    let messageContext: InboundMessageContext<V1CredentialProblemReportMessage>

    beforeEach(() => {
      credential = mockCredentialRecord({
        state: CredentialState.OfferReceived,
      })

      const credentialProblemReportMessage = new V1CredentialProblemReportMessage({
        description: {
          en: 'Indy error',
          code: CredentialProblemReportReason.IssuanceAbandoned,
        },
      })
      credentialProblemReportMessage.setThread({ threadId: 'somethreadid' })
      messageContext = new InboundMessageContext(credentialProblemReportMessage, {
        connection,
      })
    })

    test(`updates problem report error message and returns credential record`, async () => {
      const repositoryUpdateSpy = jest.spyOn(credentialRepository, 'update')

      // given
      mockFunction(credentialRepository.getSingleByQuery).mockReturnValue(Promise.resolve(credential))

      // when
      const returnedCredentialRecord = await credentialService.processProblemReport(messageContext)

      // then
      const expectedCredentialRecord = {
        errorMessage: 'issuance-abandoned: Indy error',
      }
      expect(credentialRepository.getSingleByQuery).toHaveBeenNthCalledWith(1, {
        threadId: 'somethreadid',
        connectionId: connection.id,
      })
      expect(repositoryUpdateSpy).toHaveBeenCalledTimes(1)
      const [[updatedCredentialRecord]] = repositoryUpdateSpy.mock.calls
      expect(updatedCredentialRecord).toMatchObject(expectedCredentialRecord)
      expect(returnedCredentialRecord).toMatchObject(expectedCredentialRecord)
    })
  })

  describe('repository methods', () => {
    it('getById should return value from credentialRepository.getById', async () => {
      const expected = mockCredentialRecord()
      mockFunction(credentialRepository.getById).mockReturnValue(Promise.resolve(expected))
      const result = await credentialService.getById(expected.id)
      expect(credentialRepository.getById).toBeCalledWith(expected.id)

      expect(result).toBe(expected)
    })

    it('getById should return value from credentialRepository.getSingleByQuery', async () => {
      const expected = mockCredentialRecord()
      mockFunction(credentialRepository.getSingleByQuery).mockReturnValue(Promise.resolve(expected))
      const result = await credentialService.getByThreadAndConnectionId('threadId', 'connectionId')
      expect(credentialRepository.getSingleByQuery).toBeCalledWith({
        threadId: 'threadId',
        connectionId: 'connectionId',
      })

      expect(result).toBe(expected)
    })

    it('findById should return value from credentialRepository.findById', async () => {
      const expected = mockCredentialRecord()
      mockFunction(credentialRepository.findById).mockReturnValue(Promise.resolve(expected))
      const result = await credentialService.findById(expected.id)
      expect(credentialRepository.findById).toBeCalledWith(expected.id)

      expect(result).toBe(expected)
    })

    it('getAll should return value from credentialRepository.getAll', async () => {
      const expected = [mockCredentialRecord(), mockCredentialRecord()]

      mockFunction(credentialRepository.getAll).mockReturnValue(Promise.resolve(expected))
      const result = await credentialService.getAll()
      expect(credentialRepository.getAll).toBeCalledWith()

      expect(result).toEqual(expect.arrayContaining(expected))
    })
  })

  describe('deleteCredential', () => {
    it('should call delete from repository', async () => {
      const credentialRecord = mockCredentialRecord()
      mockFunction(credentialRepository.getById).mockReturnValue(Promise.resolve(credentialRecord))

      const repositoryDeleteSpy = jest.spyOn(credentialRepository, 'delete')
      await credentialService.delete(credentialRecord)
      expect(repositoryDeleteSpy).toHaveBeenNthCalledWith(1, credentialRecord)
    })

    it('deleteAssociatedCredential parameter should call deleteCredential in indyHolderService with credentialId', async () => {
      const deleteCredentialMock = indyHolderService.deleteCredential as jest.Mock<Promise<void>, [string]>

      const credentialRecord = mockCredentialRecord()
      mockFunction(credentialRepository.getById).mockReturnValue(Promise.resolve(credentialRecord))

      await credentialService.delete(credentialRecord, {
        deleteAssociatedCredentials: true,
      })
      expect(deleteCredentialMock).toHaveBeenNthCalledWith(1, credentialRecord.credentials[0].credentialRecordId)
    })
  })

  describe('declineOffer', () => {
    const threadId = 'fd9c5ddb-ec11-4acd-bc32-540736249754'
    let credential: CredentialExchangeRecord

    beforeEach(() => {
      credential = mockCredentialRecord({
        state: CredentialState.OfferReceived,
        tags: { threadId },
      })
    })

    test(`updates state to ${CredentialState.Declined}`, async () => {
      // given
      const repositoryUpdateSpy = jest.spyOn(credentialRepository, 'update')

      // when
      await credentialService.declineOffer(credential)

      // then
      const expectedCredentialState = {
        state: CredentialState.Declined,
      }
      expect(repositoryUpdateSpy).toHaveBeenCalledTimes(1)
      expect(repositoryUpdateSpy).toHaveBeenNthCalledWith(1, expect.objectContaining(expectedCredentialState))
    })

    test(`emits stateChange event from ${CredentialState.OfferReceived} to ${CredentialState.Declined}`, async () => {
      const eventListenerMock = jest.fn()
      eventEmitter.on<CredentialStateChangedEvent>(CredentialEventTypes.CredentialStateChanged, eventListenerMock)

      // given
      mockFunction(credentialRepository.getSingleByQuery).mockReturnValue(Promise.resolve(credential))

      // when
      await credentialService.declineOffer(credential)

      // then
      expect(eventListenerMock).toHaveBeenCalledTimes(1)
      const [[event]] = eventListenerMock.mock.calls
      expect(event).toMatchObject({
        type: 'CredentialStateChanged',
        payload: {
          previousState: CredentialState.OfferReceived,
          credentialRecord: expect.objectContaining({
            state: CredentialState.Declined,
          }),
        },
      })
    })

    const validState = CredentialState.OfferReceived
    const invalidCredentialStates = Object.values(CredentialState).filter((state) => state !== validState)
    test(`throws an error when state transition is invalid`, async () => {
      await Promise.all(
        invalidCredentialStates.map(async (state) => {
          await expect(
            credentialService.declineOffer(mockCredentialRecord({ state, tags: { threadId } }))
          ).rejects.toThrowError(`Credential record is in invalid state ${state}. Valid states are: ${validState}.`)
        })
      )
    })
  })

  describe('revocationNotification', () => {
    let credential: CredentialExchangeRecord

    beforeEach(() => {
      credential = mockCredentialRecord({
        state: CredentialState.Done,
        indyRevocationRegistryId:
          'AsB27X6KRrJFsqZ3unNAH6:4:AsB27X6KRrJFsqZ3unNAH6:3:cl:48187:default:CL_ACCUM:3b24a9b0-a979-41e0-9964-2292f2b1b7e9',
        indyCredentialRevocationId: '1',
        connectionId: connection.id,
      })
      logger = agentConfig.logger
    })

    test('Test revocation notification event being emitted for V1', async () => {
      const eventListenerMock = jest.fn()
      eventEmitter.on<RevocationNotificationReceivedEvent>(
        CredentialEventTypes.RevocationNotificationReceived,
        eventListenerMock
      )
      const date = new Date(2022)

      mockFunction(credentialRepository.getSingleByQuery).mockReturnValueOnce(Promise.resolve(credential))
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      const spy = jest.spyOn(global, 'Date').mockImplementation(() => date)

      const { indyRevocationRegistryId, indyCredentialRevocationId } = credential.getTags()
      const revocationNotificationThreadId = `indy::${indyRevocationRegistryId}::${indyCredentialRevocationId}`

      const revocationNotificationMessage = new V1RevocationNotificationMessage({
        issueThread: revocationNotificationThreadId,
        comment: 'Credential has been revoked',
      })
      const messageContext = new InboundMessageContext(revocationNotificationMessage, {
        connection,
      })

      await revocationService.v1ProcessRevocationNotification(messageContext)

      expect(eventListenerMock).toHaveBeenCalledWith({
        type: 'RevocationNotificationReceived',
        payload: {
          credentialRecord: {
            ...credential,
            revocationNotification: {
              revocationDate: date,
              comment: 'Credential has been revoked',
            },
          },
        },
      })

      spy.mockRestore()
    })

    test('Error is logged when no matching credential found for revocation notification V1', async () => {
      const loggerSpy = jest.spyOn(logger, 'warn')

      const revocationRegistryId =
        'ABC12D3EFgHIjKL4mnOPQ5:4:AsB27X6KRrJFsqZ3unNAH6:3:cl:48187:default:CL_ACCUM:3b24a9b0-a979-41e0-9964-2292f2b1b7e9'
      const credentialRevocationId = '2'
      const revocationNotificationThreadId = `indy::${revocationRegistryId}::${credentialRevocationId}`
      const recordNotFoundError = new RecordNotFoundError(
        `No record found for given query '${JSON.stringify({ revocationRegistryId, credentialRevocationId })}'`,
        {
          recordType: CredentialExchangeRecord.type,
        }
      )

      mockFunction(credentialRepository.getSingleByQuery).mockReturnValue(Promise.reject(recordNotFoundError))

      const revocationNotificationMessage = new V1RevocationNotificationMessage({
        issueThread: revocationNotificationThreadId,
        comment: 'Credential has been revoked',
      })
      const messageContext = new InboundMessageContext(revocationNotificationMessage, { connection })

      await revocationService.v1ProcessRevocationNotification(messageContext)

      expect(loggerSpy).toBeCalledWith('Failed to process revocation notification message', {
        error: recordNotFoundError,
        threadId: revocationNotificationThreadId,
      })
    })

    test('Error is logged when invalid threadId is passed for revocation notification V1', async () => {
      const loggerSpy = jest.spyOn(logger, 'warn')

      const revocationNotificationThreadId = 'notIndy::invalidRevRegId::invalidCredRevId'
      const invalidThreadFormatError = new AriesFrameworkError(
        `Incorrect revocation notification threadId format: \n${revocationNotificationThreadId}\ndoes not match\n"indy::<revocation_registry_id>::<credential_revocation_id>"`
      )

      const revocationNotificationMessage = new V1RevocationNotificationMessage({
        issueThread: revocationNotificationThreadId,
        comment: 'Credential has been revoked',
      })
      const messageContext = new InboundMessageContext(revocationNotificationMessage)

      await revocationService.v1ProcessRevocationNotification(messageContext)

      expect(loggerSpy).toBeCalledWith('Failed to process revocation notification message', {
        error: invalidThreadFormatError,
        threadId: revocationNotificationThreadId,
      })
    })

    test('Test revocation notification event being emitted for V2', async () => {
      const eventListenerMock = jest.fn()
      eventEmitter.on<RevocationNotificationReceivedEvent>(
        CredentialEventTypes.RevocationNotificationReceived,
        eventListenerMock
      )
      const date = new Date(2022)

      mockFunction(credentialRepository.getSingleByQuery).mockReturnValueOnce(Promise.resolve(credential))

      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      const spy = jest.spyOn(global, 'Date').mockImplementation(() => date)

      const { indyRevocationRegistryId, indyCredentialRevocationId } = credential.getTags()
      const revocationNotificationCredentialId = `${indyRevocationRegistryId}::${indyCredentialRevocationId}`

      const revocationNotificationMessage = new V2RevocationNotificationMessage({
        credentialId: revocationNotificationCredentialId,
        revocationFormat: 'indy',
        comment: 'Credential has been revoked',
      })
      const messageContext = new InboundMessageContext(revocationNotificationMessage, {
        connection,
      })

      await revocationService.v2ProcessRevocationNotification(messageContext)

      expect(eventListenerMock).toHaveBeenCalledWith({
        type: 'RevocationNotificationReceived',
        payload: {
          credentialRecord: {
            ...credential,
            revocationNotification: {
              revocationDate: date,
              comment: 'Credential has been revoked',
            },
          },
        },
      })

      spy.mockRestore()
    })

    test('Error is logged when no matching credential found for revocation notification V2', async () => {
      const loggerSpy = jest.spyOn(logger, 'warn')

      const revocationRegistryId =
        'ABC12D3EFgHIjKL4mnOPQ5:4:AsB27X6KRrJFsqZ3unNAH6:3:cl:48187:default:CL_ACCUM:3b24a9b0-a979-41e0-9964-2292f2b1b7e9'
      const credentialRevocationId = '2'
      const credentialId = `${revocationRegistryId}::${credentialRevocationId}`

      const recordNotFoundError = new RecordNotFoundError(
        `No record found for given  query '${JSON.stringify({ revocationRegistryId, credentialRevocationId })}'`,
        {
          recordType: CredentialExchangeRecord.type,
        }
      )

      mockFunction(credentialRepository.getSingleByQuery).mockReturnValue(Promise.reject(recordNotFoundError))

      const revocationNotificationMessage = new V2RevocationNotificationMessage({
        credentialId,
        revocationFormat: 'indy',
        comment: 'Credential has been revoked',
      })
      const messageContext = new InboundMessageContext(revocationNotificationMessage, { connection })

      await revocationService.v2ProcessRevocationNotification(messageContext)

      expect(loggerSpy).toBeCalledWith('Failed to process revocation notification message', {
        error: recordNotFoundError,
        credentialId,
      })
    })

    test('Error is logged when invalid credentialId is passed for revocation notification V2', async () => {
      const loggerSpy = jest.spyOn(logger, 'warn')

      const invalidCredentialId = 'notIndy::invalidRevRegId::invalidCredRevId'
      const invalidFormatError = new AriesFrameworkError(
        `Incorrect revocation notification credentialId format: \n${invalidCredentialId}\ndoes not match\n"<revocation_registry_id>::<credential_revocation_id>"`
      )

      const revocationNotificationMessage = new V2RevocationNotificationMessage({
        credentialId: invalidCredentialId,
        revocationFormat: 'indy',
        comment: 'Credential has been revoked',
      })
      const messageContext = new InboundMessageContext(revocationNotificationMessage)

      await revocationService.v2ProcessRevocationNotification(messageContext)

      expect(loggerSpy).toBeCalledWith('Failed to process revocation notification message', {
        error: invalidFormatError,
        credentialId: invalidCredentialId,
      })
    })

    test('Test error being thrown when connection does not match issuer', async () => {
      const loggerSpy = jest.spyOn(logger, 'warn')
      const date = new Date(2022)

      const error = new AriesFrameworkError(
        "Credential record is associated with connection '123'. Current connection is 'fd9c5ddb-ec11-4acd-bc32-540736249746'"
      )

      mockFunction(credentialRepository.getSingleByQuery).mockReturnValueOnce(Promise.resolve(credential))
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      const spy = jest.spyOn(global, 'Date').mockImplementation(() => date)

      const { indyRevocationRegistryId, indyCredentialRevocationId } = credential.getTags()
      const revocationNotificationThreadId = `indy::${indyRevocationRegistryId}::${indyCredentialRevocationId}`

      const revocationNotificationMessage = new V1RevocationNotificationMessage({
        issueThread: revocationNotificationThreadId,
        comment: 'Credential has been revoked',
      })
      const messageContext = new InboundMessageContext(revocationNotificationMessage, {
        connection: {
          id: 'fd9c5ddb-ec11-4acd-bc32-540736249746',
          // eslint-disable-next-line @typescript-eslint/no-empty-function
          assertReady: () => {},
        } as ConnectionRecord,
      })

      await revocationService.v1ProcessRevocationNotification(messageContext)

      expect(loggerSpy).toBeCalledWith('Failed to process revocation notification message', {
        error,
        threadId: revocationNotificationThreadId,
      })

      spy.mockRestore()
    })

    describe('revocation registry id validation', () => {
      const revocationRegistryId =
        'ABC12D3EFgHIjKL4mnOPQ5:4:AsB27X6KRrJFsqZ3unNAH6:3:cl:48187:N4s7y-5hema_tag ;:CL_ACCUM:3b24a9b0-a979-41e0-9964-2292f2b1b7e9'
      test('V1 allows any character in tag part of RevRegId', async () => {
        const loggerSpy = jest.spyOn(logger, 'warn')
        mockFunction(credentialRepository.getSingleByQuery).mockReturnValueOnce(Promise.resolve(credential))

        const revocationNotificationThreadId = `indy::${revocationRegistryId}::2`

        const invalidThreadFormatError = new AriesFrameworkError(
          `Incorrect revocation notification threadId format: \n${revocationNotificationThreadId}\ndoes not match\n"indy::<revocation_registry_id>::<credential_revocation_id>"`
        )

        const revocationNotificationMessage = new V1RevocationNotificationMessage({
          issueThread: revocationNotificationThreadId,
          comment: 'Credential has been revoked',
        })
        const messageContext = new InboundMessageContext(revocationNotificationMessage)

        await revocationService.v1ProcessRevocationNotification(messageContext)

        expect(loggerSpy).not.toBeCalledWith('Failed to process revocation notification message', {
          error: invalidThreadFormatError,
          threadId: revocationNotificationThreadId,
        })
      })

      test('V2 allows any character in tag part of credential id', async () => {
        const loggerSpy = jest.spyOn(logger, 'warn')
        mockFunction(credentialRepository.getSingleByQuery).mockReturnValueOnce(Promise.resolve(credential))

        const credentialId = `${revocationRegistryId}::2`
        const invalidFormatError = new AriesFrameworkError(
          `Incorrect revocation notification credentialId format: \n${credentialId}\ndoes not match\n"<revocation_registry_id>::<credential_revocation_id>"`
        )

        const revocationNotificationMessage = new V2RevocationNotificationMessage({
          credentialId: credentialId,
          revocationFormat: 'indy',
          comment: 'Credenti1al has been revoked',
        })
        const messageContext = new InboundMessageContext(revocationNotificationMessage)

        await revocationService.v2ProcessRevocationNotification(messageContext)

        expect(loggerSpy).not.toBeCalledWith('Failed to process revocation notification message', {
          error: invalidFormatError,
          credentialId: credentialId,
        })
      })
    })
  })
})
