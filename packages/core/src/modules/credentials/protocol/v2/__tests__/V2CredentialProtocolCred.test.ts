/* eslint-disable @typescript-eslint/no-unused-vars */
import type { AgentContext } from '../../../../../agent'
import type { GetAgentMessageOptions } from '../../../../../storage'
import type { PlaintextMessage } from '../../../../../types'
import type { CredentialStateChangedEvent } from '../../../CredentialEvents'
import type {
  CredentialFormat,
  CredentialFormatAcceptRequestOptions,
  CredentialFormatCreateOfferOptions,
  CredentialFormatService,
} from '../../../formats'
import type { CredentialPreviewAttribute } from '../../../models/CredentialPreviewAttribute'
import type { CustomCredentialTags } from '../../../repository/CredentialExchangeRecord'

import { Subject } from 'rxjs'

import { CredoError, CredentialFormatSpec, CredentialRole } from '../../../../..'
import { getAgentConfig, getAgentContext, getMockConnection, mockFunction } from '../../../../../../tests/helpers'
import { EventEmitter } from '../../../../../agent/EventEmitter'
import { InboundMessageContext } from '../../../../../agent/models/InboundMessageContext'
import { Attachment, AttachmentData } from '../../../../../decorators/attachment/Attachment'
import { DidCommMessageRecord, DidCommMessageRole, DidCommMessageRepository } from '../../../../../storage'
import { JsonTransformer } from '../../../../../utils'
import { JsonEncoder } from '../../../../../utils/JsonEncoder'
import { AckStatus } from '../../../../common/messages/AckMessage'
import { DidExchangeState } from '../../../../connections'
import { ConnectionService } from '../../../../connections/services/ConnectionService'
import { CredentialEventTypes } from '../../../CredentialEvents'
import { credReq } from '../../../__tests__/fixtures'
import { CredentialProblemReportReason } from '../../../models/CredentialProblemReportReason'
import { CredentialState } from '../../../models/CredentialState'
import { CredentialExchangeRecord } from '../../../repository/CredentialExchangeRecord'
import { CredentialRepository } from '../../../repository/CredentialRepository'
import { V2CredentialProtocol } from '../V2CredentialProtocol'
import { V2CredentialPreview, V2ProposeCredentialMessage } from '../messages'
import { V2CredentialAckMessage } from '../messages/V2CredentialAckMessage'
import { V2CredentialProblemReportMessage } from '../messages/V2CredentialProblemReportMessage'
import { V2IssueCredentialMessage } from '../messages/V2IssueCredentialMessage'
import { V2OfferCredentialMessage } from '../messages/V2OfferCredentialMessage'
import { V2RequestCredentialMessage } from '../messages/V2RequestCredentialMessage'

// Mock classes
jest.mock('../../../repository/CredentialRepository')
jest.mock('../../../../../storage/didcomm/DidCommMessageRepository')
jest.mock('../../../../routing/services/RoutingService')
jest.mock('../../../../connections/services/ConnectionService')
jest.mock('../../../../../agent/Dispatcher')

// Mock typed object
const CredentialRepositoryMock = CredentialRepository as jest.Mock<CredentialRepository>
const DidCommMessageRepositoryMock = DidCommMessageRepository as jest.Mock<DidCommMessageRepository>
const ConnectionServiceMock = ConnectionService as jest.Mock<ConnectionService>

const credentialRepository = new CredentialRepositoryMock()
const didCommMessageRepository = new DidCommMessageRepositoryMock()
const connectionService = new ConnectionServiceMock()

const agentConfig = getAgentConfig('V2CredentialProtocolCredTest')
const eventEmitter = new EventEmitter(agentConfig.agentDependencies, new Subject())

const agentContext = getAgentContext({
  registerInstances: [
    [CredentialRepository, credentialRepository],
    [DidCommMessageRepository, didCommMessageRepository],
    [ConnectionService, connectionService],
    [EventEmitter, eventEmitter],
  ],
  agentConfig,
})

const connection = getMockConnection({
  id: '123',
  state: DidExchangeState.Completed,
})

const offerAttachment = new Attachment({
  id: 'offer-attachment-id',
  mimeType: 'application/json',
  data: new AttachmentData({
    base64:
      'eyJzY2hlbWFfaWQiOiJhYWEiLCJjcmVkX2RlZl9pZCI6IlRoN01wVGFSWlZSWW5QaWFiZHM4MVk6MzpDTDoxNzpUQUciLCJub25jZSI6Im5vbmNlIiwia2V5X2NvcnJlY3RuZXNzX3Byb29mIjp7fX0',
  }),
})

const requestAttachment = new Attachment({
  id: 'request-attachment-id',
  mimeType: 'application/json',
  data: new AttachmentData({
    base64: JsonEncoder.toBase64(credReq),
  }),
})

const credentialAttachment = new Attachment({
  id: 'credential-attachment-id',
  mimeType: 'application/json',
  data: new AttachmentData({
    base64: JsonEncoder.toBase64({
      values: {},
    }),
  }),
})

const requestFormat = new CredentialFormatSpec({
  attachmentId: 'request-attachment-id',
  format: 'hlindy/cred-filter@v2.0',
})

const proposalAttachment = new Attachment({
  id: 'proposal-attachment-id',
  data: new AttachmentData({
    json: {
      any: 'value',
    },
  }),
})

const offerFormat = new CredentialFormatSpec({
  attachmentId: 'offer-attachment-id',
  format: 'hlindy/cred-abstract@v2.0',
})

const proposalFormat = new CredentialFormatSpec({
  attachmentId: 'proposal-attachment-id',
  format: 'hlindy/cred-abstract@v2.0',
})

const credentialFormat = new CredentialFormatSpec({
  attachmentId: 'credential-attachment-id',
  format: 'hlindy/cred@v2.0',
})

const credentialProposalMessage = new V2ProposeCredentialMessage({
  formats: [proposalFormat],
  proposalAttachments: [proposalAttachment],
})
const credentialRequestMessage = new V2RequestCredentialMessage({
  formats: [requestFormat],
  requestAttachments: [requestAttachment],
})
credentialRequestMessage.setThread({ threadId: 'somethreadid' })

const credentialOfferMessage = new V2OfferCredentialMessage({
  formats: [offerFormat],
  comment: 'some comment',
  credentialPreview: new V2CredentialPreview({
    attributes: [],
  }),
  offerAttachments: [offerAttachment],
})
const credentialIssueMessage = new V2IssueCredentialMessage({
  credentialAttachments: [credentialAttachment],
  formats: [credentialFormat],
})
credentialIssueMessage.setThread({ threadId: 'somethreadid' })

const didCommMessageRecord = new DidCommMessageRecord({
  associatedRecordId: '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
  message: {} as PlaintextMessage,
  role: DidCommMessageRole.Receiver,
})

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const getAgentMessageMock = async (_agentContext: AgentContext, options: GetAgentMessageOptions<any>) => {
  if (options.messageClass === V2ProposeCredentialMessage) {
    return credentialProposalMessage
  }
  if (options.messageClass === V2OfferCredentialMessage) {
    return credentialOfferMessage
  }
  if (options.messageClass === V2RequestCredentialMessage) {
    return credentialRequestMessage
  }
  if (options.messageClass === V2IssueCredentialMessage) {
    return credentialIssueMessage
  }

  throw new CredoError('Could not find message')
}

// A record is deserialized to JSON when it's stored into the storage. We want to simulate this behaviour for `offer`
// object to test our service would behave correctly. We use type assertion for `offer` attribute to `any`.
const mockCredentialRecord = ({
  state,
  role,
  threadId,
  connectionId,
  tags,
  id,
  credentialAttributes,
}: {
  state?: CredentialState
  role?: CredentialRole
  tags?: CustomCredentialTags
  threadId?: string
  connectionId?: string
  id?: string
  credentialAttributes?: CredentialPreviewAttribute[]
} = {}) => {
  const credentialRecord = new CredentialExchangeRecord({
    id,
    credentialAttributes: credentialAttributes,
    state: state || CredentialState.OfferSent,
    role: role || CredentialRole.Issuer,
    threadId: threadId || 'thread-id',
    connectionId: connectionId ?? '123',
    credentials: [
      {
        credentialRecordType: 'test',
        credentialRecordId: '123456',
      },
    ],
    tags,
    protocolVersion: 'v2',
  })

  return credentialRecord
}

interface TestCredentialFormat extends CredentialFormat {
  formatKey: 'test'
  credentialRecordType: 'test'
}

type TestCredentialFormatService = CredentialFormatService<TestCredentialFormat>

export const testCredentialFormatService = {
  credentialRecordType: 'test',
  formatKey: 'test',
  supportsFormat: (_format: string) => true,
  createOffer: async (
    _agentContext: AgentContext,
    _options: CredentialFormatCreateOfferOptions<TestCredentialFormat>
  ) => ({
    attachment: offerAttachment,
    format: offerFormat,
  }),
  acceptRequest: async (
    _agentContext: AgentContext,
    _options: CredentialFormatAcceptRequestOptions<TestCredentialFormat>
  ) => ({ attachment: credentialAttachment, format: credentialFormat }),
  deleteCredentialById: jest.fn(),
  processCredential: jest.fn(),
  acceptOffer: () => ({ attachment: requestAttachment, format: requestFormat }),
  processRequest: jest.fn(),
} as unknown as TestCredentialFormatService

describe('credentialProtocol', () => {
  let credentialProtocol: V2CredentialProtocol

  beforeEach(async () => {
    // mock function implementations
    mockFunction(connectionService.getById).mockResolvedValue(connection)
    mockFunction(didCommMessageRepository.findAgentMessage).mockImplementation(getAgentMessageMock)
    mockFunction(didCommMessageRepository.getAgentMessage).mockImplementation(getAgentMessageMock)
    mockFunction(didCommMessageRepository.findByQuery).mockResolvedValue([
      didCommMessageRecord,
      didCommMessageRecord,
      didCommMessageRecord,
    ])

    credentialProtocol = new V2CredentialProtocol({
      credentialFormats: [testCredentialFormatService],
    })
  })

  afterEach(() => {
    jest.resetAllMocks()
  })

  describe('acceptOffer', () => {
    test(`updates state to ${CredentialState.RequestSent}`, async () => {
      const credentialRecord = mockCredentialRecord({
        state: CredentialState.OfferReceived,
        threadId: 'fd9c5ddb-ec11-4acd-bc32-540736249746',
        connectionId: 'b1e2f039-aa39-40be-8643-6ce2797b5190',
      })

      // when
      await credentialProtocol.acceptOffer(agentContext, {
        credentialRecord,
        credentialFormats: {},
      })

      // then
      expect(credentialRepository.update).toHaveBeenNthCalledWith(
        1,
        agentContext,
        expect.objectContaining({
          state: CredentialState.RequestSent,
        })
      )
    })

    test('returns credential request message base on existing credential offer message', async () => {
      // given
      const comment = 'credential request comment'

      const credentialRecord = mockCredentialRecord({
        state: CredentialState.OfferReceived,
        threadId: 'fd9c5ddb-ec11-4acd-bc32-540736249746',
        connectionId: 'b1e2f039-aa39-40be-8643-6ce2797b5190',
      })

      // when
      const { message: credentialRequest } = await credentialProtocol.acceptOffer(agentContext, {
        credentialRecord,
        comment,
      })

      // then
      expect(credentialRequest.toJSON()).toMatchObject({
        '@id': expect.any(String),
        '@type': 'https://didcomm.org/issue-credential/2.0/request-credential',
        '~thread': {
          thid: credentialRecord.threadId,
        },
        formats: [JsonTransformer.toJSON(requestFormat)],
        comment,
        'requests~attach': [JsonTransformer.toJSON(requestAttachment)],
      })
    })

    const validState = CredentialState.OfferReceived
    const invalidCredentialStates = Object.values(CredentialState).filter((state) => state !== validState)
    test(`throws an error when state transition is invalid`, async () => {
      await Promise.all(
        invalidCredentialStates.map(async (state) => {
          await expect(
            credentialProtocol.acceptOffer(agentContext, { credentialRecord: mockCredentialRecord({ state }) })
          ).rejects.toThrow(`Credential record is in invalid state ${state}. Valid states are: ${validState}.`)
        })
      )
    })
  })

  describe('processRequest', () => {
    test(`updates state to ${CredentialState.RequestReceived}, set request and returns credential record`, async () => {
      const credentialRecord = mockCredentialRecord({ state: CredentialState.OfferSent })
      const messageContext = new InboundMessageContext(credentialRequestMessage, {
        connection,
        agentContext,
      })

      // given
      mockFunction(credentialRepository.findSingleByQuery).mockResolvedValue(credentialRecord)

      // when
      const returnedCredentialRecord = await credentialProtocol.processRequest(messageContext)

      // then
      expect(credentialRepository.findSingleByQuery).toHaveBeenNthCalledWith(1, agentContext, {
        threadId: 'somethreadid',
        role: CredentialRole.Issuer,
      })
      expect(credentialRepository.update).toHaveBeenCalledTimes(1)
      expect(returnedCredentialRecord.state).toEqual(CredentialState.RequestReceived)
    })

    test(`emits stateChange event from ${CredentialState.OfferSent} to ${CredentialState.RequestReceived}`, async () => {
      const credentialRecord = mockCredentialRecord({ state: CredentialState.OfferSent })
      const messageContext = new InboundMessageContext(credentialRequestMessage, {
        connection,
        agentContext,
      })

      const eventListenerMock = jest.fn()
      eventEmitter.on<CredentialStateChangedEvent>(CredentialEventTypes.CredentialStateChanged, eventListenerMock)

      mockFunction(credentialRepository.findSingleByQuery).mockResolvedValue(credentialRecord)

      const returnedCredentialRecord = await credentialProtocol.processRequest(messageContext)

      // then
      expect(credentialRepository.findSingleByQuery).toHaveBeenNthCalledWith(1, agentContext, {
        threadId: 'somethreadid',
        role: CredentialRole.Issuer,
      })
      expect(eventListenerMock).toHaveBeenCalled()
      expect(returnedCredentialRecord.state).toEqual(CredentialState.RequestReceived)
    })

    const validState = CredentialState.OfferSent
    const invalidCredentialStates = Object.values(CredentialState).filter((state) => state !== validState)
    test(`throws an error when state transition is invalid`, async () => {
      const messageContext = new InboundMessageContext(credentialRequestMessage, {
        connection,
        agentContext,
      })

      await Promise.all(
        invalidCredentialStates.map(async (state) => {
          mockFunction(credentialRepository.findSingleByQuery).mockReturnValue(
            Promise.resolve(mockCredentialRecord({ state }))
          )
          await expect(credentialProtocol.processRequest(messageContext)).rejects.toThrow(
            `Credential record is in invalid state ${state}. Valid states are: ${validState}.`
          )
        })
      )
    })
  })

  describe('acceptRequest', () => {
    test(`updates state to ${CredentialState.CredentialIssued}`, async () => {
      const credentialRecord = mockCredentialRecord({
        state: CredentialState.RequestReceived,
        connectionId: 'b1e2f039-aa39-40be-8643-6ce2797b5190',
      })

      await credentialProtocol.acceptRequest(agentContext, {
        credentialRecord,
        comment: 'credential response comment',
      })

      // then
      expect(credentialRepository.update).toHaveBeenNthCalledWith(
        1,
        agentContext,
        expect.objectContaining({
          state: CredentialState.CredentialIssued,
        })
      )
    })

    test(`emits stateChange event from ${CredentialState.RequestReceived} to ${CredentialState.CredentialIssued}`, async () => {
      const credentialRecord = mockCredentialRecord({
        state: CredentialState.RequestReceived,
        connectionId: 'b1e2f039-aa39-40be-8643-6ce2797b5190',
      })

      const eventListenerMock = jest.fn()

      // given
      mockFunction(credentialRepository.getById).mockResolvedValue(credentialRecord)
      eventEmitter.on<CredentialStateChangedEvent>(CredentialEventTypes.CredentialStateChanged, eventListenerMock)

      // when
      await credentialProtocol.acceptRequest(agentContext, {
        credentialRecord,
        comment: 'credential response comment',
      })

      // then
      expect(eventListenerMock).toHaveBeenCalledWith({
        type: 'CredentialStateChanged',
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          previousState: CredentialState.RequestReceived,
          credentialRecord: expect.objectContaining({
            state: CredentialState.CredentialIssued,
          }),
        },
      })
    })

    test('returns credential response message base on credential request message', async () => {
      const credentialRecord = mockCredentialRecord({
        state: CredentialState.RequestReceived,
        connectionId: 'b1e2f039-aa39-40be-8643-6ce2797b5190',
      })

      // given
      mockFunction(credentialRepository.getById).mockResolvedValue(credentialRecord)
      const comment = 'credential response comment'

      // when
      const { message: credentialResponse } = await credentialProtocol.acceptRequest(agentContext, {
        comment: 'credential response comment',
        credentialRecord,
      })

      // then
      expect(credentialResponse.toJSON()).toMatchObject({
        '@id': expect.any(String),
        '@type': 'https://didcomm.org/issue-credential/2.0/issue-credential',
        '~thread': {
          thid: credentialRecord.threadId,
        },
        comment,
        formats: [JsonTransformer.toJSON(credentialFormat)],
        'credentials~attach': [JsonTransformer.toJSON(credentialAttachment)],
        '~please_ack': expect.any(Object),
      })
    })
  })

  describe('processCredential', () => {
    test('finds credential record by thread ID and saves credential attachment into the wallet', async () => {
      const credentialRecord = mockCredentialRecord({
        state: CredentialState.RequestSent,
      })

      const messageContext = new InboundMessageContext(credentialIssueMessage, {
        connection,
        agentContext,
      })

      // given
      mockFunction(credentialRepository.getSingleByQuery).mockResolvedValue(credentialRecord)

      await credentialProtocol.processCredential(messageContext)
    })
  })

  describe('acceptCredential', () => {
    test(`updates state to ${CredentialState.Done}`, async () => {
      const credentialRecord = mockCredentialRecord({
        state: CredentialState.CredentialReceived,
        threadId: 'somethreadid',
        connectionId: 'b1e2f039-aa39-40be-8643-6ce2797b5190',
      })

      // when
      await credentialProtocol.acceptCredential(agentContext, { credentialRecord })

      // then
      expect(credentialRepository.update).toHaveBeenNthCalledWith(
        1,
        agentContext,
        expect.objectContaining({
          state: CredentialState.Done,
        })
      )
    })

    test(`emits stateChange event from ${CredentialState.CredentialReceived} to ${CredentialState.Done}`, async () => {
      const credentialRecord = mockCredentialRecord({
        state: CredentialState.CredentialReceived,
        threadId: 'somethreadid',
        connectionId: 'b1e2f039-aa39-40be-8643-6ce2797b5190',
      })

      const eventListenerMock = jest.fn()
      eventEmitter.on<CredentialStateChangedEvent>(CredentialEventTypes.CredentialStateChanged, eventListenerMock)

      // when
      await credentialProtocol.acceptCredential(agentContext, { credentialRecord })

      // then
      expect(eventListenerMock).toHaveBeenCalledWith({
        type: 'CredentialStateChanged',
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          previousState: CredentialState.CredentialReceived,
          credentialRecord: expect.objectContaining({
            state: CredentialState.Done,
          }),
        },
      })
    })

    test('returns ack message base on credential issue message', async () => {
      const credentialRecord = mockCredentialRecord({
        state: CredentialState.CredentialReceived,
        threadId: 'somethreadid',
        connectionId: 'b1e2f039-aa39-40be-8643-6ce2797b5190',
      })

      // given
      mockFunction(credentialRepository.getById).mockResolvedValue(credentialRecord)

      // when
      const { message: ackMessage } = await credentialProtocol.acceptCredential(agentContext, { credentialRecord })

      // then
      expect(ackMessage.toJSON()).toMatchObject({
        '@id': expect.any(String),
        '@type': 'https://didcomm.org/issue-credential/2.0/ack',
        '~thread': {
          thid: 'somethreadid',
        },
      })
    })

    const validState = CredentialState.CredentialReceived
    const invalidCredentialStates = Object.values(CredentialState).filter((state) => state !== validState)
    test(`throws an error when state transition is invalid`, async () => {
      await Promise.all(
        invalidCredentialStates.map(async (state) => {
          await expect(
            credentialProtocol.acceptCredential(agentContext, {
              credentialRecord: mockCredentialRecord({
                state,
                threadId: 'somethreadid',
                connectionId: 'b1e2f039-aa39-40be-8643-6ce2797b5190',
              }),
            })
          ).rejects.toThrow(`Credential record is in invalid state ${state}. Valid states are: ${validState}.`)
        })
      )
    })
  })

  describe('processAck', () => {
    const credentialRequest = new V2CredentialAckMessage({
      status: AckStatus.OK,
      threadId: 'somethreadid',
    })
    const messageContext = new InboundMessageContext(credentialRequest, { agentContext, connection })

    test(`updates state to ${CredentialState.Done} and returns credential record`, async () => {
      const credentialRecord = mockCredentialRecord({
        state: CredentialState.CredentialIssued,
      })

      // given
      mockFunction(credentialRepository.getSingleByQuery).mockResolvedValue(credentialRecord)

      // when
      const returnedCredentialRecord = await credentialProtocol.processAck(messageContext)

      expect(credentialRepository.getSingleByQuery).toHaveBeenNthCalledWith(1, agentContext, {
        threadId: 'somethreadid',
        connectionId: '123',
        role: CredentialRole.Issuer,
      })

      expect(returnedCredentialRecord.state).toBe(CredentialState.Done)
    })
  })

  describe('createProblemReport', () => {
    test('returns problem report message base once get error', async () => {
      // given
      const credentialRecord = mockCredentialRecord({
        state: CredentialState.OfferReceived,
        threadId: 'somethreadid',
        connectionId: 'b1e2f039-aa39-40be-8643-6ce2797b5190',
      })
      const description = 'Indy error'
      mockFunction(credentialRepository.getById).mockResolvedValue(credentialRecord)

      // when
      const { message } = await credentialProtocol.createProblemReport(agentContext, {
        description,
        credentialRecord,
      })

      message.setThread({ threadId: 'somethreadid' })
      // then
      expect(message.toJSON()).toMatchObject({
        '@id': expect.any(String),
        '@type': 'https://didcomm.org/issue-credential/2.0/problem-report',
        '~thread': {
          thid: 'somethreadid',
        },
        description: {
          code: CredentialProblemReportReason.IssuanceAbandoned,
          en: description,
        },
      })
    })
  })

  describe('processProblemReport', () => {
    const message = new V2CredentialProblemReportMessage({
      description: {
        en: 'Indy error',
        code: CredentialProblemReportReason.IssuanceAbandoned,
      },
    })
    message.setThread({ threadId: 'somethreadid' })
    const messageContext = new InboundMessageContext(message, {
      connection,
      agentContext,
    })

    test(`updates problem report error message and returns credential record`, async () => {
      const credentialRecord = mockCredentialRecord({
        state: CredentialState.OfferReceived,
      })

      // given
      mockFunction(credentialRepository.getSingleByQuery).mockResolvedValue(credentialRecord)

      // when
      const returnedCredentialRecord = await credentialProtocol.processProblemReport(messageContext)

      // then

      expect(credentialRepository.getSingleByQuery).toHaveBeenNthCalledWith(1, agentContext, {
        threadId: 'somethreadid',
      })
      expect(credentialRepository.update).toHaveBeenCalled()
      expect(returnedCredentialRecord.errorMessage).toBe('issuance-abandoned: Indy error')
    })
  })

  describe('repository methods', () => {
    it('getById should return value from credentialRepository.getById', async () => {
      const expected = mockCredentialRecord()
      mockFunction(credentialRepository.getById).mockReturnValue(Promise.resolve(expected))
      const result = await credentialProtocol.getById(agentContext, expected.id)
      expect(credentialRepository.getById).toHaveBeenCalledWith(agentContext, expected.id)

      expect(result).toBe(expected)
    })

    it('getById should return value from credentialRepository.getSingleByQuery', async () => {
      const expected = mockCredentialRecord()
      mockFunction(credentialRepository.getSingleByQuery).mockReturnValue(Promise.resolve(expected))

      const result = await credentialProtocol.getByProperties(agentContext, {
        threadId: 'threadId',
        role: CredentialRole.Issuer,
        connectionId: 'connectionId',
      })

      expect(credentialRepository.getSingleByQuery).toHaveBeenCalledWith(agentContext, {
        threadId: 'threadId',
        role: CredentialRole.Issuer,
        connectionId: 'connectionId',
      })

      expect(result).toBe(expected)
    })

    it('findById should return value from credentialRepository.findById', async () => {
      const expected = mockCredentialRecord()
      mockFunction(credentialRepository.findById).mockReturnValue(Promise.resolve(expected))
      const result = await credentialProtocol.findById(agentContext, expected.id)
      expect(credentialRepository.findById).toHaveBeenCalledWith(agentContext, expected.id)

      expect(result).toBe(expected)
    })

    it('getAll should return value from credentialRepository.getAll', async () => {
      const expected = [mockCredentialRecord(), mockCredentialRecord()]

      mockFunction(credentialRepository.getAll).mockReturnValue(Promise.resolve(expected))
      const result = await credentialProtocol.getAll(agentContext)
      expect(credentialRepository.getAll).toHaveBeenCalledWith(agentContext)

      expect(result).toEqual(expect.arrayContaining(expected))
    })

    it('findAllByQuery should return value from credentialRepository.findByQuery', async () => {
      const expected = [mockCredentialRecord(), mockCredentialRecord()]

      mockFunction(credentialRepository.findByQuery).mockReturnValue(Promise.resolve(expected))
      const result = await credentialProtocol.findAllByQuery(agentContext, { state: CredentialState.OfferSent }, {})
      expect(credentialRepository.findByQuery).toHaveBeenCalledWith(
        agentContext,
        { state: CredentialState.OfferSent },
        {}
      )

      expect(result).toEqual(expect.arrayContaining(expected))
    })
  })

  describe('deleteCredential', () => {
    it('should call delete from repository', async () => {
      const credentialRecord = mockCredentialRecord()
      mockFunction(credentialRepository.getById).mockReturnValue(Promise.resolve(credentialRecord))

      const repositoryDeleteSpy = jest.spyOn(credentialRepository, 'delete')
      await credentialProtocol.delete(agentContext, credentialRecord)
      expect(repositoryDeleteSpy).toHaveBeenNthCalledWith(1, agentContext, credentialRecord)
    })

    it('should call deleteCredentialById in testCredentialFormatService if deleteAssociatedCredential is true', async () => {
      const deleteCredentialMock = mockFunction(testCredentialFormatService.deleteCredentialById)

      const credentialRecord = mockCredentialRecord()
      mockFunction(credentialRepository.getById).mockResolvedValue(credentialRecord)

      await credentialProtocol.delete(agentContext, credentialRecord, {
        deleteAssociatedCredentials: true,
        deleteAssociatedDidCommMessages: false,
      })

      expect(deleteCredentialMock).toHaveBeenNthCalledWith(
        1,
        agentContext,
        credentialRecord.credentials[0].credentialRecordId
      )
    })

    it('should not call deleteCredentialById in testCredentialFormatService if deleteAssociatedCredential is false', async () => {
      const deleteCredentialMock = mockFunction(testCredentialFormatService.deleteCredentialById)

      const credentialRecord = mockCredentialRecord()
      mockFunction(credentialRepository.getById).mockResolvedValue(credentialRecord)

      await credentialProtocol.delete(agentContext, credentialRecord, {
        deleteAssociatedCredentials: false,
        deleteAssociatedDidCommMessages: false,
      })

      expect(deleteCredentialMock).not.toHaveBeenCalled()
    })

    it('deleteAssociatedCredentials should default to true', async () => {
      const deleteCredentialMock = mockFunction(testCredentialFormatService.deleteCredentialById)

      const credentialRecord = mockCredentialRecord()
      mockFunction(credentialRepository.getById).mockResolvedValue(credentialRecord)

      await credentialProtocol.delete(agentContext, credentialRecord)

      expect(deleteCredentialMock).toHaveBeenNthCalledWith(
        1,
        agentContext,
        credentialRecord.credentials[0].credentialRecordId
      )
    })
    it('deleteAssociatedDidCommMessages should default to true', async () => {
      const deleteCredentialMock = mockFunction(testCredentialFormatService.deleteCredentialById)

      const credentialRecord = mockCredentialRecord()
      mockFunction(credentialRepository.getById).mockResolvedValue(credentialRecord)

      await credentialProtocol.delete(agentContext, credentialRecord)

      expect(deleteCredentialMock).toHaveBeenNthCalledWith(
        1,
        agentContext,
        credentialRecord.credentials[0].credentialRecordId
      )
      expect(didCommMessageRepository.delete).toHaveBeenCalledTimes(3)
    })
  })
})
