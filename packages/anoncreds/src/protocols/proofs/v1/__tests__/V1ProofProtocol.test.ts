import type { CustomProofTags, AgentConfig, AgentContext, ProofStateChangedEvent } from '../../../../../../core/src'

import { Subject } from 'rxjs'

import {
  ProofRole,
  DidExchangeState,
  Attachment,
  AttachmentData,
  ProofState,
  ProofExchangeRecord,
  InboundMessageContext,
  ProofEventTypes,
  PresentationProblemReportReason,
  EventEmitter,
} from '../../../../../../core/src'
import { ConnectionService } from '../../../../../../core/src/modules/connections/services/ConnectionService'
import { ProofRepository } from '../../../../../../core/src/modules/proofs/repository/ProofRepository'
import { DidCommMessageRepository } from '../../../../../../core/src/storage/didcomm/DidCommMessageRepository'
import { getMockConnection, getAgentConfig, getAgentContext, mockFunction } from '../../../../../../core/tests'
import { LegacyIndyProofFormatService } from '../../../../formats/LegacyIndyProofFormatService'
import { V1ProofProtocol } from '../V1ProofProtocol'
import { INDY_PROOF_REQUEST_ATTACHMENT_ID, V1RequestPresentationMessage } from '../messages'
import { V1PresentationProblemReportMessage } from '../messages/V1PresentationProblemReportMessage'

// Mock classes
jest.mock('../../../../../../core/src/modules/proofs/repository/ProofRepository')
jest.mock('../../../../formats/LegacyIndyProofFormatService')
jest.mock('../../../../../../core/src/storage/didcomm/DidCommMessageRepository')
jest.mock('../../../../../../core/src/modules/connections/services/ConnectionService')

// Mock typed object
const ProofRepositoryMock = ProofRepository as jest.Mock<ProofRepository>
const connectionServiceMock = ConnectionService as jest.Mock<ConnectionService>
const didCommMessageRepositoryMock = DidCommMessageRepository as jest.Mock<DidCommMessageRepository>
const indyProofFormatServiceMock = LegacyIndyProofFormatService as jest.Mock<LegacyIndyProofFormatService>

const proofRepository = new ProofRepositoryMock()
const connectionService = new connectionServiceMock()
const didCommMessageRepository = new didCommMessageRepositoryMock()
const indyProofFormatService = new indyProofFormatServiceMock()

const connection = getMockConnection({
  id: '123',
  state: DidExchangeState.Completed,
})

const requestAttachment = new Attachment({
  id: INDY_PROOF_REQUEST_ATTACHMENT_ID,
  mimeType: 'application/json',
  data: new AttachmentData({
    base64:
      'eyJuYW1lIjogIlByb29mIHJlcXVlc3QiLCAibm9uX3Jldm9rZWQiOiB7ImZyb20iOiAxNjQwOTk1MTk5LCAidG8iOiAxNjQwOTk1MTk5fSwgIm5vbmNlIjogIjEiLCAicmVxdWVzdGVkX2F0dHJpYnV0ZXMiOiB7ImFkZGl0aW9uYWxQcm9wMSI6IHsibmFtZSI6ICJmYXZvdXJpdGVEcmluayIsICJub25fcmV2b2tlZCI6IHsiZnJvbSI6IDE2NDA5OTUxOTksICJ0byI6IDE2NDA5OTUxOTl9LCAicmVzdHJpY3Rpb25zIjogW3siY3JlZF9kZWZfaWQiOiAiV2dXeHF6dHJOb29HOTJSWHZ4U1RXdjozOkNMOjIwOnRhZyJ9XX19LCAicmVxdWVzdGVkX3ByZWRpY2F0ZXMiOiB7fSwgInZlcnNpb24iOiAiMS4wIn0=',
  }),
})

// A record is deserialized to JSON when it's stored into the storage. We want to simulate this behaviour for `offer`
// object to test our service would behave correctly. We use type assertion for `offer` attribute to `any`.
const mockProofExchangeRecord = ({
  state,
  role,
  threadId,
  connectionId,
  tags,
  id,
}: {
  state?: ProofState
  role?: ProofRole
  requestMessage?: V1RequestPresentationMessage
  tags?: CustomProofTags
  threadId?: string
  connectionId?: string
  id?: string
} = {}) => {
  const requestPresentationMessage = new V1RequestPresentationMessage({
    comment: 'some comment',
    requestAttachments: [requestAttachment],
  })

  const proofRecord = new ProofExchangeRecord({
    protocolVersion: 'v1',
    id,
    state: state || ProofState.RequestSent,
    role: role || ProofRole.Verifier,
    threadId: threadId ?? requestPresentationMessage.id,
    connectionId: connectionId ?? '123',
    tags,
  })

  return proofRecord
}

describe('V1ProofProtocol', () => {
  let eventEmitter: EventEmitter
  let agentConfig: AgentConfig
  let agentContext: AgentContext
  let proofProtocol: V1ProofProtocol

  beforeEach(() => {
    // real objects
    agentConfig = getAgentConfig('V1ProofProtocolTest')
    eventEmitter = new EventEmitter(agentConfig.agentDependencies, new Subject())

    agentContext = getAgentContext({
      registerInstances: [
        [ProofRepository, proofRepository],
        [DidCommMessageRepository, didCommMessageRepository],
        [EventEmitter, eventEmitter],
        [ConnectionService, connectionService],
      ],
      agentConfig,
    })
    proofProtocol = new V1ProofProtocol({ indyProofFormat: indyProofFormatService })
  })

  describe('processRequest', () => {
    let presentationRequest: V1RequestPresentationMessage
    let messageContext: InboundMessageContext<V1RequestPresentationMessage>

    beforeEach(() => {
      presentationRequest = new V1RequestPresentationMessage({
        comment: 'abcd',
        requestAttachments: [requestAttachment],
      })
      messageContext = new InboundMessageContext(presentationRequest, {
        connection,
        agentContext,
      })
    })

    test(`creates and return proof record in ${ProofState.PresentationReceived} state with offer, without thread ID`, async () => {
      const repositorySaveSpy = jest.spyOn(proofRepository, 'save')

      // when
      const returnedProofExchangeRecord = await proofProtocol.processRequest(messageContext)

      // then
      const expectedProofExchangeRecord = {
        type: ProofExchangeRecord.type,
        id: expect.any(String),
        createdAt: expect.any(Date),
        state: ProofState.RequestReceived,
        threadId: presentationRequest.id,
        connectionId: connection.id,
      }
      expect(repositorySaveSpy).toHaveBeenCalledTimes(1)
      const [[, createdProofExchangeRecord]] = repositorySaveSpy.mock.calls
      expect(createdProofExchangeRecord).toMatchObject(expectedProofExchangeRecord)
      expect(returnedProofExchangeRecord).toMatchObject(expectedProofExchangeRecord)
    })

    test(`emits stateChange event with ${ProofState.RequestReceived}`, async () => {
      const eventListenerMock = jest.fn()
      eventEmitter.on<ProofStateChangedEvent>(ProofEventTypes.ProofStateChanged, eventListenerMock)

      // when
      await proofProtocol.processRequest(messageContext)

      // then
      expect(eventListenerMock).toHaveBeenCalledWith({
        type: 'ProofStateChanged',
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          previousState: null,
          proofRecord: expect.objectContaining({
            state: ProofState.RequestReceived,
          }),
        },
      })
    })
  })

  describe('createProblemReport', () => {
    const threadId = 'fd9c5ddb-ec11-4acd-bc32-540736249746'
    let proof: ProofExchangeRecord

    beforeEach(() => {
      proof = mockProofExchangeRecord({
        state: ProofState.RequestReceived,
        threadId,
        connectionId: 'b1e2f039-aa39-40be-8643-6ce2797b5190',
      })
    })

    test('returns problem report message base once get error', async () => {
      // given
      mockFunction(proofRepository.getById).mockReturnValue(Promise.resolve(proof))

      // when
      const presentationProblemReportMessage = await new V1PresentationProblemReportMessage({
        description: {
          en: 'Indy error',
          code: PresentationProblemReportReason.Abandoned,
        },
      })

      presentationProblemReportMessage.setThread({ threadId })
      // then
      expect(presentationProblemReportMessage.toJSON()).toMatchObject({
        '@id': expect.any(String),
        '@type': 'https://didcomm.org/present-proof/1.0/problem-report',
        '~thread': {
          thid: 'fd9c5ddb-ec11-4acd-bc32-540736249746',
        },
      })
    })
  })

  describe('processProblemReport', () => {
    let proof: ProofExchangeRecord
    let messageContext: InboundMessageContext<V1PresentationProblemReportMessage>

    beforeEach(() => {
      proof = mockProofExchangeRecord({
        state: ProofState.RequestReceived,
      })

      const presentationProblemReportMessage = new V1PresentationProblemReportMessage({
        description: {
          en: 'Indy error',
          code: PresentationProblemReportReason.Abandoned,
        },
      })
      presentationProblemReportMessage.setThread({ threadId: 'somethreadid' })
      messageContext = new InboundMessageContext(presentationProblemReportMessage, {
        connection,
        agentContext,
      })
    })

    test(`updates problem report error message and returns proof record`, async () => {
      const repositoryUpdateSpy = jest.spyOn(proofRepository, 'update')

      // given
      mockFunction(proofRepository.getSingleByQuery).mockReturnValue(Promise.resolve(proof))

      // when
      const returnedCredentialRecord = await proofProtocol.processProblemReport(messageContext)

      // then
      const expectedCredentialRecord = {
        errorMessage: 'abandoned: Indy error',
      }
      expect(proofRepository.getSingleByQuery).toHaveBeenNthCalledWith(1, agentContext, {
        threadId: 'somethreadid',
      })
      expect(repositoryUpdateSpy).toHaveBeenCalledTimes(1)
      const [[, updatedCredentialRecord]] = repositoryUpdateSpy.mock.calls
      expect(updatedCredentialRecord).toMatchObject(expectedCredentialRecord)
      expect(returnedCredentialRecord).toMatchObject(expectedCredentialRecord)
    })
  })
})
