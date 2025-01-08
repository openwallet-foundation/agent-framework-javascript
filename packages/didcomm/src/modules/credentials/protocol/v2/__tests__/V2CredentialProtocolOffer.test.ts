/* eslint-disable @typescript-eslint/no-unused-vars */
import type { AgentContext } from '@credo-ts/core/src/agent'
import type { CredentialStateChangedEvent } from '../../../CredentialEvents'
import type { CredentialFormat, CredentialFormatCreateOfferOptions, CredentialFormatService } from '../../../formats'
import type { CreateCredentialOfferOptions } from '../../CredentialProtocolOptions'

import { Subject } from 'rxjs'

import { getAgentConfig, getAgentContext, getMockConnection, mockFunction } from '@credo-ts/core/tests/helpers'
import { EventEmitter } from '@credo-ts/core/src/agent/EventEmitter'
import { JsonTransformer } from '@credo-ts/core/src/utils'
import { Dispatcher } from '../../../../../Dispatcher'
import { Attachment, AttachmentData } from '../../../../../decorators/attachment/Attachment'
import { InboundMessageContext } from '../../../../../models'
import { DidCommMessageRepository } from '../../../../../repository'
import { ConnectionService, DidExchangeState } from '../../../../connections'
import { RoutingService } from '../../../../routing/services/RoutingService'
import { CredentialEventTypes } from '../../../CredentialEvents'
import { CredentialFormatSpec } from '../../../models'
import { CredentialState } from '../../../models/CredentialState'
import { CredentialExchangeRecord } from '../../../repository/CredentialExchangeRecord'
import { CredentialRepository } from '../../../repository/CredentialRepository'
import { V2CredentialProtocol } from '../V2CredentialProtocol'
import { V2CredentialPreview } from '../messages'
import { V2OfferCredentialMessage } from '../messages/V2OfferCredentialMessage'

const offerFormat = new CredentialFormatSpec({
  attachmentId: 'offer-attachment-id',
  format: 'hlindy/cred-abstract@v2.0',
})

const offerAttachment = new Attachment({
  id: 'offer-attachment-id',
  mimeType: 'application/json',
  data: new AttachmentData({
    base64:
      'eyJzY2hlbWFfaWQiOiJhYWEiLCJjcmVkX2RlZl9pZCI6IlRoN01wVGFSWlZSWW5QaWFiZHM4MVk6MzpDTDoxNzpUQUciLCJub25jZSI6Im5vbmNlIiwia2V5X2NvcnJlY3RuZXNzX3Byb29mIjp7fX0',
  }),
})

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
    previewAttributes: [
      {
        mimeType: 'text/plain',
        name: 'name',
        value: 'John',
      },
      {
        mimeType: 'text/plain',
        name: 'age',
        value: '99',
      },
    ],
  }),
  acceptRequest: jest.fn(),
  deleteCredentialById: jest.fn(),
  processCredential: jest.fn(),
  acceptOffer: jest.fn(),
  processRequest: jest.fn(),
  processOffer: jest.fn(),
} as unknown as TestCredentialFormatService

// Mock classes
jest.mock('../../../repository/CredentialRepository')
jest.mock('../../../../../storage/didcomm/DidCommMessageRepository')
jest.mock('../../../../routing/services/RoutingService')
jest.mock('../../../../connections/services/ConnectionService')
jest.mock('../../../../../agent/Dispatcher')

// Mock typed object
const CredentialRepositoryMock = CredentialRepository as jest.Mock<CredentialRepository>
const DidCommMessageRepositoryMock = DidCommMessageRepository as jest.Mock<DidCommMessageRepository>
const RoutingServiceMock = RoutingService as jest.Mock<RoutingService>
const ConnectionServiceMock = ConnectionService as jest.Mock<ConnectionService>
const DispatcherMock = Dispatcher as jest.Mock<Dispatcher>

const credentialRepository = new CredentialRepositoryMock()
const didCommMessageRepository = new DidCommMessageRepositoryMock()
const routingService = new RoutingServiceMock()
const dispatcher = new DispatcherMock()
const connectionService = new ConnectionServiceMock()

const agentConfig = getAgentConfig('V2CredentialProtocolOfferTest')
const eventEmitter = new EventEmitter(agentConfig.agentDependencies, new Subject())

const agentContext = getAgentContext({
  registerInstances: [
    [CredentialRepository, credentialRepository],
    [DidCommMessageRepository, didCommMessageRepository],
    [RoutingService, routingService],
    [Dispatcher, dispatcher],
    [ConnectionService, connectionService],
    [EventEmitter, eventEmitter],
  ],
  agentConfig,
})

const connectionRecord = getMockConnection({
  id: '123',
  state: DidExchangeState.Completed,
})

describe('V2CredentialProtocolOffer', () => {
  let credentialProtocol: V2CredentialProtocol

  beforeEach(async () => {
    // mock function implementations
    mockFunction(connectionService.getById).mockResolvedValue(connectionRecord)

    credentialProtocol = new V2CredentialProtocol({
      credentialFormats: [testCredentialFormatService],
    })
  })

  afterEach(() => {
    jest.resetAllMocks()
  })

  describe('createOffer', () => {
    const offerOptions: CreateCredentialOfferOptions<[TestCredentialFormatService]> = {
      comment: 'some comment',
      connectionRecord,
      credentialFormats: {
        test: {},
      },
    }

    test(`creates credential record in ${CredentialState.OfferSent} state with offer, thread ID`, async () => {
      // when
      await credentialProtocol.createOffer(agentContext, offerOptions)

      // then
      expect(credentialRepository.save).toHaveBeenNthCalledWith(
        1,
        agentContext,
        expect.objectContaining({
          type: CredentialExchangeRecord.type,
          id: expect.any(String),
          createdAt: expect.any(Date),
          state: CredentialState.OfferSent,
          connectionId: connectionRecord.id,
        })
      )
    })

    test(`emits stateChange event with a new credential in ${CredentialState.OfferSent} state`, async () => {
      const eventListenerMock = jest.fn()
      eventEmitter.on<CredentialStateChangedEvent>(CredentialEventTypes.CredentialStateChanged, eventListenerMock)

      await credentialProtocol.createOffer(agentContext, offerOptions)

      expect(eventListenerMock).toHaveBeenCalledWith({
        type: 'CredentialStateChanged',
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          previousState: null,
          credentialRecord: expect.objectContaining({
            state: CredentialState.OfferSent,
          }),
        },
      })
    })

    test('returns credential offer message', async () => {
      const { message: credentialOffer } = await credentialProtocol.createOffer(agentContext, offerOptions)

      expect(credentialOffer.toJSON()).toMatchObject({
        '@id': expect.any(String),
        '@type': 'https://didcomm.org/issue-credential/2.0/offer-credential',
        comment: 'some comment',
        credential_preview: {
          '@type': 'https://didcomm.org/issue-credential/2.0/credential-preview',
          attributes: [
            {
              name: 'name',
              'mime-type': 'text/plain',
              value: 'John',
            },
            {
              name: 'age',
              'mime-type': 'text/plain',
              value: '99',
            },
          ],
        },
        formats: [JsonTransformer.toJSON(offerFormat)],
        'offers~attach': [JsonTransformer.toJSON(offerAttachment)],
      })
    })
  })

  describe('processOffer', () => {
    const credentialOfferMessage = new V2OfferCredentialMessage({
      formats: [offerFormat],
      comment: 'some comment',
      credentialPreview: new V2CredentialPreview({
        attributes: [],
      }),
      offerAttachments: [offerAttachment],
    })

    const messageContext = new InboundMessageContext(credentialOfferMessage, {
      agentContext,
      connection: connectionRecord,
    })

    test(`creates and return credential record in ${CredentialState.OfferReceived} state with offer, thread ID`, async () => {
      // when
      await credentialProtocol.processOffer(messageContext)

      // then
      expect(credentialRepository.save).toHaveBeenNthCalledWith(
        1,
        agentContext,
        expect.objectContaining({
          type: CredentialExchangeRecord.type,
          id: expect.any(String),
          createdAt: expect.any(Date),
          threadId: credentialOfferMessage.id,
          connectionId: connectionRecord.id,
          state: CredentialState.OfferReceived,
        })
      )
    })

    test(`emits stateChange event with ${CredentialState.OfferReceived}`, async () => {
      const eventListenerMock = jest.fn()
      eventEmitter.on<CredentialStateChangedEvent>(CredentialEventTypes.CredentialStateChanged, eventListenerMock)

      // when
      await credentialProtocol.processOffer(messageContext)

      // then
      expect(eventListenerMock).toHaveBeenCalledWith({
        type: 'CredentialStateChanged',
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          previousState: null,
          credentialRecord: expect.objectContaining({
            state: CredentialState.OfferReceived,
          }),
        },
      })
    })
  })
})
