import type { AgentConfig, AgentContext, Repository, Wallet } from '@credo-ts/core'
import type { QuestionAnswerStateChangedEvent, ValidResponse } from '@credo-ts/question-answer'

import { EventEmitter } from '@credo-ts/core'
import { InboundMessageContext, DidExchangeState } from '@credo-ts/didcomm'
import { agentDependencies } from '@credo-ts/node'
import { Subject } from 'rxjs'

import { InMemoryWallet } from '../../../../tests/InMemoryWallet'
import { getAgentConfig, getAgentContext, getMockConnection, mockFunction } from '../../../core/tests/helpers'

import {
  QuestionAnswerRecord,
  QuestionAnswerRepository,
  QuestionAnswerEventTypes,
  QuestionAnswerRole,
  QuestionAnswerService,
  QuestionAnswerState,
  QuestionMessage,
  AnswerMessage,
} from '@credo-ts/question-answer'

jest.mock('../repository/QuestionAnswerRepository')
const QuestionAnswerRepositoryMock = QuestionAnswerRepository as jest.Mock<QuestionAnswerRepository>

describe('QuestionAnswerService', () => {
  const mockConnectionRecord = getMockConnection({
    id: 'd3849ac3-c981-455b-a1aa-a10bea6cead8',
    did: 'did:sov:C2SsBf5QUQpqSAQfhu3sd2',
    state: DidExchangeState.Completed,
  })

  let wallet: Wallet
  let agentConfig: AgentConfig
  let questionAnswerRepository: Repository<QuestionAnswerRecord>
  let questionAnswerService: QuestionAnswerService
  let eventEmitter: EventEmitter
  let agentContext: AgentContext

  const mockQuestionAnswerRecord = (options: {
    questionText: string
    questionDetail?: string
    connectionId: string
    role: QuestionAnswerRole
    signatureRequired: boolean
    state: QuestionAnswerState
    threadId: string
    validResponses: ValidResponse[]
  }) => {
    return new QuestionAnswerRecord({
      questionText: options.questionText,
      questionDetail: options.questionDetail,
      connectionId: options.connectionId,
      role: options.role,
      signatureRequired: options.signatureRequired,
      state: options.state,
      threadId: options.threadId,
      validResponses: options.validResponses,
    })
  }

  beforeAll(async () => {
    agentConfig = getAgentConfig('QuestionAnswerServiceTest')
    wallet = new InMemoryWallet()
    agentContext = getAgentContext()
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    await wallet.createAndOpen(agentConfig.walletConfig!)
  })

  beforeEach(async () => {
    questionAnswerRepository = new QuestionAnswerRepositoryMock()
    eventEmitter = new EventEmitter(agentDependencies, new Subject())
    questionAnswerService = new QuestionAnswerService(questionAnswerRepository, eventEmitter, agentConfig.logger)
  })

  afterAll(async () => {
    await wallet.delete()
  })

  describe('create question', () => {
    it(`emits a question with question text, valid responses, and question answer record`, async () => {
      const eventListenerMock = jest.fn()
      eventEmitter.on<QuestionAnswerStateChangedEvent>(
        QuestionAnswerEventTypes.QuestionAnswerStateChanged,
        eventListenerMock
      )

      const questionMessage = new QuestionMessage({
        questionText: 'Alice, are you on the phone with Bob?',
        signatureRequired: false,
        validResponses: [{ text: 'Yes' }, { text: 'No' }],
      })

      await questionAnswerService.createQuestion(agentContext, mockConnectionRecord.id, {
        question: questionMessage.questionText,
        validResponses: questionMessage.validResponses,
      })

      expect(eventListenerMock).toHaveBeenCalledWith({
        type: 'QuestionAnswerStateChanged',
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          previousState: null,
          questionAnswerRecord: expect.objectContaining({
            connectionId: mockConnectionRecord.id,
            questionText: questionMessage.questionText,
            role: QuestionAnswerRole.Questioner,
            state: QuestionAnswerState.QuestionSent,
            validResponses: questionMessage.validResponses,
          }),
        },
      })
    })
  })
  describe('create answer', () => {
    let mockRecord: QuestionAnswerRecord

    beforeAll(() => {
      mockRecord = mockQuestionAnswerRecord({
        questionText: 'Alice, are you on the phone with Bob?',
        connectionId: mockConnectionRecord.id,
        role: QuestionAnswerRole.Responder,
        signatureRequired: false,
        state: QuestionAnswerState.QuestionReceived,
        threadId: '123',
        validResponses: [{ text: 'Yes' }, { text: 'No' }],
      })
    })

    it(`throws an error when invalid response is provided`, async () => {
      expect(questionAnswerService.createAnswer(agentContext, mockRecord, 'Maybe')).rejects.toThrowError(
        `Response does not match valid responses`
      )
    })

    it(`emits an answer with a valid response and question answer record`, async () => {
      const eventListenerMock = jest.fn()
      eventEmitter.on<QuestionAnswerStateChangedEvent>(
        QuestionAnswerEventTypes.QuestionAnswerStateChanged,
        eventListenerMock
      )

      mockFunction(questionAnswerRepository.findSingleByQuery).mockReturnValue(Promise.resolve(mockRecord))

      await questionAnswerService.createAnswer(agentContext, mockRecord, 'Yes')

      expect(eventListenerMock).toHaveBeenCalledWith({
        type: 'QuestionAnswerStateChanged',
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          previousState: QuestionAnswerState.QuestionReceived,
          questionAnswerRecord: expect.objectContaining({
            connectionId: mockConnectionRecord.id,
            role: QuestionAnswerRole.Responder,
            state: QuestionAnswerState.AnswerSent,
            response: 'Yes',
          }),
        },
      })
    })
  })

  describe('processReceiveQuestion', () => {
    let mockRecord: QuestionAnswerRecord

    beforeAll(() => {
      mockRecord = mockQuestionAnswerRecord({
        questionText: 'Alice, are you on the phone with Bob?',
        connectionId: mockConnectionRecord.id,
        role: QuestionAnswerRole.Responder,
        signatureRequired: false,
        state: QuestionAnswerState.QuestionReceived,
        threadId: '123',
        validResponses: [{ text: 'Yes' }, { text: 'No' }],
      })
    })

    it('creates record when no previous question with that thread exists', async () => {
      const questionMessage = new QuestionMessage({
        questionText: 'Alice, are you on the phone with Bob?',
        validResponses: [{ text: 'Yes' }, { text: 'No' }],
      })

      const messageContext = new InboundMessageContext(questionMessage, {
        agentContext,
        connection: mockConnectionRecord,
      })

      const questionAnswerRecord = await questionAnswerService.processReceiveQuestion(messageContext)

      expect(questionAnswerRecord).toMatchObject(
        expect.objectContaining({
          role: QuestionAnswerRole.Responder,
          state: QuestionAnswerState.QuestionReceived,
          threadId: questionMessage.id,
          questionText: 'Alice, are you on the phone with Bob?',
          validResponses: [{ text: 'Yes' }, { text: 'No' }],
        })
      )
    })

    it(`throws an error when question from the same thread exists `, async () => {
      mockFunction(questionAnswerRepository.findSingleByQuery).mockReturnValue(Promise.resolve(mockRecord))

      const questionMessage = new QuestionMessage({
        id: '123',
        questionText: 'Alice, are you on the phone with Bob?',
        validResponses: [{ text: 'Yes' }, { text: 'No' }],
      })

      const messageContext = new InboundMessageContext(questionMessage, {
        agentContext,
        connection: mockConnectionRecord,
      })

      expect(questionAnswerService.processReceiveQuestion(messageContext)).rejects.toThrowError(
        `Question answer record with thread Id ${questionMessage.id} already exists.`
      )
      jest.resetAllMocks()
    })
  })

  describe('receiveAnswer', () => {
    let mockRecord: QuestionAnswerRecord

    beforeAll(() => {
      mockRecord = mockQuestionAnswerRecord({
        questionText: 'Alice, are you on the phone with Bob?',
        connectionId: mockConnectionRecord.id,
        role: QuestionAnswerRole.Questioner,
        signatureRequired: false,
        state: QuestionAnswerState.QuestionReceived,
        threadId: '123',
        validResponses: [{ text: 'Yes' }, { text: 'No' }],
      })
    })

    it('updates state and emits event when valid response is received', async () => {
      mockRecord.state = QuestionAnswerState.QuestionSent
      mockFunction(questionAnswerRepository.findSingleByQuery).mockReturnValue(Promise.resolve(mockRecord))

      const answerMessage = new AnswerMessage({
        response: 'Yes',
        threadId: '123',
      })

      const messageContext = new InboundMessageContext(answerMessage, {
        agentContext,
        connection: mockConnectionRecord,
      })

      const questionAnswerRecord = await questionAnswerService.receiveAnswer(messageContext)

      expect(questionAnswerRecord).toMatchObject(
        expect.objectContaining({
          role: QuestionAnswerRole.Questioner,
          state: QuestionAnswerState.AnswerReceived,
          threadId: '123',
          questionText: 'Alice, are you on the phone with Bob?',
          validResponses: [{ text: 'Yes' }, { text: 'No' }],
        })
      )
      jest.resetAllMocks()
    })

    it(`throws an error when no existing question is found`, async () => {
      const answerMessage = new AnswerMessage({
        response: 'Yes',
        threadId: '123',
      })

      const messageContext = new InboundMessageContext(answerMessage, {
        agentContext,
        connection: mockConnectionRecord,
      })

      expect(questionAnswerService.receiveAnswer(messageContext)).rejects.toThrowError(
        `Question Answer record with thread Id ${answerMessage.threadId} not found.`
      )
    })

    it(`throws an error when record is in invalid state`, async () => {
      mockRecord.state = QuestionAnswerState.AnswerReceived
      mockFunction(questionAnswerRepository.findSingleByQuery).mockReturnValue(Promise.resolve(mockRecord))

      const answerMessage = new AnswerMessage({
        response: 'Yes',
        threadId: '123',
      })

      const messageContext = new InboundMessageContext(answerMessage, {
        agentContext,
        connection: mockConnectionRecord,
      })

      expect(questionAnswerService.receiveAnswer(messageContext)).rejects.toThrowError(
        `Question answer record is in invalid state ${mockRecord.state}. Valid states are: ${QuestionAnswerState.QuestionSent}`
      )
      jest.resetAllMocks()
    })

    it(`throws an error when record is in invalid role`, async () => {
      mockRecord.state = QuestionAnswerState.QuestionSent
      mockRecord.role = QuestionAnswerRole.Responder
      mockFunction(questionAnswerRepository.findSingleByQuery).mockReturnValue(Promise.resolve(mockRecord))

      const answerMessage = new AnswerMessage({
        response: 'Yes',
        threadId: '123',
      })

      const messageContext = new InboundMessageContext(answerMessage, {
        agentContext,
        connection: mockConnectionRecord,
      })

      expect(questionAnswerService.receiveAnswer(messageContext)).rejects.toThrowError(
        `Invalid question answer record role ${mockRecord.role}, expected is ${QuestionAnswerRole.Questioner}`
      )
    })
    jest.resetAllMocks()
  })
})
