import type { QuestionAnswerStateChangedEvent } from '../QuestionAnswerEvents'
import type { ValidResponse } from '../models'
import type { AgentContext, InboundMessageContext, Query, QueryOptions } from '@credo-ts/core'

import { CredoError, EventEmitter, inject, injectable, InjectionSymbols, Logger } from '@credo-ts/core'

import { QuestionAnswerEventTypes } from '../QuestionAnswerEvents'
import { QuestionAnswerRole } from '../QuestionAnswerRole'
import { AnswerMessage, QuestionMessage } from '../messages'
import { QuestionAnswerState } from '../models'
import { QuestionAnswerRepository, QuestionAnswerRecord } from '../repository'

@injectable()
export class QuestionAnswerService {
  private questionAnswerRepository: QuestionAnswerRepository
  private eventEmitter: EventEmitter
  private logger: Logger

  public constructor(
    questionAnswerRepository: QuestionAnswerRepository,
    eventEmitter: EventEmitter,
    @inject(InjectionSymbols.Logger) logger: Logger
  ) {
    this.questionAnswerRepository = questionAnswerRepository
    this.eventEmitter = eventEmitter
    this.logger = logger
  }
  /**
   * Create a question message and a new QuestionAnswer record for the questioner role
   *
   * @param question text for question message
   * @param details optional details for question message
   * @param connectionId connection for QuestionAnswer record
   * @param validResponses array of valid responses for question
   * @returns question message and QuestionAnswer record
   */
  public async createQuestion(
    agentContext: AgentContext,
    connectionId: string,
    config: {
      question: string
      validResponses: ValidResponse[]
      detail?: string
    }
  ) {
    const questionMessage = new QuestionMessage({
      questionText: config.question,
      questionDetail: config?.detail,
      signatureRequired: false,
      validResponses: config.validResponses,
    })

    const questionAnswerRecord = await this.createRecord({
      questionText: questionMessage.questionText,
      questionDetail: questionMessage.questionDetail,
      threadId: questionMessage.threadId,
      connectionId: connectionId,
      role: QuestionAnswerRole.Questioner,
      signatureRequired: false,
      state: QuestionAnswerState.QuestionSent,
      validResponses: questionMessage.validResponses,
    })

    await this.questionAnswerRepository.save(agentContext, questionAnswerRecord)

    this.eventEmitter.emit<QuestionAnswerStateChangedEvent>(agentContext, {
      type: QuestionAnswerEventTypes.QuestionAnswerStateChanged,
      payload: { previousState: null, questionAnswerRecord },
    })

    return { questionMessage, questionAnswerRecord }
  }

  /**
   * receive question message and create record for responder role
   *
   * @param messageContext the message context containing a question message
   * @returns QuestionAnswer record
   */
  public async processReceiveQuestion(
    messageContext: InboundMessageContext<QuestionMessage>
  ): Promise<QuestionAnswerRecord> {
    const { message: questionMessage } = messageContext

    this.logger.debug(`Receiving question message with id ${questionMessage.id}`)

    const connection = messageContext.assertReadyConnection()
    const questionRecord = await this.findByThreadAndConnectionId(
      messageContext.agentContext,
      connection.id,
      questionMessage.id
    )
    if (questionRecord) {
      throw new CredoError(`Question answer record with thread Id ${questionMessage.id} already exists.`)
    }
    const questionAnswerRecord = await this.createRecord({
      questionText: questionMessage.questionText,
      questionDetail: questionMessage.questionDetail,
      connectionId: connection?.id,
      threadId: questionMessage.threadId,
      role: QuestionAnswerRole.Responder,
      signatureRequired: false,
      state: QuestionAnswerState.QuestionReceived,
      validResponses: questionMessage.validResponses,
    })

    await this.questionAnswerRepository.save(messageContext.agentContext, questionAnswerRecord)

    this.eventEmitter.emit<QuestionAnswerStateChangedEvent>(messageContext.agentContext, {
      type: QuestionAnswerEventTypes.QuestionAnswerStateChanged,
      payload: { previousState: null, questionAnswerRecord },
    })

    return questionAnswerRecord
  }

  /**
   * create answer message, check that response is valid
   *
   * @param questionAnswerRecord record containing question and valid responses
   * @param response response used in answer message
   * @returns answer message and QuestionAnswer record
   */
  public async createAnswer(agentContext: AgentContext, questionAnswerRecord: QuestionAnswerRecord, response: string) {
    const answerMessage = new AnswerMessage({ response: response, threadId: questionAnswerRecord.threadId })

    questionAnswerRecord.assertState(QuestionAnswerState.QuestionReceived)

    questionAnswerRecord.response = response

    if (questionAnswerRecord.validResponses.some((e) => e.text === response)) {
      await this.updateState(agentContext, questionAnswerRecord, QuestionAnswerState.AnswerSent)
    } else {
      throw new CredoError(`Response does not match valid responses`)
    }
    return { answerMessage, questionAnswerRecord }
  }

  /**
   * receive answer as questioner
   *
   * @param messageContext the message context containing an answer message message
   * @returns QuestionAnswer record
   */
  public async receiveAnswer(messageContext: InboundMessageContext<AnswerMessage>): Promise<QuestionAnswerRecord> {
    const { message: answerMessage } = messageContext

    this.logger.debug(`Receiving answer message with id ${answerMessage.id}`)

    const connection = messageContext.assertReadyConnection()
    const questionAnswerRecord = await this.findByThreadAndConnectionId(
      messageContext.agentContext,
      connection.id,
      answerMessage.threadId
    )
    if (!questionAnswerRecord) {
      throw new CredoError(`Question Answer record with thread Id ${answerMessage.threadId} not found.`)
    }
    questionAnswerRecord.assertState(QuestionAnswerState.QuestionSent)
    questionAnswerRecord.assertRole(QuestionAnswerRole.Questioner)

    questionAnswerRecord.response = answerMessage.response

    await this.updateState(messageContext.agentContext, questionAnswerRecord, QuestionAnswerState.AnswerReceived)

    return questionAnswerRecord
  }

  /**
   * Update the record to a new state and emit an state changed event. Also updates the record
   * in storage.
   *
   * @param questionAnswerRecord The question answer record to update the state for
   * @param newState The state to update to
   *
   */
  private async updateState(
    agentContext: AgentContext,
    questionAnswerRecord: QuestionAnswerRecord,
    newState: QuestionAnswerState
  ) {
    const previousState = questionAnswerRecord.state
    questionAnswerRecord.state = newState
    await this.questionAnswerRepository.update(agentContext, questionAnswerRecord)

    this.eventEmitter.emit<QuestionAnswerStateChangedEvent>(agentContext, {
      type: QuestionAnswerEventTypes.QuestionAnswerStateChanged,
      payload: {
        previousState,
        questionAnswerRecord: questionAnswerRecord,
      },
    })
  }

  private async createRecord(options: {
    questionText: string
    questionDetail?: string
    connectionId: string
    role: QuestionAnswerRole
    signatureRequired: boolean
    state: QuestionAnswerState
    threadId: string
    validResponses: ValidResponse[]
  }): Promise<QuestionAnswerRecord> {
    const questionMessageRecord = new QuestionAnswerRecord({
      questionText: options.questionText,
      questionDetail: options.questionDetail,
      connectionId: options.connectionId,
      threadId: options.threadId,
      role: options.role,
      signatureRequired: options.signatureRequired,
      state: options.state,
      validResponses: options.validResponses,
    })

    return questionMessageRecord
  }

  /**
   * Retrieve a question answer record by connection id and thread id
   *
   * @param connectionId The connection id
   * @param threadId The thread id
   * @throws {RecordNotFoundError} If no record is found
   * @throws {RecordDuplicateError} If multiple records are found
   * @returns The question answer record
   */
  public getByThreadAndConnectionId(
    agentContext: AgentContext,
    connectionId: string,
    threadId: string
  ): Promise<QuestionAnswerRecord> {
    return this.questionAnswerRepository.getSingleByQuery(agentContext, {
      connectionId,
      threadId,
    })
  }

  /**
   * Retrieve a question answer record by thread id
   *
   * @param connectionId The connection id
   * @param threadId The thread id
   * @returns The question answer record or null if not found
   */
  public findByThreadAndConnectionId(
    agentContext: AgentContext,
    connectionId: string,
    threadId: string
  ): Promise<QuestionAnswerRecord | null> {
    return this.questionAnswerRepository.findSingleByQuery(agentContext, {
      connectionId,
      threadId,
    })
  }

  /**
   * Retrieve a question answer record by id
   *
   * @param questionAnswerId The questionAnswer record id
   * @throws {RecordNotFoundError} If no record is found
   * @return The question answer record
   *
   */
  public getById(agentContext: AgentContext, questionAnswerId: string): Promise<QuestionAnswerRecord> {
    return this.questionAnswerRepository.getById(agentContext, questionAnswerId)
  }

  /**
   * Retrieve a question answer record by id
   *
   * @param questionAnswerId The questionAnswer record id
   * @return The question answer record or null if not found
   *
   */
  public findById(agentContext: AgentContext, questionAnswerId: string): Promise<QuestionAnswerRecord | null> {
    return this.questionAnswerRepository.findById(agentContext, questionAnswerId)
  }

  /**
   * Retrieve a question answer record by id
   *
   * @param questionAnswerId The questionAnswer record id
   * @return The question answer record or null if not found
   *
   */
  public getAll(agentContext: AgentContext) {
    return this.questionAnswerRepository.getAll(agentContext)
  }

  public async findAllByQuery(
    agentContext: AgentContext,
    query: Query<QuestionAnswerRecord>,
    queryOptions?: QueryOptions
  ) {
    return this.questionAnswerRepository.findByQuery(agentContext, query, queryOptions)
  }
}
