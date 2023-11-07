import type { ConnectionRecord } from '@aries-framework/core'

import { Agent } from '@aries-framework/core'

import { askarModule } from '../../askar/tests/helpers'
import { setupSubjectTransports, testLogger, getAgentOptions, makeConnection } from '../../core/tests'

import { waitForQuestionAnswerRecord } from './helpers'

import { QuestionAnswerModule, QuestionAnswerRole, QuestionAnswerState } from '@aries-framework/question-answer'

const modules = {
  questionAnswer: new QuestionAnswerModule(),
  askar: askarModule,
}

const bobAgentOptions = getAgentOptions(
  'Bob Question Answer',
  {
    endpoints: ['rxjs:bob'],
  },
  modules
)

const aliceAgentOptions = getAgentOptions(
  'Alice Question Answer',
  {
    endpoints: ['rxjs:alice'],
  },
  modules
)

describe('Question Answer', () => {
  let bobAgent: Agent<typeof modules>
  let aliceAgent: Agent<typeof modules>
  let aliceConnection: ConnectionRecord

  beforeEach(async () => {
    bobAgent = new Agent(bobAgentOptions)
    aliceAgent = new Agent(aliceAgentOptions)
    setupSubjectTransports([bobAgent, aliceAgent])

    await bobAgent.initialize()
    await aliceAgent.initialize()
    ;[aliceConnection] = await makeConnection(aliceAgent, bobAgent)
  })

  afterEach(async () => {
    await bobAgent.shutdown()
    await bobAgent.wallet.delete()
    await aliceAgent.shutdown()
    await aliceAgent.wallet.delete()
  })

  test('Alice sends a question and Bob answers', async () => {
    testLogger.test('Alice sends question to Bob')
    let aliceQuestionAnswerRecord = await aliceAgent.modules.questionAnswer.sendQuestion(aliceConnection.id, {
      question: 'Do you want to play?',
      validResponses: [{ text: 'Yes' }, { text: 'No' }],
    })

    testLogger.test('Bob waits for question from Alice')
    const bobQuestionAnswerRecord = await waitForQuestionAnswerRecord(bobAgent, {
      threadId: aliceQuestionAnswerRecord.threadId,
      state: QuestionAnswerState.QuestionReceived,
    })

    expect(bobQuestionAnswerRecord.questionText).toEqual('Do you want to play?')
    expect(bobQuestionAnswerRecord.validResponses).toEqual([{ text: 'Yes' }, { text: 'No' }])
    testLogger.test('Bob sends answer to Alice')
    await bobAgent.modules.questionAnswer.sendAnswer(bobQuestionAnswerRecord.id, 'Yes')

    testLogger.test('Alice waits until Bob answers')
    aliceQuestionAnswerRecord = await waitForQuestionAnswerRecord(aliceAgent, {
      threadId: aliceQuestionAnswerRecord.threadId,
      state: QuestionAnswerState.AnswerReceived,
    })

    expect(aliceQuestionAnswerRecord.response).toEqual('Yes')

    const retrievedRecord = await aliceAgent.modules.questionAnswer.findById(aliceQuestionAnswerRecord.id)
    expect(retrievedRecord).toMatchObject(
      expect.objectContaining({
        id: aliceQuestionAnswerRecord.id,
        threadId: aliceQuestionAnswerRecord.threadId,
        state: QuestionAnswerState.AnswerReceived,
        role: QuestionAnswerRole.Questioner,
      })
    )
  })
})
