<p align="center">
  <br />
  <img
    alt="Hyperledger Aries logo"
    src="https://raw.githubusercontent.com/openwallet-foundation/credo-ts/aa31131825e3331dc93694bc58414d955dcb1129/images/aries-logo.png"
    height="250px"
  />
</p>
<h1 align="center"><b>Credo Question Answer Module</b></h1>
<p align="center">
  <a
    href="https://raw.githubusercontent.com/openwallet-foundation/credo-ts/main/LICENSE"
    ><img
      alt="License"
      src="https://img.shields.io/badge/License-Apache%202.0-blue.svg"
  /></a>
  <a href="https://www.typescriptlang.org/"
    ><img
      alt="typescript"
      src="https://img.shields.io/badge/%3C%2F%3E-TypeScript-%230074c1.svg"
  /></a>
    <a href="https://www.npmjs.com/package/@credo-ts/question-answer"
    ><img
      alt="@credo-ts/question-answer version"
      src="https://img.shields.io/npm/v/@credo-ts/question-answer"
  /></a>

</p>
<br />

Question Answer module for [Credo](https://github.com/openwallet-foundation/credo-ts.git). Implements [Aries RFC 0113](https://github.com/hyperledger/aries-rfcs/blob/1795d5c2d36f664f88f5e8045042ace8e573808c/features/0113-question-answer/README.md).

### Quick start

In order for this module to work, we have to inject it into the agent to access agent functionality. See the example for more information.

### Example of usage

```ts
import { QuestionAnswerModule } from '@credo-ts/question-answer'

const agent = new Agent({
  config: {
    /* config */
  },
  dependencies: agentDependencies,
  modules: {
    questionAnswer: new QuestionAnswerModule(),
    /* other custom modules */
  },
})

await agent.initialize()

// To send a question to a given connection
await agent.modules.questionAnswer.sendQuestion(connectionId, {
  question: 'Do you want to play?',
  validResponses: [{ text: 'Yes' }, { text: 'No' }],
})

// Questions and Answers are received as QuestionAnswerStateChangedEvent

// To send an answer related to a given question answer record
await agent.modules.questionAnswer.sendAnswer(questionAnswerRecordId, 'Yes')
```
