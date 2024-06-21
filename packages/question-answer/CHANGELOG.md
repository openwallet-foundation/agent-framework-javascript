# Changelog

## [0.5.3](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.2...v0.5.3) (2024-05-01)

**Note:** Version bump only for package @credo-ts/question-answer

## [0.5.2](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.1...v0.5.2) (2024-04-26)

**Note:** Version bump only for package @credo-ts/question-answer

## [0.5.1](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.0...v0.5.1) (2024-03-28)

**Note:** Version bump only for package @credo-ts/question-answer

# [0.5.0](https://github.com/openwallet-foundation/credo-ts/compare/v0.4.2...v0.5.0) (2024-03-13)

### Features

- **openid4vc:** persistance and events ([#1793](https://github.com/openwallet-foundation/credo-ts/issues/1793)) ([f4c386a](https://github.com/openwallet-foundation/credo-ts/commit/f4c386a6ccf8adb829cad30b81d524e6ffddb029))

## [0.4.2](https://github.com/hyperledger/aries-framework-javascript/compare/v0.4.1...v0.4.2) (2023-10-05)

**Note:** Version bump only for package @credo-ts/question-answer

## [0.4.1](https://github.com/hyperledger/aries-framework-javascript/compare/v0.4.0...v0.4.1) (2023-08-28)

### Features

- oob without handhsake improvements and routing ([#1511](https://github.com/hyperledger/aries-framework-javascript/issues/1511)) ([9e69cf4](https://github.com/hyperledger/aries-framework-javascript/commit/9e69cf441a75bf7a3c5556cf59e730ee3fce8c28))

# [0.4.0](https://github.com/hyperledger/aries-framework-javascript/compare/v0.3.3...v0.4.0) (2023-06-03)

### Bug Fixes

- thread id improvements ([#1311](https://github.com/hyperledger/aries-framework-javascript/issues/1311)) ([229ed1b](https://github.com/hyperledger/aries-framework-javascript/commit/229ed1b9540ca0c9380b5cca6c763fefd6628960))

- refactor!: remove Dispatcher.registerMessageHandler (#1354) ([78ecf1e](https://github.com/hyperledger/aries-framework-javascript/commit/78ecf1ed959c9daba1c119d03f4596f1db16c57c)), closes [#1354](https://github.com/hyperledger/aries-framework-javascript/issues/1354)

### Features

- outbound message send via session ([#1335](https://github.com/hyperledger/aries-framework-javascript/issues/1335)) ([582c711](https://github.com/hyperledger/aries-framework-javascript/commit/582c711728db12b7d38a0be2e9fa78dbf31b34c6))

### BREAKING CHANGES

- `Dispatcher.registerMessageHandler` has been removed in favour of `MessageHandlerRegistry.registerMessageHandler`. If you want to register message handlers in an extension module, you can use directly `agentContext.dependencyManager.registerMessageHandlers`.

Signed-off-by: Ariel Gentile <gentilester@gmail.com>

## [0.3.3](https://github.com/hyperledger/aries-framework-javascript/compare/v0.3.2...v0.3.3) (2023-01-18)

### Bug Fixes

- fix typing issues with typescript 4.9 ([#1214](https://github.com/hyperledger/aries-framework-javascript/issues/1214)) ([087980f](https://github.com/hyperledger/aries-framework-javascript/commit/087980f1adf3ee0bc434ca9782243a62c6124444))

### Features

- **indy-sdk:** add indy-sdk package ([#1200](https://github.com/hyperledger/aries-framework-javascript/issues/1200)) ([9933b35](https://github.com/hyperledger/aries-framework-javascript/commit/9933b35a6aa4524caef8a885e71b742cd0d7186b))

## [0.3.2](https://github.com/hyperledger/aries-framework-javascript/compare/v0.3.1...v0.3.2) (2023-01-04)

**Note:** Version bump only for package @credo-ts/question-answer

## [0.3.1](https://github.com/hyperledger/aries-framework-javascript/compare/v0.3.0...v0.3.1) (2022-12-27)

**Note:** Version bump only for package @credo-ts/question-answer

# [0.3.0](https://github.com/hyperledger/aries-framework-javascript/compare/v0.2.5...v0.3.0) (2022-12-22)

- refactor!: rename Handler to MessageHandler (#1161) ([5e48696](https://github.com/hyperledger/aries-framework-javascript/commit/5e48696ec16d88321f225628e6cffab243718b4c)), closes [#1161](https://github.com/hyperledger/aries-framework-javascript/issues/1161)
- feat(action-menu)!: move to separate package (#1049) ([e0df0d8](https://github.com/hyperledger/aries-framework-javascript/commit/e0df0d884b1a7816c7c638406606e45f6e169ff4)), closes [#1049](https://github.com/hyperledger/aries-framework-javascript/issues/1049)
- feat(question-answer)!: separate logic to a new module (#1040) ([97d3073](https://github.com/hyperledger/aries-framework-javascript/commit/97d3073aa9300900740c3e8aee8233d38849293d)), closes [#1040](https://github.com/hyperledger/aries-framework-javascript/issues/1040)

### BREAKING CHANGES

- Handler has been renamed to MessageHandler to be more descriptive, along with related types and methods. This means:

Handler is now MessageHandler
HandlerInboundMessage is now MessageHandlerInboundMessage
Dispatcher.registerHandler is now Dispatcher.registerMessageHandlers

- action-menu module has been removed from the core and moved to a separate package. To integrate it in an Agent instance, it can be injected in constructor like this:

```ts
const agent = new Agent({
  config: {
    /* config */
  },
  dependencies: agentDependencies,
  modules: {
    actionMenu: new ActionMenuModule(),
    /* other custom modules */
  },
})
```

Then, module API can be accessed in `agent.modules.actionMenu`.

- question-answer module has been removed from the core and moved to a separate package. To integrate it in an Agent instance, it can be injected in constructor like this:

```ts
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
```

Then, module API can be accessed in `agent.modules.questionAnswer`.
