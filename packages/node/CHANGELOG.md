# Changelog

## [0.5.3](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.2...v0.5.3) (2024-05-01)

**Note:** Version bump only for package @credo-ts/node

## [0.5.2](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.1...v0.5.2) (2024-04-26)

### Bug Fixes

- node-ffi-napi compatibility ([#1821](https://github.com/openwallet-foundation/credo-ts/issues/1821)) ([81d351b](https://github.com/openwallet-foundation/credo-ts/commit/81d351bc9d4d508ebfac9e7f2b2f10276ab1404a))

## [0.5.1](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.0...v0.5.1) (2024-03-28)

### Bug Fixes

- import of websocket ([#1804](https://github.com/openwallet-foundation/credo-ts/issues/1804)) ([48b31ae](https://github.com/openwallet-foundation/credo-ts/commit/48b31ae9229cd188defb0ed3b4e64b0346013f3d))

# [0.5.0](https://github.com/openwallet-foundation/credo-ts/compare/v0.4.2...v0.5.0) (2024-03-13)

**Note:** Version bump only for package @credo-ts/node

## [0.4.2](https://github.com/hyperledger/aries-framework-javascript/compare/v0.4.1...v0.4.2) (2023-10-05)

### Bug Fixes

- log and throw on WebSocket sending errors ([#1573](https://github.com/hyperledger/aries-framework-javascript/issues/1573)) ([11050af](https://github.com/hyperledger/aries-framework-javascript/commit/11050afc7965adfa9b00107ba34abfbe3afaf874))

## [0.4.1](https://github.com/hyperledger/aries-framework-javascript/compare/v0.4.0...v0.4.1) (2023-08-28)

### Bug Fixes

- **samples:** mediator wallet and http transport ([#1508](https://github.com/hyperledger/aries-framework-javascript/issues/1508)) ([04a8058](https://github.com/hyperledger/aries-framework-javascript/commit/04a80589b19725fb493e51e52a7345915b2c7341))

# [0.4.0](https://github.com/hyperledger/aries-framework-javascript/compare/v0.3.3...v0.4.0) (2023-06-03)

### Bug Fixes

- return HTTP 415 if unsupported content type ([#1313](https://github.com/hyperledger/aries-framework-javascript/issues/1313)) ([122cdde](https://github.com/hyperledger/aries-framework-javascript/commit/122cdde6982174a8e9cf70ef26a1393cb3912066))

- feat!: add data, cache and temp dirs to FileSystem (#1306) ([ff5596d](https://github.com/hyperledger/aries-framework-javascript/commit/ff5596d0631e93746494c017797d0191b6bdb0b1)), closes [#1306](https://github.com/hyperledger/aries-framework-javascript/issues/1306)

### Features

- add initial askar package ([#1211](https://github.com/hyperledger/aries-framework-javascript/issues/1211)) ([f18d189](https://github.com/hyperledger/aries-framework-javascript/commit/f18d1890546f7d66571fe80f2f3fc1fead1cd4c3))
- **anoncreds:** legacy indy proof format service ([#1283](https://github.com/hyperledger/aries-framework-javascript/issues/1283)) ([c72fd74](https://github.com/hyperledger/aries-framework-javascript/commit/c72fd7416f2c1bc0497a84036e16adfa80585e49))
- **askar:** import/export wallet support for SQLite ([#1377](https://github.com/hyperledger/aries-framework-javascript/issues/1377)) ([19cefa5](https://github.com/hyperledger/aries-framework-javascript/commit/19cefa54596a4e4848bdbe89306a884a5ce2e991))

### BREAKING CHANGES

- Agent-produced files will now be divided in different system paths depending on their nature: data, temp and cache. Previously, they were located at a single location, defaulting to a temporary directory.

If you specified a custom path in `FileSystem` object constructor, you now must provide an object containing `baseDataPath`, `baseTempPath` and `baseCachePath`. They can point to the same path, although it's recommended to specify different path to avoid future file clashes.

## [0.3.3](https://github.com/hyperledger/aries-framework-javascript/compare/v0.3.2...v0.3.3) (2023-01-18)

### Bug Fixes

- fix typing issues with typescript 4.9 ([#1214](https://github.com/hyperledger/aries-framework-javascript/issues/1214)) ([087980f](https://github.com/hyperledger/aries-framework-javascript/commit/087980f1adf3ee0bc434ca9782243a62c6124444))

## [0.3.2](https://github.com/hyperledger/aries-framework-javascript/compare/v0.3.1...v0.3.2) (2023-01-04)

**Note:** Version bump only for package @credo-ts/node

## [0.3.1](https://github.com/hyperledger/aries-framework-javascript/compare/v0.3.0...v0.3.1) (2022-12-27)

**Note:** Version bump only for package @credo-ts/node

# [0.3.0](https://github.com/hyperledger/aries-framework-javascript/compare/v0.2.5...v0.3.0) (2022-12-22)

- refactor!: add agent context (#920) ([b47cfcb](https://github.com/hyperledger/aries-framework-javascript/commit/b47cfcba1450cd1d6839bf8192d977bfe33f1bb0)), closes [#920](https://github.com/hyperledger/aries-framework-javascript/issues/920)

### Features

- add agent context provider ([#921](https://github.com/hyperledger/aries-framework-javascript/issues/921)) ([a1b1e5a](https://github.com/hyperledger/aries-framework-javascript/commit/a1b1e5a22fd4ab9ef593b5cd7b3c710afcab3142))
- specify httpinboundtransport path ([#1115](https://github.com/hyperledger/aries-framework-javascript/issues/1115)) ([03cdf39](https://github.com/hyperledger/aries-framework-javascript/commit/03cdf397b61253d2eb20694049baf74843b7ed92))

### BREAKING CHANGES

- To make AFJ multi-tenancy ready, all services and repositories have been made stateless. A new `AgentContext` is introduced that holds the current context, which is passed to each method call. The public API hasn't been affected, but due to the large impact of this change it is marked as breaking.

## [0.2.5](https://github.com/hyperledger/aries-framework-javascript/compare/v0.2.4...v0.2.5) (2022-10-13)

**Note:** Version bump only for package @credo-ts/node

## [0.2.4](https://github.com/hyperledger/aries-framework-javascript/compare/v0.2.3...v0.2.4) (2022-09-10)

**Note:** Version bump only for package @credo-ts/node

## [0.2.3](https://github.com/hyperledger/aries-framework-javascript/compare/v0.2.2...v0.2.3) (2022-08-30)

**Note:** Version bump only for package @credo-ts/node

## [0.2.2](https://github.com/hyperledger/aries-framework-javascript/compare/v0.2.1...v0.2.2) (2022-07-15)

**Note:** Version bump only for package @credo-ts/node

## [0.2.1](https://github.com/hyperledger/aries-framework-javascript/compare/v0.2.0...v0.2.1) (2022-07-08)

### Features

- initial plugin api ([#907](https://github.com/hyperledger/aries-framework-javascript/issues/907)) ([6d88aa4](https://github.com/hyperledger/aries-framework-javascript/commit/6d88aa4537ab2a9494ffea8cdfb4723cf915f291))

# [0.2.0](https://github.com/hyperledger/aries-framework-javascript/compare/v0.1.0...v0.2.0) (2022-06-24)

### Bug Fixes

- close session early if no return route ([#715](https://github.com/hyperledger/aries-framework-javascript/issues/715)) ([2e65408](https://github.com/hyperledger/aries-framework-javascript/commit/2e6540806f2d67bef16004f6e8398c5bf7a05bcf))
- **node:** allow to import node package without postgres ([#757](https://github.com/hyperledger/aries-framework-javascript/issues/757)) ([59e1058](https://github.com/hyperledger/aries-framework-javascript/commit/59e10589acee987fb46f9cbaa3583ba8dcd70b87))
- **node:** only send 500 if no headers sent yet ([#857](https://github.com/hyperledger/aries-framework-javascript/issues/857)) ([4be8f82](https://github.com/hyperledger/aries-framework-javascript/commit/4be8f82c214f99538eaa0fd0aac5a8f7a6e1dd6b))

### Features

- **core:** add support for postgres wallet type ([#699](https://github.com/hyperledger/aries-framework-javascript/issues/699)) ([83ff0f3](https://github.com/hyperledger/aries-framework-javascript/commit/83ff0f36401cbf6e95c0a1ceb9fa921a82dc6830))
- indy revocation (prover & verifier) ([#592](https://github.com/hyperledger/aries-framework-javascript/issues/592)) ([fb19ff5](https://github.com/hyperledger/aries-framework-javascript/commit/fb19ff555b7c10c9409450dcd7d385b1eddf41ac))

# 0.1.0 (2021-12-23)

### Bug Fixes

- **node:** node v12 support for is-indy-installed ([#542](https://github.com/hyperledger/aries-framework-javascript/issues/542)) ([17e9157](https://github.com/hyperledger/aries-framework-javascript/commit/17e9157479d6bba90c2a94bce64697d7f65fac96))

### Features

- add multiple inbound transports ([#433](https://github.com/hyperledger/aries-framework-javascript/issues/433)) ([56cb9f2](https://github.com/hyperledger/aries-framework-javascript/commit/56cb9f2202deb83b3c133905f21651bfefcb63f7))
- break out indy wallet, better indy handling ([#396](https://github.com/hyperledger/aries-framework-javascript/issues/396)) ([9f1a4a7](https://github.com/hyperledger/aries-framework-javascript/commit/9f1a4a754a61573ce3fee78d52615363c7e25d58))
- **core:** connection-less issuance and verification ([#359](https://github.com/hyperledger/aries-framework-javascript/issues/359)) ([fb46ade](https://github.com/hyperledger/aries-framework-javascript/commit/fb46ade4bc2dd4f3b63d4194bb170d2f329562b7))
- **core:** support multiple indy ledgers ([#474](https://github.com/hyperledger/aries-framework-javascript/issues/474)) ([47149bc](https://github.com/hyperledger/aries-framework-javascript/commit/47149bc5742456f4f0b75e0944ce276972e645b8))
- **node:** add http and ws inbound transport ([#392](https://github.com/hyperledger/aries-framework-javascript/issues/392)) ([34a6ff2](https://github.com/hyperledger/aries-framework-javascript/commit/34a6ff2699197b9d525422a0a405e241582a476c))
- **node:** add is-indy-installed command ([#510](https://github.com/hyperledger/aries-framework-javascript/issues/510)) ([e50b821](https://github.com/hyperledger/aries-framework-javascript/commit/e50b821343970d299a4cacdcba3a051893524ed6))
