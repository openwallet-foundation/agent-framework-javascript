# Changelog

## [0.5.3](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.2...v0.5.3) (2024-05-01)

**Note:** Version bump only for package @credo-ts/react-native

## [0.5.2](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.1...v0.5.2) (2024-04-26)

**Note:** Version bump only for package @credo-ts/react-native

## [0.5.1](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.0...v0.5.1) (2024-03-28)

**Note:** Version bump only for package @credo-ts/react-native

# [0.5.0](https://github.com/openwallet-foundation/credo-ts/compare/v0.4.2...v0.5.0) (2024-03-13)

### Bug Fixes

- **rn:** more flexible react native version ([#1760](https://github.com/openwallet-foundation/credo-ts/issues/1760)) ([af82918](https://github.com/openwallet-foundation/credo-ts/commit/af82918f5401bad113dfc32fc903d981e4389c4e))

## [0.4.2](https://github.com/hyperledger/aries-framework-javascript/compare/v0.4.1...v0.4.2) (2023-10-05)

**Note:** Version bump only for package @credo-ts/react-native

## [0.4.1](https://github.com/hyperledger/aries-framework-javascript/compare/v0.4.0...v0.4.1) (2023-08-28)

### Bug Fixes

- check if URL already encoded ([#1485](https://github.com/hyperledger/aries-framework-javascript/issues/1485)) ([38a0578](https://github.com/hyperledger/aries-framework-javascript/commit/38a0578011896cfcf217713d34f285cd381ad72c))
- encode tails url ([#1479](https://github.com/hyperledger/aries-framework-javascript/issues/1479)) ([fd190b9](https://github.com/hyperledger/aries-framework-javascript/commit/fd190b96106ca4916539d96ff6c4ecef7833f148))

# [0.4.0](https://github.com/hyperledger/aries-framework-javascript/compare/v0.3.3...v0.4.0) (2023-06-03)

- feat!: add data, cache and temp dirs to FileSystem (#1306) ([ff5596d](https://github.com/hyperledger/aries-framework-javascript/commit/ff5596d0631e93746494c017797d0191b6bdb0b1)), closes [#1306](https://github.com/hyperledger/aries-framework-javascript/issues/1306)

### Features

- add fetch indy schema method ([#1290](https://github.com/hyperledger/aries-framework-javascript/issues/1290)) ([1d782f5](https://github.com/hyperledger/aries-framework-javascript/commit/1d782f54bbb4abfeb6b6db6cd4f7164501b6c3d9))
- add initial askar package ([#1211](https://github.com/hyperledger/aries-framework-javascript/issues/1211)) ([f18d189](https://github.com/hyperledger/aries-framework-javascript/commit/f18d1890546f7d66571fe80f2f3fc1fead1cd4c3))
- **anoncreds:** legacy indy proof format service ([#1283](https://github.com/hyperledger/aries-framework-javascript/issues/1283)) ([c72fd74](https://github.com/hyperledger/aries-framework-javascript/commit/c72fd7416f2c1bc0497a84036e16adfa80585e49))
- **askar:** import/export wallet support for SQLite ([#1377](https://github.com/hyperledger/aries-framework-javascript/issues/1377)) ([19cefa5](https://github.com/hyperledger/aries-framework-javascript/commit/19cefa54596a4e4848bdbe89306a884a5ce2e991))

### BREAKING CHANGES

- Agent-produced files will now be divided in different system paths depending on their nature: data, temp and cache. Previously, they were located at a single location, defaulting to a temporary directory.

If you specified a custom path in `FileSystem` object constructor, you now must provide an object containing `baseDataPath`, `baseTempPath` and `baseCachePath`. They can point to the same path, although it's recommended to specify different path to avoid future file clashes.

## [0.3.3](https://github.com/hyperledger/aries-framework-javascript/compare/v0.3.2...v0.3.3) (2023-01-18)

### Bug Fixes

- fix typing issues with typescript 4.9 ([#1214](https://github.com/hyperledger/aries-framework-javascript/issues/1214)) ([087980f](https://github.com/hyperledger/aries-framework-javascript/commit/087980f1adf3ee0bc434ca9782243a62c6124444))

### Features

- **indy-sdk:** add indy-sdk package ([#1200](https://github.com/hyperledger/aries-framework-javascript/issues/1200)) ([9933b35](https://github.com/hyperledger/aries-framework-javascript/commit/9933b35a6aa4524caef8a885e71b742cd0d7186b))

## [0.3.2](https://github.com/hyperledger/aries-framework-javascript/compare/v0.3.1...v0.3.2) (2023-01-04)

**Note:** Version bump only for package @credo-ts/react-native

## [0.3.1](https://github.com/hyperledger/aries-framework-javascript/compare/v0.3.0...v0.3.1) (2022-12-27)

**Note:** Version bump only for package @credo-ts/react-native

# [0.3.0](https://github.com/hyperledger/aries-framework-javascript/compare/v0.2.5...v0.3.0) (2022-12-22)

### Bug Fixes

- peer dependency for rn bbs signatures ([#785](https://github.com/hyperledger/aries-framework-javascript/issues/785)) ([c751e28](https://github.com/hyperledger/aries-framework-javascript/commit/c751e286aa11a1d2b9424ae23de5647efc5d536f))
- **react-native:** move bbs dep to bbs package ([#1076](https://github.com/hyperledger/aries-framework-javascript/issues/1076)) ([c6762bb](https://github.com/hyperledger/aries-framework-javascript/commit/c6762bbe9d64ac5220915af3425d493e505dcc2c))

### Features

- bbs createKey, sign and verify ([#684](https://github.com/hyperledger/aries-framework-javascript/issues/684)) ([5f91738](https://github.com/hyperledger/aries-framework-javascript/commit/5f91738337fac1efbbb4597e7724791e542f0762))
- **dids:** add did registrar ([#953](https://github.com/hyperledger/aries-framework-javascript/issues/953)) ([93f3c93](https://github.com/hyperledger/aries-framework-javascript/commit/93f3c93310f9dae032daa04a920b7df18e2f8a65))
- jsonld-credential support ([#718](https://github.com/hyperledger/aries-framework-javascript/issues/718)) ([ea34c47](https://github.com/hyperledger/aries-framework-javascript/commit/ea34c4752712efecf3367c5a5fc4b06e66c1e9d7))

## [0.2.5](https://github.com/hyperledger/aries-framework-javascript/compare/v0.2.4...v0.2.5) (2022-10-13)

**Note:** Version bump only for package @credo-ts/react-native

## [0.2.4](https://github.com/hyperledger/aries-framework-javascript/compare/v0.2.3...v0.2.4) (2022-09-10)

**Note:** Version bump only for package @credo-ts/react-native

## [0.2.3](https://github.com/hyperledger/aries-framework-javascript/compare/v0.2.2...v0.2.3) (2022-08-30)

**Note:** Version bump only for package @credo-ts/react-native

## [0.2.2](https://github.com/hyperledger/aries-framework-javascript/compare/v0.2.1...v0.2.2) (2022-07-15)

**Note:** Version bump only for package @credo-ts/react-native

## [0.2.1](https://github.com/hyperledger/aries-framework-javascript/compare/v0.2.0...v0.2.1) (2022-07-08)

**Note:** Version bump only for package @credo-ts/react-native

# [0.2.0](https://github.com/hyperledger/aries-framework-javascript/compare/v0.1.0...v0.2.0) (2022-06-24)

- chore!: update indy-sdk-react-native version to 0.2.0 (#754) ([4146778](https://github.com/hyperledger/aries-framework-javascript/commit/414677828be7f6c08fa02905d60d6555dc4dd438)), closes [#754](https://github.com/hyperledger/aries-framework-javascript/issues/754)

### Features

- add generic did resolver ([#554](https://github.com/hyperledger/aries-framework-javascript/issues/554)) ([8e03f35](https://github.com/hyperledger/aries-framework-javascript/commit/8e03f35f8e1cd02dac4df02d1f80f2c5a921dfef))
- add update assistant for storage migrations ([#690](https://github.com/hyperledger/aries-framework-javascript/issues/690)) ([c9bff93](https://github.com/hyperledger/aries-framework-javascript/commit/c9bff93cfac43c4ae2cbcad1f96c1a74cde39602))
- delete credential from wallet ([#691](https://github.com/hyperledger/aries-framework-javascript/issues/691)) ([abec3a2](https://github.com/hyperledger/aries-framework-javascript/commit/abec3a2c95815d1c54b22a6370222f024eefb060))
- indy revocation (prover & verifier) ([#592](https://github.com/hyperledger/aries-framework-javascript/issues/592)) ([fb19ff5](https://github.com/hyperledger/aries-framework-javascript/commit/fb19ff555b7c10c9409450dcd7d385b1eddf41ac))
- ledger connections happen on agent init in background ([#580](https://github.com/hyperledger/aries-framework-javascript/issues/580)) ([61695ce](https://github.com/hyperledger/aries-framework-javascript/commit/61695ce7737ffef363b60e341ae5b0e67e0e2c90))
- support wallet key rotation ([#672](https://github.com/hyperledger/aries-framework-javascript/issues/672)) ([5cd1598](https://github.com/hyperledger/aries-framework-javascript/commit/5cd1598b496a832c82f35a363fabe8f408abd439))

### BREAKING CHANGES

- indy-sdk-react-native has been updated to 0.2.0. The new version now depends on libindy version 1.16 and requires you to update the binaries in your react-native application. See the [indy-sdk-react-native](https://github.com/hyperledger/indy-sdk-react-native) repository for instructions on how to get the latest binaries for both iOS and Android.

# 0.1.0 (2021-12-23)

### Bug Fixes

- **core:** using query-string to parse URLs ([#457](https://github.com/hyperledger/aries-framework-javascript/issues/457)) ([78e5057](https://github.com/hyperledger/aries-framework-javascript/commit/78e505750557f296cc72ef19c0edd8db8e1eaa7d))
- monorepo release issues ([#386](https://github.com/hyperledger/aries-framework-javascript/issues/386)) ([89a628f](https://github.com/hyperledger/aries-framework-javascript/commit/89a628f7c3ea9e5730d2ba5720819ac6283ee404))

### Features

- **core:** d_m invitation parameter and invitation image ([#456](https://github.com/hyperledger/aries-framework-javascript/issues/456)) ([f92c322](https://github.com/hyperledger/aries-framework-javascript/commit/f92c322b97be4a4867a82c3a35159d6068951f0b))
- **core:** ledger module registerPublicDid implementation ([#398](https://github.com/hyperledger/aries-framework-javascript/issues/398)) ([5f2d512](https://github.com/hyperledger/aries-framework-javascript/commit/5f2d5126baed2ff58268c38755c2dbe75a654947))
