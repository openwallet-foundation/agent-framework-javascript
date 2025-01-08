# Changelog

## 0.6.0

### Patch Changes

- Updated dependencies [14673b1]
- Updated dependencies [607659a]
- Updated dependencies [5f08bc6]
  - @credo-ts/core@0.6.0

## 0.5.13

### Patch Changes

- Updated dependencies [595c3d6]
  - @credo-ts/core@0.5.13

## 0.5.12

### Patch Changes

- 9756a4a: feat: add direct ecdh-es jwe encryption/decryption
- Updated dependencies [3c85565]
- Updated dependencies [3c85565]
- Updated dependencies [7d51fcb]
- Updated dependencies [9756a4a]
  - @credo-ts/core@0.5.12

## 0.5.11

### Patch Changes

- @credo-ts/core@0.5.11

## 0.5.10

### Patch Changes

- Updated dependencies [fa62b74]
  - @credo-ts/core@0.5.10

## 0.5.9

### Patch Changes

- @credo-ts/core@0.5.9

## 0.5.8

### Patch Changes

- Updated dependencies [3819eb2]
- Updated dependencies [15d0a54]
- Updated dependencies [a5235e7]
  - @credo-ts/core@0.5.8

## 0.5.7

### Patch Changes

- Updated dependencies [352383f]
- Updated dependencies [1044c9d]
  - @credo-ts/core@0.5.7

## 0.5.6

### Patch Changes

- 66e696d: Fix build issue causing error with importing packages in 0.5.5 release
- Updated dependencies [66e696d]
  - @credo-ts/core@0.5.6

## 0.5.5

### Patch Changes

- 482a630: - feat: allow serving dids from did record (#1856)
  - fix: set created at for anoncreds records (#1862)
  - feat: add goal to public api for credential and proof (#1867)
  - fix(oob): only reuse connection if enabled (#1868)
  - fix: issuer id query anoncreds w3c (#1870)
  - feat: sd-jwt issuance without holder binding (#1871)
  - chore: update oid4vci deps (#1873)
  - fix: query for qualified/unqualified forms in revocation notification (#1866)
  - fix: wrong schema id is stored for credentials (#1884)
  - fix: process credential or proof problem report message related to connectionless or out of band exchange (#1859)
  - fix: unqualified indy revRegDefId in migration (#1887)
  - feat: verify SD-JWT Token status list and SD-JWT VC fixes (#1872)
  - fix(anoncreds): combine creds into one proof (#1893)
  - fix: AnonCreds proof requests with unqualified dids (#1891)
  - fix: WebSocket priority in Message Pick Up V2 (#1888)
  - fix: anoncreds predicate only proof with unqualified dids (#1907)
  - feat: add pagination params to storage service (#1883)
  - feat: add message handler middleware and fallback (#1894)
- Updated dependencies [3239ef3]
- Updated dependencies [d548fa4]
- Updated dependencies [482a630]
  - @credo-ts/core@0.5.5

## [0.5.3](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.2...v0.5.3) (2024-05-01)

**Note:** Version bump only for package @credo-ts/askar

## [0.5.2](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.1...v0.5.2) (2024-04-26)

### Bug Fixes

- node-ffi-napi compatibility ([#1821](https://github.com/openwallet-foundation/credo-ts/issues/1821)) ([81d351b](https://github.com/openwallet-foundation/credo-ts/commit/81d351bc9d4d508ebfac9e7f2b2f10276ab1404a))

## [0.5.1](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.0...v0.5.1) (2024-03-28)

**Note:** Version bump only for package @credo-ts/askar

# [0.5.0](https://github.com/openwallet-foundation/credo-ts/compare/v0.4.2...v0.5.0) (2024-03-13)

### Features

- add support for key type k256 ([#1722](https://github.com/openwallet-foundation/credo-ts/issues/1722)) ([22d5bff](https://github.com/openwallet-foundation/credo-ts/commit/22d5bffc939f6644f324f6ddba4c8269212e9dc4))
- **openid4vc:** persistance and events ([#1793](https://github.com/openwallet-foundation/credo-ts/issues/1793)) ([f4c386a](https://github.com/openwallet-foundation/credo-ts/commit/f4c386a6ccf8adb829cad30b81d524e6ffddb029))
- optional backup on storage migration ([#1745](https://github.com/openwallet-foundation/credo-ts/issues/1745)) ([81ff63c](https://github.com/openwallet-foundation/credo-ts/commit/81ff63ccf7c71eccf342899d298a780d66045534))
- **tenants:** support for tenant storage migration ([#1747](https://github.com/openwallet-foundation/credo-ts/issues/1747)) ([12c617e](https://github.com/openwallet-foundation/credo-ts/commit/12c617efb45d20fda8965b9b4da24c92e975c9a2))

## [0.4.2](https://github.com/hyperledger/aries-framework-javascript/compare/v0.4.1...v0.4.2) (2023-10-05)

### Bug Fixes

- **askar:** throw error if imported wallet exists ([#1593](https://github.com/hyperledger/aries-framework-javascript/issues/1593)) ([c2bb2a5](https://github.com/hyperledger/aries-framework-javascript/commit/c2bb2a52f10add35de883c9a27716db01b9028df))
- update tsyringe for ts 5 support ([#1588](https://github.com/hyperledger/aries-framework-javascript/issues/1588)) ([296955b](https://github.com/hyperledger/aries-framework-javascript/commit/296955b3a648416ac6b502da05a10001920af222))

## [0.4.1](https://github.com/hyperledger/aries-framework-javascript/compare/v0.4.0...v0.4.1) (2023-08-28)

### Bug Fixes

- **askar:** in memory wallet creation ([#1498](https://github.com/hyperledger/aries-framework-javascript/issues/1498)) ([4a158e6](https://github.com/hyperledger/aries-framework-javascript/commit/4a158e64b97595be0733d4277c28c462bd47c908))

### Features

- support askar profiles for multi-tenancy ([#1538](https://github.com/hyperledger/aries-framework-javascript/issues/1538)) ([e448a2a](https://github.com/hyperledger/aries-framework-javascript/commit/e448a2a58dddff2cdf80c4549ea2d842a54b43d1))

# [0.4.0](https://github.com/hyperledger/aries-framework-javascript/compare/v0.3.3...v0.4.0) (2023-06-03)

### Bug Fixes

- **askar:** anoncrypt messages unpacking ([#1332](https://github.com/hyperledger/aries-framework-javascript/issues/1332)) ([1c6aeae](https://github.com/hyperledger/aries-framework-javascript/commit/1c6aeae31ac57e83f4059f3dba35ccb1ca36926e))
- **askar:** custom error handling ([#1372](https://github.com/hyperledger/aries-framework-javascript/issues/1372)) ([c72ba14](https://github.com/hyperledger/aries-framework-javascript/commit/c72ba149bad3a4596f5818b28516f6286b9088bf))
- **askar:** default key derivation method ([#1420](https://github.com/hyperledger/aries-framework-javascript/issues/1420)) ([7b59629](https://github.com/hyperledger/aries-framework-javascript/commit/7b5962917488cfd0c5adc170d3c3fc64aa82ef2c))
- **askar:** generate nonce suitable for anoncreds ([#1295](https://github.com/hyperledger/aries-framework-javascript/issues/1295)) ([ecce0a7](https://github.com/hyperledger/aries-framework-javascript/commit/ecce0a71578f45f55743198a1f3699bd257dc74b))
- imports from core ([#1303](https://github.com/hyperledger/aries-framework-javascript/issues/1303)) ([3e02227](https://github.com/hyperledger/aries-framework-javascript/commit/3e02227a7b23677e9886eb1c03d1a3ec154947a9))
- issuance with unqualified identifiers ([#1431](https://github.com/hyperledger/aries-framework-javascript/issues/1431)) ([de90caf](https://github.com/hyperledger/aries-framework-javascript/commit/de90cafb8d12b7a940f881184cd745c4b5043cbc))
- seed and private key validation and return type in registrars ([#1324](https://github.com/hyperledger/aries-framework-javascript/issues/1324)) ([c0e5339](https://github.com/hyperledger/aries-framework-javascript/commit/c0e5339edfa32df92f23fb9c920796b4b59adf52))
- set updateAt on records when updating a record ([#1272](https://github.com/hyperledger/aries-framework-javascript/issues/1272)) ([2669d7d](https://github.com/hyperledger/aries-framework-javascript/commit/2669d7dd3d7c0ddfd1108dfd65e6115dd3418500))
- small issues with migration and WAL files ([#1443](https://github.com/hyperledger/aries-framework-javascript/issues/1443)) ([83cf387](https://github.com/hyperledger/aries-framework-javascript/commit/83cf387fa52bb51d8adb2d5fedc5111994d4dde1))
- small updates to cheqd module and demo ([#1439](https://github.com/hyperledger/aries-framework-javascript/issues/1439)) ([61daf0c](https://github.com/hyperledger/aries-framework-javascript/commit/61daf0cb27de80a5e728e2e9dad13d729baf476c))

- feat!: add data, cache and temp dirs to FileSystem (#1306) ([ff5596d](https://github.com/hyperledger/aries-framework-javascript/commit/ff5596d0631e93746494c017797d0191b6bdb0b1)), closes [#1306](https://github.com/hyperledger/aries-framework-javascript/issues/1306)

### Features

- 0.4.0 migration script ([#1392](https://github.com/hyperledger/aries-framework-javascript/issues/1392)) ([bc5455f](https://github.com/hyperledger/aries-framework-javascript/commit/bc5455f7b42612a2b85e504bc6ddd36283a42bfa))
- add initial askar package ([#1211](https://github.com/hyperledger/aries-framework-javascript/issues/1211)) ([f18d189](https://github.com/hyperledger/aries-framework-javascript/commit/f18d1890546f7d66571fe80f2f3fc1fead1cd4c3))
- **anoncreds:** legacy indy proof format service ([#1283](https://github.com/hyperledger/aries-framework-javascript/issues/1283)) ([c72fd74](https://github.com/hyperledger/aries-framework-javascript/commit/c72fd7416f2c1bc0497a84036e16adfa80585e49))
- **askar:** import/export wallet support for SQLite ([#1377](https://github.com/hyperledger/aries-framework-javascript/issues/1377)) ([19cefa5](https://github.com/hyperledger/aries-framework-javascript/commit/19cefa54596a4e4848bdbe89306a884a5ce2e991))
- basic message pthid/thid support ([#1381](https://github.com/hyperledger/aries-framework-javascript/issues/1381)) ([f27fb99](https://github.com/hyperledger/aries-framework-javascript/commit/f27fb9921e11e5bcd654611d97d9fa1c446bc2d5))
- indy sdk aries askar migration script ([#1289](https://github.com/hyperledger/aries-framework-javascript/issues/1289)) ([4a6b99c](https://github.com/hyperledger/aries-framework-javascript/commit/4a6b99c617de06edbaf1cb07c8adfa8de9b3ec15))
- **openid4vc:** jwt format and more crypto ([#1472](https://github.com/hyperledger/aries-framework-javascript/issues/1472)) ([bd4932d](https://github.com/hyperledger/aries-framework-javascript/commit/bd4932d34f7314a6d49097b6460c7570e1ebc7a8))
- support for did:jwk and p-256, p-384, p-512 ([#1446](https://github.com/hyperledger/aries-framework-javascript/issues/1446)) ([700d3f8](https://github.com/hyperledger/aries-framework-javascript/commit/700d3f89728ce9d35e22519e505d8203a4c9031e))

### BREAKING CHANGES

- Agent-produced files will now be divided in different system paths depending on their nature: data, temp and cache. Previously, they were located at a single location, defaulting to a temporary directory.

If you specified a custom path in `FileSystem` object constructor, you now must provide an object containing `baseDataPath`, `baseTempPath` and `baseCachePath`. They can point to the same path, although it's recommended to specify different path to avoid future file clashes.
