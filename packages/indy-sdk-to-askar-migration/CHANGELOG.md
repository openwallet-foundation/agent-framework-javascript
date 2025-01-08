# Changelog

## 0.6.0

### Patch Changes

- Updated dependencies [14673b1]
- Updated dependencies [607659a]
- Updated dependencies [5f08bc6]
  - @credo-ts/core@0.6.0
  - @credo-ts/anoncreds@0.6.0
  - @credo-ts/askar@0.6.0
  - @credo-ts/node@0.6.0

## 0.5.13

### Patch Changes

- Updated dependencies [595c3d6]
  - @credo-ts/core@0.5.13
  - @credo-ts/anoncreds@0.5.13
  - @credo-ts/askar@0.5.13
  - @credo-ts/node@0.5.13

## 0.5.12

### Patch Changes

- Updated dependencies [3c85565]
- Updated dependencies [3c85565]
- Updated dependencies [7d51fcb]
- Updated dependencies [9756a4a]
  - @credo-ts/core@0.5.12
  - @credo-ts/askar@0.5.12
  - @credo-ts/anoncreds@0.5.12
  - @credo-ts/node@0.5.12

## 0.5.11

### Patch Changes

- @credo-ts/anoncreds@0.5.11
- @credo-ts/askar@0.5.11
- @credo-ts/core@0.5.11
- @credo-ts/node@0.5.11

## 0.5.10

### Patch Changes

- Updated dependencies [fa62b74]
  - @credo-ts/core@0.5.10
  - @credo-ts/anoncreds@0.5.10
  - @credo-ts/askar@0.5.10
  - @credo-ts/node@0.5.10

## 0.5.9

### Patch Changes

- @credo-ts/anoncreds@0.5.9
- @credo-ts/askar@0.5.9
- @credo-ts/core@0.5.9
- @credo-ts/node@0.5.9

## 0.5.8

### Patch Changes

- Updated dependencies [3819eb2]
- Updated dependencies [15d0a54]
- Updated dependencies [a5235e7]
  - @credo-ts/core@0.5.8
  - @credo-ts/anoncreds@0.5.8
  - @credo-ts/askar@0.5.8
  - @credo-ts/node@0.5.8

## 0.5.7

### Patch Changes

- Updated dependencies [352383f]
- Updated dependencies [1044c9d]
  - @credo-ts/core@0.5.7
  - @credo-ts/anoncreds@0.5.7
  - @credo-ts/askar@0.5.7
  - @credo-ts/node@0.5.7

## 0.5.6

### Patch Changes

- 66e696d: Fix build issue causing error with importing packages in 0.5.5 release
- Updated dependencies [66e696d]
  - @credo-ts/anoncreds@0.5.6
  - @credo-ts/askar@0.5.6
  - @credo-ts/core@0.5.6
  - @credo-ts/node@0.5.6

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
  - @credo-ts/anoncreds@0.5.5
  - @credo-ts/askar@0.5.5
  - @credo-ts/node@0.5.5

## [0.5.3](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.2...v0.5.3) (2024-05-01)

**Note:** Version bump only for package @credo-ts/indy-sdk-to-askar-migration

## [0.5.2](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.1...v0.5.2) (2024-04-26)

### Bug Fixes

- node-ffi-napi compatibility ([#1821](https://github.com/openwallet-foundation/credo-ts/issues/1821)) ([81d351b](https://github.com/openwallet-foundation/credo-ts/commit/81d351bc9d4d508ebfac9e7f2b2f10276ab1404a))

## [0.5.1](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.0...v0.5.1) (2024-03-28)

**Note:** Version bump only for package @credo-ts/indy-sdk-to-askar-migration

# [0.5.0](https://github.com/openwallet-foundation/credo-ts/compare/v0.4.2...v0.5.0) (2024-03-13)

**Note:** Version bump only for package @credo-ts/indy-sdk-to-askar-migration

## [0.4.2](https://github.com/hyperledger/aries-framework-javascript/compare/v0.4.1...v0.4.2) (2023-10-05)

**Note:** Version bump only for package @credo-ts/indy-sdk-to-askar-migration

## [0.4.1](https://github.com/hyperledger/aries-framework-javascript/compare/v0.4.0...v0.4.1) (2023-08-28)

**Note:** Version bump only for package @credo-ts/indy-sdk-to-askar-migration

# [0.4.0](https://github.com/hyperledger/aries-framework-javascript/compare/v0.3.3...v0.4.0) (2023-06-03)

### Bug Fixes

- **askar:** default key derivation method ([#1420](https://github.com/hyperledger/aries-framework-javascript/issues/1420)) ([7b59629](https://github.com/hyperledger/aries-framework-javascript/commit/7b5962917488cfd0c5adc170d3c3fc64aa82ef2c))
- migration of link secret ([#1444](https://github.com/hyperledger/aries-framework-javascript/issues/1444)) ([9a43afe](https://github.com/hyperledger/aries-framework-javascript/commit/9a43afec7ea72a6fa8c6133f0fad05d8a3d2a595))
- remove `deleteOnFinish` and added documentation ([#1418](https://github.com/hyperledger/aries-framework-javascript/issues/1418)) ([c8b16a6](https://github.com/hyperledger/aries-framework-javascript/commit/c8b16a6fec8bb693e67e65709ded05d19fd1919f))
- small issues with migration and WAL files ([#1443](https://github.com/hyperledger/aries-framework-javascript/issues/1443)) ([83cf387](https://github.com/hyperledger/aries-framework-javascript/commit/83cf387fa52bb51d8adb2d5fedc5111994d4dde1))

### Features

- **anoncreds:** store method name in records ([#1387](https://github.com/hyperledger/aries-framework-javascript/issues/1387)) ([47636b4](https://github.com/hyperledger/aries-framework-javascript/commit/47636b4a08ffbfa9a3f2a5a3c5aebda44f7d16c8))
- indy sdk aries askar migration script ([#1289](https://github.com/hyperledger/aries-framework-javascript/issues/1289)) ([4a6b99c](https://github.com/hyperledger/aries-framework-javascript/commit/4a6b99c617de06edbaf1cb07c8adfa8de9b3ec15))
