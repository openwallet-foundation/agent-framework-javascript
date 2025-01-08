# Changelog

## 0.6.0

### Patch Changes

- Updated dependencies [14673b1]
- Updated dependencies [607659a]
- Updated dependencies [5f08bc6]
  - @credo-ts/core@0.6.0
  - @credo-ts/anoncreds@0.6.0

## 0.5.13

### Patch Changes

- Updated dependencies [595c3d6]
  - @credo-ts/core@0.5.13
  - @credo-ts/anoncreds@0.5.13

## 0.5.12

### Patch Changes

- Updated dependencies [3c85565]
- Updated dependencies [3c85565]
- Updated dependencies [7d51fcb]
- Updated dependencies [9756a4a]
  - @credo-ts/core@0.5.12
  - @credo-ts/anoncreds@0.5.12

## 0.5.11

### Patch Changes

- 4485dc9: add cheqd api to allow creation of DID-Linked resources
  - @credo-ts/anoncreds@0.5.11
  - @credo-ts/core@0.5.11

## 0.5.10

### Patch Changes

- Updated dependencies [fa62b74]
  - @credo-ts/core@0.5.10
  - @credo-ts/anoncreds@0.5.10

## 0.5.9

### Patch Changes

- @credo-ts/anoncreds@0.5.9
- @credo-ts/core@0.5.9

## 0.5.8

### Patch Changes

- 1e9260a: add support for publishing AnonCreds revocation registry and statuslist for cheqd
- Updated dependencies [3819eb2]
- Updated dependencies [15d0a54]
- Updated dependencies [a5235e7]
  - @credo-ts/core@0.5.8
  - @credo-ts/anoncreds@0.5.8

## 0.5.7

### Patch Changes

- 8474776: Fix a build issue where importing cheqd pacakge would not work and give type errors
- Updated dependencies [352383f]
- Updated dependencies [1044c9d]
  - @credo-ts/core@0.5.7
  - @credo-ts/anoncreds@0.5.7

## 0.5.6

### Patch Changes

- 66e696d: Fix build issue causing error with importing packages in 0.5.5 release
- Updated dependencies [66e696d]
  - @credo-ts/anoncreds@0.5.6
  - @credo-ts/core@0.5.6

## 0.5.5

### Patch Changes

- d548fa4: feat: support new 'DIDCommMessaging' didcomm v2 service type (in addition to older 'DIDComm' service type)
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

## [0.5.3](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.2...v0.5.3) (2024-05-01)

### Bug Fixes

- cheqd create from did document ([#1850](https://github.com/openwallet-foundation/credo-ts/issues/1850)) ([dcd028e](https://github.com/openwallet-foundation/credo-ts/commit/dcd028ea04863bf9bc93e6bd2f73c6d2a70f274b))

## [0.5.2](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.1...v0.5.2) (2024-04-26)

### Bug Fixes

- udpate cheqd deps ([#1830](https://github.com/openwallet-foundation/credo-ts/issues/1830)) ([6b4b71b](https://github.com/openwallet-foundation/credo-ts/commit/6b4b71bf365262e8c2c9718547b60c44f2afc920))
- update cheqd to 2.4.2 ([#1817](https://github.com/openwallet-foundation/credo-ts/issues/1817)) ([8154df4](https://github.com/openwallet-foundation/credo-ts/commit/8154df45f45bd9da0c60abe3792ff0f081e81818))

## [0.5.1](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.0...v0.5.1) (2024-03-28)

### Bug Fixes

- **cheqd:** do not crash agent if cheqd down ([#1808](https://github.com/openwallet-foundation/credo-ts/issues/1808)) ([842efd4](https://github.com/openwallet-foundation/credo-ts/commit/842efd4512748a0787ce331add394426b3b07943))

# [0.5.0](https://github.com/openwallet-foundation/credo-ts/compare/v0.4.2...v0.5.0) (2024-03-13)

### Features

- anoncreds w3c migration ([#1744](https://github.com/openwallet-foundation/credo-ts/issues/1744)) ([d7c2bbb](https://github.com/openwallet-foundation/credo-ts/commit/d7c2bbb4fde57cdacbbf1ed40c6bd1423f7ab015))
- **anoncreds:** issue revocable credentials ([#1427](https://github.com/openwallet-foundation/credo-ts/issues/1427)) ([c59ad59](https://github.com/openwallet-foundation/credo-ts/commit/c59ad59fbe63b6d3760d19030e0f95fb2ea8488a))
- **openid4vc:** persistance and events ([#1793](https://github.com/openwallet-foundation/credo-ts/issues/1793)) ([f4c386a](https://github.com/openwallet-foundation/credo-ts/commit/f4c386a6ccf8adb829cad30b81d524e6ffddb029))

## [0.4.2](https://github.com/hyperledger/aries-framework-javascript/compare/v0.4.1...v0.4.2) (2023-10-05)

### Bug Fixes

- **cheqd:** changed the name formatting to a encoded hex value ([#1574](https://github.com/hyperledger/aries-framework-javascript/issues/1574)) ([d299f55](https://github.com/hyperledger/aries-framework-javascript/commit/d299f55113cb4c59273ae9fbbb8773b6f0009192))
- update tsyringe for ts 5 support ([#1588](https://github.com/hyperledger/aries-framework-javascript/issues/1588)) ([296955b](https://github.com/hyperledger/aries-framework-javascript/commit/296955b3a648416ac6b502da05a10001920af222))

## [0.4.1](https://github.com/hyperledger/aries-framework-javascript/compare/v0.4.0...v0.4.1) (2023-08-28)

### Bug Fixes

- **cheqd:** make cosmos payer seed optional ([#1547](https://github.com/hyperledger/aries-framework-javascript/issues/1547)) ([9377378](https://github.com/hyperledger/aries-framework-javascript/commit/9377378b0124bf2f593342dba95a13ea5d8944c8))
- force did:key resolver/registrar presence ([#1535](https://github.com/hyperledger/aries-framework-javascript/issues/1535)) ([aaa13dc](https://github.com/hyperledger/aries-framework-javascript/commit/aaa13dc77d6d5133cd02e768e4173462fa65064a))

# [0.4.0](https://github.com/hyperledger/aries-framework-javascript/compare/v0.3.3...v0.4.0) (2023-06-03)

### Bug Fixes

- small updates to cheqd module and demo ([#1439](https://github.com/hyperledger/aries-framework-javascript/issues/1439)) ([61daf0c](https://github.com/hyperledger/aries-framework-javascript/commit/61daf0cb27de80a5e728e2e9dad13d729baf476c))

### Features

- Add cheqd demo and localnet for tests ([#1435](https://github.com/hyperledger/aries-framework-javascript/issues/1435)) ([1ffb011](https://github.com/hyperledger/aries-framework-javascript/commit/1ffb0111fc3db170e5623d350cb912b22027387a))
- Add cheqd-sdk module ([#1334](https://github.com/hyperledger/aries-framework-javascript/issues/1334)) ([b38525f](https://github.com/hyperledger/aries-framework-javascript/commit/b38525f3433e50418ea149949108b4218ac9ba2a))
- support for did:jwk and p-256, p-384, p-512 ([#1446](https://github.com/hyperledger/aries-framework-javascript/issues/1446)) ([700d3f8](https://github.com/hyperledger/aries-framework-javascript/commit/700d3f89728ce9d35e22519e505d8203a4c9031e))
