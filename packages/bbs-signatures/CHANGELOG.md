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

**Note:** Version bump only for package @credo-ts/bbs-signatures

## [0.5.2](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.1...v0.5.2) (2024-04-26)

**Note:** Version bump only for package @credo-ts/bbs-signatures

## [0.5.1](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.0...v0.5.1) (2024-03-28)

**Note:** Version bump only for package @credo-ts/bbs-signatures

# [0.5.0](https://github.com/openwallet-foundation/credo-ts/compare/v0.4.2...v0.5.0) (2024-03-13)

### Bug Fixes

- jsonld document loader node 18 ([#1454](https://github.com/openwallet-foundation/credo-ts/issues/1454)) ([3656d49](https://github.com/openwallet-foundation/credo-ts/commit/3656d4902fb832e5e75142b1846074d4f39c11a2))
- unused imports ([#1733](https://github.com/openwallet-foundation/credo-ts/issues/1733)) ([e0b971e](https://github.com/openwallet-foundation/credo-ts/commit/e0b971e86b506bb78dafa21f76ae3b193abe9a9d))

## [0.4.2](https://github.com/hyperledger/aries-framework-javascript/compare/v0.4.1...v0.4.2) (2023-10-05)

**Note:** Version bump only for package @credo-ts/bbs-signatures

## [0.4.1](https://github.com/hyperledger/aries-framework-javascript/compare/v0.4.0...v0.4.1) (2023-08-28)

**Note:** Version bump only for package @credo-ts/bbs-signatures

# [0.4.0](https://github.com/hyperledger/aries-framework-javascript/compare/v0.3.3...v0.4.0) (2023-06-03)

### Bug Fixes

- jsonld credential format identifier version ([#1412](https://github.com/hyperledger/aries-framework-javascript/issues/1412)) ([c46a6b8](https://github.com/hyperledger/aries-framework-javascript/commit/c46a6b81b8a1e28e05013c27ffe2eeaee4724130))
- seed and private key validation and return type in registrars ([#1324](https://github.com/hyperledger/aries-framework-javascript/issues/1324)) ([c0e5339](https://github.com/hyperledger/aries-framework-javascript/commit/c0e5339edfa32df92f23fb9c920796b4b59adf52))

### Features

- **core:** add W3cCredentialsApi ([c888736](https://github.com/hyperledger/aries-framework-javascript/commit/c888736cb6b51014e23f5520fbc4074cf0e49e15))
- **openid4vc:** jwt format and more crypto ([#1472](https://github.com/hyperledger/aries-framework-javascript/issues/1472)) ([bd4932d](https://github.com/hyperledger/aries-framework-javascript/commit/bd4932d34f7314a6d49097b6460c7570e1ebc7a8))
