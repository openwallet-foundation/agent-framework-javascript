# Changelog

## [0.5.3](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.2...v0.5.3) (2024-05-01)

### Bug Fixes

- **anoncreds:** migration script credential id ([#1849](https://github.com/openwallet-foundation/credo-ts/issues/1849)) ([e58ec5b](https://github.com/openwallet-foundation/credo-ts/commit/e58ec5bd97043d57fcc3c5a4aee926943e6c5326))

## [0.5.2](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.1...v0.5.2) (2024-04-26)

### Bug Fixes

- **anoncreds:** credential exchange record migration ([#1844](https://github.com/openwallet-foundation/credo-ts/issues/1844)) ([93b3986](https://github.com/openwallet-foundation/credo-ts/commit/93b3986348a86365c3a2faf8023a51390528df93))
- **anoncreds:** unqualified revocation registry processing ([#1833](https://github.com/openwallet-foundation/credo-ts/issues/1833)) ([edc5735](https://github.com/openwallet-foundation/credo-ts/commit/edc5735ccb663acabe8b8480f36cc3a72a1cf63d))
- node-ffi-napi compatibility ([#1821](https://github.com/openwallet-foundation/credo-ts/issues/1821)) ([81d351b](https://github.com/openwallet-foundation/credo-ts/commit/81d351bc9d4d508ebfac9e7f2b2f10276ab1404a))

### Features

- sort requested credentials ([#1839](https://github.com/openwallet-foundation/credo-ts/issues/1839)) ([b46c7fa](https://github.com/openwallet-foundation/credo-ts/commit/b46c7fa459d7e1a81744353bf595c754fad1b3a1))

## [0.5.1](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.0...v0.5.1) (2024-03-28)

### Bug Fixes

- anoncreds w3c migration metadata ([#1803](https://github.com/openwallet-foundation/credo-ts/issues/1803)) ([069c9c4](https://github.com/openwallet-foundation/credo-ts/commit/069c9c4fe362ee6c8af233df154d2d9b2c0f2d44))

### Features

- **anoncreds:** expose methods and metadata ([#1797](https://github.com/openwallet-foundation/credo-ts/issues/1797)) ([5992c57](https://github.com/openwallet-foundation/credo-ts/commit/5992c57a34d3b48dfa86cb659c77af498b6e8708))

# [0.5.0](https://github.com/openwallet-foundation/credo-ts/compare/v0.4.2...v0.5.0) (2024-03-13)

### Bug Fixes

- abandon proof protocol if presentation fails ([#1610](https://github.com/openwallet-foundation/credo-ts/issues/1610)) ([b2ba7c7](https://github.com/openwallet-foundation/credo-ts/commit/b2ba7c7197139e780cbb95eed77dc0a2ad3b3210))
- **anoncreds:** allow for zero idx to be used for revocation ([#1742](https://github.com/openwallet-foundation/credo-ts/issues/1742)) ([a1b9901](https://github.com/openwallet-foundation/credo-ts/commit/a1b9901b8bb232560118c902d86464e28d8a73fa))
- **anoncreds:** only store the revocation registry definition when the state is finished ([#1735](https://github.com/openwallet-foundation/credo-ts/issues/1735)) ([f7785c5](https://github.com/openwallet-foundation/credo-ts/commit/f7785c52b814dfa01c6d16dbecfcc937d533b710))
- **anoncreds:** pass along options for registry and status list ([#1734](https://github.com/openwallet-foundation/credo-ts/issues/1734)) ([e4b99a8](https://github.com/openwallet-foundation/credo-ts/commit/e4b99a86c76a1a4a41aebb94da0b57f774dd6aaf))
- **core:** query credential and proof records by correct DIDComm role ([#1780](https://github.com/openwallet-foundation/credo-ts/issues/1780)) ([add7e09](https://github.com/openwallet-foundation/credo-ts/commit/add7e091e845fdaddaf604335f19557f47a31079))
- presentation submission format ([#1792](https://github.com/openwallet-foundation/credo-ts/issues/1792)) ([1a46e9f](https://github.com/openwallet-foundation/credo-ts/commit/1a46e9f02599ed8b2bf36f5b9d3951d143852f03))
- query the record by credential and proof role ([#1784](https://github.com/openwallet-foundation/credo-ts/issues/1784)) ([d2b5cd9](https://github.com/openwallet-foundation/credo-ts/commit/d2b5cd9cbbfa95cbdcde9a4fed3305bab6161faf))
- save AnonCredsCredentialRecord createdAt ([#1603](https://github.com/openwallet-foundation/credo-ts/issues/1603)) ([a1942f8](https://github.com/openwallet-foundation/credo-ts/commit/a1942f8a8dffb11558dcbb900cbeb052e7d0227e))
- w3c anoncreds ([#1791](https://github.com/openwallet-foundation/credo-ts/issues/1791)) ([913596c](https://github.com/openwallet-foundation/credo-ts/commit/913596c4e843855f77a490428c55daac220bc8c6))

### Features

- anoncreds w3c migration ([#1744](https://github.com/openwallet-foundation/credo-ts/issues/1744)) ([d7c2bbb](https://github.com/openwallet-foundation/credo-ts/commit/d7c2bbb4fde57cdacbbf1ed40c6bd1423f7ab015))
- **anoncreds:** issue revocable credentials ([#1427](https://github.com/openwallet-foundation/credo-ts/issues/1427)) ([c59ad59](https://github.com/openwallet-foundation/credo-ts/commit/c59ad59fbe63b6d3760d19030e0f95fb2ea8488a))
- **indy-vdr:** register revocation registry definitions and status list ([#1693](https://github.com/openwallet-foundation/credo-ts/issues/1693)) ([ee34fe7](https://github.com/openwallet-foundation/credo-ts/commit/ee34fe71780a0787db96e28575eeedce3b4704bd))
- **openid4vc:** persistance and events ([#1793](https://github.com/openwallet-foundation/credo-ts/issues/1793)) ([f4c386a](https://github.com/openwallet-foundation/credo-ts/commit/f4c386a6ccf8adb829cad30b81d524e6ffddb029))
- optional backup on storage migration ([#1745](https://github.com/openwallet-foundation/credo-ts/issues/1745)) ([81ff63c](https://github.com/openwallet-foundation/credo-ts/commit/81ff63ccf7c71eccf342899d298a780d66045534))
- sped up lookup for revocation registries ([#1605](https://github.com/openwallet-foundation/credo-ts/issues/1605)) ([32ef8c5](https://github.com/openwallet-foundation/credo-ts/commit/32ef8c5a002c2cfe209c72e01f95b43337922fc6))

## [0.4.2](https://github.com/hyperledger/aries-framework-javascript/compare/v0.4.1...v0.4.2) (2023-10-05)

### Bug Fixes

- **oob:** support oob with connection and messages ([#1558](https://github.com/hyperledger/aries-framework-javascript/issues/1558)) ([9732ce4](https://github.com/hyperledger/aries-framework-javascript/commit/9732ce436a0ddee8760b02ac5182e216a75176c2))

## [0.4.1](https://github.com/hyperledger/aries-framework-javascript/compare/v0.4.0...v0.4.1) (2023-08-28)

### Bug Fixes

- **anoncreds:** wrong key name for predicates in proof object ([#1517](https://github.com/hyperledger/aries-framework-javascript/issues/1517)) ([d895c78](https://github.com/hyperledger/aries-framework-javascript/commit/d895c78e0e02954a95ad1fd7e2251ee9a02445dc))

### Features

- **anoncreds:** auto create link secret ([#1521](https://github.com/hyperledger/aries-framework-javascript/issues/1521)) ([c6f03e4](https://github.com/hyperledger/aries-framework-javascript/commit/c6f03e49d79a33b1c4b459cef11add93dee051d0))
- oob without handhsake improvements and routing ([#1511](https://github.com/hyperledger/aries-framework-javascript/issues/1511)) ([9e69cf4](https://github.com/hyperledger/aries-framework-javascript/commit/9e69cf441a75bf7a3c5556cf59e730ee3fce8c28))

# [0.4.0](https://github.com/hyperledger/aries-framework-javascript/compare/v0.3.3...v0.4.0) (2023-06-03)

### Bug Fixes

- add reflect-metadata ([#1409](https://github.com/hyperledger/aries-framework-javascript/issues/1409)) ([692defa](https://github.com/hyperledger/aries-framework-javascript/commit/692defa45ffcb4f36b0fa36970c4dc27aa75317c))
- **anoncreds:** Buffer not imported from core ([#1367](https://github.com/hyperledger/aries-framework-javascript/issues/1367)) ([c133538](https://github.com/hyperledger/aries-framework-javascript/commit/c133538356471a6a0887322a3f6245aa5193e7e4))
- **anoncreds:** include prover_did for legacy indy ([#1342](https://github.com/hyperledger/aries-framework-javascript/issues/1342)) ([d38ecb1](https://github.com/hyperledger/aries-framework-javascript/commit/d38ecb14cb58f1eb78e01c91699bb990d805dc08))
- **anoncreds:** make revocation status list inline with the spec ([#1421](https://github.com/hyperledger/aries-framework-javascript/issues/1421)) ([644e860](https://github.com/hyperledger/aries-framework-javascript/commit/644e860a05f40166e26c497a2e8619c9a38df11d))
- **askar:** anoncrypt messages unpacking ([#1332](https://github.com/hyperledger/aries-framework-javascript/issues/1332)) ([1c6aeae](https://github.com/hyperledger/aries-framework-javascript/commit/1c6aeae31ac57e83f4059f3dba35ccb1ca36926e))
- incorrect type for anoncreds registration ([#1396](https://github.com/hyperledger/aries-framework-javascript/issues/1396)) ([9f0f8f2](https://github.com/hyperledger/aries-framework-javascript/commit/9f0f8f21e7436c0a422d8c3a42a4cb601bcf7c77))
- issuance with unqualified identifiers ([#1431](https://github.com/hyperledger/aries-framework-javascript/issues/1431)) ([de90caf](https://github.com/hyperledger/aries-framework-javascript/commit/de90cafb8d12b7a940f881184cd745c4b5043cbc))
- migration of link secret ([#1444](https://github.com/hyperledger/aries-framework-javascript/issues/1444)) ([9a43afe](https://github.com/hyperledger/aries-framework-javascript/commit/9a43afec7ea72a6fa8c6133f0fad05d8a3d2a595))
- various anoncreds revocation fixes ([#1416](https://github.com/hyperledger/aries-framework-javascript/issues/1416)) ([d9cfc7d](https://github.com/hyperledger/aries-framework-javascript/commit/d9cfc7df6679d2008d66070a6c8a818440d066ab))

- feat!: add data, cache and temp dirs to FileSystem (#1306) ([ff5596d](https://github.com/hyperledger/aries-framework-javascript/commit/ff5596d0631e93746494c017797d0191b6bdb0b1)), closes [#1306](https://github.com/hyperledger/aries-framework-javascript/issues/1306)

### Features

- 0.4.0 migration script ([#1392](https://github.com/hyperledger/aries-framework-javascript/issues/1392)) ([bc5455f](https://github.com/hyperledger/aries-framework-javascript/commit/bc5455f7b42612a2b85e504bc6ddd36283a42bfa))
- add anoncreds-rs package ([#1275](https://github.com/hyperledger/aries-framework-javascript/issues/1275)) ([efe0271](https://github.com/hyperledger/aries-framework-javascript/commit/efe0271198f21f1307df0f934c380f7a5c720b06))
- **anoncreds:** add anoncreds API ([#1232](https://github.com/hyperledger/aries-framework-javascript/issues/1232)) ([3a4c5ec](https://github.com/hyperledger/aries-framework-javascript/commit/3a4c5ecd940e49d4d192eef1d41f2aaedb34d85a))
- **anoncreds:** add AnonCreds format services ([#1385](https://github.com/hyperledger/aries-framework-javascript/issues/1385)) ([5f71dc2](https://github.com/hyperledger/aries-framework-javascript/commit/5f71dc2b403f6cb0fc9bb13f35051d377c2d1250))
- **anoncreds:** add getCredential(s) methods ([#1386](https://github.com/hyperledger/aries-framework-javascript/issues/1386)) ([2efc009](https://github.com/hyperledger/aries-framework-javascript/commit/2efc0097138585391940fbb2eb504e50df57ec87))
- **anoncreds:** add legacy indy credential format ([#1220](https://github.com/hyperledger/aries-framework-javascript/issues/1220)) ([13f3740](https://github.com/hyperledger/aries-framework-javascript/commit/13f374079262168f90ec7de7c3393beb9651295c))
- **anoncreds:** legacy indy proof format service ([#1283](https://github.com/hyperledger/aries-framework-javascript/issues/1283)) ([c72fd74](https://github.com/hyperledger/aries-framework-javascript/commit/c72fd7416f2c1bc0497a84036e16adfa80585e49))
- **anoncreds:** store method name in records ([#1387](https://github.com/hyperledger/aries-framework-javascript/issues/1387)) ([47636b4](https://github.com/hyperledger/aries-framework-javascript/commit/47636b4a08ffbfa9a3f2a5a3c5aebda44f7d16c8))
- **anoncreds:** support credential attribute value and marker ([#1369](https://github.com/hyperledger/aries-framework-javascript/issues/1369)) ([5559996](https://github.com/hyperledger/aries-framework-javascript/commit/555999686a831e6988564fd5c9c937fc1023f567))
- **anoncreds:** use legacy prover did ([#1374](https://github.com/hyperledger/aries-framework-javascript/issues/1374)) ([c17013c](https://github.com/hyperledger/aries-framework-javascript/commit/c17013c808a278d624210ce9e4333860cd78fc19))
- default return route ([#1327](https://github.com/hyperledger/aries-framework-javascript/issues/1327)) ([dbfebb4](https://github.com/hyperledger/aries-framework-javascript/commit/dbfebb4720da731dbe11efdccdd061d1da3d1323))
- **indy-vdr:** schema + credential definition endorsement ([#1451](https://github.com/hyperledger/aries-framework-javascript/issues/1451)) ([25b981b](https://github.com/hyperledger/aries-framework-javascript/commit/25b981b6e23d02409e90dabdccdccc8904d4e357))
- outbound message send via session ([#1335](https://github.com/hyperledger/aries-framework-javascript/issues/1335)) ([582c711](https://github.com/hyperledger/aries-framework-javascript/commit/582c711728db12b7d38a0be2e9fa78dbf31b34c6))

### BREAKING CHANGES

- Agent-produced files will now be divided in different system paths depending on their nature: data, temp and cache. Previously, they were located at a single location, defaulting to a temporary directory.

If you specified a custom path in `FileSystem` object constructor, you now must provide an object containing `baseDataPath`, `baseTempPath` and `baseCachePath`. They can point to the same path, although it's recommended to specify different path to avoid future file clashes.
