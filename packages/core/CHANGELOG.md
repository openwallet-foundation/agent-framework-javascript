# Changelog

## [0.5.3](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.2...v0.5.3) (2024-05-01)

### Bug Fixes

- allow did document for didcomm without authentication or keyAgreement ([#1848](https://github.com/openwallet-foundation/credo-ts/issues/1848)) ([5d986f0](https://github.com/openwallet-foundation/credo-ts/commit/5d986f0da67de78b4df2ad7ab92eeb2bdf9f2c83))
- store recipient keys by default ([#1847](https://github.com/openwallet-foundation/credo-ts/issues/1847)) ([e9238cf](https://github.com/openwallet-foundation/credo-ts/commit/e9238cfde4d76c5b927f6f76b3529d4c80808a3a))

## [0.5.2](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.1...v0.5.2) (2024-04-26)

### Bug Fixes

- oid4vp can be used separate from idtoken ([#1827](https://github.com/openwallet-foundation/credo-ts/issues/1827)) ([ca383c2](https://github.com/openwallet-foundation/credo-ts/commit/ca383c284e2073992a1fd280fca99bee1c2e19f8))
- remove mediation keys after hangup ([#1843](https://github.com/openwallet-foundation/credo-ts/issues/1843)) ([9c3b950](https://github.com/openwallet-foundation/credo-ts/commit/9c3b9507ec5e33d155cebf9fab97703267b549bd))

### Features

- add disclosures so you know which fields are disclosed ([#1834](https://github.com/openwallet-foundation/credo-ts/issues/1834)) ([6ec43eb](https://github.com/openwallet-foundation/credo-ts/commit/6ec43eb1f539bd8d864d5bbd2ab35459809255ec))
- apply new version of SD JWT package ([#1787](https://github.com/openwallet-foundation/credo-ts/issues/1787)) ([b41e158](https://github.com/openwallet-foundation/credo-ts/commit/b41e158098773d2f59b5b5cfb82cc6be06a57acd))
- did rotate event ([#1840](https://github.com/openwallet-foundation/credo-ts/issues/1840)) ([d16bebb](https://github.com/openwallet-foundation/credo-ts/commit/d16bebb7d63bfbad90cedea3c6b4fb3ec20a4be1))
- queued messages reception time ([#1824](https://github.com/openwallet-foundation/credo-ts/issues/1824)) ([0b4b8dd](https://github.com/openwallet-foundation/credo-ts/commit/0b4b8dd42117eb8e92fcc4be695ff149b49a06c7))
- support invitationDid when creating an invitation ([#1811](https://github.com/openwallet-foundation/credo-ts/issues/1811)) ([e5c6698](https://github.com/openwallet-foundation/credo-ts/commit/e5c66988e75fd9a5f047fd96774c0bf494061cbc))

## [0.5.1](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.0...v0.5.1) (2024-03-28)

### Bug Fixes

- **openid4vc:** several fixes and improvements ([#1795](https://github.com/openwallet-foundation/credo-ts/issues/1795)) ([b83c517](https://github.com/openwallet-foundation/credo-ts/commit/b83c5173070594448d92f801331b3a31c7ac8049))
- remove strict w3c subjectId uri validation ([#1805](https://github.com/openwallet-foundation/credo-ts/issues/1805)) ([65f7611](https://github.com/openwallet-foundation/credo-ts/commit/65f7611b7668d3242b4526831f442c68d6cfbea8))
- unsubscribe from emitter after pickup completion ([#1806](https://github.com/openwallet-foundation/credo-ts/issues/1806)) ([9fb6ae0](https://github.com/openwallet-foundation/credo-ts/commit/9fb6ae0005f11197eefdb864aa8a7cf3b79357f0))

### Features

- credentials api decline offer report ([#1800](https://github.com/openwallet-foundation/credo-ts/issues/1800)) ([15c62a8](https://github.com/openwallet-foundation/credo-ts/commit/15c62a8e20df7189ae8068e3ff42bf7e20a38ad5))

# [0.5.0](https://github.com/openwallet-foundation/credo-ts/compare/v0.4.2...v0.5.0) (2024-03-13)

### Bug Fixes

- abandon proof protocol if presentation fails ([#1610](https://github.com/openwallet-foundation/credo-ts/issues/1610)) ([b2ba7c7](https://github.com/openwallet-foundation/credo-ts/commit/b2ba7c7197139e780cbb95eed77dc0a2ad3b3210))
- **core:** allow string for did document controller ([#1644](https://github.com/openwallet-foundation/credo-ts/issues/1644)) ([ed874ce](https://github.com/openwallet-foundation/credo-ts/commit/ed874ce38ed1a1a0f01b12958e5b14823661b06a))
- **core:** query credential and proof records by correct DIDComm role ([#1780](https://github.com/openwallet-foundation/credo-ts/issues/1780)) ([add7e09](https://github.com/openwallet-foundation/credo-ts/commit/add7e091e845fdaddaf604335f19557f47a31079))
- did:peer:2 creation and parsing ([#1752](https://github.com/openwallet-foundation/credo-ts/issues/1752)) ([7c60918](https://github.com/openwallet-foundation/credo-ts/commit/7c609183b2da16f2a698646ac39b03c2ab44318e))
- jsonld document loader node 18 ([#1454](https://github.com/openwallet-foundation/credo-ts/issues/1454)) ([3656d49](https://github.com/openwallet-foundation/credo-ts/commit/3656d4902fb832e5e75142b1846074d4f39c11a2))
- **present-proof:** isolated tests ([#1696](https://github.com/openwallet-foundation/credo-ts/issues/1696)) ([1d33377](https://github.com/openwallet-foundation/credo-ts/commit/1d333770dcc9e261446b43b5f4cd5626fa7ac4a7))
- presentation submission format ([#1792](https://github.com/openwallet-foundation/credo-ts/issues/1792)) ([1a46e9f](https://github.com/openwallet-foundation/credo-ts/commit/1a46e9f02599ed8b2bf36f5b9d3951d143852f03))
- properly print key class ([#1684](https://github.com/openwallet-foundation/credo-ts/issues/1684)) ([99b801d](https://github.com/openwallet-foundation/credo-ts/commit/99b801dfb6edcd3b7baaa8108ad361be4e05ff67))
- query the record by credential and proof role ([#1784](https://github.com/openwallet-foundation/credo-ts/issues/1784)) ([d2b5cd9](https://github.com/openwallet-foundation/credo-ts/commit/d2b5cd9cbbfa95cbdcde9a4fed3305bab6161faf))
- remove check for DifPresentationExchangeService dependency ([#1702](https://github.com/openwallet-foundation/credo-ts/issues/1702)) ([93d9d8b](https://github.com/openwallet-foundation/credo-ts/commit/93d9d8bb3a93e47197a2c01998807523d783b0bf))
- some log messages ([#1636](https://github.com/openwallet-foundation/credo-ts/issues/1636)) ([d40bfd1](https://github.com/openwallet-foundation/credo-ts/commit/d40bfd1b96001870a3a1553cb9d6faaefe71e364))
- support all minor versions handshake ([#1711](https://github.com/openwallet-foundation/credo-ts/issues/1711)) ([40063e0](https://github.com/openwallet-foundation/credo-ts/commit/40063e06ff6afc139516459e81e85b36195985ca))
- w3c anoncreds ([#1791](https://github.com/openwallet-foundation/credo-ts/issues/1791)) ([913596c](https://github.com/openwallet-foundation/credo-ts/commit/913596c4e843855f77a490428c55daac220bc8c6))
- websocket outbound transport ([#1788](https://github.com/openwallet-foundation/credo-ts/issues/1788)) ([ed06d00](https://github.com/openwallet-foundation/credo-ts/commit/ed06d002c2c3d1f35b6790b8624cda0e506cf7d4))

### Features

- add goal codes to v2 protocols ([#1739](https://github.com/openwallet-foundation/credo-ts/issues/1739)) ([c5c5b85](https://github.com/openwallet-foundation/credo-ts/commit/c5c5b850f27e66f7a2e39acd5fc14267babee208))
- add Multikey as supported vm type ([#1720](https://github.com/openwallet-foundation/credo-ts/issues/1720)) ([5562cb1](https://github.com/openwallet-foundation/credo-ts/commit/5562cb1751643eee16b4bf3304a5178a394a7f15))
- add secp256k1 diddoc and verification method ([#1736](https://github.com/openwallet-foundation/credo-ts/issues/1736)) ([f245386](https://github.com/openwallet-foundation/credo-ts/commit/f245386eef2e0daad7a5c948df29625f60a020ea))
- add some default contexts ([#1741](https://github.com/openwallet-foundation/credo-ts/issues/1741)) ([0bec03c](https://github.com/openwallet-foundation/credo-ts/commit/0bec03c3b97590a1484e8b803401569998655b87))
- add support for key type k256 ([#1722](https://github.com/openwallet-foundation/credo-ts/issues/1722)) ([22d5bff](https://github.com/openwallet-foundation/credo-ts/commit/22d5bffc939f6644f324f6ddba4c8269212e9dc4))
- anoncreds w3c migration ([#1744](https://github.com/openwallet-foundation/credo-ts/issues/1744)) ([d7c2bbb](https://github.com/openwallet-foundation/credo-ts/commit/d7c2bbb4fde57cdacbbf1ed40c6bd1423f7ab015))
- **anoncreds:** issue revocable credentials ([#1427](https://github.com/openwallet-foundation/credo-ts/issues/1427)) ([c59ad59](https://github.com/openwallet-foundation/credo-ts/commit/c59ad59fbe63b6d3760d19030e0f95fb2ea8488a))
- did rotate ([#1699](https://github.com/openwallet-foundation/credo-ts/issues/1699)) ([adc7d4e](https://github.com/openwallet-foundation/credo-ts/commit/adc7d4ecfea9be5f707ab7b50d19dbe7690c6d25))
- did:peer:2 and did:peer:4 support in DID Exchange ([#1550](https://github.com/openwallet-foundation/credo-ts/issues/1550)) ([edf493d](https://github.com/openwallet-foundation/credo-ts/commit/edf493dd7e707543af5bbdbf6daba2b02c74158d))
- **indy-vdr:** register revocation registry definitions and status list ([#1693](https://github.com/openwallet-foundation/credo-ts/issues/1693)) ([ee34fe7](https://github.com/openwallet-foundation/credo-ts/commit/ee34fe71780a0787db96e28575eeedce3b4704bd))
- **mesage-pickup:** option for awaiting completion ([#1755](https://github.com/openwallet-foundation/credo-ts/issues/1755)) ([faa390f](https://github.com/openwallet-foundation/credo-ts/commit/faa390f2e2bb438596b5d9e3a69e1442f551ff1e))
- **openid4vc:** persistance and events ([#1793](https://github.com/openwallet-foundation/credo-ts/issues/1793)) ([f4c386a](https://github.com/openwallet-foundation/credo-ts/commit/f4c386a6ccf8adb829cad30b81d524e6ffddb029))
- optional backup on storage migration ([#1745](https://github.com/openwallet-foundation/credo-ts/issues/1745)) ([81ff63c](https://github.com/openwallet-foundation/credo-ts/commit/81ff63ccf7c71eccf342899d298a780d66045534))
- **present-proof:** add support for aries RFC 510 ([#1676](https://github.com/openwallet-foundation/credo-ts/issues/1676)) ([40c9bb6](https://github.com/openwallet-foundation/credo-ts/commit/40c9bb6e9efe6cceb62c79d34366edf77ba84b0d))
- **presentation-exchange:** added PresentationExchangeService ([#1672](https://github.com/openwallet-foundation/credo-ts/issues/1672)) ([50db5c7](https://github.com/openwallet-foundation/credo-ts/commit/50db5c7d207130b80e38ce5d94afb9e3b96f2fb1))
- **sd-jwt-vc:** Module for Issuer, Holder and verifier ([#1607](https://github.com/openwallet-foundation/credo-ts/issues/1607)) ([ec3182d](https://github.com/openwallet-foundation/credo-ts/commit/ec3182d9934319b761649edb4c80ede2dd46dbd4))
- support short legacy connectionless invitations ([#1705](https://github.com/openwallet-foundation/credo-ts/issues/1705)) ([34a6c9f](https://github.com/openwallet-foundation/credo-ts/commit/34a6c9f185d7b177956e5e2c5d79408e52915136))
- **tenants:** support for tenant storage migration ([#1747](https://github.com/openwallet-foundation/credo-ts/issues/1747)) ([12c617e](https://github.com/openwallet-foundation/credo-ts/commit/12c617efb45d20fda8965b9b4da24c92e975c9a2))

## [0.4.2](https://github.com/hyperledger/aries-framework-javascript/compare/v0.4.1...v0.4.2) (2023-10-05)

### Bug Fixes

- **askar:** throw error if imported wallet exists ([#1593](https://github.com/hyperledger/aries-framework-javascript/issues/1593)) ([c2bb2a5](https://github.com/hyperledger/aries-framework-javascript/commit/c2bb2a52f10add35de883c9a27716db01b9028df))
- **core:** remove node-fetch dependency ([#1578](https://github.com/hyperledger/aries-framework-javascript/issues/1578)) ([9ee2ce7](https://github.com/hyperledger/aries-framework-javascript/commit/9ee2ce7f0913510fc5b36aef1b7eeffb259b4aed))
- do not send package via outdated session ([#1559](https://github.com/hyperledger/aries-framework-javascript/issues/1559)) ([de6a735](https://github.com/hyperledger/aries-framework-javascript/commit/de6a735a900b6d7444b17d79e63acaca19cb812a))
- duplicate service ids in connections protocol ([#1589](https://github.com/hyperledger/aries-framework-javascript/issues/1589)) ([dd75be8](https://github.com/hyperledger/aries-framework-javascript/commit/dd75be88c4e257b6ca76868ceaeb3a8b7d67c185))
- implicit invitation to specific service ([#1592](https://github.com/hyperledger/aries-framework-javascript/issues/1592)) ([4071dc9](https://github.com/hyperledger/aries-framework-javascript/commit/4071dc97b8ca779e6def3711a538ae821e1e513c))
- log and throw on WebSocket sending errors ([#1573](https://github.com/hyperledger/aries-framework-javascript/issues/1573)) ([11050af](https://github.com/hyperledger/aries-framework-javascript/commit/11050afc7965adfa9b00107ba34abfbe3afaf874))
- **oob:** support oob with connection and messages ([#1558](https://github.com/hyperledger/aries-framework-javascript/issues/1558)) ([9732ce4](https://github.com/hyperledger/aries-framework-javascript/commit/9732ce436a0ddee8760b02ac5182e216a75176c2))
- service validation in OOB invitation objects ([#1575](https://github.com/hyperledger/aries-framework-javascript/issues/1575)) ([91a9434](https://github.com/hyperledger/aries-framework-javascript/commit/91a9434efd53ccbaf80f5613cd908913ad3b806b))
- update tsyringe for ts 5 support ([#1588](https://github.com/hyperledger/aries-framework-javascript/issues/1588)) ([296955b](https://github.com/hyperledger/aries-framework-javascript/commit/296955b3a648416ac6b502da05a10001920af222))

### Features

- allow connection invitation encoded in oob url param ([#1583](https://github.com/hyperledger/aries-framework-javascript/issues/1583)) ([9d789fa](https://github.com/hyperledger/aries-framework-javascript/commit/9d789fa4e9d159312872f45089d73609eb3d6835))

## [0.4.1](https://github.com/hyperledger/aries-framework-javascript/compare/v0.4.0...v0.4.1) (2023-08-28)

### Bug Fixes

- create message subscription first ([#1549](https://github.com/hyperledger/aries-framework-javascript/issues/1549)) ([93276de](https://github.com/hyperledger/aries-framework-javascript/commit/93276debeff1e56c9803e7700875c4254a48236b))
- force did:key resolver/registrar presence ([#1535](https://github.com/hyperledger/aries-framework-javascript/issues/1535)) ([aaa13dc](https://github.com/hyperledger/aries-framework-javascript/commit/aaa13dc77d6d5133cd02e768e4173462fa65064a))
- listen to incoming messages on agent initialize not constructor ([#1542](https://github.com/hyperledger/aries-framework-javascript/issues/1542)) ([8f2d593](https://github.com/hyperledger/aries-framework-javascript/commit/8f2d593bcda0bb2d7bea25ad06b9e37784961997))
- priority sorting for didcomm services ([#1555](https://github.com/hyperledger/aries-framework-javascript/issues/1555)) ([80c37b3](https://github.com/hyperledger/aries-framework-javascript/commit/80c37b30eb9ac3b438288e14c252f79f619dd12f))
- race condition singleton records ([#1495](https://github.com/hyperledger/aries-framework-javascript/issues/1495)) ([6c2dda5](https://github.com/hyperledger/aries-framework-javascript/commit/6c2dda544bf5f5d3a972a778c389340da6df97c4))
- **transport:** Use connection in WebSocket ID ([#1551](https://github.com/hyperledger/aries-framework-javascript/issues/1551)) ([8d2057f](https://github.com/hyperledger/aries-framework-javascript/commit/8d2057f3fe6f3ba236ba5a811b57a7256eae92bf))

### Features

- **anoncreds:** auto create link secret ([#1521](https://github.com/hyperledger/aries-framework-javascript/issues/1521)) ([c6f03e4](https://github.com/hyperledger/aries-framework-javascript/commit/c6f03e49d79a33b1c4b459cef11add93dee051d0))
- oob without handhsake improvements and routing ([#1511](https://github.com/hyperledger/aries-framework-javascript/issues/1511)) ([9e69cf4](https://github.com/hyperledger/aries-framework-javascript/commit/9e69cf441a75bf7a3c5556cf59e730ee3fce8c28))
- support askar profiles for multi-tenancy ([#1538](https://github.com/hyperledger/aries-framework-javascript/issues/1538)) ([e448a2a](https://github.com/hyperledger/aries-framework-javascript/commit/e448a2a58dddff2cdf80c4549ea2d842a54b43d1))
- **w3c:** add convenience methods to vc and vp ([#1477](https://github.com/hyperledger/aries-framework-javascript/issues/1477)) ([83cbfe3](https://github.com/hyperledger/aries-framework-javascript/commit/83cbfe38e788366b616dc244fe34cc49a5a4d331))

# [0.4.0](https://github.com/hyperledger/aries-framework-javascript/compare/v0.3.3...v0.4.0) (2023-06-03)

### Bug Fixes

- connection id in sessions for new connections ([#1383](https://github.com/hyperledger/aries-framework-javascript/issues/1383)) ([0351eec](https://github.com/hyperledger/aries-framework-javascript/commit/0351eec52a9f5e581508819df3005be7b995e59e))
- **connections:** store imageUrl when using DIDExchange ([#1433](https://github.com/hyperledger/aries-framework-javascript/issues/1433)) ([66afda2](https://github.com/hyperledger/aries-framework-javascript/commit/66afda2fe7311977047928e0b1c857ed2c5602c7))
- **core:** repository event when calling deleteById ([#1356](https://github.com/hyperledger/aries-framework-javascript/issues/1356)) ([953069a](https://github.com/hyperledger/aries-framework-javascript/commit/953069a785f2a6b8d1e11123aab3a09aab1e65ff))
- create new socket if socket state is 'closing' ([#1337](https://github.com/hyperledger/aries-framework-javascript/issues/1337)) ([da8f2ad](https://github.com/hyperledger/aries-framework-javascript/commit/da8f2ad36c386497b16075790a364faae50fcd47))
- Emit RoutingCreated event for mediator routing record ([#1445](https://github.com/hyperledger/aries-framework-javascript/issues/1445)) ([4145957](https://github.com/hyperledger/aries-framework-javascript/commit/414595727d611ff774c4f404a4eeea509cf03a71))
- imports from core ([#1303](https://github.com/hyperledger/aries-framework-javascript/issues/1303)) ([3e02227](https://github.com/hyperledger/aries-framework-javascript/commit/3e02227a7b23677e9886eb1c03d1a3ec154947a9))
- isNewSocket logic ([#1355](https://github.com/hyperledger/aries-framework-javascript/issues/1355)) ([18abb18](https://github.com/hyperledger/aries-framework-javascript/commit/18abb18316f155d0375af477dedef9cdfdada70e))
- issuance with unqualified identifiers ([#1431](https://github.com/hyperledger/aries-framework-javascript/issues/1431)) ([de90caf](https://github.com/hyperledger/aries-framework-javascript/commit/de90cafb8d12b7a940f881184cd745c4b5043cbc))
- jsonld credential format identifier version ([#1412](https://github.com/hyperledger/aries-framework-javascript/issues/1412)) ([c46a6b8](https://github.com/hyperledger/aries-framework-javascript/commit/c46a6b81b8a1e28e05013c27ffe2eeaee4724130))
- loosen base64 validation ([#1312](https://github.com/hyperledger/aries-framework-javascript/issues/1312)) ([af384e8](https://github.com/hyperledger/aries-framework-javascript/commit/af384e8a92f877c647999f9356b72a8017308230))
- registered connection problem report message handler ([#1462](https://github.com/hyperledger/aries-framework-javascript/issues/1462)) ([d2d8ee0](https://github.com/hyperledger/aries-framework-javascript/commit/d2d8ee09c4eb6c050660b2bf9973195fd531df18))
- seed and private key validation and return type in registrars ([#1324](https://github.com/hyperledger/aries-framework-javascript/issues/1324)) ([c0e5339](https://github.com/hyperledger/aries-framework-javascript/commit/c0e5339edfa32df92f23fb9c920796b4b59adf52))
- set updateAt on records when updating a record ([#1272](https://github.com/hyperledger/aries-framework-javascript/issues/1272)) ([2669d7d](https://github.com/hyperledger/aries-framework-javascript/commit/2669d7dd3d7c0ddfd1108dfd65e6115dd3418500))
- thread id improvements ([#1311](https://github.com/hyperledger/aries-framework-javascript/issues/1311)) ([229ed1b](https://github.com/hyperledger/aries-framework-javascript/commit/229ed1b9540ca0c9380b5cca6c763fefd6628960))

- refactor!: remove Dispatcher.registerMessageHandler (#1354) ([78ecf1e](https://github.com/hyperledger/aries-framework-javascript/commit/78ecf1ed959c9daba1c119d03f4596f1db16c57c)), closes [#1354](https://github.com/hyperledger/aries-framework-javascript/issues/1354)
- refactor!: set default outbound content type to didcomm v1 (#1314) ([4ab3b54](https://github.com/hyperledger/aries-framework-javascript/commit/4ab3b54e9db630a6ba022af6becdd7276692afc5)), closes [#1314](https://github.com/hyperledger/aries-framework-javascript/issues/1314)
- feat!: add data, cache and temp dirs to FileSystem (#1306) ([ff5596d](https://github.com/hyperledger/aries-framework-javascript/commit/ff5596d0631e93746494c017797d0191b6bdb0b1)), closes [#1306](https://github.com/hyperledger/aries-framework-javascript/issues/1306)

### Features

- 0.4.0 migration script ([#1392](https://github.com/hyperledger/aries-framework-javascript/issues/1392)) ([bc5455f](https://github.com/hyperledger/aries-framework-javascript/commit/bc5455f7b42612a2b85e504bc6ddd36283a42bfa))
- add anoncreds-rs package ([#1275](https://github.com/hyperledger/aries-framework-javascript/issues/1275)) ([efe0271](https://github.com/hyperledger/aries-framework-javascript/commit/efe0271198f21f1307df0f934c380f7a5c720b06))
- Add cheqd-sdk module ([#1334](https://github.com/hyperledger/aries-framework-javascript/issues/1334)) ([b38525f](https://github.com/hyperledger/aries-framework-javascript/commit/b38525f3433e50418ea149949108b4218ac9ba2a))
- add fetch indy schema method ([#1290](https://github.com/hyperledger/aries-framework-javascript/issues/1290)) ([1d782f5](https://github.com/hyperledger/aries-framework-javascript/commit/1d782f54bbb4abfeb6b6db6cd4f7164501b6c3d9))
- add initial askar package ([#1211](https://github.com/hyperledger/aries-framework-javascript/issues/1211)) ([f18d189](https://github.com/hyperledger/aries-framework-javascript/commit/f18d1890546f7d66571fe80f2f3fc1fead1cd4c3))
- add message pickup module ([#1413](https://github.com/hyperledger/aries-framework-javascript/issues/1413)) ([a8439db](https://github.com/hyperledger/aries-framework-javascript/commit/a8439db90fd11e014b457db476e8327b6ced6358))
- added endpoint setter to agent InitConfig ([#1278](https://github.com/hyperledger/aries-framework-javascript/issues/1278)) ([1d487b1](https://github.com/hyperledger/aries-framework-javascript/commit/1d487b1a7e11b3f18b5229ba580bd035a7f564a0))
- allow sending problem report when declining a proof request ([#1408](https://github.com/hyperledger/aries-framework-javascript/issues/1408)) ([b35fec4](https://github.com/hyperledger/aries-framework-javascript/commit/b35fec433f8fab513be2b8b6d073f23c6371b2ee))
- **anoncreds:** add legacy indy credential format ([#1220](https://github.com/hyperledger/aries-framework-javascript/issues/1220)) ([13f3740](https://github.com/hyperledger/aries-framework-javascript/commit/13f374079262168f90ec7de7c3393beb9651295c))
- **anoncreds:** legacy indy proof format service ([#1283](https://github.com/hyperledger/aries-framework-javascript/issues/1283)) ([c72fd74](https://github.com/hyperledger/aries-framework-javascript/commit/c72fd7416f2c1bc0497a84036e16adfa80585e49))
- **anoncreds:** store method name in records ([#1387](https://github.com/hyperledger/aries-framework-javascript/issues/1387)) ([47636b4](https://github.com/hyperledger/aries-framework-javascript/commit/47636b4a08ffbfa9a3f2a5a3c5aebda44f7d16c8))
- **askar:** import/export wallet support for SQLite ([#1377](https://github.com/hyperledger/aries-framework-javascript/issues/1377)) ([19cefa5](https://github.com/hyperledger/aries-framework-javascript/commit/19cefa54596a4e4848bdbe89306a884a5ce2e991))
- basic message pthid/thid support ([#1381](https://github.com/hyperledger/aries-framework-javascript/issues/1381)) ([f27fb99](https://github.com/hyperledger/aries-framework-javascript/commit/f27fb9921e11e5bcd654611d97d9fa1c446bc2d5))
- **cache:** add caching interface ([#1229](https://github.com/hyperledger/aries-framework-javascript/issues/1229)) ([25b2bcf](https://github.com/hyperledger/aries-framework-javascript/commit/25b2bcf81648100b572784e4489a288cc9da0557))
- **core:** add W3cCredentialsApi ([c888736](https://github.com/hyperledger/aries-framework-javascript/commit/c888736cb6b51014e23f5520fbc4074cf0e49e15))
- default return route ([#1327](https://github.com/hyperledger/aries-framework-javascript/issues/1327)) ([dbfebb4](https://github.com/hyperledger/aries-framework-javascript/commit/dbfebb4720da731dbe11efdccdd061d1da3d1323))
- **indy-vdr:** add indy-vdr package and indy vdr pool ([#1160](https://github.com/hyperledger/aries-framework-javascript/issues/1160)) ([e8d6ac3](https://github.com/hyperledger/aries-framework-javascript/commit/e8d6ac31a8e18847d99d7998bd7658439e48875b))
- **oob:** implicit invitations ([#1348](https://github.com/hyperledger/aries-framework-javascript/issues/1348)) ([fd13bb8](https://github.com/hyperledger/aries-framework-javascript/commit/fd13bb87a9ce9efb73bd780bd076b1da867688c5))
- **openid4vc-client:** openid authorization flow ([#1384](https://github.com/hyperledger/aries-framework-javascript/issues/1384)) ([996c08f](https://github.com/hyperledger/aries-framework-javascript/commit/996c08f8e32e58605408f5ed5b6d8116cea3b00c))
- **openid4vc-client:** pre-authorized ([#1243](https://github.com/hyperledger/aries-framework-javascript/issues/1243)) ([3d86e78](https://github.com/hyperledger/aries-framework-javascript/commit/3d86e78a4df87869aa5df4e28b79cd91787b61fb))
- **openid4vc:** jwt format and more crypto ([#1472](https://github.com/hyperledger/aries-framework-javascript/issues/1472)) ([bd4932d](https://github.com/hyperledger/aries-framework-javascript/commit/bd4932d34f7314a6d49097b6460c7570e1ebc7a8))
- optional routing for legacy connectionless invitation ([#1271](https://github.com/hyperledger/aries-framework-javascript/issues/1271)) ([7f65ba9](https://github.com/hyperledger/aries-framework-javascript/commit/7f65ba999ad1f49065d24966a1d7f3b82264ea55))
- outbound message send via session ([#1335](https://github.com/hyperledger/aries-framework-javascript/issues/1335)) ([582c711](https://github.com/hyperledger/aries-framework-javascript/commit/582c711728db12b7d38a0be2e9fa78dbf31b34c6))
- **proofs:** sort credentials based on revocation ([#1225](https://github.com/hyperledger/aries-framework-javascript/issues/1225)) ([0f6d231](https://github.com/hyperledger/aries-framework-javascript/commit/0f6d2312471efab20f560782c171434f907b6b9d))
- support for did:jwk and p-256, p-384, p-512 ([#1446](https://github.com/hyperledger/aries-framework-javascript/issues/1446)) ([700d3f8](https://github.com/hyperledger/aries-framework-javascript/commit/700d3f89728ce9d35e22519e505d8203a4c9031e))
- support more key types in jws service ([#1453](https://github.com/hyperledger/aries-framework-javascript/issues/1453)) ([8a3f03e](https://github.com/hyperledger/aries-framework-javascript/commit/8a3f03eb0dffcf46635556defdcebe1d329cf428))

### BREAKING CHANGES

- `Dispatcher.registerMessageHandler` has been removed in favour of `MessageHandlerRegistry.registerMessageHandler`. If you want to register message handlers in an extension module, you can use directly `agentContext.dependencyManager.registerMessageHandlers`.

Signed-off-by: Ariel Gentile <gentilester@gmail.com>

- Agent default outbound content type has been changed to DIDComm V1. If you want to use former behaviour, you can do it so by manually setting `didcommMimeType` in `Agent`'s init config:

```
  const agent = new Agent({ config: {
     ...
     didCommMimeType: DidCommMimeType.V0
  }, ...  })
```

- Agent-produced files will now be divided in different system paths depending on their nature: data, temp and cache. Previously, they were located at a single location, defaulting to a temporary directory.

If you specified a custom path in `FileSystem` object constructor, you now must provide an object containing `baseDataPath`, `baseTempPath` and `baseCachePath`. They can point to the same path, although it's recommended to specify different path to avoid future file clashes.

## [0.3.3](https://github.com/hyperledger/aries-framework-javascript/compare/v0.3.2...v0.3.3) (2023-01-18)

### Bug Fixes

- fix typing issues with typescript 4.9 ([#1214](https://github.com/hyperledger/aries-framework-javascript/issues/1214)) ([087980f](https://github.com/hyperledger/aries-framework-javascript/commit/087980f1adf3ee0bc434ca9782243a62c6124444))

### Features

- adding trust ping events and trust ping command ([#1182](https://github.com/hyperledger/aries-framework-javascript/issues/1182)) ([fd006f2](https://github.com/hyperledger/aries-framework-javascript/commit/fd006f262a91f901e7f8a9c6e6882ea178230005))
- **indy-sdk:** add indy-sdk package ([#1200](https://github.com/hyperledger/aries-framework-javascript/issues/1200)) ([9933b35](https://github.com/hyperledger/aries-framework-javascript/commit/9933b35a6aa4524caef8a885e71b742cd0d7186b))

## [0.3.2](https://github.com/hyperledger/aries-framework-javascript/compare/v0.3.1...v0.3.2) (2023-01-04)

### Bug Fixes

- **credentials:** typing if no modules provided ([#1188](https://github.com/hyperledger/aries-framework-javascript/issues/1188)) ([541356e](https://github.com/hyperledger/aries-framework-javascript/commit/541356e866bcd3ce06c69093d8cb6100dca4d09f))

## [0.3.1](https://github.com/hyperledger/aries-framework-javascript/compare/v0.3.0...v0.3.1) (2022-12-27)

### Bug Fixes

- missing migration script and exports ([#1184](https://github.com/hyperledger/aries-framework-javascript/issues/1184)) ([460510d](https://github.com/hyperledger/aries-framework-javascript/commit/460510db43a7c63fd8dc1c3614be03fd8772f63c))

# [0.3.0](https://github.com/hyperledger/aries-framework-javascript/compare/v0.2.5...v0.3.0) (2022-12-22)

### Bug Fixes

- **connections:** do not log AgentContext object ([#1085](https://github.com/hyperledger/aries-framework-javascript/issues/1085)) ([ef20f1e](https://github.com/hyperledger/aries-framework-javascript/commit/ef20f1ef420e5345825cc9e79f52ecfb191489fc))
- **connections:** use new did for each connection from reusable invitation ([#1174](https://github.com/hyperledger/aries-framework-javascript/issues/1174)) ([c0569b8](https://github.com/hyperledger/aries-framework-javascript/commit/c0569b88c27ee7785cf150ee14a5f9ebcc99898b))
- credential values encoding ([#1157](https://github.com/hyperledger/aries-framework-javascript/issues/1157)) ([0e89e6c](https://github.com/hyperledger/aries-framework-javascript/commit/0e89e6c9f4a3cdbf98c5d85de2e015becdc3e1fc))
- expose AttachmentData and DiscoverFeaturesEvents ([#1146](https://github.com/hyperledger/aries-framework-javascript/issues/1146)) ([e48f481](https://github.com/hyperledger/aries-framework-javascript/commit/e48f481024810a0eba17e32b995a8db0730bbcb1))
- expose OutOfBandEvents ([#1151](https://github.com/hyperledger/aries-framework-javascript/issues/1151)) ([3c040b6](https://github.com/hyperledger/aries-framework-javascript/commit/3c040b68e0c8a7f5625df427a2ace28f0223bfbc))
- invalid injection symbols in W3cCredService ([#786](https://github.com/hyperledger/aries-framework-javascript/issues/786)) ([38cb106](https://github.com/hyperledger/aries-framework-javascript/commit/38cb1065e6fbf46c676c7ad52e160b721cb1b4e6))
- **problem-report:** proper string interpolation ([#1120](https://github.com/hyperledger/aries-framework-javascript/issues/1120)) ([c4e9679](https://github.com/hyperledger/aries-framework-javascript/commit/c4e96799d8390225ba5aaecced19c79ec1f12fa8))
- **proofs:** await shouldAutoRespond to correctly handle the check ([#1116](https://github.com/hyperledger/aries-framework-javascript/issues/1116)) ([f294129](https://github.com/hyperledger/aries-framework-javascript/commit/f294129821cd6fcb9b82d875f19cab5a63310b23))
- remove sensitive information from agent config toJSON() method ([#1112](https://github.com/hyperledger/aries-framework-javascript/issues/1112)) ([427a80f](https://github.com/hyperledger/aries-framework-javascript/commit/427a80f7759e029222119cf815a866fe9899a170))
- **routing:** add connection type on mediation grant ([#1147](https://github.com/hyperledger/aries-framework-javascript/issues/1147)) ([979c695](https://github.com/hyperledger/aries-framework-javascript/commit/979c69506996fb1853e200b53d052d474f497bf1))
- **routing:** async message pickup on init ([#1093](https://github.com/hyperledger/aries-framework-javascript/issues/1093)) ([15cfd91](https://github.com/hyperledger/aries-framework-javascript/commit/15cfd91d1c6ba8e3f8355db4c4941fcbd85382ac))
- unable to resolve nodejs document loader in react native environment ([#1003](https://github.com/hyperledger/aries-framework-javascript/issues/1003)) ([5cdcfa2](https://github.com/hyperledger/aries-framework-javascript/commit/5cdcfa203e6d457f74250028678dbc3393d8eb5c))
- use custom document loader in jsonld.frame ([#1119](https://github.com/hyperledger/aries-framework-javascript/issues/1119)) ([36d4656](https://github.com/hyperledger/aries-framework-javascript/commit/36d465669c6714b00167b17fe2924f3c53b5fa68))
- **vc:** change pubKey input from Buffer to Uint8Array ([#935](https://github.com/hyperledger/aries-framework-javascript/issues/935)) ([80c3740](https://github.com/hyperledger/aries-framework-javascript/commit/80c3740f625328125fe8121035f2d83ce1dee6a5))

- refactor!: rename Handler to MessageHandler (#1161) ([5e48696](https://github.com/hyperledger/aries-framework-javascript/commit/5e48696ec16d88321f225628e6cffab243718b4c)), closes [#1161](https://github.com/hyperledger/aries-framework-javascript/issues/1161)
- feat!: use did:key in protocols by default (#1149) ([9f10da8](https://github.com/hyperledger/aries-framework-javascript/commit/9f10da85d8739f7be6c5e6624ba5f53a1d6a3116)), closes [#1149](https://github.com/hyperledger/aries-framework-javascript/issues/1149)
- feat(action-menu)!: move to separate package (#1049) ([e0df0d8](https://github.com/hyperledger/aries-framework-javascript/commit/e0df0d884b1a7816c7c638406606e45f6e169ff4)), closes [#1049](https://github.com/hyperledger/aries-framework-javascript/issues/1049)
- feat(question-answer)!: separate logic to a new module (#1040) ([97d3073](https://github.com/hyperledger/aries-framework-javascript/commit/97d3073aa9300900740c3e8aee8233d38849293d)), closes [#1040](https://github.com/hyperledger/aries-framework-javascript/issues/1040)
- feat!: agent module registration api (#955) ([82a17a3](https://github.com/hyperledger/aries-framework-javascript/commit/82a17a3a1eff61008b2e91695f6527501fe44237)), closes [#955](https://github.com/hyperledger/aries-framework-javascript/issues/955)
- feat!: Discover Features V2 (#991) ([273e353](https://github.com/hyperledger/aries-framework-javascript/commit/273e353f4b36ab5d2420356eb3a53dcfb1c59ec6)), closes [#991](https://github.com/hyperledger/aries-framework-javascript/issues/991)
- refactor!: module to api and module config (#943) ([7cbccb1](https://github.com/hyperledger/aries-framework-javascript/commit/7cbccb1ce9dae2cb1e4887220898f2f74cca8dbe)), closes [#943](https://github.com/hyperledger/aries-framework-javascript/issues/943)
- refactor!: add agent context (#920) ([b47cfcb](https://github.com/hyperledger/aries-framework-javascript/commit/b47cfcba1450cd1d6839bf8192d977bfe33f1bb0)), closes [#920](https://github.com/hyperledger/aries-framework-javascript/issues/920)

### Features

- add agent context provider ([#921](https://github.com/hyperledger/aries-framework-javascript/issues/921)) ([a1b1e5a](https://github.com/hyperledger/aries-framework-javascript/commit/a1b1e5a22fd4ab9ef593b5cd7b3c710afcab3142))
- add base agent class ([#922](https://github.com/hyperledger/aries-framework-javascript/issues/922)) ([113a575](https://github.com/hyperledger/aries-framework-javascript/commit/113a5756ed1b630b3c05929d79f6afcceae4fa6a))
- add dynamic suite and signing provider ([#949](https://github.com/hyperledger/aries-framework-javascript/issues/949)) ([ab8b8ef](https://github.com/hyperledger/aries-framework-javascript/commit/ab8b8ef1357c7a8dc338eaea16b20d93a0c92d4f))
- add indynamespace for ledger id for anoncreds ([#965](https://github.com/hyperledger/aries-framework-javascript/issues/965)) ([df3777e](https://github.com/hyperledger/aries-framework-javascript/commit/df3777ee394211a401940bf27b3e5a9e1688f6b2))
- add present proof v2 ([#979](https://github.com/hyperledger/aries-framework-javascript/issues/979)) ([f38ac05](https://github.com/hyperledger/aries-framework-javascript/commit/f38ac05875e38b6cc130bcb9f603e82657aabe9c))
- bbs createKey, sign and verify ([#684](https://github.com/hyperledger/aries-framework-javascript/issues/684)) ([5f91738](https://github.com/hyperledger/aries-framework-javascript/commit/5f91738337fac1efbbb4597e7724791e542f0762))
- **bbs:** extract bbs logic into separate module ([#1035](https://github.com/hyperledger/aries-framework-javascript/issues/1035)) ([991151b](https://github.com/hyperledger/aries-framework-javascript/commit/991151bfff829fa11cd98a1951be9b54a77385a8))
- **dids:** add did registrar ([#953](https://github.com/hyperledger/aries-framework-javascript/issues/953)) ([93f3c93](https://github.com/hyperledger/aries-framework-javascript/commit/93f3c93310f9dae032daa04a920b7df18e2f8a65))
- fetch verification method types by proof type ([#913](https://github.com/hyperledger/aries-framework-javascript/issues/913)) ([ed69dac](https://github.com/hyperledger/aries-framework-javascript/commit/ed69dac7784feea7abe430ad685911faa477fa11))
- issue credentials v2 (W3C/JSON-LD) ([#1092](https://github.com/hyperledger/aries-framework-javascript/issues/1092)) ([574e6a6](https://github.com/hyperledger/aries-framework-javascript/commit/574e6a62ebbd77902c50da821afdfd1b1558abe7))
- jsonld-credential support ([#718](https://github.com/hyperledger/aries-framework-javascript/issues/718)) ([ea34c47](https://github.com/hyperledger/aries-framework-javascript/commit/ea34c4752712efecf3367c5a5fc4b06e66c1e9d7))
- **ledger:** smart schema and credential definition registration ([#900](https://github.com/hyperledger/aries-framework-javascript/issues/900)) ([1e708e9](https://github.com/hyperledger/aries-framework-javascript/commit/1e708e9aeeb63977a7305999a5027d9743a56f91))
- **oob:** receive Invitation with timeout ([#1156](https://github.com/hyperledger/aries-framework-javascript/issues/1156)) ([9352fa5](https://github.com/hyperledger/aries-framework-javascript/commit/9352fa5eea1e01d29acd0757298398aac45fcab2))
- **proofs:** add getRequestedCredentialsForProofRequest ([#1028](https://github.com/hyperledger/aries-framework-javascript/issues/1028)) ([26bb9c9](https://github.com/hyperledger/aries-framework-javascript/commit/26bb9c9989a97bf22859a7eccbeabc632521a6c2))
- **proofs:** delete associated didcomm messages ([#1021](https://github.com/hyperledger/aries-framework-javascript/issues/1021)) ([dba46c3](https://github.com/hyperledger/aries-framework-javascript/commit/dba46c3bc3a1d6b5669f296f0c45cd03dc2294b1))
- **proofs:** proof negotiation ([#1131](https://github.com/hyperledger/aries-framework-javascript/issues/1131)) ([c752461](https://github.com/hyperledger/aries-framework-javascript/commit/c75246147ffc6be3c815c66b0a7ad66e48996568))
- **proofs:** proofs module migration script for 0.3.0 ([#1020](https://github.com/hyperledger/aries-framework-javascript/issues/1020)) ([5e9e0fc](https://github.com/hyperledger/aries-framework-javascript/commit/5e9e0fcc7f13b8a27e35761464c8fd970c17d28c))
- remove keys on mediator when deleting connections ([#1143](https://github.com/hyperledger/aries-framework-javascript/issues/1143)) ([1af57fd](https://github.com/hyperledger/aries-framework-javascript/commit/1af57fde5016300e243eafbbdea5ea26bd8ef313))
- **routing:** add reconnection parameters to RecipientModuleConfig ([#1070](https://github.com/hyperledger/aries-framework-javascript/issues/1070)) ([d4fd1ae](https://github.com/hyperledger/aries-framework-javascript/commit/d4fd1ae16dc1fd99b043835b97b33f4baece6790))
- **tenants:** initial tenants module ([#932](https://github.com/hyperledger/aries-framework-javascript/issues/932)) ([7cbd08c](https://github.com/hyperledger/aries-framework-javascript/commit/7cbd08c9bb4b14ab2db92b0546d6fcb520f5fec9))
- **tenants:** tenant lifecycle ([#942](https://github.com/hyperledger/aries-framework-javascript/issues/942)) ([adfa65b](https://github.com/hyperledger/aries-framework-javascript/commit/adfa65b13152a980ba24b03082446e91d8ec5b37))
- **vc:** delete w3c credential record ([#886](https://github.com/hyperledger/aries-framework-javascript/issues/886)) ([be37011](https://github.com/hyperledger/aries-framework-javascript/commit/be37011c139c5cc69fc591060319d8c373e9508b))
- **w3c:** add custom document loader option ([#1159](https://github.com/hyperledger/aries-framework-javascript/issues/1159)) ([ff6abdf](https://github.com/hyperledger/aries-framework-javascript/commit/ff6abdfc4e8ca64dd5a3b9859474bfc09e1a6c21))

### BREAKING CHANGES

- Handler has been renamed to MessageHandler to be more descriptive, along with related types and methods. This means:

Handler is now MessageHandler
HandlerInboundMessage is now MessageHandlerInboundMessage
Dispatcher.registerHandler is now Dispatcher.registerMessageHandlers

- `useDidKeyInProtocols` configuration parameter is now enabled by default. If your agent only interacts with modern agents (e.g. Credo 0.2.5 and newer) this will not represent any issue. Otherwise it is safer to explicitly set it to `false`. However, keep in mind that we expect this setting to be deprecated in the future, so we encourage you to update all your agents to use did:key.
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

- custom modules have been moved to the .modules namespace. In addition the agent constructor has been updated to a single options object that contains the `config` and `dependencies` properties. Instead of constructing the agent like this:

```ts
const agent = new Agent(
  {
    /* config */
  },
  agentDependencies
)
```

You should now construct it like this:

```ts
const agent = new Agent({
  config: {
    /* config */
  },
  dependencies: agentDependencies,
})
```

This allows for the new custom modules to be defined in the agent constructor.

- - `queryFeatures` method parameters have been unified to a single `QueryFeaturesOptions` object that requires specification of Discover Features protocol to be used.

* `isProtocolSupported` has been replaced by the more general synchronous mode of `queryFeatures`, which works when `awaitDisclosures` in options is set. Instead of returning a boolean, it returns an object with matching features
* Custom modules implementing protocols must register them in Feature Registry in order to let them be discovered by other agents (this can be done in module `register(dependencyManager, featureRegistry)` method)

- All module api classes have been renamed from `XXXModule` to `XXXApi`. A module now represents a module plugin, and is separate from the API of a module. If you previously imported e.g. the `CredentialsModule` class, you should now import the `CredentialsApi` class
- To make AFJ multi-tenancy ready, all services and repositories have been made stateless. A new `AgentContext` is introduced that holds the current context, which is passed to each method call. The public API hasn't been affected, but due to the large impact of this change it is marked as breaking.

## [0.2.5](https://github.com/hyperledger/aries-framework-javascript/compare/v0.2.4...v0.2.5) (2022-10-13)

### Bug Fixes

- **oob:** allow encoding in content type header ([#1037](https://github.com/hyperledger/aries-framework-javascript/issues/1037)) ([e1d6592](https://github.com/hyperledger/aries-framework-javascript/commit/e1d6592b818bc4348078ca6593eea4641caafae5))
- **oob:** set connection alias when creating invitation ([#1047](https://github.com/hyperledger/aries-framework-javascript/issues/1047)) ([7be979a](https://github.com/hyperledger/aries-framework-javascript/commit/7be979a74b86c606db403c8df04cfc8be2aae249))

### Features

- connection type ([#994](https://github.com/hyperledger/aries-framework-javascript/issues/994)) ([0d14a71](https://github.com/hyperledger/aries-framework-javascript/commit/0d14a7157e2118592829109dbc5c793faee1e201))
- expose findAllByQuery method in modules and services ([#1044](https://github.com/hyperledger/aries-framework-javascript/issues/1044)) ([9dd95e8](https://github.com/hyperledger/aries-framework-javascript/commit/9dd95e81770d3140558196d2b5b508723f918f04))
- improve sending error handling ([#1045](https://github.com/hyperledger/aries-framework-javascript/issues/1045)) ([a230841](https://github.com/hyperledger/aries-framework-javascript/commit/a230841aa99102bcc8b60aa2a23040f13a929a6c))
- possibility to set masterSecretId inside of WalletConfig ([#1043](https://github.com/hyperledger/aries-framework-javascript/issues/1043)) ([8a89ad2](https://github.com/hyperledger/aries-framework-javascript/commit/8a89ad2624922e5e5455f8881d1ccc656d6b33ec))
- use did:key flag ([#1029](https://github.com/hyperledger/aries-framework-javascript/issues/1029)) ([8efade5](https://github.com/hyperledger/aries-framework-javascript/commit/8efade5b2a885f0767ac8b10cba8582fe9ff486a))

## [0.2.4](https://github.com/hyperledger/aries-framework-javascript/compare/v0.2.3...v0.2.4) (2022-09-10)

### Bug Fixes

- avoid crash when an unexpected message arrives ([#1019](https://github.com/hyperledger/aries-framework-javascript/issues/1019)) ([2cfadd9](https://github.com/hyperledger/aries-framework-javascript/commit/2cfadd9167438a9446d26b933aa64521d8be75e7))
- **ledger:** check taa version instad of aml version ([#1013](https://github.com/hyperledger/aries-framework-javascript/issues/1013)) ([4ca56f6](https://github.com/hyperledger/aries-framework-javascript/commit/4ca56f6b677f45aa96c91b5c5ee8df210722609e))
- **ledger:** remove poolConnected on pool close ([#1011](https://github.com/hyperledger/aries-framework-javascript/issues/1011)) ([f0ca8b6](https://github.com/hyperledger/aries-framework-javascript/commit/f0ca8b6346385fc8c4811fbd531aa25a386fcf30))
- **question-answer:** question answer protocol state/role check ([#1001](https://github.com/hyperledger/aries-framework-javascript/issues/1001)) ([4b90e87](https://github.com/hyperledger/aries-framework-javascript/commit/4b90e876cc8377e7518e05445beb1a6b524840c4))

### Features

- Action Menu protocol (Aries RFC 0509) implementation ([#974](https://github.com/hyperledger/aries-framework-javascript/issues/974)) ([60a8091](https://github.com/hyperledger/aries-framework-javascript/commit/60a8091d6431c98f764b2b94bff13ee97187b915))
- **routing:** add settings to control back off strategy on mediator reconnection ([#1017](https://github.com/hyperledger/aries-framework-javascript/issues/1017)) ([543437c](https://github.com/hyperledger/aries-framework-javascript/commit/543437cd94d3023139b259ee04d6ad51cf653794))

## [0.2.3](https://github.com/hyperledger/aries-framework-javascript/compare/v0.2.2...v0.2.3) (2022-08-30)

### Bug Fixes

- export the KeyDerivationMethod ([#958](https://github.com/hyperledger/aries-framework-javascript/issues/958)) ([04ab1cc](https://github.com/hyperledger/aries-framework-javascript/commit/04ab1cca853284d144fd64d35e26e9dfe77d4a1b))
- expose oob domain ([#990](https://github.com/hyperledger/aries-framework-javascript/issues/990)) ([dad975d](https://github.com/hyperledger/aries-framework-javascript/commit/dad975d9d9b658c6b37749ece2a91381e2a314c9))
- **generic-records:** support custom id property ([#964](https://github.com/hyperledger/aries-framework-javascript/issues/964)) ([0f690a0](https://github.com/hyperledger/aries-framework-javascript/commit/0f690a0564a25204cacfae7cd958f660f777567e))

### Features

- always initialize mediator ([#985](https://github.com/hyperledger/aries-framework-javascript/issues/985)) ([b699977](https://github.com/hyperledger/aries-framework-javascript/commit/b69997744ac9e30ffba22daac7789216d2683e36))
- delete by record id ([#983](https://github.com/hyperledger/aries-framework-javascript/issues/983)) ([d8a30d9](https://github.com/hyperledger/aries-framework-javascript/commit/d8a30d94d336cf3417c2cd00a8110185dde6a106))
- **ledger:** handle REQNACK response for write request ([#967](https://github.com/hyperledger/aries-framework-javascript/issues/967)) ([6468a93](https://github.com/hyperledger/aries-framework-javascript/commit/6468a9311c8458615871e1e85ba3f3b560453715))
- OOB public did ([#930](https://github.com/hyperledger/aries-framework-javascript/issues/930)) ([c99f3c9](https://github.com/hyperledger/aries-framework-javascript/commit/c99f3c9152a79ca6a0a24fdc93e7f3bebbb9d084))
- **proofs:** present proof as nested protocol ([#972](https://github.com/hyperledger/aries-framework-javascript/issues/972)) ([52247d9](https://github.com/hyperledger/aries-framework-javascript/commit/52247d997c5910924d3099c736dd2e20ec86a214))
- **routing:** manual mediator pickup lifecycle management ([#989](https://github.com/hyperledger/aries-framework-javascript/issues/989)) ([69d4906](https://github.com/hyperledger/aries-framework-javascript/commit/69d4906a0ceb8a311ca6bdad5ed6d2048335109a))
- **routing:** pickup v2 mediator role basic implementation ([#975](https://github.com/hyperledger/aries-framework-javascript/issues/975)) ([a989556](https://github.com/hyperledger/aries-framework-javascript/commit/a98955666853471d504f8a5c8c4623e18ba8c8ed))
- **routing:** support promise in message repo ([#959](https://github.com/hyperledger/aries-framework-javascript/issues/959)) ([79c5d8d](https://github.com/hyperledger/aries-framework-javascript/commit/79c5d8d76512b641167bce46e82f34cf22bc285e))

## [0.2.2](https://github.com/hyperledger/aries-framework-javascript/compare/v0.2.1...v0.2.2) (2022-07-15)

### Bug Fixes

- no return routing and wait for ping ([#946](https://github.com/hyperledger/aries-framework-javascript/issues/946)) ([f48f3c1](https://github.com/hyperledger/aries-framework-javascript/commit/f48f3c18bcc550b5304f43d8564dbeb1192490e0))

### Features

- **oob:** support fetching shortened invitation urls ([#840](https://github.com/hyperledger/aries-framework-javascript/issues/840)) ([60ee0e5](https://github.com/hyperledger/aries-framework-javascript/commit/60ee0e59bbcdf7fab0e5880a714f0ca61d5da508))
- **routing:** support did:key in RFC0211 ([#950](https://github.com/hyperledger/aries-framework-javascript/issues/950)) ([dc45c01](https://github.com/hyperledger/aries-framework-javascript/commit/dc45c01a27fa68f8caacf3e51382c37f26b1d4fa))

## [0.2.1](https://github.com/hyperledger/aries-framework-javascript/compare/v0.2.0...v0.2.1) (2022-07-08)

### Bug Fixes

- clone record before emitting event ([#938](https://github.com/hyperledger/aries-framework-javascript/issues/938)) ([f907fe9](https://github.com/hyperledger/aries-framework-javascript/commit/f907fe99558dd77dc2f77696be2a1b846466ab95))
- missing module exports ([#927](https://github.com/hyperledger/aries-framework-javascript/issues/927)) ([95f90a5](https://github.com/hyperledger/aries-framework-javascript/commit/95f90a5dbe16a90ecb697d164324db20115976ae))
- **oob:** support legacy prefix in attachments ([#931](https://github.com/hyperledger/aries-framework-javascript/issues/931)) ([82863f3](https://github.com/hyperledger/aries-framework-javascript/commit/82863f326d95025c4c01349a4c14b37e6ff6a1db))

### Features

- **credentials:** added credential sendProblemReport method ([#906](https://github.com/hyperledger/aries-framework-javascript/issues/906)) ([90dc7bb](https://github.com/hyperledger/aries-framework-javascript/commit/90dc7bbdb18a77e62026f4d837723ed9a208c19b))
- initial plugin api ([#907](https://github.com/hyperledger/aries-framework-javascript/issues/907)) ([6d88aa4](https://github.com/hyperledger/aries-framework-javascript/commit/6d88aa4537ab2a9494ffea8cdfb4723cf915f291))
- **oob:** allow to append attachments to invitations ([#926](https://github.com/hyperledger/aries-framework-javascript/issues/926)) ([4800700](https://github.com/hyperledger/aries-framework-javascript/commit/4800700e9f138f02e67c93e8882f45d723dd22cb))
- **routing:** add routing service ([#909](https://github.com/hyperledger/aries-framework-javascript/issues/909)) ([6e51e90](https://github.com/hyperledger/aries-framework-javascript/commit/6e51e9023cca524252f40a18bf37ec81ec582a1a))

# [0.2.0](https://github.com/hyperledger/aries-framework-javascript/compare/v0.1.0...v0.2.0) (2022-06-24)

### Bug Fixes

- add BBS context to DidDoc ([#789](https://github.com/hyperledger/aries-framework-javascript/issues/789)) ([c8ca091](https://github.com/hyperledger/aries-framework-javascript/commit/c8ca091f22c58c8d5273be36908df0a188020ddb))
- add oob state and role check ([#777](https://github.com/hyperledger/aries-framework-javascript/issues/777)) ([1c74618](https://github.com/hyperledger/aries-framework-javascript/commit/1c7461836578a62ec545de3a0c8fcdc7de2f4d8f))
- agent isinitialized on shutdown ([#665](https://github.com/hyperledger/aries-framework-javascript/issues/665)) ([d1049e0](https://github.com/hyperledger/aries-framework-javascript/commit/d1049e0fe99665e7fff8c4f1fe89f7ce19ccce84))
- allow agent without inbound endpoint to connect when using multi-use invitation ([#712](https://github.com/hyperledger/aries-framework-javascript/issues/712)) ([01c5bb3](https://github.com/hyperledger/aries-framework-javascript/commit/01c5bb3b67786fa7efa361d02bfddde7d113eacf)), closes [#483](https://github.com/hyperledger/aries-framework-javascript/issues/483)
- **basic-message:** assert connection is ready ([#657](https://github.com/hyperledger/aries-framework-javascript/issues/657)) ([9f9156c](https://github.com/hyperledger/aries-framework-javascript/commit/9f9156cb96a4e8d7013d4968359bd0858830f833))
- check for "REQNACK" response from indy ledger ([#626](https://github.com/hyperledger/aries-framework-javascript/issues/626)) ([ce66f07](https://github.com/hyperledger/aries-framework-javascript/commit/ce66f0744976e8f2abfa05055bfa384f3d084321))
- check proof request group names do not overlap ([#638](https://github.com/hyperledger/aries-framework-javascript/issues/638)) ([0731ccd](https://github.com/hyperledger/aries-framework-javascript/commit/0731ccd7683ab1e0e8057fbf3b909bdd3227da88))
- clone record before emitting event ([#833](https://github.com/hyperledger/aries-framework-javascript/issues/833)) ([8192861](https://github.com/hyperledger/aries-framework-javascript/commit/819286190985934438cb236e8d3f4ea7145f0cec))
- close session early if no return route ([#715](https://github.com/hyperledger/aries-framework-javascript/issues/715)) ([2e65408](https://github.com/hyperledger/aries-framework-javascript/commit/2e6540806f2d67bef16004f6e8398c5bf7a05bcf))
- **connections:** allow ; to convert legacy did ([#882](https://github.com/hyperledger/aries-framework-javascript/issues/882)) ([448a29d](https://github.com/hyperledger/aries-framework-javascript/commit/448a29db44e5ec0b8f01d36ba139ac760654a635))
- **connections:** didexchange to connection state ([#823](https://github.com/hyperledger/aries-framework-javascript/issues/823)) ([dda1bd3](https://github.com/hyperledger/aries-framework-javascript/commit/dda1bd33882f7915a0ef1720eff0b1804f2c946c))
- **connections:** fix log of object in string ([#904](https://github.com/hyperledger/aries-framework-javascript/issues/904)) ([95d893e](https://github.com/hyperledger/aries-framework-javascript/commit/95d893e6f37014f14bb991c5f12a9da0f4d627ab))
- **connections:** set image url in create request ([#896](https://github.com/hyperledger/aries-framework-javascript/issues/896)) ([8396965](https://github.com/hyperledger/aries-framework-javascript/commit/8396965bfb2922bd5606383c12788d9c60968918))
- **core:** allow JSON as input for indy attributes ([#813](https://github.com/hyperledger/aries-framework-javascript/issues/813)) ([478fda3](https://github.com/hyperledger/aries-framework-javascript/commit/478fda3bb28171ce395bb67f25d2f2e3668c52b0))
- **core:** error if unpacked message does not match JWE structure ([#639](https://github.com/hyperledger/aries-framework-javascript/issues/639)) ([c43cfaa](https://github.com/hyperledger/aries-framework-javascript/commit/c43cfaa340c6ea8f42f015f6f280cbaece8c58bb))
- **core:** expose CredentialPreviewAttribute ([#796](https://github.com/hyperledger/aries-framework-javascript/issues/796)) ([65d7f15](https://github.com/hyperledger/aries-framework-javascript/commit/65d7f15cff3384c2f34e9b0c64fab574e6299484))
- **core:** set tags in MediationRecord constructor ([#686](https://github.com/hyperledger/aries-framework-javascript/issues/686)) ([1b01bce](https://github.com/hyperledger/aries-framework-javascript/commit/1b01bceed3435fc7f92b051110fcc315bcac08f3))
- credential preview attributes mismatch schema attributes ([#625](https://github.com/hyperledger/aries-framework-javascript/issues/625)) ([c0095b8](https://github.com/hyperledger/aries-framework-javascript/commit/c0095b8ee855514c7b3c01010041e623458eb8de))
- **credentials:** add missing issue credential v1 proposal attributes ([#798](https://github.com/hyperledger/aries-framework-javascript/issues/798)) ([966cc3d](https://github.com/hyperledger/aries-framework-javascript/commit/966cc3d178be7296f073eb815c36792e2137b64b))
- **credentials:** default for credentials in exchange record ([#816](https://github.com/hyperledger/aries-framework-javascript/issues/816)) ([df1a00b](https://github.com/hyperledger/aries-framework-javascript/commit/df1a00b0968fa42dbaf606c9ec2325b778a0317d))
- **credentials:** do not store offer attributes ([#892](https://github.com/hyperledger/aries-framework-javascript/issues/892)) ([39c4c0d](https://github.com/hyperledger/aries-framework-javascript/commit/39c4c0ddee5e8b9563b6f174a8ad808d4b9cf307))
- **credentials:** indy cred attachment format ([#862](https://github.com/hyperledger/aries-framework-javascript/issues/862)) ([16935e2](https://github.com/hyperledger/aries-framework-javascript/commit/16935e2976252aac6bd67c5000779da1c5c1a828))
- **credentials:** miscellaneous typing issues ([#880](https://github.com/hyperledger/aries-framework-javascript/issues/880)) ([ad35b08](https://github.com/hyperledger/aries-framework-javascript/commit/ad35b0826b5ee592b64d898fe629391bd34444aa))
- **credentials:** parse and validate preview [@type](https://github.com/type) ([#861](https://github.com/hyperledger/aries-framework-javascript/issues/861)) ([1cc8f46](https://github.com/hyperledger/aries-framework-javascript/commit/1cc8f4661c666fb49625cf935877ff5e5d88b524))
- **credentials:** proposal preview attribute ([#855](https://github.com/hyperledger/aries-framework-javascript/issues/855)) ([3022bd2](https://github.com/hyperledger/aries-framework-javascript/commit/3022bd2c37dac381f2045f5afab329bcc3806d26))
- **credentials:** store revocation identifiers ([#864](https://github.com/hyperledger/aries-framework-javascript/issues/864)) ([7374799](https://github.com/hyperledger/aries-framework-javascript/commit/73747996dab4f7d63f616ebfc9758d0fcdffd3eb))
- **credentials:** use interface in module api ([#856](https://github.com/hyperledger/aries-framework-javascript/issues/856)) ([58e6603](https://github.com/hyperledger/aries-framework-javascript/commit/58e6603ab925aa1f4f41673452b83ef75b538bdc))
- delete credentials ([#766](https://github.com/hyperledger/aries-framework-javascript/issues/766)) ([cbdff28](https://github.com/hyperledger/aries-framework-javascript/commit/cbdff28d566e3eaabcb806d9158c62476379b5dd))
- delete credentials ([#770](https://github.com/hyperledger/aries-framework-javascript/issues/770)) ([f1e0412](https://github.com/hyperledger/aries-framework-javascript/commit/f1e0412200fcc77ba928c0af2b099326f7a47ebf))
- did sov service type resolving ([#689](https://github.com/hyperledger/aries-framework-javascript/issues/689)) ([dbcd8c4](https://github.com/hyperledger/aries-framework-javascript/commit/dbcd8c4ae88afd12098b55acccb70237a8d54cd7))
- disallow floating promises ([#704](https://github.com/hyperledger/aries-framework-javascript/issues/704)) ([549647d](https://github.com/hyperledger/aries-framework-javascript/commit/549647db6b7492e593022dff1d4162efd2d95a39))
- disallow usage of global buffer ([#601](https://github.com/hyperledger/aries-framework-javascript/issues/601)) ([87ecd8c](https://github.com/hyperledger/aries-framework-javascript/commit/87ecd8c622c6b602a23af9fa2ecc50820bce32f8))
- do not import from src dir ([#748](https://github.com/hyperledger/aries-framework-javascript/issues/748)) ([1dfa32e](https://github.com/hyperledger/aries-framework-javascript/commit/1dfa32edc6029793588040de9b8b933a0615e926))
- do not import test logger in src ([#746](https://github.com/hyperledger/aries-framework-javascript/issues/746)) ([5c80004](https://github.com/hyperledger/aries-framework-javascript/commit/5c80004228211a338c1358c99921a45c344a33bb))
- do not use basic message id as record id ([#677](https://github.com/hyperledger/aries-framework-javascript/issues/677)) ([3713398](https://github.com/hyperledger/aries-framework-javascript/commit/3713398b87f732841db8131055d2437b0af9a435))
- extract indy did from peer did in indy credential request ([#790](https://github.com/hyperledger/aries-framework-javascript/issues/790)) ([09e5557](https://github.com/hyperledger/aries-framework-javascript/commit/09e55574440e63418df0697067b9ffad11936027))
- incorrect encoding of services for did:peer ([#610](https://github.com/hyperledger/aries-framework-javascript/issues/610)) ([28b1715](https://github.com/hyperledger/aries-framework-javascript/commit/28b1715e388f5ed15cb937712b663627c3619465))
- **indy:** async ledger connection issues on iOS ([#803](https://github.com/hyperledger/aries-framework-javascript/issues/803)) ([8055652](https://github.com/hyperledger/aries-framework-javascript/commit/8055652e63309cf7b20676119b71d846b295d468))
- issue where attributes and predicates match ([#640](https://github.com/hyperledger/aries-framework-javascript/issues/640)) ([15a5e6b](https://github.com/hyperledger/aries-framework-javascript/commit/15a5e6be73d1d752dbaef40fc26416e545f763a4))
- leading zeros in credential value encoding ([#632](https://github.com/hyperledger/aries-framework-javascript/issues/632)) ([0d478a7](https://github.com/hyperledger/aries-framework-javascript/commit/0d478a7f198fec2ed5fceada77c9819ebab96a81))
- mediation record checks for pickup v2 ([#736](https://github.com/hyperledger/aries-framework-javascript/issues/736)) ([2ad600c](https://github.com/hyperledger/aries-framework-javascript/commit/2ad600c066598526c421244cbe82bafc6cfbb85a))
- miscellaneous issue credential v2 fixes ([#769](https://github.com/hyperledger/aries-framework-javascript/issues/769)) ([537b51e](https://github.com/hyperledger/aries-framework-javascript/commit/537b51efbf5ca1d50cd03e3ca4314da8b431c076))
- **node:** allow to import node package without postgres ([#757](https://github.com/hyperledger/aries-framework-javascript/issues/757)) ([59e1058](https://github.com/hyperledger/aries-framework-javascript/commit/59e10589acee987fb46f9cbaa3583ba8dcd70b87))
- **oob:** allow legacy did sov prefix ([#889](https://github.com/hyperledger/aries-framework-javascript/issues/889)) ([c7766d0](https://github.com/hyperledger/aries-framework-javascript/commit/c7766d0454cb764b771bb1ef263e81210368588a))
- **oob:** check service is string instance ([#814](https://github.com/hyperledger/aries-framework-javascript/issues/814)) ([bd1e677](https://github.com/hyperledger/aries-framework-javascript/commit/bd1e677f41a6d37f75746616681fc6d6ad7ca90e))
- **oob:** export messages to public ([#828](https://github.com/hyperledger/aries-framework-javascript/issues/828)) ([10cf74d](https://github.com/hyperledger/aries-framework-javascript/commit/10cf74d473ce00dca4bc624d60f379e8a78f9b63))
- **oob:** expose oob record ([#839](https://github.com/hyperledger/aries-framework-javascript/issues/839)) ([c297dfd](https://github.com/hyperledger/aries-framework-javascript/commit/c297dfd9cbdafcb2cdb1f7bcbd466c42f1b8e319))
- **oob:** expose parseInvitation publicly ([#834](https://github.com/hyperledger/aries-framework-javascript/issues/834)) ([5767500](https://github.com/hyperledger/aries-framework-javascript/commit/5767500b3a797f794fc9ed8147e501e9566d2675))
- **oob:** legacy invitation with multiple endpoint ([#825](https://github.com/hyperledger/aries-framework-javascript/issues/825)) ([8dd7f80](https://github.com/hyperledger/aries-framework-javascript/commit/8dd7f8049ea9c566b5c66b0c46c36f69e001ed3a))
- optional fields in did document ([#726](https://github.com/hyperledger/aries-framework-javascript/issues/726)) ([2da845d](https://github.com/hyperledger/aries-framework-javascript/commit/2da845dd4c88c5e93fa9f02107d69f479946024f))
- process ws return route messages serially ([#826](https://github.com/hyperledger/aries-framework-javascript/issues/826)) ([2831a8e](https://github.com/hyperledger/aries-framework-javascript/commit/2831a8ee1bcda649e33eb68b002890f6670f660e))
- **proofs:** allow duplicates in proof attributes ([#848](https://github.com/hyperledger/aries-framework-javascript/issues/848)) ([ca6c1ce](https://github.com/hyperledger/aries-framework-javascript/commit/ca6c1ce82bb84a638f98977191b04a249633be76))
- propose payload attachment in in snake_case JSON format ([#775](https://github.com/hyperledger/aries-framework-javascript/issues/775)) ([6c2dfdb](https://github.com/hyperledger/aries-framework-javascript/commit/6c2dfdb625f7a8f2504f8bc8cf878e01ee1c50cc))
- relax validation of thread id in revocation notification ([#768](https://github.com/hyperledger/aries-framework-javascript/issues/768)) ([020e6ef](https://github.com/hyperledger/aries-framework-javascript/commit/020e6efa6e878401dede536dd99b3c9814d9541b))
- remove deprecated multibase and multihash ([#674](https://github.com/hyperledger/aries-framework-javascript/issues/674)) ([3411f1d](https://github.com/hyperledger/aries-framework-javascript/commit/3411f1d20f09cab47b77bf9eb6b66cf135d19d4c))
- remove unqualified did from out of band record ([#782](https://github.com/hyperledger/aries-framework-javascript/issues/782)) ([0c1423d](https://github.com/hyperledger/aries-framework-javascript/commit/0c1423d7203d92aea5440aac0488dae5dad6b05e))
- remove usage of const enum ([#888](https://github.com/hyperledger/aries-framework-javascript/issues/888)) ([a7754bd](https://github.com/hyperledger/aries-framework-javascript/commit/a7754bd7bfeaac1ca30df8437554e041d4cf103e))
- **routing:** also use pickup strategy from config ([#808](https://github.com/hyperledger/aries-framework-javascript/issues/808)) ([fd08ae3](https://github.com/hyperledger/aries-framework-javascript/commit/fd08ae3afaa334c4644aaacee2b6547f171d9d7d))
- **routing:** mediation recipient role for recipient ([#661](https://github.com/hyperledger/aries-framework-javascript/issues/661)) ([88ad790](https://github.com/hyperledger/aries-framework-javascript/commit/88ad790d8291aaf9113f0de5c7b13563a4967ee7))
- **routing:** remove sentTime from request message ([#670](https://github.com/hyperledger/aries-framework-javascript/issues/670)) ([1e9715b](https://github.com/hyperledger/aries-framework-javascript/commit/1e9715b894538f57e6ff3aa2d2e4225f8b2f7dc1))
- **routing:** sending of trustping in pickup v2 ([#787](https://github.com/hyperledger/aries-framework-javascript/issues/787)) ([45b024d](https://github.com/hyperledger/aries-framework-javascript/commit/45b024d62d370e2c646b20993647740f314356e2))
- send message to service ([#838](https://github.com/hyperledger/aries-framework-javascript/issues/838)) ([270c347](https://github.com/hyperledger/aries-framework-javascript/commit/270c3478f76ba5c3702377d78027afb71549de5c))
- support pre-aip2 please ack decorator ([#835](https://github.com/hyperledger/aries-framework-javascript/issues/835)) ([a4bc215](https://github.com/hyperledger/aries-framework-javascript/commit/a4bc2158351129aef5281639bbb44127ebcf5ad8))
- update inbound message validation ([#678](https://github.com/hyperledger/aries-framework-javascript/issues/678)) ([e383343](https://github.com/hyperledger/aries-framework-javascript/commit/e3833430104e3a0415194bd6f27d71c3b5b5ef9b))
- verify jws contains at least 1 signature ([#600](https://github.com/hyperledger/aries-framework-javascript/issues/600)) ([9c96518](https://github.com/hyperledger/aries-framework-javascript/commit/9c965185de7908bdde1776369453cce384f9e82c))

### Code Refactoring

- delete credentials by default when deleting exchange ([#767](https://github.com/hyperledger/aries-framework-javascript/issues/767)) ([656ed73](https://github.com/hyperledger/aries-framework-javascript/commit/656ed73b95d8a8483a38ff0b5462a4671cb82898))
- do not add ~service in createOOBOffer method ([#772](https://github.com/hyperledger/aries-framework-javascript/issues/772)) ([a541949](https://github.com/hyperledger/aries-framework-javascript/commit/a541949c7dbf907e29eb798e60901b92fbec6443))

### Features

- 0.2.0 migration script for connections ([#773](https://github.com/hyperledger/aries-framework-javascript/issues/773)) ([0831b9b](https://github.com/hyperledger/aries-framework-javascript/commit/0831b9b451d8ac74a018fc525cdbac8ec9f6cd1c))
- ability to add generic records ([#702](https://github.com/hyperledger/aries-framework-javascript/issues/702)) ([e617496](https://github.com/hyperledger/aries-framework-javascript/commit/e61749609a072f0f8d869e6c278d0a4a79938ee4)), closes [#688](https://github.com/hyperledger/aries-framework-javascript/issues/688)
- add didcomm message record ([#593](https://github.com/hyperledger/aries-framework-javascript/issues/593)) ([e547fb1](https://github.com/hyperledger/aries-framework-javascript/commit/e547fb1c0b01f821b5425bf9bb632e885f92b398))
- add find and save/update methods to DidCommMessageRepository ([#620](https://github.com/hyperledger/aries-framework-javascript/issues/620)) ([beff6b0](https://github.com/hyperledger/aries-framework-javascript/commit/beff6b0ae0ad100ead1a4820ebf6c12fb3ad148d))
- add generic did resolver ([#554](https://github.com/hyperledger/aries-framework-javascript/issues/554)) ([8e03f35](https://github.com/hyperledger/aries-framework-javascript/commit/8e03f35f8e1cd02dac4df02d1f80f2c5a921dfef))
- add issue credential v2 ([#745](https://github.com/hyperledger/aries-framework-javascript/issues/745)) ([245223a](https://github.com/hyperledger/aries-framework-javascript/commit/245223acbc6f50de418b310025665e5c1316f1af))
- add out-of-band and did exchange ([#717](https://github.com/hyperledger/aries-framework-javascript/issues/717)) ([16c6d60](https://github.com/hyperledger/aries-framework-javascript/commit/16c6d6080db93b5f4a86e81bdbd7a3e987728d82))
- add question answer protocol ([#557](https://github.com/hyperledger/aries-framework-javascript/issues/557)) ([b5a2536](https://github.com/hyperledger/aries-framework-javascript/commit/b5a25364ff523214fc8e56a7133bfa5c1db9b935))
- add role and method to did record tags ([#692](https://github.com/hyperledger/aries-framework-javascript/issues/692)) ([3b6504b](https://github.com/hyperledger/aries-framework-javascript/commit/3b6504ba6053c62f0841cb64a0e9a5be0e78bf80))
- add support for did:peer ([#608](https://github.com/hyperledger/aries-framework-javascript/issues/608)) ([c5c4172](https://github.com/hyperledger/aries-framework-javascript/commit/c5c41722e9b626d7cea929faff562c2a69a079fb))
- add support for signed attachments ([#595](https://github.com/hyperledger/aries-framework-javascript/issues/595)) ([eb49374](https://github.com/hyperledger/aries-framework-javascript/commit/eb49374c7ac7a61c10c8cb9079acffe689d0b402))
- add update assistant for storage migrations ([#690](https://github.com/hyperledger/aries-framework-javascript/issues/690)) ([c9bff93](https://github.com/hyperledger/aries-framework-javascript/commit/c9bff93cfac43c4ae2cbcad1f96c1a74cde39602))
- add validation to JSON transformer ([#830](https://github.com/hyperledger/aries-framework-javascript/issues/830)) ([5b9efe3](https://github.com/hyperledger/aries-framework-javascript/commit/5b9efe3b6fdaaec6dda387c542979e0e8fd51d5c))
- add wallet key derivation method option ([#650](https://github.com/hyperledger/aries-framework-javascript/issues/650)) ([8386506](https://github.com/hyperledger/aries-framework-javascript/commit/83865067402466ffb51ba5008f52ea3e4169c31d))
- add wallet module with import export ([#652](https://github.com/hyperledger/aries-framework-javascript/issues/652)) ([6cf5a7b](https://github.com/hyperledger/aries-framework-javascript/commit/6cf5a7b9de84dee1be61c315a734328ec209e87d))
- **core:** add support for postgres wallet type ([#699](https://github.com/hyperledger/aries-framework-javascript/issues/699)) ([83ff0f3](https://github.com/hyperledger/aries-framework-javascript/commit/83ff0f36401cbf6e95c0a1ceb9fa921a82dc6830))
- **core:** added timeOut to the module level ([#603](https://github.com/hyperledger/aries-framework-javascript/issues/603)) ([09950c7](https://github.com/hyperledger/aries-framework-javascript/commit/09950c706c0827a75eb93ffb05cc926f8472f66d))
- **core:** allow to set auto accept connetion exchange when accepting invitation ([#589](https://github.com/hyperledger/aries-framework-javascript/issues/589)) ([2d95dce](https://github.com/hyperledger/aries-framework-javascript/commit/2d95dce70fb36dbbae459e17cfb0dea4dbbbe237))
- **core:** generic repository events ([#842](https://github.com/hyperledger/aries-framework-javascript/issues/842)) ([74dd289](https://github.com/hyperledger/aries-framework-javascript/commit/74dd289669080b1406562ac575dd7c3c3d442e72))
- **credentials:** add get format data method ([#877](https://github.com/hyperledger/aries-framework-javascript/issues/877)) ([521d489](https://github.com/hyperledger/aries-framework-javascript/commit/521d489cccaf9c4c3f3650ccf980a8dec0b8f729))
- **credentials:** delete associated didCommMessages ([#870](https://github.com/hyperledger/aries-framework-javascript/issues/870)) ([1f8b6ab](https://github.com/hyperledger/aries-framework-javascript/commit/1f8b6aba9c34bd45ea61cdfdc5f7ab1e825368fc))
- **credentials:** find didcomm message methods ([#887](https://github.com/hyperledger/aries-framework-javascript/issues/887)) ([dc12427](https://github.com/hyperledger/aries-framework-javascript/commit/dc12427bb308e53bb1c5749c61769b5f08c684c2))
- delete credential from wallet ([#691](https://github.com/hyperledger/aries-framework-javascript/issues/691)) ([abec3a2](https://github.com/hyperledger/aries-framework-javascript/commit/abec3a2c95815d1c54b22a6370222f024eefb060))
- extension module creation ([#688](https://github.com/hyperledger/aries-framework-javascript/issues/688)) ([2b6441a](https://github.com/hyperledger/aries-framework-javascript/commit/2b6441a2de5e9940bdf225b1ad9028cdfbf15cd5))
- filter retrieved credential by revocation state ([#641](https://github.com/hyperledger/aries-framework-javascript/issues/641)) ([5912c0c](https://github.com/hyperledger/aries-framework-javascript/commit/5912c0ce2dbc8f773cec5324ffb19c40b15009b0))
- indy revocation (prover & verifier) ([#592](https://github.com/hyperledger/aries-framework-javascript/issues/592)) ([fb19ff5](https://github.com/hyperledger/aries-framework-javascript/commit/fb19ff555b7c10c9409450dcd7d385b1eddf41ac))
- **indy:** add choice for taa mechanism ([#849](https://github.com/hyperledger/aries-framework-javascript/issues/849)) ([ba03fa0](https://github.com/hyperledger/aries-framework-javascript/commit/ba03fa0c23f270274a592dfd6556a35adf387b51))
- ledger connections happen on agent init in background ([#580](https://github.com/hyperledger/aries-framework-javascript/issues/580)) ([61695ce](https://github.com/hyperledger/aries-framework-javascript/commit/61695ce7737ffef363b60e341ae5b0e67e0e2c90))
- pickup v2 protocol ([#711](https://github.com/hyperledger/aries-framework-javascript/issues/711)) ([b281673](https://github.com/hyperledger/aries-framework-javascript/commit/b281673b3503bb85ebda7afdd68b6d792d8f5bf5))
- regex for schemaVersion, issuerDid, credDefId, schemaId, schemaIssuerDid ([#679](https://github.com/hyperledger/aries-framework-javascript/issues/679)) ([36b9d46](https://github.com/hyperledger/aries-framework-javascript/commit/36b9d466d400a0f87f6272bc428965601023581a))
- **routing:** allow to discover mediator pickup strategy ([#669](https://github.com/hyperledger/aries-framework-javascript/issues/669)) ([5966da1](https://github.com/hyperledger/aries-framework-javascript/commit/5966da130873607a41919bbe1239e5e44afb47e4))
- support advanced wallet query ([#831](https://github.com/hyperledger/aries-framework-javascript/issues/831)) ([28e0ffa](https://github.com/hyperledger/aries-framework-javascript/commit/28e0ffa151d41a39197f01bcc5f9c9834a0b2537))
- support handling messages with different minor version ([#714](https://github.com/hyperledger/aries-framework-javascript/issues/714)) ([ad12360](https://github.com/hyperledger/aries-framework-javascript/commit/ad123602682214f02250e82a80ac7cf5255b8d12))
- support new did document in didcomm message exchange ([#609](https://github.com/hyperledger/aries-framework-javascript/issues/609)) ([a1a3b7d](https://github.com/hyperledger/aries-framework-javascript/commit/a1a3b7d95a6e6656dc5630357ac4e692b33b49bc))
- support revocation notification messages ([#579](https://github.com/hyperledger/aries-framework-javascript/issues/579)) ([9f04375](https://github.com/hyperledger/aries-framework-javascript/commit/9f04375edc5eaffa0aa3583efcf05c83d74987bb))
- support wallet key rotation ([#672](https://github.com/hyperledger/aries-framework-javascript/issues/672)) ([5cd1598](https://github.com/hyperledger/aries-framework-javascript/commit/5cd1598b496a832c82f35a363fabe8f408abd439))
- update recursive backoff & trust ping record updates ([#631](https://github.com/hyperledger/aries-framework-javascript/issues/631)) ([f64a9da](https://github.com/hyperledger/aries-framework-javascript/commit/f64a9da2ef9fda9693b23ddbd25bd885b88cdb1e))

### BREAKING CHANGES

- **indy:** the transaction author agreement acceptance mechanism was previously automatically the first acceptance mechanism from the acceptance mechanism list. With this addition, the framework never automatically selects the acceptance mechanism anymore and it needs to be specified in the transactionAuthorAgreement in the indyLedgers agent config array.
- the credentials associated with a credential exchange record are now deleted by default when deleting a credential exchange record. If you only want to delete the credential exchange record and not the associated credentials, you can pass the deleteAssociatedCredentials to the deleteById method:

```ts
await agent.credentials.deleteById('credentialExchangeId', {
  deleteAssociatedCredentials: false,
})
```

- with the addition of the out of band module `credentials.createOutOfBandOffer` is renamed to `credentials.createOffer` and no longer adds the `~service` decorator to the message. You need to call `oob.createLegacyConnectionlessInvitation` afterwards to use it for AIP-1 style connectionless exchanges. See [Migrating from AFJ 0.1.0 to 0.2.x](https://github.com/hyperledger/aries-framework-javascript/blob/main/docs/migration/0.1-to-0.2.md) for detailed migration instructions.
- the connections module has been extended with an out of band module and support for the DID Exchange protocol. Some methods have been moved to the out of band module, see [Migrating from AFJ 0.1.0 to 0.2.x](https://github.com/hyperledger/aries-framework-javascript/blob/main/docs/migration/0.1-to-0.2.md) for detailed migration instructions.
- The mediator pickup strategy enum value `MediatorPickupStrategy.Explicit` has been renamed to `MediatorPickupStrategy.PickUpV1` to better align with the naming of the new `MediatorPickupStrategy.PickUpV2`
- attachment method `getDataAsJson` is now located one level up. So instead of `attachment.data.getDataAsJson()` you should now call `attachment.getDataAsJson()`

# 0.1.0 (2021-12-23)

### Bug Fixes

- add details to connection signing error ([#484](https://github.com/hyperledger/aries-framework-javascript/issues/484)) ([e24eafd](https://github.com/hyperledger/aries-framework-javascript/commit/e24eafd83f53a9833b95bc3a4587cf825ee5d975))
- add option check to attribute constructor ([#450](https://github.com/hyperledger/aries-framework-javascript/issues/450)) ([8aad3e9](https://github.com/hyperledger/aries-framework-javascript/commit/8aad3e9f16c249e9f9291388ec8efc9bf27213c8))
- added ariesframeworkerror to httpoutboundtransport ([#438](https://github.com/hyperledger/aries-framework-javascript/issues/438)) ([ee1a229](https://github.com/hyperledger/aries-framework-javascript/commit/ee1a229f8fc21739bca05c516a7b561f53726b91))
- alter mediation recipient websocket transport priority ([#434](https://github.com/hyperledger/aries-framework-javascript/issues/434)) ([52c7897](https://github.com/hyperledger/aries-framework-javascript/commit/52c789724c731340daa8528b7d7b4b7fdcb40032))
- **core:** convert legacy prefix for inner msgs ([#479](https://github.com/hyperledger/aries-framework-javascript/issues/479)) ([a2b655a](https://github.com/hyperledger/aries-framework-javascript/commit/a2b655ac79bf0c7460671c8d31e92828e6f5ccf0))
- **core:** do not throw error on timeout in http ([#512](https://github.com/hyperledger/aries-framework-javascript/issues/512)) ([4e73a7b](https://github.com/hyperledger/aries-framework-javascript/commit/4e73a7b0d9224bc102b396d821a8ea502a9a509d))
- **core:** do not use did-communication service ([#402](https://github.com/hyperledger/aries-framework-javascript/issues/402)) ([cdf2edd](https://github.com/hyperledger/aries-framework-javascript/commit/cdf2eddc61e12f7ecd5a29e260eef82394d2e467))
- **core:** export AgentMessage ([#480](https://github.com/hyperledger/aries-framework-javascript/issues/480)) ([af39ad5](https://github.com/hyperledger/aries-framework-javascript/commit/af39ad535320133ee38fc592309f42670a8517a1))
- **core:** expose record metadata types ([#556](https://github.com/hyperledger/aries-framework-javascript/issues/556)) ([68995d7](https://github.com/hyperledger/aries-framework-javascript/commit/68995d7e2b049ff6496723d8a895e07b72fe72fb))
- **core:** fix empty error log in console logger ([#524](https://github.com/hyperledger/aries-framework-javascript/issues/524)) ([7d9c541](https://github.com/hyperledger/aries-framework-javascript/commit/7d9c541de22fb2644455cf1949184abf3d8e528c))
- **core:** improve wallet not initialized error ([#513](https://github.com/hyperledger/aries-framework-javascript/issues/513)) ([b948d4c](https://github.com/hyperledger/aries-framework-javascript/commit/b948d4c83b4eb0ab0594ae2117c0bb05b0955b21))
- **core:** improved present-proof tests ([#482](https://github.com/hyperledger/aries-framework-javascript/issues/482)) ([41d9282](https://github.com/hyperledger/aries-framework-javascript/commit/41d9282ca561ca823b28f179d409c70a22d95e9b))
- **core:** log errors if message is undeliverable ([#528](https://github.com/hyperledger/aries-framework-javascript/issues/528)) ([20b586d](https://github.com/hyperledger/aries-framework-javascript/commit/20b586db6eb9f92cce16d87d0dcfa4919f27ffa8))
- **core:** remove isPositive validation decorators ([#477](https://github.com/hyperledger/aries-framework-javascript/issues/477)) ([e316e04](https://github.com/hyperledger/aries-framework-javascript/commit/e316e047b3e5aeefb929a5c47ad65d8edd4caba5))
- **core:** remove unused url import ([#466](https://github.com/hyperledger/aries-framework-javascript/issues/466)) ([0f1323f](https://github.com/hyperledger/aries-framework-javascript/commit/0f1323f5bccc2dc3b67426525b161d7e578bb961))
- **core:** requested predicates transform type ([#393](https://github.com/hyperledger/aries-framework-javascript/issues/393)) ([69684bc](https://github.com/hyperledger/aries-framework-javascript/commit/69684bc48a4002483662a211ec1ddd289dbaf59b))
- **core:** send messages now takes a connection id ([#491](https://github.com/hyperledger/aries-framework-javascript/issues/491)) ([ed9db11](https://github.com/hyperledger/aries-framework-javascript/commit/ed9db11592b4948a1d313dbeb074e15d59503d82))
- **core:** using query-string to parse URLs ([#457](https://github.com/hyperledger/aries-framework-javascript/issues/457)) ([78e5057](https://github.com/hyperledger/aries-framework-javascript/commit/78e505750557f296cc72ef19c0edd8db8e1eaa7d))
- date parsing ([#426](https://github.com/hyperledger/aries-framework-javascript/issues/426)) ([2d31b87](https://github.com/hyperledger/aries-framework-javascript/commit/2d31b87e99d04136f57cb457e2c67397ad65cc62))
- export indy pool config ([#504](https://github.com/hyperledger/aries-framework-javascript/issues/504)) ([b1e2b8c](https://github.com/hyperledger/aries-framework-javascript/commit/b1e2b8c54e909927e5afa8b8212e0c8e156b97f7))
- include error when message cannot be handled ([#533](https://github.com/hyperledger/aries-framework-javascript/issues/533)) ([febfb05](https://github.com/hyperledger/aries-framework-javascript/commit/febfb05330c097aa918087ec3853a247d6a31b7c))
- incorrect recip key with multi routing keys ([#446](https://github.com/hyperledger/aries-framework-javascript/issues/446)) ([db76823](https://github.com/hyperledger/aries-framework-javascript/commit/db76823400cfecc531575584ef7210af0c3b3e5c))
- make records serializable ([#448](https://github.com/hyperledger/aries-framework-javascript/issues/448)) ([7e2946e](https://github.com/hyperledger/aries-framework-javascript/commit/7e2946eaa9e35083f3aa70c26c732a972f6eb12f))
- mediator transports ([#419](https://github.com/hyperledger/aries-framework-javascript/issues/419)) ([87bc589](https://github.com/hyperledger/aries-framework-javascript/commit/87bc589695505de21294a1373afcf874fe8d22f6))
- mediator updates ([#432](https://github.com/hyperledger/aries-framework-javascript/issues/432)) ([163cda1](https://github.com/hyperledger/aries-framework-javascript/commit/163cda19ba8437894a48c9bc948528ea0486ccdf))
- proof configurable on proofRecord ([#397](https://github.com/hyperledger/aries-framework-javascript/issues/397)) ([8e83c03](https://github.com/hyperledger/aries-framework-javascript/commit/8e83c037e1d59c670cfd4a8a575d4459999a64f8))
- removed check for senderkey for connectionless exchange ([#555](https://github.com/hyperledger/aries-framework-javascript/issues/555)) ([ba3f17e](https://github.com/hyperledger/aries-framework-javascript/commit/ba3f17e073b28ee5f16031f0346de0b71119e6f3))
- support mediation for connectionless exchange ([#577](https://github.com/hyperledger/aries-framework-javascript/issues/577)) ([3dadfc7](https://github.com/hyperledger/aries-framework-javascript/commit/3dadfc7a202b3642e93e39cd79c9fd98a3dc4de2))
- their did doc not ours ([#436](https://github.com/hyperledger/aries-framework-javascript/issues/436)) ([0226609](https://github.com/hyperledger/aries-framework-javascript/commit/0226609a279303f5e8d09a2c01e54ff97cf61839))

- fix(core)!: Improved typing on metadata api (#585) ([4ab8d73](https://github.com/hyperledger/aries-framework-javascript/commit/4ab8d73e5fc866a91085f95f973022846ed431fb)), closes [#585](https://github.com/hyperledger/aries-framework-javascript/issues/585)
- fix(core)!: update class transformer library (#547) ([dee03e3](https://github.com/hyperledger/aries-framework-javascript/commit/dee03e38d2732ba0bd38eeacca6ad58b191e87f8)), closes [#547](https://github.com/hyperledger/aries-framework-javascript/issues/547)
- fix(core)!: prefixed internal metadata with \_internal/ (#535) ([aa1b320](https://github.com/hyperledger/aries-framework-javascript/commit/aa1b3206027fdb71e6aaa4c6491f8ba84dca7b9a)), closes [#535](https://github.com/hyperledger/aries-framework-javascript/issues/535)
- feat(core)!: metadata on records (#505) ([c92393a](https://github.com/hyperledger/aries-framework-javascript/commit/c92393a8b5d8abd38d274c605cd5c3f97f96cee9)), closes [#505](https://github.com/hyperledger/aries-framework-javascript/issues/505)
- fix(core)!: do not request ping res for connection (#527) ([3db5519](https://github.com/hyperledger/aries-framework-javascript/commit/3db5519f0d9f49b71b647ca86be3b336399459cb)), closes [#527](https://github.com/hyperledger/aries-framework-javascript/issues/527)
- refactor(core)!: simplify get creds for proof api (#523) ([ba9698d](https://github.com/hyperledger/aries-framework-javascript/commit/ba9698de2606e5c78f018dc5e5253aeb1f5fc616)), closes [#523](https://github.com/hyperledger/aries-framework-javascript/issues/523)
- fix(core)!: improve proof request validation (#525) ([1b4d8d6](https://github.com/hyperledger/aries-framework-javascript/commit/1b4d8d6b6c06821a2a981fffb6c47f728cac803e)), closes [#525](https://github.com/hyperledger/aries-framework-javascript/issues/525)
- feat(core)!: added basic message sent event (#507) ([d2c04c3](https://github.com/hyperledger/aries-framework-javascript/commit/d2c04c36c00d772943530bd599dbe56f3e1fb17d)), closes [#507](https://github.com/hyperledger/aries-framework-javascript/issues/507)

### Features

- add delete methods to services and modules ([#447](https://github.com/hyperledger/aries-framework-javascript/issues/447)) ([e7ed602](https://github.com/hyperledger/aries-framework-javascript/commit/e7ed6027d2aa9be7f64d5968c4338e63e56657fb))
- add from record method to cred preview ([#428](https://github.com/hyperledger/aries-framework-javascript/issues/428)) ([895f7d0](https://github.com/hyperledger/aries-framework-javascript/commit/895f7d084287f99221c9492a25fed58191868edd))
- add multiple inbound transports ([#433](https://github.com/hyperledger/aries-framework-javascript/issues/433)) ([56cb9f2](https://github.com/hyperledger/aries-framework-javascript/commit/56cb9f2202deb83b3c133905f21651bfefcb63f7))
- add problem report protocol ([#560](https://github.com/hyperledger/aries-framework-javascript/issues/560)) ([baee5db](https://github.com/hyperledger/aries-framework-javascript/commit/baee5db29f3d545c16a651c80392ddcbbca6bf0e))
- add toJson method to BaseRecord ([#455](https://github.com/hyperledger/aries-framework-javascript/issues/455)) ([f3790c9](https://github.com/hyperledger/aries-framework-javascript/commit/f3790c97c4d9a0aaec9abdce417ecd5429c6026f))
- added decline credential offer method ([#416](https://github.com/hyperledger/aries-framework-javascript/issues/416)) ([d9ac141](https://github.com/hyperledger/aries-framework-javascript/commit/d9ac141122f1d4902f91f9537e6526796fef1e01))
- added declined proof state and decline method for presentations ([e5aedd0](https://github.com/hyperledger/aries-framework-javascript/commit/e5aedd02737d3764871c6b5d4ae61a3a33ed8398))
- allow to use legacy did sov prefix ([#442](https://github.com/hyperledger/aries-framework-javascript/issues/442)) ([c41526f](https://github.com/hyperledger/aries-framework-javascript/commit/c41526fb57a7e2e89e923b95ede43f890a6cbcbb))
- auto accept proofs ([#367](https://github.com/hyperledger/aries-framework-javascript/issues/367)) ([735d578](https://github.com/hyperledger/aries-framework-javascript/commit/735d578f72fc5f3bfcbcf40d27394bd013e7cf4f))
- break out indy wallet, better indy handling ([#396](https://github.com/hyperledger/aries-framework-javascript/issues/396)) ([9f1a4a7](https://github.com/hyperledger/aries-framework-javascript/commit/9f1a4a754a61573ce3fee78d52615363c7e25d58))
- **core:** add discover features protocol ([#390](https://github.com/hyperledger/aries-framework-javascript/issues/390)) ([3347424](https://github.com/hyperledger/aries-framework-javascript/commit/3347424326cd15e8bf2544a8af53b2fa57b1dbb8))
- **core:** add support for multi use inviations ([#460](https://github.com/hyperledger/aries-framework-javascript/issues/460)) ([540ad7b](https://github.com/hyperledger/aries-framework-javascript/commit/540ad7be2133ee6609c2336b22b726270db98d6c))
- **core:** connection-less issuance and verification ([#359](https://github.com/hyperledger/aries-framework-javascript/issues/359)) ([fb46ade](https://github.com/hyperledger/aries-framework-javascript/commit/fb46ade4bc2dd4f3b63d4194bb170d2f329562b7))
- **core:** d_m invitation parameter and invitation image ([#456](https://github.com/hyperledger/aries-framework-javascript/issues/456)) ([f92c322](https://github.com/hyperledger/aries-framework-javascript/commit/f92c322b97be4a4867a82c3a35159d6068951f0b))
- **core:** ledger module registerPublicDid implementation ([#398](https://github.com/hyperledger/aries-framework-javascript/issues/398)) ([5f2d512](https://github.com/hyperledger/aries-framework-javascript/commit/5f2d5126baed2ff58268c38755c2dbe75a654947))
- **core:** store mediator id in connection record ([#503](https://github.com/hyperledger/aries-framework-javascript/issues/503)) ([da51f2e](https://github.com/hyperledger/aries-framework-javascript/commit/da51f2e8337f5774d23e9aeae0459bd7355a3760))
- **core:** support image url in invitations ([#463](https://github.com/hyperledger/aries-framework-javascript/issues/463)) ([9fda24e](https://github.com/hyperledger/aries-framework-javascript/commit/9fda24ecf55fdfeba74211447e9fadfdcbf57385))
- **core:** support multiple indy ledgers ([#474](https://github.com/hyperledger/aries-framework-javascript/issues/474)) ([47149bc](https://github.com/hyperledger/aries-framework-javascript/commit/47149bc5742456f4f0b75e0944ce276972e645b8))
- **core:** update agent label and imageUrl plus per connection label and imageUrl ([#516](https://github.com/hyperledger/aries-framework-javascript/issues/516)) ([5e9a641](https://github.com/hyperledger/aries-framework-javascript/commit/5e9a64130c02c8a5fdf11f0e25d0c23929a33a4f))
- **core:** validate outbound messages ([#526](https://github.com/hyperledger/aries-framework-javascript/issues/526)) ([9c3910f](https://github.com/hyperledger/aries-framework-javascript/commit/9c3910f1e67200b71bb4888c6fee62942afaff20))
- expose wallet API ([#566](https://github.com/hyperledger/aries-framework-javascript/issues/566)) ([4027fc9](https://github.com/hyperledger/aries-framework-javascript/commit/4027fc975d7e4118892f43cb8c6a0eea412eaad4))
- generic attachment handler ([#578](https://github.com/hyperledger/aries-framework-javascript/issues/578)) ([4d7d3c1](https://github.com/hyperledger/aries-framework-javascript/commit/4d7d3c1502d5eafa2b884a4a84934e072fe70ea6))
- **node:** add http and ws inbound transport ([#392](https://github.com/hyperledger/aries-framework-javascript/issues/392)) ([34a6ff2](https://github.com/hyperledger/aries-framework-javascript/commit/34a6ff2699197b9d525422a0a405e241582a476c))

### BREAKING CHANGES

- removed the getAll() function.
- The agent’s `shutdown` method does not delete the wallet anymore. If you want to delete the wallet, you can do it via exposed wallet API.
- class-transformer released a breaking change in a patch version, causing AFJ to break. I updated to the newer version and pinned the version exactly as this is the second time this has happened now.

Signed-off-by: Timo Glastra <timo@animo.id>

- internal metadata is now prefixed with \_internal to avoid clashing and accidental overwriting of internal data.

- fix(core): added \_internal/ prefix on metadata

Signed-off-by: Berend Sliedrecht <berend@animo.id>

- credentialRecord.credentialMetadata has been replaced by credentialRecord.metadata.

Signed-off-by: Berend Sliedrecht <berend@animo.id>

- a trust ping response will not be requested anymore after completing a connection. This is not required, and also non-standard behaviour. It was also causing some tests to be flaky as response messages were stil being sent after one of the agents had already shut down.

Signed-off-by: Timo Glastra <timo@animo.id>

- The `ProofsModule.getRequestedCredentialsForProofRequest` expected some low level message objects as input. This is not in line with the public API of the rest of the framework and has been simplified to only require a proof record id and optionally a boolean whether the retrieved credentials should be filtered based on the proof proposal (if available).

Signed-off-by: Timo Glastra <timo@animo.id>

- Proof request requestedAttributes and requestedPredicates are now a map instead of record. This is needed to have proper validation using class-validator.

Signed-off-by: Timo Glastra <timo@animo.id>

- `BasicMessageReceivedEvent` has been replaced by the more general `BasicMessageStateChanged` event which triggers when a basic message is received or sent.

Signed-off-by: NeilSMyers <mmyersneil@gmail.com>
