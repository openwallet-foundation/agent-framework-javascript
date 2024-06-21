# Changelog

## [0.5.3](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.2...v0.5.3) (2024-05-01)

### Bug Fixes

- store recipient keys by default ([#1847](https://github.com/openwallet-foundation/credo-ts/issues/1847)) ([e9238cf](https://github.com/openwallet-foundation/credo-ts/commit/e9238cfde4d76c5b927f6f76b3529d4c80808a3a))

## [0.5.2](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.1...v0.5.2) (2024-04-26)

### Bug Fixes

- node-ffi-napi compatibility ([#1821](https://github.com/openwallet-foundation/credo-ts/issues/1821)) ([81d351b](https://github.com/openwallet-foundation/credo-ts/commit/81d351bc9d4d508ebfac9e7f2b2f10276ab1404a))

## [0.5.1](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.0...v0.5.1) (2024-03-28)

**Note:** Version bump only for package @credo-ts/indy-vdr

# [0.5.0](https://github.com/openwallet-foundation/credo-ts/compare/v0.4.2...v0.5.0) (2024-03-13)

### Bug Fixes

- **indy-vdr:** for creating latest delta ([#1737](https://github.com/openwallet-foundation/credo-ts/issues/1737)) ([68f0d70](https://github.com/openwallet-foundation/credo-ts/commit/68f0d70b9fd2b7acc8b6120b23b65144c93af391))

- feat(indy-vdr)!: include config in getAllPoolTransactions (#1770) ([29c589d](https://github.com/openwallet-foundation/credo-ts/commit/29c589dd2f5b6da0a6bed129b5f733851785ccba)), closes [#1770](https://github.com/openwallet-foundation/credo-ts/issues/1770)

### Features

- **anoncreds:** issue revocable credentials ([#1427](https://github.com/openwallet-foundation/credo-ts/issues/1427)) ([c59ad59](https://github.com/openwallet-foundation/credo-ts/commit/c59ad59fbe63b6d3760d19030e0f95fb2ea8488a))
- bump indy-vdr version ([#1637](https://github.com/openwallet-foundation/credo-ts/issues/1637)) ([a641a96](https://github.com/openwallet-foundation/credo-ts/commit/a641a9699b7816825a88f2c883c9e65aaa4c0f87))
- **indy-vdr:** ability to refresh the pool manually ([#1623](https://github.com/openwallet-foundation/credo-ts/issues/1623)) ([0865ea5](https://github.com/openwallet-foundation/credo-ts/commit/0865ea52fb99103fba0cc71cb118f0eb3fb909e4))
- **indy-vdr:** register revocation registry definitions and status list ([#1693](https://github.com/openwallet-foundation/credo-ts/issues/1693)) ([ee34fe7](https://github.com/openwallet-foundation/credo-ts/commit/ee34fe71780a0787db96e28575eeedce3b4704bd))
- **openid4vc:** persistance and events ([#1793](https://github.com/openwallet-foundation/credo-ts/issues/1793)) ([f4c386a](https://github.com/openwallet-foundation/credo-ts/commit/f4c386a6ccf8adb829cad30b81d524e6ffddb029))

### BREAKING CHANGES

- `IndyVdrApi.getAllPoolTransactions()` now returns an array of objects containing transactions and config of each pool

```
{
    config: IndyVdrPoolConfig;
    transactions: Transactions;
}
```

## [0.4.2](https://github.com/hyperledger/aries-framework-javascript/compare/v0.4.1...v0.4.2) (2023-10-05)

**Note:** Version bump only for package @credo-ts/indy-vdr

## [0.4.1](https://github.com/hyperledger/aries-framework-javascript/compare/v0.4.0...v0.4.1) (2023-08-28)

### Bug Fixes

- **indy-vdr:** role property not included in nym request ([#1488](https://github.com/hyperledger/aries-framework-javascript/issues/1488)) ([002be4f](https://github.com/hyperledger/aries-framework-javascript/commit/002be4f578729aed1c8ae337f3d2eeecce9e3725))

# [0.4.0](https://github.com/hyperledger/aries-framework-javascript/compare/v0.3.3...v0.4.0) (2023-06-03)

### Bug Fixes

- **anoncreds:** make revocation status list inline with the spec ([#1421](https://github.com/hyperledger/aries-framework-javascript/issues/1421)) ([644e860](https://github.com/hyperledger/aries-framework-javascript/commit/644e860a05f40166e26c497a2e8619c9a38df11d))
- did cache key not being set correctly ([#1394](https://github.com/hyperledger/aries-framework-javascript/issues/1394)) ([1125e81](https://github.com/hyperledger/aries-framework-javascript/commit/1125e81962ffa752bf40fa8f7f4226e186f22013))
- expose indy pool configs and action menu messages ([#1333](https://github.com/hyperledger/aries-framework-javascript/issues/1333)) ([518e5e4](https://github.com/hyperledger/aries-framework-javascript/commit/518e5e4dfb59f9c0457bfd233409e9f4b3c429ee))
- **indy-vdr:** do not force indy-vdr version ([#1434](https://github.com/hyperledger/aries-framework-javascript/issues/1434)) ([8a933c0](https://github.com/hyperledger/aries-framework-javascript/commit/8a933c057e0c88870779bf8eb98b4684de4745de))
- **indy-vdr:** export relevant packages from root ([#1291](https://github.com/hyperledger/aries-framework-javascript/issues/1291)) ([b570e0f](https://github.com/hyperledger/aries-framework-javascript/commit/b570e0f923fc46adef3ce20ee76a683a867b85f4))
- issuance with unqualified identifiers ([#1431](https://github.com/hyperledger/aries-framework-javascript/issues/1431)) ([de90caf](https://github.com/hyperledger/aries-framework-javascript/commit/de90cafb8d12b7a940f881184cd745c4b5043cbc))
- reference to indyLedgers in IndyXXXNotConfiguredError ([#1397](https://github.com/hyperledger/aries-framework-javascript/issues/1397)) ([d6e2ea2](https://github.com/hyperledger/aries-framework-javascript/commit/d6e2ea2194a4860265fe299ef8ee4cb4799ab1a6))
- remove named capture groups ([#1378](https://github.com/hyperledger/aries-framework-javascript/issues/1378)) ([a4204ef](https://github.com/hyperledger/aries-framework-javascript/commit/a4204ef2db769de53d12f0d881d2c4422545c390))
- seed and private key validation and return type in registrars ([#1324](https://github.com/hyperledger/aries-framework-javascript/issues/1324)) ([c0e5339](https://github.com/hyperledger/aries-framework-javascript/commit/c0e5339edfa32df92f23fb9c920796b4b59adf52))

### Features

- 0.4.0 migration script ([#1392](https://github.com/hyperledger/aries-framework-javascript/issues/1392)) ([bc5455f](https://github.com/hyperledger/aries-framework-javascript/commit/bc5455f7b42612a2b85e504bc6ddd36283a42bfa))
- add fetch indy schema method ([#1290](https://github.com/hyperledger/aries-framework-javascript/issues/1290)) ([1d782f5](https://github.com/hyperledger/aries-framework-javascript/commit/1d782f54bbb4abfeb6b6db6cd4f7164501b6c3d9))
- **anoncreds:** store method name in records ([#1387](https://github.com/hyperledger/aries-framework-javascript/issues/1387)) ([47636b4](https://github.com/hyperledger/aries-framework-javascript/commit/47636b4a08ffbfa9a3f2a5a3c5aebda44f7d16c8))
- **indy-vdr:** add indy-vdr package and indy vdr pool ([#1160](https://github.com/hyperledger/aries-framework-javascript/issues/1160)) ([e8d6ac3](https://github.com/hyperledger/aries-framework-javascript/commit/e8d6ac31a8e18847d99d7998bd7658439e48875b))
- **indy-vdr:** add IndyVdrAnonCredsRegistry ([#1270](https://github.com/hyperledger/aries-framework-javascript/issues/1270)) ([d056316](https://github.com/hyperledger/aries-framework-javascript/commit/d056316712b5ee5c42a159816b5dda0b05ad84a8))
- **indy-vdr:** did:sov resolver ([#1247](https://github.com/hyperledger/aries-framework-javascript/issues/1247)) ([b5eb08e](https://github.com/hyperledger/aries-framework-javascript/commit/b5eb08e99d7ea61adefb8c6c0c5c99c6c1ba1597))
- **indy-vdr:** module registration ([#1285](https://github.com/hyperledger/aries-framework-javascript/issues/1285)) ([51030d4](https://github.com/hyperledger/aries-framework-javascript/commit/51030d43a7e3cca3da29c5add38e35f731576927))
- **indy-vdr:** resolver and registrar for did:indy ([#1253](https://github.com/hyperledger/aries-framework-javascript/issues/1253)) ([efab8dd](https://github.com/hyperledger/aries-framework-javascript/commit/efab8ddfc34e47a3f0ffe35b55fa5018a7e96544))
- **indy-vdr:** schema + credential definition endorsement ([#1451](https://github.com/hyperledger/aries-framework-javascript/issues/1451)) ([25b981b](https://github.com/hyperledger/aries-framework-javascript/commit/25b981b6e23d02409e90dabdccdccc8904d4e357))
- **indy-vdr:** use [@hyperledger](https://github.com/hyperledger) packages ([#1252](https://github.com/hyperledger/aries-framework-javascript/issues/1252)) ([acdb20a](https://github.com/hyperledger/aries-framework-javascript/commit/acdb20a79d038fb4163d281ee8de0ccb649fdc32))
- IndyVdrAnonCredsRegistry revocation methods ([#1328](https://github.com/hyperledger/aries-framework-javascript/issues/1328)) ([fb7ee50](https://github.com/hyperledger/aries-framework-javascript/commit/fb7ee5048c33d5335cd9f07cad3dffc60dee7376))
