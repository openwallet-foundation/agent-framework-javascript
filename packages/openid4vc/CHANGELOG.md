# Changelog

## 0.6.0

### Minor Changes

- 5f08bc6: feat: allow dynamicaly providing x509 certificates for all types of verifications
- 17ec6b8: feat(openid4vc): oid4vci authorization code flow, presentation during issuance and batch issuance.

  This is a big change to OpenID4VCI in Credo, with the neccsary breaking changes since we first added it to the framework. Over time the spec has changed significantly, but also our understanding of the standards and protocols.

  **Authorization Code Flow**
  Credo now supports the authorization code flow, for both issuer and holder. An issuer can configure multiple authorization servers, and work with external authorization servers as well. The integration is based on OAuth2, with several extension specifications, mainly the OAuth2 JWT Access Token Profile, as well as Token Introspection (for opaque access tokens). Verification works out of the box, as longs as the authorization server has a `jwks_uri` configured. For Token Introspection it's also required to provide a `clientId` and `clientSecret` in the authorization server config.

  To use an external authorization server, the authorization server MUST include the `issuer_state` parameter from the credential offer in the access token. Otherwise it's not possible for Credo to correlate the authorization session to the offer session.

  The demo-openid contains an example with external authorization server, which can be used as reference. The Credo authorization server supports DPoP and PKCE.

  **Batch Issuance**
  The credential request to credential mapper has been updated to support multiple proofs, and also multiple credential instances. The client can now also handle batch issuance.

  **Presentation During Issuance**
  The presenation during issuance allows to request presentation using OID4VP before granting authorization for issuance of one or more credentials. This flow is automatically handled by the `resolveAuthorizationRequest` method on the oid4vci holder service.

### Patch Changes

- 17ec6b8: fix(openid4vc): use `vp_formats` in client_metadata instead of `vp_formats supported` (#2089)
- 607659a: feat: fetch sd-jwt type metadata
- 17ec6b8: feat(openid4vc): support jwk thumbprint for openid token issuer
- Updated dependencies [14673b1]
- Updated dependencies [607659a]
- Updated dependencies [5f08bc6]
  - @credo-ts/core@0.6.0

## 0.5.13

### Patch Changes

- 595c3d6: feat: mdoc device response and presentation over oid4vp
- Updated dependencies [595c3d6]
  - @credo-ts/core@0.5.13

## 0.5.12

### Patch Changes

- 1d83159: feat: add jarm-support
- Updated dependencies [3c85565]
- Updated dependencies [3c85565]
- Updated dependencies [7d51fcb]
- Updated dependencies [9756a4a]
  - @credo-ts/core@0.5.12

## 0.5.11

### Patch Changes

- 6c2dd88: add support for cose_key as cryptographic_binding_methods_supported value
  - @credo-ts/core@0.5.11

## 0.5.10

### Patch Changes

- 2110e4a: fix: incorrect generation of code verifier for pkce
- 2110e4a: fix: include client_id when requesting credential using authorization_code flow
- 35a04e3: fix v11 metadata typing and update v11<->v13 tranformation logic accordingly
- fa62b74: Add support for Demonstrating Proof of Possesion (DPoP) when receiving credentials using OpenID4VCI
- a093150: fix: pass the `clientId` in the `requestCredentials` method from the API down to the service
- Updated dependencies [fa62b74]
  - @credo-ts/core@0.5.10

## 0.5.9

### Patch Changes

- a12d80c: feat: update to openid4vc v1 draft 13, with v11 compatibility
  - @credo-ts/core@0.5.9

## 0.5.8

### Patch Changes

- 3819eb2: Adds support for issuance and verification of SD-JWT VCs using x509 certificates over OpenID4VC, as well as adds support for the `x509_san_uri` and `x509_san_dns` values for `client_id_scheme`. It also adds support for OpenID4VP Draft 20
- Updated dependencies [3819eb2]
- Updated dependencies [15d0a54]
- Updated dependencies [a5235e7]
  - @credo-ts/core@0.5.8

## 0.5.7

### Patch Changes

- 2173952: Fix an issue where `express` was being bundled in React Native applications even though the `OpenId4VcIssuerModule` and `OpenId4VcVerifierModule` were not used, causing runtime errors.
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

**Note:** Version bump only for package @credo-ts/openid4vc

## [0.5.2](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.1...v0.5.2) (2024-04-26)

### Bug Fixes

- access token can only be used for offer ([#1828](https://github.com/openwallet-foundation/credo-ts/issues/1828)) ([f54b90b](https://github.com/openwallet-foundation/credo-ts/commit/f54b90b0530b43a04df6299a39414a142d73276e))
- oid4vp can be used separate from idtoken ([#1827](https://github.com/openwallet-foundation/credo-ts/issues/1827)) ([ca383c2](https://github.com/openwallet-foundation/credo-ts/commit/ca383c284e2073992a1fd280fca99bee1c2e19f8))
- **openid4vc:** update verified state for more states ([#1831](https://github.com/openwallet-foundation/credo-ts/issues/1831)) ([958bf64](https://github.com/openwallet-foundation/credo-ts/commit/958bf647c086a2ca240e9ad140defc39b7f20f43))

### Features

- add disclosures so you know which fields are disclosed ([#1834](https://github.com/openwallet-foundation/credo-ts/issues/1834)) ([6ec43eb](https://github.com/openwallet-foundation/credo-ts/commit/6ec43eb1f539bd8d864d5bbd2ab35459809255ec))
- apply new version of SD JWT package ([#1787](https://github.com/openwallet-foundation/credo-ts/issues/1787)) ([b41e158](https://github.com/openwallet-foundation/credo-ts/commit/b41e158098773d2f59b5b5cfb82cc6be06a57acd))
- openid4vc issued state per credential ([#1829](https://github.com/openwallet-foundation/credo-ts/issues/1829)) ([229c621](https://github.com/openwallet-foundation/credo-ts/commit/229c62177c04060c7ca4c19dfd35bab328035067))

## [0.5.1](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.0...v0.5.1) (2024-03-28)

### Bug Fixes

- **openid4vc:** several fixes and improvements ([#1795](https://github.com/openwallet-foundation/credo-ts/issues/1795)) ([b83c517](https://github.com/openwallet-foundation/credo-ts/commit/b83c5173070594448d92f801331b3a31c7ac8049))

# [0.5.0](https://github.com/openwallet-foundation/credo-ts/compare/v0.4.2...v0.5.0) (2024-03-13)

### Features

- anoncreds w3c migration ([#1744](https://github.com/openwallet-foundation/credo-ts/issues/1744)) ([d7c2bbb](https://github.com/openwallet-foundation/credo-ts/commit/d7c2bbb4fde57cdacbbf1ed40c6bd1423f7ab015))
- **openid4vc:** persistance and events ([#1793](https://github.com/openwallet-foundation/credo-ts/issues/1793)) ([f4c386a](https://github.com/openwallet-foundation/credo-ts/commit/f4c386a6ccf8adb829cad30b81d524e6ffddb029))
