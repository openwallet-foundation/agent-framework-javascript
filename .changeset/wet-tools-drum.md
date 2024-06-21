---
'@credo-ts/action-menu': patch
'@credo-ts/anoncreds': patch
'@credo-ts/askar': patch
'@credo-ts/bbs-signatures': patch
'@credo-ts/cheqd': patch
'@credo-ts/core': patch
'@credo-ts/drpc': patch
'@credo-ts/indy-sdk-to-askar-migration': patch
'@credo-ts/indy-vdr': patch
'@credo-ts/node': patch
'@credo-ts/openid4vc': patch
'@credo-ts/question-answer': patch
'@credo-ts/react-native': patch
'@credo-ts/tenants': patch
---

- feat: allow serving dids from did record (#1856)
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
