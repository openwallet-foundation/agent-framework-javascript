---
'@credo-ts/core': patch
---

fix: issue where all available credentials were selected for queried DIF PEX definition. Now it only selects `needsCount` credentials, so it won't disclose more credentials than neccesary.
