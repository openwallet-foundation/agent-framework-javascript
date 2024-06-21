/**simpleJwtVc
  {
    "jwt": {
      "header": {
        "typ": "vc+sd-jwt",
        "alg": "EdDSA",
        "kid": "#z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW"
      },
      "payload": {
        "claim": "some-claim",
        "vct": "IdentityCredential",
        "cnf": {
          "jwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "oENVsxOUiH54X8wJLaVkicCRk00wBIQ4sRgbk54N8Mo"
          }
        },
        "iss": "did:key:z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW",
        "iat": 1698151532
      },
      "signature": "vLkigrBr1IIVRJeYE5DQx0rKUVzO3KT9T0XBATWJE89pWCyvB3Rzs8VD7qfi0vDk_QVCPIiHq1U1PsmSe4ZqCg"
    },
    "disclosures": []
  }
 */
export const simpleJwtVc =
  'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6IiN6Nk1rdHF0WE5HOENEVVk5UHJydG9TdEZ6ZUNuaHBNbWd4WUwxZ2lrY1czQnp2TlcifQ.eyJjbGFpbSI6InNvbWUtY2xhaW0iLCJ2Y3QiOiJJZGVudGl0eUNyZWRlbnRpYWwiLCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4Ijoib0VOVnN4T1VpSDU0WDh3SkxhVmtpY0NSazAwd0JJUTRzUmdiazU0TjhNbyJ9fSwiaXNzIjoiZGlkOmtleTp6Nk1rdHF0WE5HOENEVVk5UHJydG9TdEZ6ZUNuaHBNbWd4WUwxZ2lrY1czQnp2TlciLCJpYXQiOjE2OTgxNTE1MzJ9.vLkigrBr1IIVRJeYE5DQx0rKUVzO3KT9T0XBATWJE89pWCyvB3Rzs8VD7qfi0vDk_QVCPIiHq1U1PsmSe4ZqCg~'

export const expiredSdJwtVc =
  'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6IiN6Nk1rdHF0WE5HOENEVVk5UHJydG9TdEZ6ZUNuaHBNbWd4WUwxZ2lrY1czQnp2TlcifQ.eyJjbGFpbSI6InNvbWUtY2xhaW0iLCJ2Y3QiOiJJZGVudGl0eUNyZWRlbnRpYWwiLCJleHAiOjE3MTYxMTE5MTksImlzcyI6ImRpZDprZXk6ejZNa3RxdFhORzhDRFVZOVBycnRvU3RGemVDbmhwTW1neFlMMWdpa2NXM0J6dk5XIiwiaWF0IjoxNjk4MTUxNTMyfQ.hOQ-CnT-iaL2_Dlui0NgVhBk2Lej4_AqDrEK-7bQNT2b6mJkaikvUXdNtg-z7GnCUNrjq35vm5ProqiyYQz_AA~'

export const notBeforeInFutureSdJwtVc =
  'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6IiN6Nk1rdHF0WE5HOENEVVk5UHJydG9TdEZ6ZUNuaHBNbWd4WUwxZ2lrY1czQnp2TlcifQ.eyJjbGFpbSI6InNvbWUtY2xhaW0iLCJ2Y3QiOiJJZGVudGl0eUNyZWRlbnRpYWwiLCJuYmYiOjQwNzg5NDQwMDAsImlzcyI6ImRpZDprZXk6ejZNa3RxdFhORzhDRFVZOVBycnRvU3RGemVDbmhwTW1neFlMMWdpa2NXM0J6dk5XIiwiaWF0IjoxNjk4MTUxNTMyfQ.u0GPVCt7gPTrvT3sAwXxwkKW_Zy6YRRTaVRkrcSWt9VPonxQHUua2ggOERAu5cgtLeSdXzyqvS8nE9xFJg7xCw~'

export const contentChangedSdJwtVc =
  'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6IiN6Nk1rdHF0WE5HOENEVVk5UHJydG9TdEZ6ZUNuaHBNbWd4WUwxZ2lrY1czQnp2TlcifQ.eyJjbGFpbSI6InNvbWUtY2xhaW0iLCJ2Y3QiOiJJZGVudGl0eUNyZWRlbnRpYWwyIiwiaXNzIjoiZGlkOmtleTp6Nk1rdHF0WE5HOENEVVk5UHJydG9TdEZ6ZUNuaHBNbWd4WUwxZ2lrY1czQnp2TlciLCJpYXQiOjE2OTgxNTE1MzJ9.TsFJUFKwdw5kVL4eY5vHOPGHqXBCFJ-n9c9KwPHkXAVfZ1TZkGA8m0_sNuTDy5n_pCutS6uzKJDAM0dfeGPyDg~'

export const signatureInvalidSdJwtVc =
  'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6IiN6Nk1rdHF0WE5HOENEVVk5UHJydG9TdEZ6ZUNuaHBNbWd4WUwxZ2lrY1czQnp2TlcifQ.eyJjbGFpbSI6InNvbWUtY2xhaW0iLCJ2Y3QiOiJJZGVudGl0eUNyZWRlbnRpYWwiLCJpc3MiOiJkaWQ6a2V5Ono2TWt0cXRYTkc4Q0RVWTlQcnJ0b1N0RnplQ25ocE1tZ3hZTDFnaWtjVzNCenZOVyIsImlhdCI6MTY5ODE1MTUzMn0.TsFJUFKwdw5kVL4eY5vHOPGHqXBCFJ-n9c9KwPHkXAVfZ1TZkGA8m0_sNuTDy5n_pCutd6uzKJDAM0dfeGPyDg~'

/**simpleSdJwtVcWithStatus
  {
    "jwt": {
      "header": {
        "typ": "vc+sd-jwt",
        "alg": "EdDSA",
        "kid": "#z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW"
      },
      "payload": {
        "claim": "some-claim",
        "vct": "IdentityCredential",
        "iss": "did:key:z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW",
        "iat": 1698151532,
        "status": {
          "status_list": {
            "idx": 12,
            "uri": "https://example.com/status-list"
          }
        }
      },
      "signature": "vLkigrBr1IIVRJeYE5DQx0rKUVzO3KT9T0XBATWJE89pWCyvB3Rzs8VD7qfi0vDk_QVCPIiHq1U1PsmSe4ZqCg"
    },
    "disclosures": []
  }
 */
export const simpleSdJwtVcWithStatus =
  'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6IiN6Nk1rdHF0WE5HOENEVVk5UHJydG9TdEZ6ZUNuaHBNbWd4WUwxZ2lrY1czQnp2TlcifQ.eyJjbGFpbSI6InNvbWUtY2xhaW0iLCJ2Y3QiOiJJZGVudGl0eUNyZWRlbnRpYWwiLCJzdGF0dXMiOnsic3RhdHVzX2xpc3QiOnsiaWR4IjoxMiwidXJpIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9zdGF0dXMtbGlzdCJ9fSwiaXNzIjoiZGlkOmtleTp6Nk1rdHF0WE5HOENEVVk5UHJydG9TdEZ6ZUNuaHBNbWd4WUwxZ2lrY1czQnp2TlciLCJpYXQiOjE2OTgxNTE1MzJ9.JWE6RRGt032UsQ9EoyJnvxq7dAQX2DjW6mLYuvDkCuq0fzse5V_7RO6R0RBCPHXWWIfnCNAA8oEI3QM6A3avDg~'

/**simpleJwtVcWithoutHolderBinding
  {
    "jwt": {
      "header": {
        "typ": "vc+sd-jwt",
        "alg": "EdDSA",
        "kid": "#z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW"
      },
      "payload": {
        "claim": "some-claim",
        "vct": "IdentityCredential",
        "iss": "did:key:z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW",
        "iat": 1698151532,
      },
      "signature": "vLkigrBr1IIVRJeYE5DQx0rKUVzO3KT9T0XBATWJE89pWCyvB3Rzs8VD7qfi0vDk_QVCPIiHq1U1PsmSe4ZqCg"
    },
    "disclosures": []
  }
 */
export const simpleJwtVcWithoutHolderBinding =
  'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6IiN6Nk1rdHF0WE5HOENEVVk5UHJydG9TdEZ6ZUNuaHBNbWd4WUwxZ2lrY1czQnp2TlcifQ.eyJjbGFpbSI6InNvbWUtY2xhaW0iLCJ2Y3QiOiJJZGVudGl0eUNyZWRlbnRpYWwiLCJpc3MiOiJkaWQ6a2V5Ono2TWt0cXRYTkc4Q0RVWTlQcnJ0b1N0RnplQ25ocE1tZ3hZTDFnaWtjVzNCenZOVyIsImlhdCI6MTY5ODE1MTUzMn0.TsFJUFKwdw5kVL4eY5vHOPGHqXBCFJ-n9c9KwPHkXAVfZ1TZkGA8m0_sNuTDy5n_pCutS6uzKJDAM0dfeGPyDg~'

/**simpleJwtVcPresentation
 * {
    "jwt": {
      "header": {
        "typ": "vc+sd-jwt",
        "alg": "EdDSA",
        "kid": "#z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW"
      },
      "payload": {
        "claim": "some-claim",
        "vct": "IdentityCredential",
        "cnf": {
          "jwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "oENVsxOUiH54X8wJLaVkicCRk00wBIQ4sRgbk54N8Mo"
          }
        },
        "iss": "did:key:z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW",
        "iat": 1698151532
      },
      "signature": "vLkigrBr1IIVRJeYE5DQx0rKUVzO3KT9T0XBATWJE89pWCyvB3Rzs8VD7qfi0vDk_QVCPIiHq1U1PsmSe4ZqCg"
    },
    "disclosures": [],
    "kbJwt": {
      "header": {
        "typ": "kb+jwt",
        "alg": "EdDSA"
      },
      "payload": {
        "iat": 1698151532,
        "nonce": "salt",
        "aud": "did:key:zUC74VEqqhEHQcgv4zagSPkqFJxuNWuoBPKjJuHETEUeHLoSqWt92viSsmaWjy82y",
        "sd_hash": "f48YBevUG5JVuAHMryWQ4i2OF7XJoI-dL-jjYx-HqxQ"
      },
      "signature": "skMqC7ej50kOeGEJZ_8J5eK1YqKN7vkqS_t8DQ4Y3i6DdN20eAXbaGMU4G4AOGk_hAYctTZwxaeQQEBX8pu5Cg"
    }
  }
 */
export const simpleJwtVcPresentation =
  'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6IiN6Nk1rdHF0WE5HOENEVVk5UHJydG9TdEZ6ZUNuaHBNbWd4WUwxZ2lrY1czQnp2TlcifQ.eyJjbGFpbSI6InNvbWUtY2xhaW0iLCJ2Y3QiOiJJZGVudGl0eUNyZWRlbnRpYWwiLCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4Ijoib0VOVnN4T1VpSDU0WDh3SkxhVmtpY0NSazAwd0JJUTRzUmdiazU0TjhNbyJ9fSwiaXNzIjoiZGlkOmtleTp6Nk1rdHF0WE5HOENEVVk5UHJydG9TdEZ6ZUNuaHBNbWd4WUwxZ2lrY1czQnp2TlciLCJpYXQiOjE2OTgxNTE1MzJ9.vLkigrBr1IIVRJeYE5DQx0rKUVzO3KT9T0XBATWJE89pWCyvB3Rzs8VD7qfi0vDk_QVCPIiHq1U1PsmSe4ZqCg~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE2OTgxNTE1MzIsIm5vbmNlIjoic2FsdCIsImF1ZCI6ImRpZDprZXk6elVDNzRWRXFxaEVIUWNndjR6YWdTUGtxRkp4dU5XdW9CUEtqSnVIRVRFVWVITG9TcVd0OTJ2aVNzbWFXank4MnkiLCJzZF9oYXNoIjoiZjQ4WUJldlVHNUpWdUFITXJ5V1E0aTJPRjdYSm9JLWRMLWpqWXgtSHF4USJ9.skMqC7ej50kOeGEJZ_8J5eK1YqKN7vkqS_t8DQ4Y3i6DdN20eAXbaGMU4G4AOGk_hAYctTZwxaeQQEBX8pu5Cg'

/**sdJwtVcWithSingleDisclosure
 * {
  "jwt": {
    "header": {
      "typ": "vc+sd-jwt",
      "alg": "EdDSA",
      "kid": "#z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW"
    },
    "payload": {
      "vct": "IdentityCredential",
      "cnf": {
        "jwk": {
          "kty": "OKP",
          "crv": "Ed25519",
          "x": "oENVsxOUiH54X8wJLaVkicCRk00wBIQ4sRgbk54N8Mo"
        }
      },
      "iss": "did:key:z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW",
      "iat": 1698151532,
      "_sd": [
        "vcvFU4DsFKTqQ1vl4nelJWXTb_-0dNoBks6iqNFptyg"
      ],
      "_sd_alg": "sha-256"
    },
    "signature": "wX-7AyTsGMFDpgaw-TMjFK2zyywB94lKAwXlc4DtNoYjhnvKEe6eln1YhKTD_IIPNyTDOCT-TgtzA-8tCg9NCQ"
  },
  "disclosures": [
    {
      "_digest": "vcvFU4DsFKTqQ1vl4nelJWXTb_-0dNoBks6iqNFptyg",
      "_encoded": "WyJzYWx0IiwiY2xhaW0iLCJzb21lLWNsYWltIl0",
      "salt": "salt",
      "key": "claim",
      "value": "some-claim"
    }
  ]
}
 *
 * claim:
{
  vct: 'IdentityCredential',
  cnf: {
    jwk: {
      kty: 'OKP',
      crv: 'Ed25519',
      x: 'oENVsxOUiH54X8wJLaVkicCRk00wBIQ4sRgbk54N8Mo'
    }
  },
  iss: 'did:key:z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW',
  iat: 1698151532,
  claim: 'some-claim'
}
 */
export const sdJwtVcWithSingleDisclosure =
  'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6IiN6Nk1rdHF0WE5HOENEVVk5UHJydG9TdEZ6ZUNuaHBNbWd4WUwxZ2lrY1czQnp2TlcifQ.eyJ2Y3QiOiJJZGVudGl0eUNyZWRlbnRpYWwiLCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4Ijoib0VOVnN4T1VpSDU0WDh3SkxhVmtpY0NSazAwd0JJUTRzUmdiazU0TjhNbyJ9fSwiaXNzIjoiZGlkOmtleTp6Nk1rdHF0WE5HOENEVVk5UHJydG9TdEZ6ZUNuaHBNbWd4WUwxZ2lrY1czQnp2TlciLCJpYXQiOjE2OTgxNTE1MzIsIl9zZCI6WyJ2Y3ZGVTREc0ZLVHFRMXZsNG5lbEpXWFRiXy0wZE5vQmtzNmlxTkZwdHlnIl0sIl9zZF9hbGciOiJzaGEtMjU2In0.wX-7AyTsGMFDpgaw-TMjFK2zyywB94lKAwXlc4DtNoYjhnvKEe6eln1YhKTD_IIPNyTDOCT-TgtzA-8tCg9NCQ~WyJzYWx0IiwiY2xhaW0iLCJzb21lLWNsYWltIl0~'

/**sdJwtVcWithSingleDisclosurePresentation
 * {
  "jwt": {
    "header": {
      "typ": "vc+sd-jwt",
      "alg": "EdDSA",
      "kid": "#z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW"
    },
    "payload": {
      "vct": "IdentityCredential",
      "cnf": {
        "jwk": {
          "kty": "OKP",
          "crv": "Ed25519",
          "x": "oENVsxOUiH54X8wJLaVkicCRk00wBIQ4sRgbk54N8Mo"
        }
      },
      "iss": "did:key:z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW",
      "iat": 1698151532,
      "_sd": [
        "vcvFU4DsFKTqQ1vl4nelJWXTb_-0dNoBks6iqNFptyg"
      ],
      "_sd_alg": "sha-256"
    },
    "signature": "wX-7AyTsGMFDpgaw-TMjFK2zyywB94lKAwXlc4DtNoYjhnvKEe6eln1YhKTD_IIPNyTDOCT-TgtzA-8tCg9NCQ"
  },
  "disclosures": [
    {
      "_digest": "vcvFU4DsFKTqQ1vl4nelJWXTb_-0dNoBks6iqNFptyg",
      "_encoded": "WyJzYWx0IiwiY2xhaW0iLCJzb21lLWNsYWltIl0",
      "salt": "salt",
      "key": "claim",
      "value": "some-claim"
    }
  ],
  "kbJwt": {
    "header": {
      "typ": "kb+jwt",
      "alg": "EdDSA"
    },
    "payload": {
      "iat": 1698151532,
      "nonce": "salt",
      "aud": "did:key:zUC74VEqqhEHQcgv4zagSPkqFJxuNWuoBPKjJuHETEUeHLoSqWt92viSsmaWjy82y",
      "sd_hash": "9F5VQwSVO7ZAwIgyh1jrwnJWgy7fTId1mj1MRp41nM8"
    },
    "signature": "9TcpFkSLYMbsQzkPMyqrT5kMk8sobEvTzfkwym5HvbTfEMa_J23LB-UFhY0FsBhe-1rYqnAykGuimQNaWIwODw"
  }
}

 * claims
{
  vct: 'IdentityCredential',
  cnf: {
    jwk: {
      kty: 'OKP',
      crv: 'Ed25519',
      x: 'oENVsxOUiH54X8wJLaVkicCRk00wBIQ4sRgbk54N8Mo'
    }
  },
  iss: 'did:key:z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW',
  iat: 1698151532,
  claim: 'some-claim'
}
 */
export const sdJwtVcWithSingleDisclosurePresentation =
  'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6IiN6Nk1rdHF0WE5HOENEVVk5UHJydG9TdEZ6ZUNuaHBNbWd4WUwxZ2lrY1czQnp2TlcifQ.eyJ2Y3QiOiJJZGVudGl0eUNyZWRlbnRpYWwiLCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4Ijoib0VOVnN4T1VpSDU0WDh3SkxhVmtpY0NSazAwd0JJUTRzUmdiazU0TjhNbyJ9fSwiaXNzIjoiZGlkOmtleTp6Nk1rdHF0WE5HOENEVVk5UHJydG9TdEZ6ZUNuaHBNbWd4WUwxZ2lrY1czQnp2TlciLCJpYXQiOjE2OTgxNTE1MzIsIl9zZCI6WyJ2Y3ZGVTREc0ZLVHFRMXZsNG5lbEpXWFRiXy0wZE5vQmtzNmlxTkZwdHlnIl0sIl9zZF9hbGciOiJzaGEtMjU2In0.wX-7AyTsGMFDpgaw-TMjFK2zyywB94lKAwXlc4DtNoYjhnvKEe6eln1YhKTD_IIPNyTDOCT-TgtzA-8tCg9NCQ~WyJzYWx0IiwiY2xhaW0iLCJzb21lLWNsYWltIl0~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE2OTgxNTE1MzIsIm5vbmNlIjoic2FsdCIsImF1ZCI6ImRpZDprZXk6elVDNzRWRXFxaEVIUWNndjR6YWdTUGtxRkp4dU5XdW9CUEtqSnVIRVRFVWVITG9TcVd0OTJ2aVNzbWFXank4MnkiLCJzZF9oYXNoIjoiOUY1VlF3U1ZPN1pBd0lneWgxanJ3bkpXZ3k3ZlRJZDFtajFNUnA0MW5NOCJ9.9TcpFkSLYMbsQzkPMyqrT5kMk8sobEvTzfkwym5HvbTfEMa_J23LB-UFhY0FsBhe-1rYqnAykGuimQNaWIwODw'

/**complexSdJwtVc
 * {
  "jwt": {
    "header": {
      "typ": "vc+sd-jwt",
      "alg": "EdDSA",
      "kid": "#z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW"
    },
    "payload": {
      "vct": "IdentityCredential",
      "family_name": "Doe",
      "phone_number": "+1-202-555-0101",
      "address": {
        "street_address": "123 Main St",
        "locality": "Anytown",
        "_sd": [
          "NJnmct0BqBME1JfBlC6jRQVRuevpEONiYw7A7MHuJyQ",
          "om5ZztZHB-Gd00LG21CV_xM4FaENSoiaOXnTAJNczB4"
        ]
      },
      "cnf": {
        "jwk": {
          "kty": "OKP",
          "crv": "Ed25519",
          "x": "oENVsxOUiH54X8wJLaVkicCRk00wBIQ4sRgbk54N8Mo"
        }
      },
      "iss": "did:key:z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW",
      "iat": 1698151532,
      "_sd": [
        "1Cur2k2A2oIB5CshSIf_A_Kg-l26u_qKuWQ79P0Vdas",
        "R1zTUvOYHgcepj0jHypGHz9EHttVKft0yswbc9ETPbU",
        "eDqQpdTXJXbWhf-EsI7zw5X6OvYmFN-UZQQMesXwKPw",
        "pdDk2_XAKHo7gOAfwF1b7OdCUVTit2kJHaxSECQ9xfc",
        "psauKUNWEi09nu3Cl89xKXgmpWENZl5uy1N1nyn_jMk",
        "sN_ge0pHXF6qmsYnX1A9SdwJ8ch8aENkxbODsT74YwI"
      ],
      "_sd_alg": "sha-256"
    },
    "signature": "Kkhrxy2acd52JTl4g_0x25D5d1QNCTbqHrD9Qu9HzXMxPMu_5T4z-cSiutDYb5cIdi9NzMXPe4MXax-fUymEDg"
  },
  "disclosures": [
    {
      "_digest": "NJnmct0BqBME1JfBlC6jRQVRuevpEONiYw7A7MHuJyQ",
      "_encoded": "WyJzYWx0IiwicmVnaW9uIiwiQW55c3RhdGUiXQ",
      "salt": "salt",
      "key": "region",
      "value": "Anystate"
    },
    {
      "_digest": "om5ZztZHB-Gd00LG21CV_xM4FaENSoiaOXnTAJNczB4",
      "_encoded": "WyJzYWx0IiwiY291bnRyeSIsIlVTIl0",
      "salt": "salt",
      "key": "country",
      "value": "US"
    },
    {
      "_digest": "eDqQpdTXJXbWhf-EsI7zw5X6OvYmFN-UZQQMesXwKPw",
      "_encoded": "WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ",
      "salt": "salt",
      "key": "given_name",
      "value": "John"
    },
    {
      "_digest": "psauKUNWEi09nu3Cl89xKXgmpWENZl5uy1N1nyn_jMk",
      "_encoded": "WyJzYWx0IiwiZW1haWwiLCJqb2huZG9lQGV4YW1wbGUuY29tIl0",
      "salt": "salt",
      "key": "email",
      "value": "johndoe@example.com"
    },
    {
      "_digest": "pdDk2_XAKHo7gOAfwF1b7OdCUVTit2kJHaxSECQ9xfc",
      "_encoded": "WyJzYWx0IiwiYmlydGhkYXRlIiwiMTk0MC0wMS0wMSJd",
      "salt": "salt",
      "key": "birthdate",
      "value": "1940-01-01"
    },
    {
      "_digest": "1Cur2k2A2oIB5CshSIf_A_Kg-l26u_qKuWQ79P0Vdas",
      "_encoded": "WyJzYWx0IiwiaXNfb3Zlcl8xOCIsdHJ1ZV0",
      "salt": "salt",
      "key": "is_over_18",
      "value": true
    },
    {
      "_digest": "R1zTUvOYHgcepj0jHypGHz9EHttVKft0yswbc9ETPbU",
      "_encoded": "WyJzYWx0IiwiaXNfb3Zlcl8yMSIsdHJ1ZV0",
      "salt": "salt",
      "key": "is_over_21",
      "value": true
    },
    {
      "_digest": "sN_ge0pHXF6qmsYnX1A9SdwJ8ch8aENkxbODsT74YwI",
      "_encoded": "WyJzYWx0IiwiaXNfb3Zlcl82NSIsdHJ1ZV0",
      "salt": "salt",
      "key": "is_over_65",
      "value": true
    }
  ]
}

 * claims
{
  vct: 'IdentityCredential',
  family_name: 'Doe',
  phone_number: '+1-202-555-0101',
  address: {
    street_address: '123 Main St',
    locality: 'Anytown',
    region: 'Anystate',
    country: 'US'
  },
  cnf: {
    jwk: {
      kty: 'OKP',
      crv: 'Ed25519',
      x: 'oENVsxOUiH54X8wJLaVkicCRk00wBIQ4sRgbk54N8Mo'
    }
  },
  iss: 'did:key:z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW',
  iat: 1698151532,
  is_over_18: true,
  is_over_21: true,
  given_name: 'John',
  birthdate: '1940-01-01',
  email: 'johndoe@example.com',
  is_over_65: true
}
 */
export const complexSdJwtVc =
  'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6IiN6Nk1rdHF0WE5HOENEVVk5UHJydG9TdEZ6ZUNuaHBNbWd4WUwxZ2lrY1czQnp2TlcifQ.eyJ2Y3QiOiJJZGVudGl0eUNyZWRlbnRpYWwiLCJmYW1pbHlfbmFtZSI6IkRvZSIsInBob25lX251bWJlciI6IisxLTIwMi01NTUtMDEwMSIsImFkZHJlc3MiOnsic3RyZWV0X2FkZHJlc3MiOiIxMjMgTWFpbiBTdCIsImxvY2FsaXR5IjoiQW55dG93biIsIl9zZCI6WyJOSm5tY3QwQnFCTUUxSmZCbEM2alJRVlJ1ZXZwRU9OaVl3N0E3TUh1SnlRIiwib201Wnp0WkhCLUdkMDBMRzIxQ1ZfeE00RmFFTlNvaWFPWG5UQUpOY3pCNCJdfSwiY25mIjp7Imp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Im9FTlZzeE9VaUg1NFg4d0pMYVZraWNDUmswMHdCSVE0c1JnYms1NE44TW8ifX0sImlzcyI6ImRpZDprZXk6ejZNa3RxdFhORzhDRFVZOVBycnRvU3RGemVDbmhwTW1neFlMMWdpa2NXM0J6dk5XIiwiaWF0IjoxNjk4MTUxNTMyLCJfc2QiOlsiMUN1cjJrMkEyb0lCNUNzaFNJZl9BX0tnLWwyNnVfcUt1V1E3OVAwVmRhcyIsIlIxelRVdk9ZSGdjZXBqMGpIeXBHSHo5RUh0dFZLZnQweXN3YmM5RVRQYlUiLCJlRHFRcGRUWEpYYldoZi1Fc0k3enc1WDZPdlltRk4tVVpRUU1lc1h3S1B3IiwicGREazJfWEFLSG83Z09BZndGMWI3T2RDVVZUaXQya0pIYXhTRUNROXhmYyIsInBzYXVLVU5XRWkwOW51M0NsODl4S1hnbXBXRU5abDV1eTFOMW55bl9qTWsiLCJzTl9nZTBwSFhGNnFtc1luWDFBOVNkd0o4Y2g4YUVOa3hiT0RzVDc0WXdJIl0sIl9zZF9hbGciOiJzaGEtMjU2In0.Kkhrxy2acd52JTl4g_0x25D5d1QNCTbqHrD9Qu9HzXMxPMu_5T4z-cSiutDYb5cIdi9NzMXPe4MXax-fUymEDg~WyJzYWx0IiwicmVnaW9uIiwiQW55c3RhdGUiXQ~WyJzYWx0IiwiY291bnRyeSIsIlVTIl0~WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJzYWx0IiwiZW1haWwiLCJqb2huZG9lQGV4YW1wbGUuY29tIl0~WyJzYWx0IiwiYmlydGhkYXRlIiwiMTk0MC0wMS0wMSJd~WyJzYWx0IiwiaXNfb3Zlcl8xOCIsdHJ1ZV0~WyJzYWx0IiwiaXNfb3Zlcl8yMSIsdHJ1ZV0~WyJzYWx0IiwiaXNfb3Zlcl82NSIsdHJ1ZV0~'

/**complexSdJwtVcPresentation
 * {
  "jwt": {
    "header": {
      "typ": "vc+sd-jwt",
      "alg": "EdDSA",
      "kid": "#z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW"
    },
    "payload": {
      "vct": "IdentityCredential",
      "family_name": "Doe",
      "phone_number": "+1-202-555-0101",
      "address": {
        "street_address": "123 Main St",
        "locality": "Anytown",
        "_sd": [
          "NJnmct0BqBME1JfBlC6jRQVRuevpEONiYw7A7MHuJyQ",
          "om5ZztZHB-Gd00LG21CV_xM4FaENSoiaOXnTAJNczB4"
        ]
      },
      "cnf": {
        "jwk": {
          "kty": "OKP",
          "crv": "Ed25519",
          "x": "oENVsxOUiH54X8wJLaVkicCRk00wBIQ4sRgbk54N8Mo"
        }
      },
      "iss": "did:key:z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW",
      "iat": 1698151532,
      "_sd": [
        "1Cur2k2A2oIB5CshSIf_A_Kg-l26u_qKuWQ79P0Vdas",
        "R1zTUvOYHgcepj0jHypGHz9EHttVKft0yswbc9ETPbU",
        "eDqQpdTXJXbWhf-EsI7zw5X6OvYmFN-UZQQMesXwKPw",
        "pdDk2_XAKHo7gOAfwF1b7OdCUVTit2kJHaxSECQ9xfc",
        "psauKUNWEi09nu3Cl89xKXgmpWENZl5uy1N1nyn_jMk",
        "sN_ge0pHXF6qmsYnX1A9SdwJ8ch8aENkxbODsT74YwI"
      ],
      "_sd_alg": "sha-256"
    },
    "signature": "Kkhrxy2acd52JTl4g_0x25D5d1QNCTbqHrD9Qu9HzXMxPMu_5T4z-cSiutDYb5cIdi9NzMXPe4MXax-fUymEDg"
  },
  "disclosures": [
    {
      "_digest": "om5ZztZHB-Gd00LG21CV_xM4FaENSoiaOXnTAJNczB4",
      "_encoded": "WyJzYWx0IiwiY291bnRyeSIsIlVTIl0",
      "salt": "salt",
      "key": "country",
      "value": "US"
    },
    {
      "_digest": "psauKUNWEi09nu3Cl89xKXgmpWENZl5uy1N1nyn_jMk",
      "_encoded": "WyJzYWx0IiwiZW1haWwiLCJqb2huZG9lQGV4YW1wbGUuY29tIl0",
      "salt": "salt",
      "key": "email",
      "value": "johndoe@example.com"
    },
    {
      "_digest": "eDqQpdTXJXbWhf-EsI7zw5X6OvYmFN-UZQQMesXwKPw",
      "_encoded": "WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ",
      "salt": "salt",
      "key": "given_name",
      "value": "John"
    },
    {
      "_digest": "R1zTUvOYHgcepj0jHypGHz9EHttVKft0yswbc9ETPbU",
      "_encoded": "WyJzYWx0IiwiaXNfb3Zlcl8yMSIsdHJ1ZV0",
      "salt": "salt",
      "key": "is_over_21",
      "value": true
    },
    {
      "_digest": "sN_ge0pHXF6qmsYnX1A9SdwJ8ch8aENkxbODsT74YwI",
      "_encoded": "WyJzYWx0IiwiaXNfb3Zlcl82NSIsdHJ1ZV0",
      "salt": "salt",
      "key": "is_over_65",
      "value": true
    }
  ],
  "kbJwt": {
    "header": {
      "typ": "kb+jwt",
      "alg": "EdDSA"
    },
    "payload": {
      "iat": 1698151532,
      "nonce": "salt",
      "aud": "did:key:zUC74VEqqhEHQcgv4zagSPkqFJxuNWuoBPKjJuHETEUeHLoSqWt92viSsmaWjy82y",
      "sd_hash": "8qgm3cypUxDaa_grER613U9UNETnbLragU6UVwJ4HlM"
    },
    "signature": "62HzMUsjlMq3BWyEBZwCuQnR5LzouSZKWh6es5CtC9HphOrh0ps1Lj_2iiZHfMv_lVF5Np_ZOiZNqsHfPL3GAA"
  }
}
 * claims
{
  vct: 'IdentityCredential',
  family_name: 'Doe',
  phone_number: '+1-202-555-0101',
  address: { street_address: '123 Main St', locality: 'Anytown', country: 'US' },
  cnf: {
    jwk: {
      kty: 'OKP',
      crv: 'Ed25519',
      x: 'oENVsxOUiH54X8wJLaVkicCRk00wBIQ4sRgbk54N8Mo'
    }
  },
  iss: 'did:key:z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW',
  iat: 1698151532,
  is_over_21: true,
  given_name: 'John',
  email: 'johndoe@example.com',
  is_over_65: true
}
 */
export const complexSdJwtVcPresentation =
  'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6IiN6Nk1rdHF0WE5HOENEVVk5UHJydG9TdEZ6ZUNuaHBNbWd4WUwxZ2lrY1czQnp2TlcifQ.eyJ2Y3QiOiJJZGVudGl0eUNyZWRlbnRpYWwiLCJmYW1pbHlfbmFtZSI6IkRvZSIsInBob25lX251bWJlciI6IisxLTIwMi01NTUtMDEwMSIsImFkZHJlc3MiOnsic3RyZWV0X2FkZHJlc3MiOiIxMjMgTWFpbiBTdCIsImxvY2FsaXR5IjoiQW55dG93biIsIl9zZCI6WyJOSm5tY3QwQnFCTUUxSmZCbEM2alJRVlJ1ZXZwRU9OaVl3N0E3TUh1SnlRIiwib201Wnp0WkhCLUdkMDBMRzIxQ1ZfeE00RmFFTlNvaWFPWG5UQUpOY3pCNCJdfSwiY25mIjp7Imp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Im9FTlZzeE9VaUg1NFg4d0pMYVZraWNDUmswMHdCSVE0c1JnYms1NE44TW8ifX0sImlzcyI6ImRpZDprZXk6ejZNa3RxdFhORzhDRFVZOVBycnRvU3RGemVDbmhwTW1neFlMMWdpa2NXM0J6dk5XIiwiaWF0IjoxNjk4MTUxNTMyLCJfc2QiOlsiMUN1cjJrMkEyb0lCNUNzaFNJZl9BX0tnLWwyNnVfcUt1V1E3OVAwVmRhcyIsIlIxelRVdk9ZSGdjZXBqMGpIeXBHSHo5RUh0dFZLZnQweXN3YmM5RVRQYlUiLCJlRHFRcGRUWEpYYldoZi1Fc0k3enc1WDZPdlltRk4tVVpRUU1lc1h3S1B3IiwicGREazJfWEFLSG83Z09BZndGMWI3T2RDVVZUaXQya0pIYXhTRUNROXhmYyIsInBzYXVLVU5XRWkwOW51M0NsODl4S1hnbXBXRU5abDV1eTFOMW55bl9qTWsiLCJzTl9nZTBwSFhGNnFtc1luWDFBOVNkd0o4Y2g4YUVOa3hiT0RzVDc0WXdJIl0sIl9zZF9hbGciOiJzaGEtMjU2In0.Kkhrxy2acd52JTl4g_0x25D5d1QNCTbqHrD9Qu9HzXMxPMu_5T4z-cSiutDYb5cIdi9NzMXPe4MXax-fUymEDg~WyJzYWx0IiwiaXNfb3Zlcl82NSIsdHJ1ZV0~WyJzYWx0IiwiaXNfb3Zlcl8yMSIsdHJ1ZV0~WyJzYWx0IiwiZW1haWwiLCJqb2huZG9lQGV4YW1wbGUuY29tIl0~WyJzYWx0IiwiY291bnRyeSIsIlVTIl0~WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE2OTgxNTE1MzIsIm5vbmNlIjoic2FsdCIsImF1ZCI6ImRpZDprZXk6elVDNzRWRXFxaEVIUWNndjR6YWdTUGtxRkp4dU5XdW9CUEtqSnVIRVRFVWVITG9TcVd0OTJ2aVNzbWFXank4MnkiLCJzZF9oYXNoIjoiaFRtUklwNFQ1Y2ZqQlUxbTVvcXNNWDZuUlFObGpEdXZSSThTWnlTeWhsZyJ9.D0G1__PslfgjkwTC1082x3r8Wp5mf13977y7Ef2xhvDrOO7V3zio5BZzqrDwzXIi3Y5GA1Vv3ptqpUKMn14EBA'
