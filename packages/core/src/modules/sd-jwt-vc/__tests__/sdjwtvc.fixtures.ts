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

export const simpleX509 = {
  sdJwtVc:
    'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsIng1YyI6WyJNSUhlTUlHUm9BTUNBUUlDRUIwYW80ZVVBZUhrQjg2dzhmSUVuR2N3QlFZREsyVndNQUF3SGhjTk1qUXdOekUyTVRNek5URTNXaGNOTWpReE1ESXpNVEkwTlRNeVdqQUFNQ293QlFZREsyVndBeUVBMWMra1AwdFlodlN2LzJCdzdvSlFiQ1dZT2JUY0IyS1VPVHB3K0x0TG85dWpJVEFmTUIwR0ExVWRFUVFXTUJTR0VtaDBkSEJ6T2k4dmFYTnpkV1Z5TG1OdmJUQUZCZ01yWlhBRFFRQkU0SmFrbTh2bjI1NUI4ZEFneWdiaFIwWlBTZkNFbmdGdWlXREJkeUFYalc2YWhpdDZtOGlsZW05MDhreGsyeUpOZ2hUSVNCbERod2tmcmx5UFJ4NE0iXX0.eyJjbGFpbSI6InNvbWUtY2xhaW0iLCJ2Y3QiOiJJZGVudGl0eUNyZWRlbnRpYWwiLCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4Ijoib0VOVnN4T1VpSDU0WDh3SkxhVmtpY0NSazAwd0JJUTRzUmdiazU0TjhNbyJ9fSwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIuY29tIiwiaWF0IjoxNjk4MTUxNTMyfQ.d254hz7u-mziOtFA3yA9tVNNDP5_6eJL-owg9prcr1jzVnYoiRyjPvzY7NuKuDqN5PeOaZ2x5GFYp7VwYX5RBw~',
  trustedCertficate:
    'MIHeMIGRoAMCAQICEB0ao4eUAeHkB86w8fIEnGcwBQYDK2VwMAAwHhcNMjQwNzE2MTMzNTE3WhcNMjQxMDIzMTI0NTMyWjAAMCowBQYDK2VwAyEA1c+kP0tYhvSv/2Bw7oJQbCWYObTcB2KUOTpw+LtLo9ujITAfMB0GA1UdEQQWMBSGEmh0dHBzOi8vaXNzdWVyLmNvbTAFBgMrZXADQQBE4Jakm8vn255B8dAgygbhR0ZPSfCEngFuiWDBdyAXjW6ahit6m8ilem908kxk2yJNghTISBlDhwkfrlyPRx4M',
  certificateIssuer: 'https://issuer.com',
}

export const funkeX509 = {
  sdJwtVc:
    'eyJ4NWMiOlsiTUlJQ2REQ0NBaHVnQXdJQkFnSUJBakFLQmdncWhrak9QUVFEQWpDQmlERUxNQWtHQTFVRUJoTUNSRVV4RHpBTkJnTlZCQWNNQmtKbGNteHBiakVkTUJzR0ExVUVDZ3dVUW5WdVpHVnpaSEoxWTJ0bGNtVnBJRWR0WWtneEVUQVBCZ05WQkFzTUNGUWdRMU1nU1VSRk1UWXdOQVlEVlFRRERDMVRVRkpKVGtRZ1JuVnVhMlVnUlZWRVNTQlhZV3hzWlhRZ1VISnZkRzkwZVhCbElFbHpjM1ZwYm1jZ1EwRXdIaGNOTWpRd05UTXhNRGd4TXpFM1doY05NalV3TnpBMU1EZ3hNekUzV2pCc01Rc3dDUVlEVlFRR0V3SkVSVEVkTUJzR0ExVUVDZ3dVUW5WdVpHVnpaSEoxWTJ0bGNtVnBJRWR0WWtneENqQUlCZ05WQkFzTUFVa3hNakF3QmdOVkJBTU1LVk5RVWtsT1JDQkdkVzVyWlNCRlZVUkpJRmRoYkd4bGRDQlFjbTkwYjNSNWNHVWdTWE56ZFdWeU1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRU9GQnE0WU1LZzR3NWZUaWZzeXR3QnVKZi83RTdWaFJQWGlObTUyUzNxMUVUSWdCZFh5REsza1Z4R3hnZUhQaXZMUDN1dU12UzZpREVjN3FNeG12ZHVLT0JrRENCalRBZEJnTlZIUTRFRmdRVWlQaENrTEVyRFhQTFcyL0owV1ZlZ2h5dyttSXdEQVlEVlIwVEFRSC9CQUl3QURBT0JnTlZIUThCQWY4RUJBTUNCNEF3TFFZRFZSMFJCQ1l3SklJaVpHVnRieTV3YVdRdGFYTnpkV1Z5TG1KMWJtUmxjMlJ5ZFdOclpYSmxhUzVrWlRBZkJnTlZIU01FR0RBV2dCVFVWaGpBaVRqb0RsaUVHTWwyWXIrcnU4V1F2akFLQmdncWhrak9QUVFEQWdOSEFEQkVBaUFiZjVUemtjUXpoZldvSW95aTFWTjdkOEk5QnNGS20xTVdsdVJwaDJieUdRSWdLWWtkck5mMnhYUGpWU2JqVy9VLzVTNXZBRUM1WHhjT2FudXNPQnJvQmJVPSIsIk1JSUNlVENDQWlDZ0F3SUJBZ0lVQjVFOVFWWnRtVVljRHRDaktCL0gzVlF2NzJnd0NnWUlLb1pJemowRUF3SXdnWWd4Q3pBSkJnTlZCQVlUQWtSRk1ROHdEUVlEVlFRSERBWkNaWEpzYVc0eEhUQWJCZ05WQkFvTUZFSjFibVJsYzJSeWRXTnJaWEpsYVNCSGJXSklNUkV3RHdZRFZRUUxEQWhVSUVOVElFbEVSVEUyTURRR0ExVUVBd3d0VTFCU1NVNUVJRVoxYm10bElFVlZSRWtnVjJGc2JHVjBJRkJ5YjNSdmRIbHdaU0JKYzNOMWFXNW5JRU5CTUI0WERUSTBNRFV6TVRBMk5EZ3dPVm9YRFRNME1EVXlPVEEyTkRnd09Wb3dnWWd4Q3pBSkJnTlZCQVlUQWtSRk1ROHdEUVlEVlFRSERBWkNaWEpzYVc0eEhUQWJCZ05WQkFvTUZFSjFibVJsYzJSeWRXTnJaWEpsYVNCSGJXSklNUkV3RHdZRFZRUUxEQWhVSUVOVElFbEVSVEUyTURRR0ExVUVBd3d0VTFCU1NVNUVJRVoxYm10bElFVlZSRWtnVjJGc2JHVjBJRkJ5YjNSdmRIbHdaU0JKYzNOMWFXNW5JRU5CTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFWUd6ZHdGRG5jNytLbjVpYkF2Q09NOGtlNzdWUXhxZk1jd1pMOElhSUErV0NST2NDZm1ZL2dpSDkycU1ydTVwL2t5T2l2RTBSQy9JYmRNT052RG9VeWFObU1HUXdIUVlEVlIwT0JCWUVGTlJXR01DSk9PZ09XSVFZeVhaaXY2dTd4WkMrTUI4R0ExVWRJd1FZTUJhQUZOUldHTUNKT09nT1dJUVl5WFppdjZ1N3haQytNQklHQTFVZEV3RUIvd1FJTUFZQkFmOENBUUF3RGdZRFZSMFBBUUgvQkFRREFnR0dNQW9HQ0NxR1NNNDlCQU1DQTBjQU1FUUNJR0VtN3drWktIdC9hdGI0TWRGblhXNnlybndNVVQydTEzNmdkdGwxMFk2aEFpQnVURnF2Vll0aDFyYnh6Q1AweFdaSG1RSzlrVnl4bjhHUGZYMjdFSXp6c3c9PSJdLCJraWQiOiJNSUdVTUlHT3BJR0xNSUdJTVFzd0NRWURWUVFHRXdKRVJURVBNQTBHQTFVRUJ3d0dRbVZ5YkdsdU1SMHdHd1lEVlFRS0RCUkNkVzVrWlhOa2NuVmphMlZ5WldrZ1IyMWlTREVSTUE4R0ExVUVDd3dJVkNCRFV5QkpSRVV4TmpBMEJnTlZCQU1NTFZOUVVrbE9SQ0JHZFc1clpTQkZWVVJKSUZkaGJHeGxkQ0JRY205MGIzUjVjR1VnU1hOemRXbHVaeUJEUVFJQkFnPT0iLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJwbGFjZV9vZl9iaXJ0aCI6eyJfc2QiOlsiZVNReDlVNFI4S2dKUnJISWZOYTdPeUhTR2I3WTh3bFNaWkc0MXVwWFN2ayJdfSwiX3NkIjpbIkdxZVRITW1mWFNyLVRpWHNscGVidTd2ay1aTzBnYkJ3N0ktbWtPR2k4UlEiLCIzMlpvemdIRl9kVFhRTVZMRWl6d0ZzelJ5b0IxVks5bHNnakFHaHlUdnBnIiwib2htY1pCTE1JUFRhOWN2cHVNdXRzcWRZdVFhaTRiR2RibmFJZDRSeDBQayIsIndQQ0lfbzQtbFhWVzkySkVCQkJPazUwUWVISGQtYWl4WGJzOWJ5dGhueWMiLCJqaTJ3VXd6RWJCWmFGOHRtLWRLaUZSVTZpbVp0bTU1ZGFOZkVaYW9xWTBzIiwidk5CS2RKNUVpakFuZWwxaVM4ZGFLS0J5TWd6d3JSelBzTU9vUEZTWkJQQSIsInlfeG5PUGVNU2M5Y2FjZ25VanBYYkFFeW9OZXVIZVpDYkdJdi1WYXU1YWsiXSwiYWRkcmVzcyI6eyJfc2QiOlsiWjhZbDBCalFaZGZ3LWZtbzRCZGR0SzVxMEM3Vk9OLXJ5ZjBUbEZwVUtZayIsIktWbUtzNnBCR0VsNHZTTTJrTF9RZ1FFTEdqLU5mR084blJGbkx0NWdlRlkiLCJabHJibS1BMHdMTURSVWQ0Z1o5SDRSUWJaR3BUMVpRNG5ZSGlxdFI2WU9NIl19LCJpc3N1aW5nX2NvdW50cnkiOiJERSIsInZjdCI6InVybjpldS5ldXJvcGEuZWMuZXVkaTpwaWQ6MSIsImlzc3VpbmdfYXV0aG9yaXR5IjoiREUiLCJfc2RfYWxnIjoic2hhLTI1NiIsImlzcyI6Imh0dHBzOi8vZGVtby5waWQtaXNzdWVyLmJ1bmRlc2RydWNrZXJlaS5kZS9jIiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlU2WDhQb3FpelozLVByTm93UlVRaDduLXR3bTlabzF3VTh0WDkxUEVtXzgiLCJ5IjoidGZjZHFnS3JVVTIyR2VFV0U3NDlMYThkSFlFTGJmSkdDWVFfYVFSM3BPcyJ9fSwiZXhwIjoxNzE4NzA3ODA0LCJpYXQiOjE3MTc0OTgyMDQsImFnZV9lcXVhbF9vcl9vdmVyIjp7Il9zZCI6WyJMOVN3ZS04cHUxZ1llS0ltdUNlQ1RKcTYwODQzeWlSeVV1Rlh0aUdSb1lzIiwiVWFWeWlOSlZzeFR1dHlJVG9rWXVsUDJ2cjVaaHEzRUVRMWNrZ1ptNHRHUSIsIlhGeWVmQ09vZHFJdkkyQm91Rl9hQVBVMF9tZDlaLUI3a1BvaXd4NTdYRk0iLCJsUXlnaFhaclY0dnRROUtwVVpKNnB6R0g5VlRIRUI5MDkzVjdjQmYySEQ4IiwiX2NzVjc3OEdSdEd1dlB1dlJ3Vi11SFhCeklvUTNPMEY0bVB1UHVlWGpYTSIsInptYm1xU2gwMTlNZzF3QVZpdWJyaWxNSW00UnpsTWhuc041Wi1kQkVIeWsiXX19.eX-vYUtV2FcJ2Qq8mlQybSlwmXjZ6jCzKdav-G5xR1mFOQFcLOWZ1j3dPRmdFCat3MWqsHbx6eaZjue4tmDF2Q~WyJKNm55NUdXVzlJZHNXQURKblNEQnN3IiwiZmFtaWx5X25hbWUiLCJNVVNURVJNQU5OIl0~WyJqcnVqMGV4RjdOVElGWEptOUJWQ1VnIiwiZ2l2ZW5fbmFtZSIsIkVSSUtBIl0~WyJRRkJBbnFIaUo3Y1A1MHBDak1IdUFBIiwiYmlydGhkYXRlIiwiMTk2NC0wOC0xMiJd~WyI1MmQxQVNmbmE3N1JERXE3bnR4ODFnIiwiYWdlX2JpcnRoX3llYXIiLDE5NjRd~WyJiZmRSdEl5NV9kRWloc3BRTmwzNDNBIiwiYWdlX2luX3llYXJzIiw1OV0~WyJXbG43VmxHTXhaXzRlSkc0dmNkYTRnIiwiYmlydGhfZmFtaWx5X25hbWUiLCJHQUJMRVIiXQ~WyJBUFdMWlRVOHRzS3NNWXBzazhtclVnIiwibmF0aW9uYWxpdGllcyIsWyJERSJdXQ~WyJOaE9LaFRNdEhxU2pzdmV1ekFLbWpBIiwiMTIiLHRydWVd~WyJFTlFGWURlTEV0bEo3cDhzdEFMSDJRIiwiMTQiLHRydWVd~WyJtNE5QUHFxY0VxVm4tWVNyQkFNMHVBIiwiMTYiLHRydWVd~WyJNT1R4eG1kUk05alhoX3dHbzZTQXpRIiwiMTgiLHRydWVd~WyJNZ3oySzRqTzFJVlZCU015RTNoZ1JRIiwiMjEiLHRydWVd~WyJNN0tjb0JIMjZPVzhPZUFicmZMakx3IiwiNjUiLGZhbHNlXQ~WyJRaW5JUERxdnJFem5Talp1MkZqOUl3IiwibG9jYWxpdHkiLCJCRVJMSU4iXQ~WyJxVFg0Si1URFBqTHh3TElhU3NZLWlBIiwibG9jYWxpdHkiLCJLw5ZMTiJd~WyJFSlNfdFlyVGI4VWVYWXJGY3pkNUd3IiwicG9zdGFsX2NvZGUiLCI1MTE0NyJd~WyJRZFhXN3BaWkVpV1ZLbXFZOGg1d0VBIiwic3RyZWV0X2FkZHJlc3MiLCJIRUlERVNUUkHhup5FIDE3Il0~',
  trustedCertificate:
    'MIICdDCCAhugAwIBAgIBAjAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwHhcNMjQwNTMxMDgxMzE3WhcNMjUwNzA1MDgxMzE3WjBsMQswCQYDVQQGEwJERTEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxCjAIBgNVBAsMAUkxMjAwBgNVBAMMKVNQUklORCBGdW5rZSBFVURJIFdhbGxldCBQcm90b3R5cGUgSXNzdWVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOFBq4YMKg4w5fTifsytwBuJf/7E7VhRPXiNm52S3q1ETIgBdXyDK3kVxGxgeHPivLP3uuMvS6iDEc7qMxmvduKOBkDCBjTAdBgNVHQ4EFgQUiPhCkLErDXPLW2/J0WVeghyw+mIwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwLQYDVR0RBCYwJIIiZGVtby5waWQtaXNzdWVyLmJ1bmRlc2RydWNrZXJlaS5kZTAfBgNVHSMEGDAWgBTUVhjAiTjoDliEGMl2Yr+ru8WQvjAKBggqhkjOPQQDAgNHADBEAiAbf5TzkcQzhfWoIoyi1VN7d8I9BsFKm1MWluRph2byGQIgKYkdrNf2xXPjVSbjW/U/5S5vAEC5XxcOanusOBroBbU=',
}

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

export const sdJwtVcPid =
  'eyJ4NWMiOlsiTUlJQ2REQ0NBaHVnQXdJQkFnSUJBakFLQmdncWhrak9QUVFEQWpDQmlERUxNQWtHQTFVRUJoTUNSRVV4RHpBTkJnTlZCQWNNQmtKbGNteHBiakVkTUJzR0ExVUVDZ3dVUW5WdVpHVnpaSEoxWTJ0bGNtVnBJRWR0WWtneEVUQVBCZ05WQkFzTUNGUWdRMU1nU1VSRk1UWXdOQVlEVlFRRERDMVRVRkpKVGtRZ1JuVnVhMlVnUlZWRVNTQlhZV3hzWlhRZ1VISnZkRzkwZVhCbElFbHpjM1ZwYm1jZ1EwRXdIaGNOTWpRd05UTXhNRGd4TXpFM1doY05NalV3TnpBMU1EZ3hNekUzV2pCc01Rc3dDUVlEVlFRR0V3SkVSVEVkTUJzR0ExVUVDZ3dVUW5WdVpHVnpaSEoxWTJ0bGNtVnBJRWR0WWtneENqQUlCZ05WQkFzTUFVa3hNakF3QmdOVkJBTU1LVk5RVWtsT1JDQkdkVzVyWlNCRlZVUkpJRmRoYkd4bGRDQlFjbTkwYjNSNWNHVWdTWE56ZFdWeU1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRU9GQnE0WU1LZzR3NWZUaWZzeXR3QnVKZi83RTdWaFJQWGlObTUyUzNxMUVUSWdCZFh5REsza1Z4R3hnZUhQaXZMUDN1dU12UzZpREVjN3FNeG12ZHVLT0JrRENCalRBZEJnTlZIUTRFRmdRVWlQaENrTEVyRFhQTFcyL0owV1ZlZ2h5dyttSXdEQVlEVlIwVEFRSC9CQUl3QURBT0JnTlZIUThCQWY4RUJBTUNCNEF3TFFZRFZSMFJCQ1l3SklJaVpHVnRieTV3YVdRdGFYTnpkV1Z5TG1KMWJtUmxjMlJ5ZFdOclpYSmxhUzVrWlRBZkJnTlZIU01FR0RBV2dCVFVWaGpBaVRqb0RsaUVHTWwyWXIrcnU4V1F2akFLQmdncWhrak9QUVFEQWdOSEFEQkVBaUFiZjVUemtjUXpoZldvSW95aTFWTjdkOEk5QnNGS20xTVdsdVJwaDJieUdRSWdLWWtkck5mMnhYUGpWU2JqVy9VLzVTNXZBRUM1WHhjT2FudXNPQnJvQmJVPSIsIk1JSUNlVENDQWlDZ0F3SUJBZ0lVQjVFOVFWWnRtVVljRHRDaktCL0gzVlF2NzJnd0NnWUlLb1pJemowRUF3SXdnWWd4Q3pBSkJnTlZCQVlUQWtSRk1ROHdEUVlEVlFRSERBWkNaWEpzYVc0eEhUQWJCZ05WQkFvTUZFSjFibVJsYzJSeWRXTnJaWEpsYVNCSGJXSklNUkV3RHdZRFZRUUxEQWhVSUVOVElFbEVSVEUyTURRR0ExVUVBd3d0VTFCU1NVNUVJRVoxYm10bElFVlZSRWtnVjJGc2JHVjBJRkJ5YjNSdmRIbHdaU0JKYzNOMWFXNW5JRU5CTUI0WERUSTBNRFV6TVRBMk5EZ3dPVm9YRFRNME1EVXlPVEEyTkRnd09Wb3dnWWd4Q3pBSkJnTlZCQVlUQWtSRk1ROHdEUVlEVlFRSERBWkNaWEpzYVc0eEhUQWJCZ05WQkFvTUZFSjFibVJsYzJSeWRXTnJaWEpsYVNCSGJXSklNUkV3RHdZRFZRUUxEQWhVSUVOVElFbEVSVEUyTURRR0ExVUVBd3d0VTFCU1NVNUVJRVoxYm10bElFVlZSRWtnVjJGc2JHVjBJRkJ5YjNSdmRIbHdaU0JKYzNOMWFXNW5JRU5CTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFWUd6ZHdGRG5jNytLbjVpYkF2Q09NOGtlNzdWUXhxZk1jd1pMOElhSUErV0NST2NDZm1ZL2dpSDkycU1ydTVwL2t5T2l2RTBSQy9JYmRNT052RG9VeWFObU1HUXdIUVlEVlIwT0JCWUVGTlJXR01DSk9PZ09XSVFZeVhaaXY2dTd4WkMrTUI4R0ExVWRJd1FZTUJhQUZOUldHTUNKT09nT1dJUVl5WFppdjZ1N3haQytNQklHQTFVZEV3RUIvd1FJTUFZQkFmOENBUUF3RGdZRFZSMFBBUUgvQkFRREFnR0dNQW9HQ0NxR1NNNDlCQU1DQTBjQU1FUUNJR0VtN3drWktIdC9hdGI0TWRGblhXNnlybndNVVQydTEzNmdkdGwxMFk2aEFpQnVURnF2Vll0aDFyYnh6Q1AweFdaSG1RSzlrVnl4bjhHUGZYMjdFSXp6c3c9PSJdLCJraWQiOiJNSUdVTUlHT3BJR0xNSUdJTVFzd0NRWURWUVFHRXdKRVJURVBNQTBHQTFVRUJ3d0dRbVZ5YkdsdU1SMHdHd1lEVlFRS0RCUkNkVzVrWlhOa2NuVmphMlZ5WldrZ1IyMWlTREVSTUE4R0ExVUVDd3dJVkNCRFV5QkpSRVV4TmpBMEJnTlZCQU1NTFZOUVVrbE9SQ0JHZFc1clpTQkZWVVJKSUZkaGJHeGxkQ0JRY205MGIzUjVjR1VnU1hOemRXbHVaeUJEUVFJQkFnPT0iLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJwbGFjZV9vZl9iaXJ0aCI6eyJfc2QiOlsiaG9zSHlUSkpYRXRtbHdvcC13TU9QR1NWd1J3MTdzOW83M0kyc3plQlZEbyJdfSwiX3NkIjpbIjRDbDVaZ0trN256V09FZmFXa2xhZ0FqQU53QmRMeDJST25UVUhrS1JZY1UiLCI1amQtYXFEZFRfQnUtV2tGOXNvbW5NeEVISnRyVGxRYlRfRU9Eay1yUlNzIiwiNmZ6NEdoRVp5ZnpaRndNY1dOTF9CVHRwdHNEd3RrV1habjdqTl9rU1FnWSIsIkM3VG1jS1lsVHA0Ty05VnI0SEZ0cUdBQWUwNERHX3Fmcy04MzRpSVJMVG8iLCJQVEprTlByTEw3a3pvcFpPTnZWc2pmaWppSi1rdXc2MW5BTGJUWFpsOFhvIiwiUmd0eHNOSHBVNUZJN0xNa1ktb0Q3ZFZ4eUtNMkc4RUc5aHR2TVJpZFBQRSIsImJ4YUwyQ2tpX3B2VGxhYWRRU0MwMVlhakVQcXlYMzlORFdEU2dCU2RuZlEiXSwiYWRkcmVzcyI6eyJfc2QiOlsiOTZqVjZZXy04d2VtcVgxallMdkN1N3R4dVRRT01LMTczeUdZZ1FtOUNQQSIsIkdZdWk3cHZ4bW8yQXFlblY1WWdCQmtFdGs4WGdzNktiTUZHS0o3T1c3YmciLCJmZHQwWG14OEkyOGRmcm1iQTQtbDl5ZDI5anBWSzhkUFd5clIzQ1ZMWm9JIiwicXJnQzVxM25xZWxlOGpZbVkzQmt6QjBQeEFsdHkxNl9GaHJPa2FGaGtkWSJdfSwiaXNzdWluZ19jb3VudHJ5IjoiREUiLCJ2Y3QiOiJodHRwczovL2V4YW1wbGUuYm1pLmJ1bmQuZGUvY3JlZGVudGlhbC9waWQvMS4wIiwiaXNzdWluZ19hdXRob3JpdHkiOiJERSIsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiaHR0cHM6Ly9kZW1vLnBpZC1pc3N1ZXIuYnVuZGVzZHJ1Y2tlcmVpLmRlL2MxIiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Ik5lWF9abml3eERPSkRfS3lxZjY3OFYtWXgzZjMtRFoweUQ5WGVycEZtY2MiLCJ5IjoiZ3BvNUgweldhUE05eWM3TTJyZXg0SVo2R2ViOUoyODQyVDN0Nlg4ZnJBTSJ9fSwiZXhwIjoxNzMzNzA5NTE0LCJpYXQiOjE3MzI0OTk5MTQsImFnZV9lcXVhbF9vcl9vdmVyIjp7Il9zZCI6WyJIbUQtNnlpYVZPWVB6ZG1XTFBteU94enI4cTJnb3VPOUo5VjZVMFBPT1Y0IiwiSW5zX2JNOVZOaUJGV0ZNNXR1NXZ0M3RrWmhaUUJtY25LTUl5QU16dXYxcyIsImE5ZjNPaWp0NHByZGYtV2lvclkxZ09jZEliX1dDc1JwVzlCS2JPb0ZxUW8iLCJlQ19QbG9nMEMtZTJuN0s0WVNuU3NBQjRLS1dUdmxnMlpkOXhEQm1pRDVnIiwib2E2UVV5SGxQbmU5QW1tT29KTjdFQ1AwRHpEZy1TSVlKUnQtcVNheUxWSSIsInZUZlcwY2VQd0VDQXNUbTVWMFNaZlp6T0lLQUdmRHIyMTlqOWpmaFRIQUUiXX19.m5m6mQQu6O-4Y18VoIiv4mg4Jp5QPd0RStE8hPM_caqWo5prs8spXBB_0NBANGpqnNqEdK2yLRzGidZY8GRNHA~WyI5NmhWUFZxWDJYOU5rUU9IME5WLW5nIiwiZmFtaWx5X25hbWUiLCJNVVNURVJNQU5OIl0~WyJuME1ZOXVodmFCMEZ5YnZkQ2VDNHBnIiwiZ2l2ZW5fbmFtZSIsIkVSSUtBIl0~WyJIYmwzTGZHeXFOaE5rZ05GajZyV2RBIiwiYmlydGhkYXRlIiwiMTk2NC0wOC0xMiJd~WyJPcU9TTEdXNF9JTUdRLUdjRkpSS2pBIiwiYWdlX2JpcnRoX3llYXIiLDE5NjRd~WyJsdGpKV1k2cVM0V1p1bXlTNF9xcW5RIiwiYWdlX2luX3llYXJzIiw2MF0~WyJvVnFxdEY3LXdHSE5xNXJnSURlQTdnIiwiYmlydGhfZmFtaWx5X25hbWUiLCJHQUJMRVIiXQ~WyI2TDZaSjRyN2lCTmdRVjY3SXR1c1JRIiwibmF0aW9uYWxpdGllcyIsWyJERSJdXQ~WyJQLV9LSjhieTQ1NkJpenNWZ2N4UER3IiwiMTIiLHRydWVd~WyIwSmxOY0ZYd1FUYmMzMUF0SGlhY1lBIiwiMTQiLHRydWVd~WyJldjR6UE85ckZZc3QtRE55V2hzMVZRIiwiMTYiLHRydWVd~WyJ1OWxaSzljaE4wWVJWV082ZG9ySThRIiwiMTgiLHRydWVd~WyJnWkZqMUhmRS12azJFNmEzTzRESl93IiwiMjEiLHRydWVd~WyJweGNQWWIzZEFkYnhLMTdTUXR4SWRRIiwiNjUiLGZhbHNlXQ~WyJHU25uUnF0T2p0dl9FMk1Qd3l1bFZRIiwibG9jYWxpdHkiLCJCRVJMSU4iXQ~WyJoRmJNbnZGSWhtUXNpanpUT1Q1VFVnIiwibG9jYWxpdHkiLCJLw5ZMTiJd~WyJUc3lxN3RSSm9LMmEzeF9PWFlmMWp3IiwiY291bnRyeSIsIkRFIl0~WyJLQUwyVHFfSlZRLS1PMXBzYUJtSzhBIiwicG9zdGFsX2NvZGUiLCI1MTE0NyJd~WyJ4SFVxVkNwaGNSdVJYSVRZbDZsSndnIiwic3RyZWV0X2FkZHJlc3MiLCJIRUlERVNUUkHhup5FIDE3Il0~'
