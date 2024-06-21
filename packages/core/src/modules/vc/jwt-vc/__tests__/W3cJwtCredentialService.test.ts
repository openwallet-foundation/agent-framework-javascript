import { InMemoryWallet } from '../../../../../../../tests/InMemoryWallet'
import { getAgentConfig, getAgentContext, testLogger } from '../../../../../tests'
import { InjectionSymbols } from '../../../../constants'
import { JwsService, KeyType } from '../../../../crypto'
import { JwaSignatureAlgorithm } from '../../../../crypto/jose/jwa'
import { getJwkFromKey } from '../../../../crypto/jose/jwk'
import { CredoError, ClassValidationError } from '../../../../error'
import { JsonTransformer } from '../../../../utils'
import { DidJwk, DidKey, DidRepository, DidsModuleConfig } from '../../../dids'
import { CREDENTIALS_CONTEXT_V1_URL } from '../../constants'
import { ClaimFormat, W3cCredential, W3cPresentation } from '../../models'
import { W3cJwtCredentialService } from '../W3cJwtCredentialService'
import { W3cJwtVerifiableCredential } from '../W3cJwtVerifiableCredential'

import {
  CredoEs256DidJwkJwtVc,
  CredoEs256DidJwkJwtVcIssuerSeed,
  CredoEs256DidJwkJwtVcSubjectSeed,
  CredoEs256DidKeyJwtVp,
  Ed256DidJwkJwtVcUnsigned,
} from './fixtures/credo-jwt-vc'
import { didIonJwtVcPresentationProfileJwtVc } from './fixtures/jwt-vc-presentation-profile'
import { didKeyTransmuteJwtVc, didKeyTransmuteJwtVp } from './fixtures/transmute-verifiable-data'

const config = getAgentConfig('W3cJwtCredentialService')
const wallet = new InMemoryWallet()
const agentContext = getAgentContext({
  wallet,
  registerInstances: [
    [InjectionSymbols.Logger, testLogger],
    [DidsModuleConfig, new DidsModuleConfig()],
    [DidRepository, {} as unknown as DidRepository],
  ],
  agentConfig: config,
})

const jwsService = new JwsService()
const w3cJwtCredentialService = new W3cJwtCredentialService(jwsService)

// Runs in Node 18 because of usage of Askar
describe('W3cJwtCredentialService', () => {
  let issuerDidJwk: DidJwk
  let holderDidKey: DidKey

  beforeAll(async () => {
    await wallet.createAndOpen(config.walletConfig)

    const issuerKey = await agentContext.wallet.createKey({
      keyType: KeyType.P256,
      seed: CredoEs256DidJwkJwtVcIssuerSeed,
    })
    issuerDidJwk = DidJwk.fromJwk(getJwkFromKey(issuerKey))

    const holderKey = await agentContext.wallet.createKey({
      keyType: KeyType.Ed25519,
      seed: CredoEs256DidJwkJwtVcSubjectSeed,
    })
    holderDidKey = new DidKey(holderKey)
  })

  describe('signCredential', () => {
    test('signs an ES256 JWT vc', async () => {
      const credential = JsonTransformer.fromJSON(Ed256DidJwkJwtVcUnsigned, W3cCredential)

      const vcJwt = await w3cJwtCredentialService.signCredential(agentContext, {
        alg: JwaSignatureAlgorithm.ES256,
        format: ClaimFormat.JwtVc,
        verificationMethod: issuerDidJwk.verificationMethodId,
        credential,
      })

      expect(vcJwt.serializedJwt).toEqual(CredoEs256DidJwkJwtVc)
    })

    test('throws when invalid credential is passed', async () => {
      const credentialJson = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential'],
        issuer:
          'did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6InpRT293SUMxZ1dKdGRkZEI1R0F0NGxhdTZMdDhJaHk3NzFpQWZhbS0xcGMiLCJ5IjoiY2pEXzdvM2dkUTF2Z2lReTNfc01HczdXcndDTVU5RlFZaW1BM0h4bk1sdyJ9',
        issuanceDate: '2023-01-25T16:58:06.292Z',
        credentialSubject: {
          id: 'did:key:z6MkqgkLrRyLg6bqk27djwbbaQWgaSYgFVCKq9YKxZbNkpVv',
        },
      }

      // Throw when verificationMethod is not a did
      await expect(
        w3cJwtCredentialService.signCredential(agentContext, {
          verificationMethod: 'hello',
          alg: JwaSignatureAlgorithm.ES256,
          credential: JsonTransformer.fromJSON(credentialJson, W3cCredential),
          format: ClaimFormat.JwtVc,
        })
      ).rejects.toThrowError('Only did identifiers are supported as verification method')

      // Throw when not according to data model
      await expect(
        w3cJwtCredentialService.signCredential(agentContext, {
          verificationMethod: issuerDidJwk.verificationMethodId,
          alg: JwaSignatureAlgorithm.ES256,
          credential: JsonTransformer.fromJSON({ ...credentialJson, issuanceDate: undefined }, W3cCredential, {
            validate: false,
          }),
          format: ClaimFormat.JwtVc,
        })
      ).rejects.toThrowError(
        'property issuanceDate has failed the following constraints: issuanceDate must be RFC 3339 date'
      )

      // Throw when verificationMethod id does not exist in did document
      await expect(
        w3cJwtCredentialService.signCredential(agentContext, {
          verificationMethod: issuerDidJwk.verificationMethodId + 'extra',
          alg: JwaSignatureAlgorithm.ES256,
          credential: JsonTransformer.fromJSON(credentialJson, W3cCredential),
          format: ClaimFormat.JwtVc,
        })
      ).rejects.toThrowError(
        `Unable to locate verification method with id 'did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6InpRT293SUMxZ1dKdGRkZEI1R0F0NGxhdTZMdDhJaHk3NzFpQWZhbS0xcGMiLCJ5IjoiY2pEXzdvM2dkUTF2Z2lReTNfc01HczdXcndDTVU5RlFZaW1BM0h4bk1sdyJ9#0extra' in purposes assertionMethod`
      )
    })
  })

  describe('verifyCredential', () => {
    // Fails because the `jti` is not an uri (and the `vc.id` MUST be an uri according to vc data model)
    test.skip('verifies a vc from the vc-jwt-presentation-profile', async () => {
      const result = await w3cJwtCredentialService.verifyCredential(agentContext, {
        credential: didIonJwtVcPresentationProfileJwtVc,
        verifyCredentialStatus: false,
      })

      expect(result).toMatchObject({
        verified: true,
      })
    })

    test('verifies an ES256 JWT vc signed by Credo', async () => {
      const result = await w3cJwtCredentialService.verifyCredential(agentContext, {
        credential: CredoEs256DidJwkJwtVc,
      })

      expect(result).toEqual({
        isValid: true,
        validations: {
          // credential has no credentialStatus, so always valid
          credentialStatus: {
            isValid: true,
          },
          // This both validates whether the credential matches the
          // data model, as well as whether the credential is expired etc..
          dataModel: {
            isValid: true,
          },
          // This validates whether the signature is valid
          signature: {
            isValid: true,
          },
          // This validates whether the issuer is also the signer of the credential
          issuerIsSigner: {
            isValid: true,
          },
        },
      })
    })

    test('verifies an EdDSA JWT vc from the transmute vc.js library', async () => {
      const result = await w3cJwtCredentialService.verifyCredential(agentContext, {
        credential: didKeyTransmuteJwtVc,
      })

      expect(result).toEqual({
        isValid: true,
        validations: {
          // credential has no credentialStatus, so always valid
          credentialStatus: {
            isValid: true,
          },
          // This both validates whether the credential matches the
          // data model, as well as whether the credential is expired etc..
          dataModel: {
            isValid: true,
          },
          // This validates whether the signature is valid
          signature: {
            isValid: true,
          },
          // This validates whether the issuer is also the signer of the credential
          issuerIsSigner: {
            isValid: true,
          },
        },
      })
    })

    test('returns invalid result when credential is not according to data model', async () => {
      const jwtVc = W3cJwtVerifiableCredential.fromSerializedJwt(CredoEs256DidJwkJwtVc)

      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      delete jwtVc.credential.issuer

      const result = await w3cJwtCredentialService.verifyCredential(agentContext, {
        credential: jwtVc,
        verifyCredentialStatus: false,
      })

      expect(result).toEqual({
        isValid: false,
        validations: {
          dataModel: {
            isValid: false,
            error: expect.any(ClassValidationError),
          },
        },
      })

      expect(result.validations.dataModel?.error?.message).toContain('Failed to validate class')
    })

    test('returns invalid result when credential is expired', async () => {
      const jwtVc = W3cJwtVerifiableCredential.fromSerializedJwt(CredoEs256DidJwkJwtVc)

      jwtVc.jwt.payload.exp = new Date('2020-01-01').getTime() / 1000

      const result = await w3cJwtCredentialService.verifyCredential(agentContext, {
        credential: jwtVc,
        verifyCredentialStatus: false,
      })

      expect(result).toEqual({
        isValid: false,
        validations: {
          dataModel: {
            isValid: false,
            error: expect.any(CredoError),
          },
        },
      })

      expect(result.validations.dataModel?.error?.message).toContain('JWT expired at 1577836800')
    })

    test('returns invalid result when signature is not valid', async () => {
      const jwtVc = W3cJwtVerifiableCredential.fromSerializedJwt(CredoEs256DidJwkJwtVc + 'a')

      const result = await w3cJwtCredentialService.verifyCredential(agentContext, {
        credential: jwtVc,
      })

      expect(result).toEqual({
        isValid: false,
        validations: {
          dataModel: {
            isValid: true,
          },
          signature: {
            isValid: false,
            error: expect.any(CredoError),
          },
          issuerIsSigner: {
            isValid: false,
            error: expect.any(CredoError),
          },
          credentialStatus: {
            isValid: true,
          },
        },
      })

      expect(result.validations.signature?.error?.message).toContain('Invalid JWS signature')
    })
  })

  describe('signPresentation', () => {
    test('signs an ES256 JWT vp', async () => {
      // Create a new instance of the credential from the serialized JWT
      const parsedJwtVc = W3cJwtVerifiableCredential.fromSerializedJwt(CredoEs256DidJwkJwtVc)

      const presentation = new W3cPresentation({
        context: [CREDENTIALS_CONTEXT_V1_URL],
        type: ['VerifiablePresentation'],
        verifiableCredential: [parsedJwtVc],
        id: 'urn:21ff21f1-3cf9-4fa3-88b4-a045efbb1b5f',
        holder: holderDidKey.did,
      })

      const signedJwtVp = await w3cJwtCredentialService.signPresentation(agentContext, {
        presentation,
        alg: JwaSignatureAlgorithm.EdDSA,
        challenge: 'daf942ad-816f-45ee-a9fc-facd08e5abca',
        domain: 'example.com',
        format: ClaimFormat.JwtVp,
        verificationMethod: `${holderDidKey.did}#${holderDidKey.key.fingerprint}`,
      })

      expect(signedJwtVp.serializedJwt).toEqual(CredoEs256DidKeyJwtVp)
    })
  })

  describe('verifyPresentation', () => {
    test('verifies an ES256 JWT vp signed by Credo', async () => {
      const result = await w3cJwtCredentialService.verifyPresentation(agentContext, {
        presentation: CredoEs256DidKeyJwtVp,
        challenge: 'daf942ad-816f-45ee-a9fc-facd08e5abca',
        domain: 'example.com',
      })

      expect(result).toEqual({
        isValid: true,
        validations: {
          dataModel: {
            isValid: true,
          },
          presentationSignature: {
            isValid: true,
          },
          holderIsSigner: {
            isValid: true,
          },
          credentials: [
            {
              isValid: true,
              validations: {
                dataModel: {
                  isValid: true,
                },
                signature: {
                  isValid: true,
                },
                issuerIsSigner: {
                  isValid: true,
                },
                credentialStatus: {
                  isValid: true,
                },
                credentialSubjectAuthentication: {
                  isValid: true,
                },
              },
            },
          ],
        },
      })
    })

    // NOTE: this test doesn't fully succeed because the VP from the transmute
    // library doesn't authenticate the credentialSubject.id in the credential
    // in the VP. For now, all VPs must authenticate the credentialSubject, if
    // the credential has a credential subject id (so it's not a bearer credential)
    test('verifies an EdDSA JWT vp from the transmute vc.js library', async () => {
      const result = await w3cJwtCredentialService.verifyPresentation(agentContext, {
        presentation: didKeyTransmuteJwtVp,
        challenge: '123',
        domain: 'example.com',
      })

      expect(result).toEqual({
        isValid: false,
        validations: {
          dataModel: {
            isValid: true,
          },
          presentationSignature: {
            isValid: true,
          },
          holderIsSigner: {
            isValid: true,
          },
          credentials: [
            {
              isValid: false,
              validations: {
                dataModel: {
                  isValid: true,
                },
                signature: {
                  isValid: true,
                },
                issuerIsSigner: {
                  isValid: true,
                },
                credentialStatus: {
                  isValid: true,
                },
                credentialSubjectAuthentication: {
                  isValid: false,
                  error: new CredoError(
                    'Credential has one or more credentialSubject ids, but presentation does not authenticate credential subject'
                  ),
                },
              },
            },
          ],
        },
      })
    })
  })
})
