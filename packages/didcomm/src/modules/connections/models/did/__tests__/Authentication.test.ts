import type { Authentication } from '../authentication'

import { instanceToPlain, plainToInstance } from 'class-transformer'

import { AuthenticationTransformer, ReferencedAuthentication, EmbeddedAuthentication } from '../authentication'
import { PublicKey, RsaSig2018 } from '../publicKey'

describe('Did | Authentication', () => {
  describe('EmbeddedAuthentication', () => {
    it('should correctly transform ReferencedAuthentication class to Json', async () => {
      const publicKey = new RsaSig2018({
        controller: 'test',
        publicKeyPem: 'test',
        id: 'test#1',
      })

      const referencedAuthentication = new ReferencedAuthentication(publicKey, 'RsaSignatureAuthentication2018')
      const transformed = instanceToPlain(referencedAuthentication)

      expect(transformed).toMatchObject({
        type: 'RsaSignatureAuthentication2018',
        publicKey: 'test#1',
      })
    })
  })

  describe('AuthenticationTransformer', () => {
    class AuthenticationTransformerTest {
      public publicKey: PublicKey[] = []

      @AuthenticationTransformer()
      public authentication: Authentication[] = []
    }

    it("should use generic 'publicKey' type when no matching public key type class is present", async () => {
      const embeddedAuthenticationJson = {
        controller: 'did:sov:1123123',
        id: 'did:sov:1123123#1',
        type: 'RandomType',
        publicKeyPem: '-----BEGIN PUBLIC X...',
      }

      const referencedAuthenticationJson = {
        type: 'RandomType',
        publicKey: 'did:sov:1123123#1',
      }

      const authenticationWrapperJson = {
        publicKey: [embeddedAuthenticationJson],
        authentication: [referencedAuthenticationJson, embeddedAuthenticationJson],
      }
      const authenticationWrapper = plainToInstance(AuthenticationTransformerTest, authenticationWrapperJson)

      expect(authenticationWrapper.authentication.length).toBe(2)

      const [referencedAuthentication, embeddedAuthentication] = authenticationWrapper.authentication as [
        ReferencedAuthentication,
        EmbeddedAuthentication
      ]
      expect(referencedAuthentication.publicKey).toBeInstanceOf(PublicKey)
      expect(embeddedAuthentication.publicKey).toBeInstanceOf(PublicKey)
    })

    it("should transform Json to ReferencedAuthentication class when the 'publicKey' key is present on the authentication object", async () => {
      const publicKeyJson = {
        controller: 'did:sov:1123123',
        id: 'did:sov:1123123#1',
        type: 'RsaVerificationKey2018',
        publicKeyPem: '-----BEGIN PUBLIC X...',
      }
      const referencedAuthenticationJson = {
        type: 'RsaSignatureAuthentication2018',
        publicKey: 'did:sov:1123123#1',
      }

      const authenticationWrapperJson = {
        publicKey: [publicKeyJson],
        authentication: [referencedAuthenticationJson],
      }
      const authenticationWrapper = plainToInstance(AuthenticationTransformerTest, authenticationWrapperJson)

      expect(authenticationWrapper.authentication.length).toBe(1)

      const firstAuth = authenticationWrapper.authentication[0] as ReferencedAuthentication
      expect(firstAuth).toBeInstanceOf(ReferencedAuthentication)
      expect(firstAuth.publicKey).toBeInstanceOf(RsaSig2018)
      expect(firstAuth.type).toBe(referencedAuthenticationJson.type)
    })

    it("should throw an error when the 'publicKey' is present, but no publicKey entry exists with the corresponding id", async () => {
      const referencedAuthenticationJson = {
        type: 'RsaVerificationKey2018',
        publicKey: 'did:sov:1123123#1',
      }

      const authenticationWrapperJson = {
        publicKey: [],
        authentication: [referencedAuthenticationJson],
      }

      expect(() => plainToInstance(AuthenticationTransformerTest, authenticationWrapperJson)).toThrowError(
        `Invalid public key referenced ${referencedAuthenticationJson.publicKey}`
      )
    })

    it("should transform Json to EmbeddedAuthentication class when the 'publicKey' key is not present on the authentication object", async () => {
      const publicKeyJson = {
        controller: 'did:sov:1123123',
        id: 'did:sov:1123123#1',
        type: 'RsaVerificationKey2018',
        publicKeyPem: '-----BEGIN PUBLIC X...',
      }

      const authenticationWrapperJson = {
        authentication: [publicKeyJson],
      }
      const authenticationWrapper = plainToInstance(AuthenticationTransformerTest, authenticationWrapperJson)

      expect(authenticationWrapper.authentication.length).toBe(1)

      const firstAuth = authenticationWrapper.authentication[0] as EmbeddedAuthentication
      expect(firstAuth).toBeInstanceOf(EmbeddedAuthentication)
      expect(firstAuth.publicKey).toBeInstanceOf(RsaSig2018)
      expect(firstAuth.publicKey.value).toBe(publicKeyJson.publicKeyPem)
    })

    it('should transform EmbeddedAuthentication and ReferencedAuthentication class to Json', async () => {
      const authenticationWrapper = new AuthenticationTransformerTest()
      authenticationWrapper.authentication = [
        new EmbeddedAuthentication(
          new RsaSig2018({
            controller: 'test',
            publicKeyPem: 'test',
            id: 'test#1',
          })
        ),
        new ReferencedAuthentication(
          new RsaSig2018({
            controller: 'test',
            publicKeyPem: 'test',
            id: 'test#1',
          }),
          'RsaSignatureAuthentication2018'
        ),
      ]

      expect(authenticationWrapper.authentication.length).toBe(2)
      const [embeddedJson, referencedJson] = instanceToPlain(authenticationWrapper).authentication

      expect(embeddedJson).toMatchObject({
        controller: 'test',
        publicKeyPem: 'test',
        id: 'test#1',
        type: 'RsaVerificationKey2018',
      })

      expect(referencedJson).toMatchObject({
        type: 'RsaSignatureAuthentication2018',
        publicKey: 'test#1',
      })
    })
  })
})
