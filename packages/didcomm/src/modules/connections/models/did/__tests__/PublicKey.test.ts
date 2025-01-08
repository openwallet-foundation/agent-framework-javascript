import type { ClassConstructor } from 'class-transformer'

import { instanceToPlain, plainToInstance } from 'class-transformer'

import {
  PublicKeyTransformer,
  PublicKey,
  publicKeyTypes,
  EddsaSaSigSecp256k1,
  Ed25119Sig2018,
  RsaSig2018,
} from '../publicKey'

const publicKeysJson = [
  {
    class: RsaSig2018,
    valueKey: 'publicKeyPem',
    json: {
      id: '3',
      type: 'RsaVerificationKey2018',
      controller: 'did:sov:LjgpST2rjsoxYegQDRm7EL',
      publicKeyPem: '-----BEGIN PUBLIC X...',
    },
  },
  {
    class: Ed25119Sig2018,
    valueKey: 'publicKeyBase58',
    json: {
      id: '4',
      type: 'Ed25519VerificationKey2018',
      controller: 'did:sov:LjgpST2rjsoxYegQDRm7EL',
      publicKeyBase58: '-----BEGIN PUBLIC X...',
    },
  },
  {
    class: EddsaSaSigSecp256k1,
    valueKey: 'publicKeyHex',
    json: {
      id: 'did:sov:LjgpST2rjsoxYegQDRm7EL#5',
      type: 'Secp256k1VerificationKey2018',
      controller: 'did:sov:LjgpST2rjsoxYegQDRm7EL',
      publicKeyHex: '-----BEGIN PUBLIC X...',
    },
  },
]

describe('Did | PublicKey', () => {
  it('should correctly transform Json to PublicKey class', async () => {
    const json = {
      id: 'did:sov:LjgpST2rjsoxYegQDRm7EL#5',
      type: 'RandomType',
      controller: 'did:sov:LjgpST2rjsoxYegQDRm7EL',
    }

    const service = plainToInstance(PublicKey, json)
    expect(service.id).toBe(json.id)
    expect(service.type).toBe(json.type)
    expect(service.controller).toBe(json.controller)
  })

  it('should correctly transform PublicKey class to Json', async () => {
    const json = {
      id: 'did:sov:LjgpST2rjsoxYegQDRm7EL#5',
      type: 'RandomType',
      controller: 'did:sov:LjgpST2rjsoxYegQDRm7EL',
    }
    const publicKey = new PublicKey({
      ...json,
    })
    const transformed = instanceToPlain(publicKey)
    expect(transformed).toEqual(json)
  })

  const publicKeyJsonToClassTests: [string, ClassConstructor<PublicKey>, Record<string, string | undefined>, string][] =
    publicKeysJson.map((pk) => [pk.class.name, pk.class, pk.json, pk.valueKey])
  test.each(publicKeyJsonToClassTests)(
    'should correctly transform Json to %s class',
    async (_, publicKeyClass, json, valueKey) => {
      const publicKey = plainToInstance(publicKeyClass, json)

      expect(publicKey.id).toBe(json.id)
      expect(publicKey.type).toBe(json.type)
      expect(publicKey.controller).toBe(json.controller)
      expect(publicKey.value).toBe(json[valueKey])
    }
  )

  const publicKeyClassToJsonTests: [string, PublicKey, Record<string, string | undefined>, string][] =
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    publicKeysJson.map((pk) => [pk.class.name, new pk.class({ ...(pk.json as any) }), pk.json, pk.valueKey])

  test.each(publicKeyClassToJsonTests)(
    'should correctly transform %s class to Json',
    async (_, publicKey, json, valueKey) => {
      const publicKeyJson = instanceToPlain(publicKey)

      expect(publicKey.value).toBe(json[valueKey])
      expect(publicKeyJson).toMatchObject(json)
    }
  )

  describe('PublicKeyTransformer', () => {
    class PublicKeyTransformerTest {
      @PublicKeyTransformer()
      public publicKey: PublicKey[] = []
    }

    it("should transform Json to default PublicKey class when the 'type' key is not present in 'publicKeyTypes'", async () => {
      const publicKeyJson = {
        id: '3',
        type: 'RsaVerificationKey2018--unknown',
        controller: 'did:sov:LjgpST2rjsoxYegQDRm7EL',
        publicKeyPem: '-----BEGIN PUBLIC X...',
      }

      const publicKeyWrapperJson = {
        publicKey: [publicKeyJson],
      }
      const publicKeyWrapper = plainToInstance(PublicKeyTransformerTest, publicKeyWrapperJson)

      expect(publicKeyWrapper.publicKey.length).toBe(1)

      const firstPublicKey = publicKeyWrapper.publicKey[0]
      expect(firstPublicKey).toBeInstanceOf(PublicKey)
      expect(firstPublicKey.id).toBe(publicKeyJson.id)
      expect(firstPublicKey.type).toBe(publicKeyJson.type)
      expect(firstPublicKey.controller).toBe(publicKeyJson.controller)
      expect(firstPublicKey.value).toBeUndefined()
    })

    it("should transform Json to corresponding class when the 'type' key is present in 'publicKeyTypes'", async () => {
      const publicKeyArray = publicKeysJson.map((pk) => pk.json)

      const publicKeyWrapperJson = {
        publicKey: publicKeyArray,
      }
      const publicKeyWrapper = plainToInstance(PublicKeyTransformerTest, publicKeyWrapperJson)

      expect(publicKeyWrapper.publicKey.length).toBe(publicKeyArray.length)

      for (let i = 0; i < publicKeyArray.length; i++) {
        const publicKeyJson = publicKeyArray[i]
        const publicKey = publicKeyWrapper.publicKey[i]

        expect(publicKey).toBeInstanceOf(publicKeyTypes[publicKeyJson.type])
      }
    })
  })
})
