import { instanceToPlain, plainToInstance } from 'class-transformer'

import { DidCommV1Service, DidDocumentService, IndyAgentService } from '../../../../../dids'
import { DidDoc } from '../DidDoc'
import { ReferencedAuthentication, EmbeddedAuthentication } from '../authentication'
import { Ed25119Sig2018, EddsaSaSigSecp256k1, RsaSig2018 } from '../publicKey'

import diddoc from './diddoc.json'

const didDoc = new DidDoc({
  authentication: [
    new ReferencedAuthentication(
      new RsaSig2018({
        id: '3',
        controller: 'did:sov:LjgpST2rjsoxYegQDRm7EL',
        publicKeyPem: '-----BEGIN PUBLIC X...',
      }),
      'RsaSignatureAuthentication2018'
    ),
    new EmbeddedAuthentication(
      new EddsaSaSigSecp256k1({
        id: '6',
        controller: 'did:sov:LjgpST2rjsoxYegQDRm7EL',
        publicKeyHex: '-----BEGIN PUBLIC A...',
      })
    ),
  ],
  id: 'test-id',
  publicKey: [
    new RsaSig2018({
      id: '3',
      controller: 'did:sov:LjgpST2rjsoxYegQDRm7EL',
      publicKeyPem: '-----BEGIN PUBLIC X...',
    }),
    new Ed25119Sig2018({
      id: 'did:sov:LjgpST2rjsoxYegQDRm7EL#4',
      controller: 'did:sov:LjgpST2rjsoxYegQDRm7EL',
      publicKeyBase58: '-----BEGIN PUBLIC 9...',
    }),
    new EddsaSaSigSecp256k1({
      id: '6',
      controller: 'did:sov:LjgpST2rjsoxYegQDRm7EL',
      publicKeyHex: '-----BEGIN PUBLIC A...',
    }),
  ],
  service: [
    new DidDocumentService({
      id: '0',
      type: 'Mediator',
      serviceEndpoint: 'did:sov:Q4zqM7aXqm7gDQkUVLng9h',
    }),
    new IndyAgentService({
      id: '6',
      serviceEndpoint: 'did:sov:Q4zqM7aXqm7gDQkUVLng9h',
      recipientKeys: ['Q4zqM7aXqm7gDQkUVLng9h'],
      routingKeys: ['Q4zqM7aXqm7gDQkUVLng9h'],
      priority: 5,
    }),
    new DidCommV1Service({
      id: '7',
      serviceEndpoint: 'https://agent.com/did-comm',
      recipientKeys: ['DADEajsDSaksLng9h'],
      routingKeys: ['DADEajsDSaksLng9h'],
      priority: 10,
    }),
  ],
})

// Test adopted from ACA-Py
// TODO: add more tests
describe('Did | DidDoc', () => {
  it('should correctly transforms Json to DidDoc class', () => {
    const didDoc = plainToInstance(DidDoc, diddoc)

    // Check array length of all items
    expect(didDoc.publicKey.length).toBe(diddoc.publicKey.length)
    expect(didDoc.service.length).toBe(diddoc.service.length)
    expect(didDoc.authentication.length).toBe(diddoc.authentication.length)

    // Check other properties
    expect(didDoc.id).toBe(diddoc.id)
    expect(didDoc.context).toBe(diddoc['@context'])

    // Check publicKey
    expect(didDoc.publicKey[0]).toBeInstanceOf(RsaSig2018)
    expect(didDoc.publicKey[1]).toBeInstanceOf(Ed25119Sig2018)
    expect(didDoc.publicKey[2]).toBeInstanceOf(EddsaSaSigSecp256k1)

    // Check Service
    expect(didDoc.service[0]).toBeInstanceOf(DidDocumentService)
    expect(didDoc.service[1]).toBeInstanceOf(IndyAgentService)
    expect(didDoc.service[2]).toBeInstanceOf(DidCommV1Service)

    // Check Authentication
    expect(didDoc.authentication[0]).toBeInstanceOf(ReferencedAuthentication)
    expect(didDoc.authentication[1]).toBeInstanceOf(EmbeddedAuthentication)
  })

  it('should correctly transforms DidDoc class to Json', () => {
    const json = instanceToPlain(didDoc)

    // Check array length of all items
    expect(json.publicKey.length).toBe(didDoc.publicKey.length)
    expect(json.service.length).toBe(didDoc.service.length)
    expect(json.authentication.length).toBe(didDoc.authentication.length)

    // Check other properties
    expect(json.id).toBe(didDoc.id)
    expect(json['@context']).toBe(didDoc.context)

    // Check publicKey
    expect(json.publicKey[0]).toMatchObject({
      id: '3',
      type: 'RsaVerificationKey2018',
      controller: 'did:sov:LjgpST2rjsoxYegQDRm7EL',
      publicKeyPem: '-----BEGIN PUBLIC X...',
    })
    expect(json.publicKey[1]).toMatchObject({
      id: 'did:sov:LjgpST2rjsoxYegQDRm7EL#4',
      type: 'Ed25519VerificationKey2018',
      controller: 'did:sov:LjgpST2rjsoxYegQDRm7EL',
      publicKeyBase58: '-----BEGIN PUBLIC 9...',
    })
    expect(json.publicKey[2]).toMatchObject({
      id: '6',
      type: 'Secp256k1VerificationKey2018',
      controller: 'did:sov:LjgpST2rjsoxYegQDRm7EL',
      publicKeyHex: '-----BEGIN PUBLIC A...',
    })

    // Check Service
    expect(json.service[0]).toMatchObject({
      id: '0',
      type: 'Mediator',
      serviceEndpoint: 'did:sov:Q4zqM7aXqm7gDQkUVLng9h',
    })
    expect(json.service[1]).toMatchObject({
      id: '6',
      type: 'IndyAgent',
      serviceEndpoint: 'did:sov:Q4zqM7aXqm7gDQkUVLng9h',
      recipientKeys: ['Q4zqM7aXqm7gDQkUVLng9h'],
      routingKeys: ['Q4zqM7aXqm7gDQkUVLng9h'],
      priority: 5,
    })
    expect(json.service[2]).toMatchObject({
      id: '7',
      type: 'did-communication',
      serviceEndpoint: 'https://agent.com/did-comm',
      recipientKeys: ['DADEajsDSaksLng9h'],
      routingKeys: ['DADEajsDSaksLng9h'],
      priority: 10,
    })

    // Check Authentication
    expect(json.authentication[0]).toMatchObject({
      type: 'RsaSignatureAuthentication2018',
      publicKey: '3',
    })
    expect(json.authentication[1]).toMatchObject({
      id: '6',
      controller: 'did:sov:LjgpST2rjsoxYegQDRm7EL',
      type: 'Secp256k1VerificationKey2018',
      publicKeyHex: '-----BEGIN PUBLIC A...',
    })
  })

  describe('getPublicKey', () => {
    it('return the public key with the specified id', async () => {
      expect(didDoc.getPublicKey('3')).toEqual(didDoc.publicKey.find((item) => item.id === '3'))
    })
  })

  describe('getServicesByType', () => {
    it('returns all services with specified type', async () => {
      expect(didDoc.getServicesByType('IndyAgent')).toEqual(
        didDoc.service.filter((service) => service.type === 'IndyAgent')
      )
    })
  })

  describe('getServicesByClassType', () => {
    it('returns all services with specified class', async () => {
      expect(didDoc.getServicesByClassType(IndyAgentService)).toEqual(
        didDoc.service.filter((service) => service instanceof IndyAgentService)
      )
    })
  })

  describe('didCommServices', () => {
    it('returns all IndyAgentService and DidCommService instances', async () => {
      expect(didDoc.didCommServices).toEqual(expect.arrayContaining([didDoc.service[1], didDoc.service[2]]))
    })

    it('returns all IndyAgentService and DidCommService instances sorted by priority', async () => {
      expect(didDoc.didCommServices).toEqual([didDoc.service[1], didDoc.service[2]])
    })
  })
})
