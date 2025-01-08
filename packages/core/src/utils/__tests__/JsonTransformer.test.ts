import { ConnectionInvitationMessage } from '../../../../didcomm/src'
import { DidDocument, VerificationMethod } from '../../modules/dids'
import { JsonTransformer } from '../JsonTransformer'

describe('JsonTransformer', () => {
  describe('toJSON', () => {
    it('transforms class instance to JSON object', () => {
      const invitation = new ConnectionInvitationMessage({
        did: 'did:sov:test1234',
        id: 'afe2867e-58c3-4a8d-85b2-23370dd9c9f0',
        label: 'test-label',
      })

      const json = {
        '@type': 'https://didcomm.org/connections/1.0/invitation',
        '@id': 'afe2867e-58c3-4a8d-85b2-23370dd9c9f0',
        label: 'test-label',
        did: 'did:sov:test1234',
      }

      expect(JsonTransformer.toJSON(invitation)).toEqual(json)
    })
  })

  describe('fromJSON', () => {
    it('transforms JSON object to class instance', () => {
      const json = {
        '@type': 'https://didcomm.org/connections/1.0/invitation',
        '@id': 'afe2867e-58c3-4a8d-85b2-23370dd9c9f0',
        label: 'test-label',
        did: 'did:sov:test1234',
      }

      const invitation = new ConnectionInvitationMessage({
        did: 'did:sov:test1234',
        id: 'afe2867e-58c3-4a8d-85b2-23370dd9c9f0',
        label: 'test-label',
      })

      expect(JsonTransformer.fromJSON(json, ConnectionInvitationMessage)).toEqual(invitation)
    })
  })

  describe('serialize', () => {
    it('transforms class instance to JSON string', () => {
      const invitation = new ConnectionInvitationMessage({
        did: 'did:sov:test1234',
        id: 'afe2867e-58c3-4a8d-85b2-23370dd9c9f0',
        label: 'test-label',
      })

      const jsonString =
        '{"@type":"https://didcomm.org/connections/1.0/invitation","@id":"afe2867e-58c3-4a8d-85b2-23370dd9c9f0","label":"test-label","did":"did:sov:test1234"}'

      expect(JsonTransformer.serialize(invitation)).toEqual(jsonString)
    })
  })

  describe('deserialize', () => {
    it('transforms JSON string to class instance', () => {
      const jsonString =
        '{"@type":"https://didcomm.org/connections/1.0/invitation","@id":"afe2867e-58c3-4a8d-85b2-23370dd9c9f0","label":"test-label","did":"did:sov:test1234"}'

      const invitation = new ConnectionInvitationMessage({
        did: 'did:sov:test1234',
        id: 'afe2867e-58c3-4a8d-85b2-23370dd9c9f0',
        label: 'test-label',
      })

      expect(JsonTransformer.deserialize(jsonString, ConnectionInvitationMessage)).toEqual(invitation)
    })

    it('transforms JSON string to nested class instance', () => {
      const didDocumentString =
        '{"@context":["https://w3id.org/did/v1"],"id":"did:peer:1zQmRYBx1pL86DrsxoJ2ZD3w42d7Ng92ErPgFsCSqg8Q1h4i","controller": "nowYouAreUnderMyControl", "keyAgreement":[{"id":"#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V", "controller": "#id", "type":"Ed25519VerificationKey2018","publicKeyBase58":"ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7"}],"service":[{"id":"#service-0","type":"did-communication","serviceEndpoint":"https://example.com/endpoint","recipientKeys":["#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"],"routingKeys":["did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"],"accept":["didcomm/v2","didcomm/aip2;env=rfc587"]}]}'

      const didDocument = JsonTransformer.deserialize(didDocumentString, DidDocument)

      const keyAgreement = didDocument.keyAgreement ?? []

      expect(keyAgreement[0]).toBeInstanceOf(VerificationMethod)
    })
  })
})
