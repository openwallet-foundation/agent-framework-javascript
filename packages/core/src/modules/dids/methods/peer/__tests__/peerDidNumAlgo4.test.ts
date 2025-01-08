import { OutOfBandDidCommService } from '../../../../../../../didcomm//src/modules/oob'
import { JsonTransformer } from '../../../../../utils'
import { DidDocument } from '../../../domain'
import { didDocumentToNumAlgo4Did, didToNumAlgo4DidDocument, outOfBandServiceToNumAlgo4Did } from '../peerDidNumAlgo4'

import didPeer4zQmUJdJ from './__fixtures__/didPeer4zQmUJdJ.json'
import didPeer4zQmd8Cp from './__fixtures__/didPeer4zQmd8Cp.json'

describe('peerDidNumAlgo4', () => {
  describe('didToNumAlgo4DidDocument', () => {
    test('transforms method 4 peer did to a did document', async () => {
      expect(didToNumAlgo4DidDocument(didPeer4zQmd8Cp.id).toJSON()).toMatchObject(didPeer4zQmd8Cp)
    })
  })

  describe('didDocumentToNumAlgo4Did', () => {
    test('transforms method 4 peer did document to a did', async () => {
      const longFormDid = didPeer4zQmUJdJ.id
      const shortFormDid = didPeer4zQmUJdJ.alsoKnownAs[0]

      const didDocument = JsonTransformer.fromJSON(didPeer4zQmUJdJ, DidDocument)

      expect(didDocumentToNumAlgo4Did(didDocument)).toEqual({ longFormDid, shortFormDid })
    })
  })

  describe('outOfBandServiceToNumAlgo4Did', () => {
    test('transforms a did comm service into a valid method 4 did', () => {
      const service = new OutOfBandDidCommService({
        id: '#service-0',
        serviceEndpoint: 'https://example.com/endpoint',
        recipientKeys: ['did:key:z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V'],
        routingKeys: ['did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH'],
        accept: ['didcomm/v2', 'didcomm/aip2;env=rfc587'],
      })
      const { longFormDid } = outOfBandServiceToNumAlgo4Did(service)
      const peerDidDocument = didToNumAlgo4DidDocument(longFormDid)

      expect(longFormDid).toBe(
        'did:peer:4zQmXU3HDFaMvdiuUh7eC2hUzFxZHgaKUJpiCAkSDfRE6qSn:z2gxx5mnuv7Tuc5GxjJ3BgJ69g1ucM27iVW9xYSg9tbBjjGLKsWGSpEwqQPbCdCt4qs1aoB3HSM4eoUQALBvR52hCEq2quLwo5RzuZBjZZmuNf6FXvVCrRLQdMG52QJ285W5MUd3hK9QGCUoCNAHJprhtpvcJpoohcg5otvuHeZiffYDRWrfxKUGS83X4X7Hp2vYqdFPgBQcwoveyJcyYByu7zT3Fn8faMffCE5oP125gwsHxjkquEnCy3RMbf64NVL9bLDDk391k7W4HyScbLyh7ooJcWaDDjiFMtoi1J856cDocYtxZ7rjmWmG15pgTcBLX7o8ebKhWCrFSMWtspRuKs9VFaY366Sjce5ZxTUsBWUMCpWhQZxeZQ2h42UST5XiJJ7TV1E13a3ttWrHijPcHgX1MvvDAPGKVgU2jXSgH8bCL4mKuVjdEm4Kx5wMdDW88ougUFuLfwhXkDfP7sYAfuaCFWx286kWqkfYdopcGntPjCvDu6uonghRmxeC2qNfXkYmk3ZQJXzsxgQToixevEvfxQgFY1uuNo5288zJPQcfLHtTvgxEhHxD5wwYYeGFqgV6FTg9mZVU5xqg7w6456cLuZNPuARkfpZK78xMEUHtnr95tK91UY'
      )
      expect(longFormDid).toBe(peerDidDocument.id)
    })
  })
})
