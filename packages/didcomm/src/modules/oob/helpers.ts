import type { OutOfBandDidCommService } from './domain/OutOfBandDidCommService'

import {
  DidCommV1Service,
  DidDocumentBuilder,
  DidKey,
  didDocumentToNumAlgo2Did,
  createPeerDidDocumentFromServices,
  didKeyToInstanceOfKey,
} from '@credo-ts/core'

// This method is kept to support searching for existing connections created by
// credo-ts <= 0.5.1
// TODO: Remove in 0.6.0 (when ConnectionRecord.invitationDid will be migrated)
export function outOfBandServiceToInlineKeysNumAlgo2Did(service: OutOfBandDidCommService) {
  const didDocument = new DidDocumentBuilder('')
    .addService(
      new DidCommV1Service({
        id: service.id,
        serviceEndpoint: service.serviceEndpoint,
        accept: service.accept,
        recipientKeys: service.recipientKeys.map((recipientKey) => {
          const did = DidKey.fromDid(recipientKey)
          return `${did.did}#${did.key.fingerprint}`
        }),
        // Map did:key:xxx to actual did:key:xxx#123
        routingKeys: service.routingKeys?.map((routingKey) => {
          const did = DidKey.fromDid(routingKey)
          return `${did.did}#${did.key.fingerprint}`
        }),
      })
    )
    .build()

  const did = didDocumentToNumAlgo2Did(didDocument)

  return did
}

export function outOfBandServiceToNumAlgo2Did(service: OutOfBandDidCommService) {
  const didDocument = createPeerDidDocumentFromServices([
    {
      id: service.id,
      recipientKeys: service.recipientKeys.map(didKeyToInstanceOfKey),
      serviceEndpoint: service.serviceEndpoint,
      routingKeys: service.routingKeys?.map(didKeyToInstanceOfKey) ?? [],
    },
  ])

  const did = didDocumentToNumAlgo2Did(didDocument)

  return did
}
