import type { IndyEndpointAttrib, IndyLedgerService } from '../../ledger'
import type { ParsedDID, DIDResolutionResult, ServiceEndpoint } from '../types'
import type { DidResolver } from './DidResolver'

import { convertPublicKeyToX25519 } from '@stablelib/ed25519'

import { BufferEncoder } from '../../../utils/BufferEncoder'
import { getFullVerkey } from '../../../utils/did'
import { DidDocumentBuilder } from '../DidDocumentBuilder'

interface DidCommunicationService extends ServiceEndpoint {
  priority?: number
  routingKeys?: string[]
  recipientKeys: string[]
  accept: string[]
}

interface DidCommunicationV2Service extends ServiceEndpoint {
  routingKeys?: string[]
  accept: string[]
}

export class IndyDidResolver implements DidResolver {
  private indyLedgerService: IndyLedgerService

  public constructor(indyLedgerService: IndyLedgerService) {
    this.indyLedgerService = indyLedgerService
  }

  public readonly supportedMethods = ['sov']

  public async resolve(did: string, parsed: ParsedDID): Promise<DIDResolutionResult> {
    const didDocumentMetadata = {}

    try {
      const nym = await this.indyLedgerService.getPublicDid(parsed.id)
      const endpoints = await this.indyLedgerService.getEndpointsForDid(did)

      const verificationMethodId = `${parsed.did}#key-1`
      const keyAgreementId = `${parsed.did}#key-agreement-1`

      const publicKeyBase58 = getFullVerkey(nym.did, nym.verkey)
      const publicKeyX25519 = BufferEncoder.toBase58(
        convertPublicKeyToX25519(BufferEncoder.fromBase58(publicKeyBase58))
      )

      const builder = new DidDocumentBuilder(parsed.did)
        .addContext('https://w3id.org/security/suites/ed25519-2018/v1')
        .addContext('https://w3id.org/security/suites/x25519-2019/v1')
        .addVerificationMethod({
          controller: parsed.did,
          id: verificationMethodId,
          publicKeyBase58: getFullVerkey(nym.did, nym.verkey),
          type: 'Ed25519VerificationKey2018',
        })
        .addVerificationMethod({
          controller: parsed.did,
          id: keyAgreementId,
          publicKeyBase58: publicKeyX25519,
          type: 'X25519KeyAgreementKey2019',
        })
        .addAuthentication(verificationMethodId)
        .addAssertionMethod(verificationMethodId)
        .addKeyAgreement(keyAgreementId)

      this.addServices(builder, parsed, endpoints, keyAgreementId)

      return {
        didDocument: builder.build(),
        didDocumentMetadata,
        didResolutionMetadata: { contentType: 'application/did+ld+json' },
      }
    } catch (error) {
      return {
        didDocument: null,
        didDocumentMetadata,
        didResolutionMetadata: {
          error: 'notFound',
          message: `resolver_error: Unable to resolve did '${did}': ${error}`,
        },
      }
    }
  }

  private addServices(
    builder: DidDocumentBuilder,
    parsed: ParsedDID,
    endpoints: IndyEndpointAttrib,
    keyAgreementId: string
  ) {
    const { endpoint, routingKeys, types, ...otherEndpoints } = endpoints

    // If 'endpoint' type add id to the services array
    if (endpoint) {
      builder.addService({
        id: `${parsed.did}#endpoint`,
        serviceEndpoint: endpoint,
        type: 'endpoint',
      })

      // If 'did-communication' included in types, add DIDComm v1 entry
      if (types?.includes('did-communication')) {
        builder.addService({
          type: 'did-communication',
          id: `${parsed.did}#did-communication`,
          serviceEndpoint: endpoint,
          priority: 0,
          routingKeys: routingKeys ?? [],
          recipientKeys: [keyAgreementId],
          accept: ['didcomm/aip2;env=rfc19'],
        } as DidCommunicationService)

        // If 'DIDComm' included in types, add DIDComm v2 entry
        if (types?.includes('DIDComm')) {
          builder
            .addService({
              type: 'DIDComm',
              id: `${parsed.did}#didcomm-1`,
              serviceEndpoint: endpoint,
              routingKeys: routingKeys ?? [],
              accept: ['didcomm/v2'],
            } as DidCommunicationV2Service)
            .addContext('https://didcomm.org/messaging/contexts/v2')
        }
      }
    }

    // Add other endpoint types
    for (const [type, endpoint] of Object.entries(otherEndpoints)) {
      builder.addService({
        id: `${parsed.did}#${type}`,
        serviceEndpoint: endpoint as string,
        type,
      })
    }
  }
}
