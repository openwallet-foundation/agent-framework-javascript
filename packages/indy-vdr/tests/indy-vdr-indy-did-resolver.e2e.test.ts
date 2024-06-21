import { DidsModule, Agent, TypedArrayEncoder, JsonTransformer } from '@credo-ts/core'
import { indyVdr } from '@hyperledger/indy-vdr-nodejs'

import { getInMemoryAgentOptions, importExistingIndyDidFromPrivateKey } from '../../core/tests/helpers'
import { IndyVdrModule } from '../src'
import { IndyVdrIndyDidRegistrar, IndyVdrIndyDidResolver, IndyVdrSovDidResolver } from '../src/dids'

import { createDidOnLedger, indyVdrModuleConfig } from './helpers'

const agent = new Agent(
  getInMemoryAgentOptions(
    'Indy VDR Indy DID resolver',
    {},
    {
      indyVdr: new IndyVdrModule({
        indyVdr,
        networks: indyVdrModuleConfig.networks,
      }),
      dids: new DidsModule({
        registrars: [new IndyVdrIndyDidRegistrar()],
        resolvers: [new IndyVdrIndyDidResolver(), new IndyVdrSovDidResolver()],
      }),
    }
  )
)

describe('indy-vdr DID Resolver E2E', () => {
  beforeAll(async () => {
    await agent.initialize()
  })

  afterAll(async () => {
    await agent.shutdown()
    await agent.wallet.delete()
  })

  test('resolve a did:indy did', async () => {
    const did = 'did:indy:pool:localtest:TL1EaPFCZ8Si5aUrqScBDt'
    const didResult = await agent.dids.resolve(did)

    expect(JsonTransformer.toJSON(didResult)).toMatchObject({
      didDocument: {
        '@context': ['https://w3id.org/did/v1', 'https://w3id.org/security/suites/ed25519-2018/v1'],
        id: did,
        alsoKnownAs: undefined,
        controller: undefined,
        verificationMethod: [
          {
            type: 'Ed25519VerificationKey2018',
            controller: did,
            id: `${did}#verkey`,
            publicKeyBase58: expect.any(String),
          },
        ],
        capabilityDelegation: undefined,
        capabilityInvocation: undefined,
        authentication: [`${did}#verkey`],
        assertionMethod: undefined,
        keyAgreement: undefined,
        service: undefined,
      },
      didDocumentMetadata: {},
      didResolutionMetadata: {
        contentType: 'application/did+ld+json',
      },
    })
  })

  test('resolve a did with endpoints', async () => {
    const unqualifiedSubmitterDid = await importExistingIndyDidFromPrivateKey(
      agent,
      TypedArrayEncoder.fromString('000000000000000000000000Trustee9')
    )

    // First we need to create a new DID and add ATTRIB endpoint to it
    const { did } = await createDidOnLedger(agent, `did:indy:pool:localtest:${unqualifiedSubmitterDid}`)

    // DID created. Now resolve it
    const didResult = await agent.dids.resolve(did, {
      useLocalCreatedDidRecord: false,
    })
    expect(JsonTransformer.toJSON(didResult)).toMatchObject({
      didDocument: {
        '@context': [
          'https://w3id.org/did/v1',
          'https://w3id.org/security/suites/ed25519-2018/v1',
          'https://w3id.org/security/suites/x25519-2019/v1',
          'https://didcomm.org/messaging/contexts/v2',
        ],
        id: did,
        alsoKnownAs: undefined,
        controller: undefined,
        verificationMethod: [
          {
            type: 'Ed25519VerificationKey2018',
            controller: did,
            id: `${did}#verkey`,
            publicKeyBase58: expect.any(String),
          },
          {
            controller: did,
            type: 'X25519KeyAgreementKey2019',
            id: `${did}#key-agreement-1`,
            publicKeyBase58: expect.any(String),
          },
        ],
        capabilityDelegation: undefined,
        capabilityInvocation: undefined,
        authentication: [`${did}#verkey`],
        assertionMethod: undefined,
        keyAgreement: [`${did}#key-agreement-1`],
        service: [
          {
            id: `${did}#endpoint`,
            serviceEndpoint: 'http://localhost:3000',
            type: 'endpoint',
          },
          {
            id: `${did}#did-communication`,
            accept: ['didcomm/aip2;env=rfc19'],
            priority: 0,
            recipientKeys: [`${did}#key-agreement-1`],
            routingKeys: ['a-routing-key'],
            serviceEndpoint: 'http://localhost:3000',
            type: 'did-communication',
          },
          {
            id: `${did}#didcomm-1`,
            accept: ['didcomm/v2'],
            routingKeys: ['a-routing-key'],
            serviceEndpoint: 'http://localhost:3000',
            type: 'DIDComm',
          },
        ],
      },
      didDocumentMetadata: {},
      didResolutionMetadata: {
        contentType: 'application/did+ld+json',
      },
    })
  })
})
