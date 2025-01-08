import { DidCommV1Service, IndyAgentService, VerificationMethod } from '@credo-ts/core/src/modules/dids'
import {
  DidDoc,
  Ed25119Sig2018,
  EddsaSaSigSecp256k1,
  EmbeddedAuthentication,
  ReferencedAuthentication,
  RsaSig2018,
} from '../../../models/connections'
import { convertToNewDidDocument } from '../services/helpers'

const key = new Ed25119Sig2018({
  id: 'did:sov:SKJVx2kn373FNgvff1SbJo#4',
  controller: 'did:sov:SKJVx2kn373FNgvff1SbJo',
  publicKeyBase58: 'EoGusetSxDJktp493VCyh981nUnzMamTRjvBaHZAy68d',
})
const didDoc = new DidDoc({
  authentication: [
    new ReferencedAuthentication(key, 'Ed25519SignatureAuthentication2018'),
    new EmbeddedAuthentication(
      new Ed25119Sig2018({
        id: '#8',
        controller: 'did:sov:SKJVx2kn373FNgvff1SbJo',
        publicKeyBase58: '5UQ3drtEMMQXaLLmEywbciW92jZaQgRYgfuzXfonV8iz',
      })
    ),
  ],
  id: 'did:sov:LjgpST2rjsoxYegQDRm7EL',
  publicKey: [
    key,
    new RsaSig2018({
      id: '#3',
      controller: 'did:sov:LjgpST2rjsoxYegQDRm7EL',
      publicKeyPem: '-----BEGIN PUBLIC X...',
    }),
    new EddsaSaSigSecp256k1({
      id: '#6',
      controller: 'did:sov:LjgpST2rjsoxYegQDRm7EL',
      publicKeyHex: '-----BEGIN PUBLIC A...',
    }),
  ],
  service: [
    new IndyAgentService({
      id: 'did:sov:SKJVx2kn373FNgvff1SbJo#service-1',
      serviceEndpoint: 'did:sov:SKJVx2kn373FNgvff1SbJo',
      recipientKeys: ['EoGusetSxDJktp493VCyh981nUnzMamTRjvBaHZAy68d'],
      routingKeys: ['EoGusetSxDJktp493VCyh981nUnzMamTRjvBaHZAy68d'],
      priority: 5,
    }),
    new DidCommV1Service({
      id: '#service-2',
      serviceEndpoint: 'https://agent.com',
      recipientKeys: ['did:sov:SKJVx2kn373FNgvff1SbJo#4', '#8'],
      routingKeys: [
        'did:key:z6MktFXxTu8tHkoE1Jtqj4ApYEg1c44qmU1p7kq7QZXBtJv1#z6MktFXxTu8tHkoE1Jtqj4ApYEg1c44qmU1p7kq7QZXBtJv1',
      ],
      priority: 2,
    }),
  ],
})

describe('convertToNewDidDocument', () => {
  test('create a new DidDocument and with authentication, publicKey and service from DidDoc', () => {
    const oldDocument = didDoc
    const newDocument = convertToNewDidDocument(oldDocument)

    expect(newDocument.authentication).toEqual(['#EoGusetS', '#5UQ3drtE'])

    expect(newDocument.verificationMethod).toEqual([
      new VerificationMethod({
        id: '#5UQ3drtE',
        type: 'Ed25519VerificationKey2018',
        controller: '#id',
        publicKeyBase58: '5UQ3drtEMMQXaLLmEywbciW92jZaQgRYgfuzXfonV8iz',
      }),
      new VerificationMethod({
        id: '#EoGusetS',
        type: 'Ed25519VerificationKey2018',
        controller: '#id',
        publicKeyBase58: 'EoGusetSxDJktp493VCyh981nUnzMamTRjvBaHZAy68d',
      }),
    ])

    expect(newDocument.service).toEqual([
      new IndyAgentService({
        id: '#service-1',
        serviceEndpoint: 'did:sov:SKJVx2kn373FNgvff1SbJo',
        recipientKeys: ['EoGusetSxDJktp493VCyh981nUnzMamTRjvBaHZAy68d'],
        routingKeys: ['EoGusetSxDJktp493VCyh981nUnzMamTRjvBaHZAy68d'],
        priority: 5,
      }),
      new DidCommV1Service({
        id: '#service-2',
        serviceEndpoint: 'https://agent.com',
        recipientKeys: ['#EoGusetS', '#5UQ3drtE'],
        routingKeys: [
          'did:key:z6MktFXxTu8tHkoE1Jtqj4ApYEg1c44qmU1p7kq7QZXBtJv1#z6MktFXxTu8tHkoE1Jtqj4ApYEg1c44qmU1p7kq7QZXBtJv1',
        ],
        priority: 2,
      }),
    ])
  })

  test('will use ; as an id mark instead of # if the # is missing in a service id', () => {
    const oldDocument = new DidDoc({
      id: 'did:sov:LjgpST2rjsoxYegQDRm7EL',
      authentication: [],
      publicKey: [],
      service: [
        new IndyAgentService({
          id: 'did:sov:SKJVx2kn373FNgvff1SbJo;service-1',
          serviceEndpoint: 'did:sov:SKJVx2kn373FNgvff1SbJo',
          recipientKeys: ['EoGusetSxDJktp493VCyh981nUnzMamTRjvBaHZAy68d'],
          routingKeys: ['EoGusetSxDJktp493VCyh981nUnzMamTRjvBaHZAy68d'],
          priority: 5,
        }),
      ],
    })
    const newDocument = convertToNewDidDocument(oldDocument)

    expect(newDocument.service).toEqual([
      new IndyAgentService({
        id: '#service-1',
        serviceEndpoint: 'did:sov:SKJVx2kn373FNgvff1SbJo',
        recipientKeys: ['EoGusetSxDJktp493VCyh981nUnzMamTRjvBaHZAy68d'],
        routingKeys: ['EoGusetSxDJktp493VCyh981nUnzMamTRjvBaHZAy68d'],
        priority: 5,
      }),
    ])
  })

  test('will only split on the first ; or # and leave the other ones in place as id values', () => {
    const oldDocument = new DidDoc({
      id: 'did:sov:LjgpST2rjsoxYegQDRm7EL',
      authentication: [],
      publicKey: [],
      service: [
        new IndyAgentService({
          id: 'did:sov:SKJVx2kn373FNgvff1SbJo;service-1;something-extra',
          serviceEndpoint: 'did:sov:SKJVx2kn373FNgvff1SbJo',
          recipientKeys: ['EoGusetSxDJktp493VCyh981nUnzMamTRjvBaHZAy68d'],
          routingKeys: ['EoGusetSxDJktp493VCyh981nUnzMamTRjvBaHZAy68d'],
          priority: 6,
        }),
        new IndyAgentService({
          id: 'did:sov:SKJVx2kn373FNgvff1SbJo#service-2#something-extra',
          serviceEndpoint: 'did:sov:SKJVx2kn373FNgvff1SbJo',
          recipientKeys: ['EoGusetSxDJktp493VCyh981nUnzMamTRjvBaHZAy68d'],
          routingKeys: ['EoGusetSxDJktp493VCyh981nUnzMamTRjvBaHZAy68d'],
          priority: 5,
        }),
      ],
    })
    const newDocument = convertToNewDidDocument(oldDocument)

    expect(newDocument.service).toEqual([
      new IndyAgentService({
        id: '#service-1;something-extra',
        serviceEndpoint: 'did:sov:SKJVx2kn373FNgvff1SbJo',
        recipientKeys: ['EoGusetSxDJktp493VCyh981nUnzMamTRjvBaHZAy68d'],
        routingKeys: ['EoGusetSxDJktp493VCyh981nUnzMamTRjvBaHZAy68d'],
        priority: 6,
      }),
      new IndyAgentService({
        id: '#service-2#something-extra',
        serviceEndpoint: 'did:sov:SKJVx2kn373FNgvff1SbJo',
        recipientKeys: ['EoGusetSxDJktp493VCyh981nUnzMamTRjvBaHZAy68d'],
        routingKeys: ['EoGusetSxDJktp493VCyh981nUnzMamTRjvBaHZAy68d'],
        priority: 5,
      }),
    ])
  })
})
