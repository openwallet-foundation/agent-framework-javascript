import { JsonEncoder, JsonTransformer, MessageValidator } from '@credo-ts/core'

import { agentDependencies } from '../../../../core/tests'
import { ConnectionInvitationMessage } from '../../modules/connections'
import { InvitationType, OutOfBandInvitation } from '../../modules/oob'
import { convertToNewInvitation } from '../../modules/oob/converters'
import { oobInvitationFromShortUrl, parseInvitationShortUrl } from '../parseInvitation'

const mockOobInvite = {
  '@type': 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/out-of-band/1.0/invitation',
  '@id': '764af259-8bb4-4546-b91a-924c912d0bb8',
  label: 'Alice',
  handshake_protocols: ['did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0'],
  services: ['did:sov:MvTqVXCEmJ87usL9uQTo7v'],
}

const mockConnectionInvite = {
  '@type': 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation',
  '@id': '20971ef0-1029-46db-a25b-af4c465dd16b',
  label: 'test',
  serviceEndpoint: 'http://sour-cow-15.tun1.indiciotech.io',
  recipientKeys: ['5Gvpf9M4j7vWpHyeTyvBKbjYe7qWc72kGo6qZaLHkLrd'],
}

const mockLegacyConnectionless = {
  '@id': '035b6404-f496-4cb6-a2b5-8bd09e8c92c1',
  '@type': 'https://didcomm.org/some-protocol/1.0/some-message',
  '~service': {
    recipientKeys: ['5Gvpf9M4j7vWpHyeTyvBKbjYe7qWc72kGo6qZaLHkLrd'],
    routingKeys: ['5Gvpf9M4j7vWpHyeTyvBKbjYe7qWc72kGo6qZaLHkLrd'],
    serviceEndpoint: 'https://example.com/endpoint',
  },
}

const header = new Headers()

const dummyHeader = new Headers()

header.append('Content-Type', 'application/json')

const mockedResponseOobJson = {
  status: 200,
  ok: true,
  headers: header,
  json: async () => ({
    '@type': 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/out-of-band/1.0/invitation',
    '@id': '764af259-8bb4-4546-b91a-924c912d0bb8',
    label: 'Alice',
    handshake_protocols: ['did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0'],
    services: ['did:sov:MvTqVXCEmJ87usL9uQTo7v'],
  }),
} as Response

const mockedResponseOobUrl = {
  status: 200,
  ok: true,
  headers: dummyHeader,
  url: 'https://wonderful-rabbit-5.tun2.indiciotech.io?oob=eyJAdHlwZSI6ICJkaWQ6c292OkJ6Q2JzTlloTXJqSGlxWkRUVUFTSGc7c3BlYy9vdXQtb2YtYmFuZC8xLjAvaW52aXRhdGlvbiIsICJAaWQiOiAiNzY0YWYyNTktOGJiNC00NTQ2LWI5MWEtOTI0YzkxMmQwYmI4IiwgImxhYmVsIjogIkFsaWNlIiwgImhhbmRzaGFrZV9wcm90b2NvbHMiOiBbImRpZDpzb3Y6QnpDYnNOWWhNcmpIaXFaRFRVQVNIZztzcGVjL2Nvbm5lY3Rpb25zLzEuMCJdLCAic2VydmljZXMiOiBbImRpZDpzb3Y6TXZUcVZYQ0VtSjg3dXNMOXVRVG83diJdfQ====',
} as Response

dummyHeader.forEach(mockedResponseOobUrl.headers.append)

const mockedLegacyConnectionlessInvitationJson = {
  status: 200,
  ok: true,
  json: async () => mockLegacyConnectionless,
  headers: header,
} as Response

const mockedResponseConnectionJson = {
  status: 200,
  ok: true,
  json: async () => ({
    '@type': 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation',
    '@id': '20971ef0-1029-46db-a25b-af4c465dd16b',
    label: 'test',
    serviceEndpoint: 'http://sour-cow-15.tun1.indiciotech.io',
    recipientKeys: ['5Gvpf9M4j7vWpHyeTyvBKbjYe7qWc72kGo6qZaLHkLrd'],
  }),
  headers: header,
} as Response

const mockedResponseConnectionUrl = {
  status: 200,
  ok: true,
  url: 'http://sour-cow-15.tun1.indiciotech.io?c_i=eyJAdHlwZSI6ICJkaWQ6c292OkJ6Q2JzTlloTXJqSGlxWkRUVUFTSGc7c3BlYy9jb25uZWN0aW9ucy8xLjAvaW52aXRhdGlvbiIsICJAaWQiOiAiMjA5NzFlZjAtMTAyOS00NmRiLWEyNWItYWY0YzQ2NWRkMTZiIiwgImxhYmVsIjogInRlc3QiLCAic2VydmljZUVuZHBvaW50IjogImh0dHA6Ly9zb3VyLWNvdy0xNS50dW4xLmluZGljaW90ZWNoLmlvIiwgInJlY2lwaWVudEtleXMiOiBbIjVHdnBmOU00ajd2V3BIeWVUeXZCS2JqWWU3cVdjNzJrR282cVphTEhrTHJkIl19',
  headers: dummyHeader,
} as Response

let outOfBandInvitationMock: OutOfBandInvitation
let connectionInvitationMock: ConnectionInvitationMessage
let connectionInvitationToNew: OutOfBandInvitation

beforeAll(async () => {
  outOfBandInvitationMock = JsonTransformer.fromJSON(mockOobInvite, OutOfBandInvitation)
  outOfBandInvitationMock.invitationType = InvitationType.OutOfBand
  MessageValidator.validateSync(outOfBandInvitationMock)
  connectionInvitationMock = JsonTransformer.fromJSON(mockConnectionInvite, ConnectionInvitationMessage)
  MessageValidator.validateSync(connectionInvitationMock)
  connectionInvitationToNew = convertToNewInvitation(connectionInvitationMock)
})

describe('shortened urls resolving to oob invitations', () => {
  test('Resolve a mocked response in the form of a oob invitation as a json object', async () => {
    const short = await oobInvitationFromShortUrl(mockedResponseOobJson)
    expect(short).toEqual(outOfBandInvitationMock)
  })
  test('Resolve a mocked response in the form of a oob invitation encoded in an url', async () => {
    const short = await oobInvitationFromShortUrl(mockedResponseOobUrl)
    expect(short).toEqual(outOfBandInvitationMock)
  })

  test("Resolve a mocked response in the form of a oob invitation as a json object with header 'application/json; charset=utf-8'", async () => {
    const short = await oobInvitationFromShortUrl({
      ...mockedResponseOobJson,
      headers: new Headers({
        'content-type': 'application/json; charset=utf-8',
      }),
    } as Response)
    expect(short).toEqual(outOfBandInvitationMock)
  })
})

describe('legacy connectionless', () => {
  test('parse url containing d_m ', async () => {
    const parsed = await parseInvitationShortUrl(
      `https://example.com?d_m=${JsonEncoder.toBase64URL(mockLegacyConnectionless)}`,
      agentDependencies
    )
    expect(parsed.toJSON()).toMatchObject({
      '@id': expect.any(String),
      '@type': 'https://didcomm.org/out-of-band/1.1/invitation',
      label: undefined,
      'requests~attach': [
        {
          '@id': expect.any(String),
          data: {
            base64:
              'eyJAaWQiOiIwMzViNjQwNC1mNDk2LTRjYjYtYTJiNS04YmQwOWU4YzkyYzEiLCJAdHlwZSI6Imh0dHBzOi8vZGlkY29tbS5vcmcvc29tZS1wcm90b2NvbC8xLjAvc29tZS1tZXNzYWdlIn0=',
          },
          'mime-type': 'application/json',
        },
      ],
      services: [
        {
          id: expect.any(String),
          recipientKeys: ['did:key:z6MkijBsFPbW4fQyvnpM9Yt2AhHYTh7N1zH6xp1mPrJJfZe1'],
          routingKeys: ['did:key:z6MkijBsFPbW4fQyvnpM9Yt2AhHYTh7N1zH6xp1mPrJJfZe1'],
          serviceEndpoint: 'https://example.com/endpoint',
          type: 'did-communication',
        },
      ],
    })
  })

  test('parse short url returning legacy connectionless invitation to out of band invitation', async () => {
    const parsed = await oobInvitationFromShortUrl(mockedLegacyConnectionlessInvitationJson)
    expect(parsed.toJSON()).toMatchObject({
      '@id': expect.any(String),
      '@type': 'https://didcomm.org/out-of-band/1.1/invitation',
      label: undefined,
      'requests~attach': [
        {
          '@id': expect.any(String),
          data: {
            base64:
              'eyJAaWQiOiIwMzViNjQwNC1mNDk2LTRjYjYtYTJiNS04YmQwOWU4YzkyYzEiLCJAdHlwZSI6Imh0dHBzOi8vZGlkY29tbS5vcmcvc29tZS1wcm90b2NvbC8xLjAvc29tZS1tZXNzYWdlIn0=',
          },
          'mime-type': 'application/json',
        },
      ],
      services: [
        {
          id: expect.any(String),
          recipientKeys: ['did:key:z6MkijBsFPbW4fQyvnpM9Yt2AhHYTh7N1zH6xp1mPrJJfZe1'],
          routingKeys: ['did:key:z6MkijBsFPbW4fQyvnpM9Yt2AhHYTh7N1zH6xp1mPrJJfZe1'],
          serviceEndpoint: 'https://example.com/endpoint',
          type: 'did-communication',
        },
      ],
    })
  })
})

describe('shortened urls resolving to connection invitations', () => {
  test('Resolve a mocked response in the form of a connection invitation as a json object', async () => {
    const short = await oobInvitationFromShortUrl(mockedResponseConnectionJson)
    expect(short).toEqual(connectionInvitationToNew)
  })

  test('Resolve a mocked Response in the form of a connection invitation encoded in an url c_i query parameter', async () => {
    const short = await oobInvitationFromShortUrl(mockedResponseConnectionUrl)
    expect(short).toEqual(connectionInvitationToNew)
  })

  test('Resolve a mocked Response in the form of a connection invitation encoded in an url oob query parameter', async () => {
    const mockedResponseConnectionInOobUrl = {
      status: 200,
      ok: true,
      headers: dummyHeader,
      url: 'https://oob.lissi.io/ssi?oob=eyJAdHlwZSI6ImRpZDpzb3Y6QnpDYnNOWWhNcmpIaXFaRFRVQVNIZztzcGVjL2Nvbm5lY3Rpb25zLzEuMC9pbnZpdGF0aW9uIiwiQGlkIjoiMGU0NmEzYWEtMzUyOC00OTIxLWJmYjItN2JjYjk0NjVjNjZjIiwibGFiZWwiOiJTdGFkdCB8IExpc3NpLURlbW8iLCJzZXJ2aWNlRW5kcG9pbnQiOiJodHRwczovL2RlbW8tYWdlbnQuaW5zdGl0dXRpb25hbC1hZ2VudC5saXNzaS5pZC9kaWRjb21tLyIsImltYWdlVXJsIjoiaHR0cHM6Ly9yb3V0aW5nLmxpc3NpLmlvL2FwaS9JbWFnZS9kZW1vTXVzdGVyaGF1c2VuIiwicmVjaXBpZW50S2V5cyI6WyJEZlcxbzM2ekxuczlVdGlDUGQyalIyS2pvcnRvZkNhcFNTWTdWR2N2WEF6aCJdfQ',
    } as Response

    dummyHeader.forEach(mockedResponseConnectionInOobUrl.headers.append)

    const expectedOobMessage = convertToNewInvitation(
      JsonTransformer.fromJSON(
        {
          '@type': 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation',
          '@id': '0e46a3aa-3528-4921-bfb2-7bcb9465c66c',
          label: 'Stadt | Lissi-Demo',
          serviceEndpoint: 'https://demo-agent.institutional-agent.lissi.id/didcomm/',
          imageUrl: 'https://routing.lissi.io/api/Image/demoMusterhausen',
          recipientKeys: ['DfW1o36zLns9UtiCPd2jR2KjortofCapSSY7VGcvXAzh'],
        },
        ConnectionInvitationMessage
      )
    )
    const short = await oobInvitationFromShortUrl(mockedResponseConnectionInOobUrl)
    expect(short).toEqual(expectedOobMessage)
  })
})
