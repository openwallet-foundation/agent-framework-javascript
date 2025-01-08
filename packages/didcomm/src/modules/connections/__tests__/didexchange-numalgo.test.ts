/* eslint-disable @typescript-eslint/no-non-null-assertion */
import type { ConnectionStateChangedEvent } from '../ConnectionEvents'

import { firstValueFrom } from 'rxjs'
import { filter, first, map, timeout } from 'rxjs/operators'

import { setupSubjectTransports } from '@credo-ts/core/tests'
import { getInMemoryAgentOptions } from '@credo-ts/core/tests/helpers'
import { Agent } from '@credo-ts/core/src/agent/Agent'
import { uuid } from '@credo-ts/core/src/utils/uuid'
import { DidsModule, PeerDidNumAlgo, createPeerDidDocumentFromServices } from '@credo-ts/core/src/modules/dids'
import { ConnectionEventTypes } from '../ConnectionEvents'
import { ConnectionsModule } from '../ConnectionsModule'
import { DidExchangeState } from '../../../models/connections'

import { InMemoryDidRegistry } from './InMemoryDidRegistry'

function waitForRequest(agent: Agent, theirLabel: string) {
  return firstValueFrom(
    agent.events.observable<ConnectionStateChangedEvent>(ConnectionEventTypes.ConnectionStateChanged).pipe(
      map((event) => event.payload.connectionRecord),
      // Wait for request received
      filter(
        (connectionRecord) =>
          connectionRecord.state === DidExchangeState.RequestReceived && connectionRecord.theirLabel === theirLabel
      ),
      first(),
      timeout(5000)
    )
  )
}

function waitForResponse(agent: Agent, connectionId: string) {
  return firstValueFrom(
    agent.events.observable<ConnectionStateChangedEvent>(ConnectionEventTypes.ConnectionStateChanged).pipe(
      // Wait for response received
      map((event) => event.payload.connectionRecord),
      filter(
        (connectionRecord) =>
          connectionRecord.state === DidExchangeState.ResponseReceived && connectionRecord.id === connectionId
      ),
      first(),
      timeout(5000)
    )
  )
}

describe('Did Exchange numalgo settings', () => {
  test('Connect using default setting (numalgo 1)', async () => {
    await didExchangeNumAlgoBaseTest({})
  })

  test('Connect using default setting for requester and numalgo 2 for responder', async () => {
    await didExchangeNumAlgoBaseTest({ responderNumAlgoSetting: PeerDidNumAlgo.MultipleInceptionKeyWithoutDoc })
  })

  test('Connect using numalgo 2 for requester and default setting for responder', async () => {
    await didExchangeNumAlgoBaseTest({ requesterNumAlgoSetting: PeerDidNumAlgo.MultipleInceptionKeyWithoutDoc })
  })

  test('Connect using numalgo 2 for both requester and responder', async () => {
    await didExchangeNumAlgoBaseTest({
      requesterNumAlgoSetting: PeerDidNumAlgo.MultipleInceptionKeyWithoutDoc,
      responderNumAlgoSetting: PeerDidNumAlgo.MultipleInceptionKeyWithoutDoc,
    })
  })

  test('Connect using default setting for requester and numalgo 4 for responder', async () => {
    await didExchangeNumAlgoBaseTest({ responderNumAlgoSetting: PeerDidNumAlgo.ShortFormAndLongForm })
  })

  test('Connect using numalgo 4 for requester and default setting for responder', async () => {
    await didExchangeNumAlgoBaseTest({ requesterNumAlgoSetting: PeerDidNumAlgo.ShortFormAndLongForm })
  })

  test('Connect using numalgo 4 for both requester and responder', async () => {
    await didExchangeNumAlgoBaseTest({
      requesterNumAlgoSetting: PeerDidNumAlgo.ShortFormAndLongForm,
      responderNumAlgoSetting: PeerDidNumAlgo.ShortFormAndLongForm,
    })
  })

  test('Connect using an externally defined did for the requested', async () => {
    await didExchangeNumAlgoBaseTest({
      createExternalDidForRequester: true,
    })
  })
})

async function didExchangeNumAlgoBaseTest(options: {
  requesterNumAlgoSetting?: PeerDidNumAlgo
  responderNumAlgoSetting?: PeerDidNumAlgo
  createExternalDidForRequester?: boolean
}) {
  // Make a common in-memory did registry for both agents
  const didRegistry = new InMemoryDidRegistry()

  const aliceAgentOptions = getInMemoryAgentOptions(
    'DID Exchange numalgo settings Alice',
    {
      label: 'alice',
      endpoints: ['rxjs:alice'],
    },
    {
      connections: new ConnectionsModule({
        autoAcceptConnections: false,
        peerNumAlgoForDidExchangeRequests: options.requesterNumAlgoSetting,
      }),
      dids: new DidsModule({ registrars: [didRegistry], resolvers: [didRegistry] }),
    }
  )
  const faberAgentOptions = getInMemoryAgentOptions(
    'DID Exchange numalgo settings Alice',
    {
      endpoints: ['rxjs:faber'],
    },
    {
      connections: new ConnectionsModule({
        autoAcceptConnections: false,
        peerNumAlgoForDidExchangeRequests: options.responderNumAlgoSetting,
      }),
      dids: new DidsModule({ registrars: [didRegistry], resolvers: [didRegistry] }),
    }
  )

  const aliceAgent = new Agent(aliceAgentOptions)
  const faberAgent = new Agent(faberAgentOptions)

  setupSubjectTransports([aliceAgent, faberAgent])
  await aliceAgent.initialize()
  await faberAgent.initialize()

  const faberOutOfBandRecord = await faberAgent.oob.createInvitation({
    autoAcceptConnection: false,
    multiUseInvitation: false,
  })

  const waitForAliceRequest = waitForRequest(faberAgent, 'alice')

  let ourDid, routing
  if (options.createExternalDidForRequester) {
    // Create did externally
    const didRouting = await aliceAgent.mediationRecipient.getRouting({})
    ourDid = `did:inmemory:${uuid()}`
    const didDocument = createPeerDidDocumentFromServices([
      {
        id: 'didcomm',
        recipientKeys: [didRouting.recipientKey],
        routingKeys: didRouting.routingKeys,
        serviceEndpoint: didRouting.endpoints[0],
      },
    ])
    didDocument.id = ourDid

    await aliceAgent.dids.create({
      did: ourDid,
      didDocument,
    })
  }

  let { connectionRecord: aliceConnectionRecord } = await aliceAgent.oob.receiveInvitation(
    faberOutOfBandRecord.outOfBandInvitation,
    {
      autoAcceptInvitation: true,
      autoAcceptConnection: false,
      routing,
      ourDid,
    }
  )

  let faberAliceConnectionRecord = await waitForAliceRequest

  const waitForAliceResponse = waitForResponse(aliceAgent, aliceConnectionRecord!.id)

  await faberAgent.connections.acceptRequest(faberAliceConnectionRecord.id)

  aliceConnectionRecord = await waitForAliceResponse
  await aliceAgent.connections.acceptResponse(aliceConnectionRecord!.id)

  aliceConnectionRecord = await aliceAgent.connections.returnWhenIsConnected(aliceConnectionRecord!.id)
  faberAliceConnectionRecord = await faberAgent.connections.returnWhenIsConnected(faberAliceConnectionRecord!.id)

  expect(aliceConnectionRecord).toBeConnectedWith(faberAliceConnectionRecord)

  await aliceAgent.wallet.delete()
  await aliceAgent.shutdown()

  await faberAgent.wallet.delete()
  await faberAgent.shutdown()
}
