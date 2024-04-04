import { JsonTransformer } from '../../../../utils'
import { DidExchangeRole, DidExchangeState, HandshakeProtocol } from '../../models'
import { ConnectionRecord } from '../ConnectionRecord'

describe('ConnectionRecord', () => {
  describe('getTags', () => {
    it('should return default tags', () => {
      const connectionRecord = new ConnectionRecord({
        state: DidExchangeState.Completed,
        role: DidExchangeRole.Requester,
        threadId: 'a-thread-id',
        mediatorId: 'a-mediator-id',
        did: 'a-did',
        alias: 'a-alias',
        theirDid: 'a-their-did',
        theirLabel: 'a-their-label',
        outOfBandId: 'a-out-of-band-id',
        invitationDid: 'a-invitation-did',
      })

      expect(connectionRecord.getTags()).toEqual({
        state: DidExchangeState.Completed,
        role: DidExchangeRole.Requester,
        threadId: 'a-thread-id',
        mediatorId: 'a-mediator-id',
        did: 'a-did',
        alias: 'a-alias',
        theirDid: 'a-their-did',
        theirLabel: 'a-their-label',
        outOfBandId: 'a-out-of-band-id',
        invitationDid: 'a-invitation-did',
        connectionTypes: [],
        previousDids: [],
        previousTheirDids: [],
      })
    })
  })

  it('should transform handshake protocol with minor version to .x', () => {
    const connectionRecord = JsonTransformer.fromJSON(
      {
        protocol: 'https://didcomm.org/didexchange/1.0',
      },
      ConnectionRecord
    )

    expect(connectionRecord.protocol).toEqual(HandshakeProtocol.DidExchange)
  })

  it('should not transform handshake protocol when minor version is .x', () => {
    const connectionRecord = JsonTransformer.fromJSON(
      {
        protocol: 'https://didcomm.org/didexchange/1.x',
      },
      ConnectionRecord
    )

    expect(connectionRecord.protocol).toEqual(HandshakeProtocol.DidExchange)
  })
})
