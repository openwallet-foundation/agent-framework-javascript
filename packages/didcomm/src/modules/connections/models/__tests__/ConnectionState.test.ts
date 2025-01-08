import { ConnectionState, rfc0160StateFromDidExchangeState } from '../ConnectionState'
import { DidExchangeState } from '../DidExchangeState'

describe('ConnectionState', () => {
  test('state matches Connection 1.0 (RFC 0160) state value', () => {
    expect(ConnectionState.Null).toBe('null')
    expect(ConnectionState.Invited).toBe('invited')
    expect(ConnectionState.Requested).toBe('requested')
    expect(ConnectionState.Responded).toBe('responded')
    expect(ConnectionState.Complete).toBe('complete')
  })

  describe('rfc0160StateFromDidExchangeState', () => {
    it('should return the connection state for all did exchanges states', () => {
      expect(rfc0160StateFromDidExchangeState(DidExchangeState.Abandoned)).toEqual(ConnectionState.Null)
      expect(rfc0160StateFromDidExchangeState(DidExchangeState.Start)).toEqual(ConnectionState.Null)

      expect(rfc0160StateFromDidExchangeState(DidExchangeState.InvitationReceived)).toEqual(ConnectionState.Invited)
      expect(rfc0160StateFromDidExchangeState(DidExchangeState.InvitationSent)).toEqual(ConnectionState.Invited)

      expect(rfc0160StateFromDidExchangeState(DidExchangeState.RequestReceived)).toEqual(ConnectionState.Requested)
      expect(rfc0160StateFromDidExchangeState(DidExchangeState.RequestSent)).toEqual(ConnectionState.Requested)

      expect(rfc0160StateFromDidExchangeState(DidExchangeState.ResponseReceived)).toEqual(ConnectionState.Responded)
      expect(rfc0160StateFromDidExchangeState(DidExchangeState.ResponseReceived)).toEqual(ConnectionState.Responded)

      expect(rfc0160StateFromDidExchangeState(DidExchangeState.Completed)).toEqual(ConnectionState.Complete)
    })
  })
})
