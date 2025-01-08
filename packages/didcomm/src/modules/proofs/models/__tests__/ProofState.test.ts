import { ProofState } from '../ProofState'

describe('ProofState', () => {
  test('state matches Present Proof 1.0 (RFC 0037) state value', () => {
    expect(ProofState.ProposalSent).toBe('proposal-sent')
    expect(ProofState.ProposalReceived).toBe('proposal-received')
    expect(ProofState.RequestSent).toBe('request-sent')
    expect(ProofState.RequestReceived).toBe('request-received')
    expect(ProofState.PresentationSent).toBe('presentation-sent')
    expect(ProofState.PresentationReceived).toBe('presentation-received')
    expect(ProofState.Declined).toBe('declined')
    expect(ProofState.Done).toBe('done')
  })
})
