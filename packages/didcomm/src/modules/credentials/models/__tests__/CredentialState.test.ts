import { CredentialState } from '../CredentialState'

describe('CredentialState', () => {
  test('state matches Issue Credential 1.0 (RFC 0036) state value', () => {
    expect(CredentialState.ProposalSent).toBe('proposal-sent')
    expect(CredentialState.ProposalReceived).toBe('proposal-received')
    expect(CredentialState.OfferSent).toBe('offer-sent')
    expect(CredentialState.OfferReceived).toBe('offer-received')
    expect(CredentialState.Declined).toBe('declined')
    expect(CredentialState.RequestSent).toBe('request-sent')
    expect(CredentialState.RequestReceived).toBe('request-received')
    expect(CredentialState.CredentialIssued).toBe('credential-issued')
    expect(CredentialState.CredentialReceived).toBe('credential-received')
    expect(CredentialState.Done).toBe('done')
  })

  test('state matches Issue Credential 2.0 (RFC 0453) state value', () => {
    expect(CredentialState.ProposalSent).toBe('proposal-sent')
    expect(CredentialState.ProposalReceived).toBe('proposal-received')
    expect(CredentialState.OfferSent).toBe('offer-sent')
    expect(CredentialState.OfferReceived).toBe('offer-received')
    expect(CredentialState.Declined).toBe('declined')
    expect(CredentialState.RequestSent).toBe('request-sent')
    expect(CredentialState.RequestReceived).toBe('request-received')
    expect(CredentialState.CredentialIssued).toBe('credential-issued')
    expect(CredentialState.CredentialReceived).toBe('credential-received')
    expect(CredentialState.Done).toBe('done')
  })
})
