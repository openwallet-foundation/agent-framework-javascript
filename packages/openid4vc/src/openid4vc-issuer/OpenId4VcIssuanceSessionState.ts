export enum OpenId4VcIssuanceSessionState {
  OfferCreated = 'OfferCreated',
  OfferUriRetrieved = 'OfferUriRetrieved',
  AccessTokenRequested = 'AccessTokenRequested',
  AccessTokenCreated = 'AccessTokenCreated',
  CredentialRequestReceived = 'CredentialRequestReceived',
  CredentialsPartiallyIssued = 'CredentialsPartiallyIssued',
  Completed = 'Completed',
  Error = 'Error',
}
