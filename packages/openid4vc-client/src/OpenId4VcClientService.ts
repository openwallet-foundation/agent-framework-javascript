import { injectable, W3cCredentialService } from '@aries-framework/core'

@injectable()
export class OpenId4VcClientService {
  private w3cCredentialService: W3cCredentialService

  public constructor(w3cCredentialService: W3cCredentialService) {
    this.w3cCredentialService = w3cCredentialService
  }
}
