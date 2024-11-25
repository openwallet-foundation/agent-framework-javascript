import type { MdocRecord, SdJwtVcRecord, W3cCredentialRecord } from '@credo-ts/core'
import type {
  OpenId4VciCredentialConfigurationsSupportedWithFormats,
  OpenId4VcSiopResolvedAuthorizationRequest,
  OpenId4VciResolvedCredentialOffer,
} from '@credo-ts/openid4vc'

import { Mdoc } from '@credo-ts/core'
import { preAuthorizedCodeGrantIdentifier } from '@credo-ts/openid4vc'
import console, { clear } from 'console'
import { textSync } from 'figlet'

import { BaseInquirer } from './BaseInquirer'
import { Holder } from './Holder'
import { Title, greenText, redText } from './OutputClass'

export const runHolder = async () => {
  clear()
  console.log(textSync('Holder', { horizontalLayout: 'full' }))
  const holder = await HolderInquirer.build()
  await holder.processAnswer()
}

enum PromptOptions {
  ResolveCredentialOffer = 'Resolve a credential offer.',
  DynamicCredentialRequest = 'Dynamically request issuance of credential from issuer.',
  RequestCredential = 'Accept the credential offer.',
  ResolveProofRequest = 'Resolve a proof request.',
  AcceptPresentationRequest = 'Accept the presentation request.',
  AddTrustedCertificate = 'Add trusted certificate',
  Exit = 'Exit',
  Restart = 'Restart',
}

export class HolderInquirer extends BaseInquirer {
  public holder: Holder
  public resolvedCredentialOffer?: OpenId4VciResolvedCredentialOffer
  public resolvedPresentationRequest?: OpenId4VcSiopResolvedAuthorizationRequest

  public constructor(holder: Holder) {
    super()
    this.holder = holder
  }

  public static async build(): Promise<HolderInquirer> {
    const holder = await Holder.build()
    return new HolderInquirer(holder)
  }

  private async getPromptChoice() {
    const promptOptions = [
      PromptOptions.ResolveCredentialOffer,
      PromptOptions.DynamicCredentialRequest,
      PromptOptions.ResolveProofRequest,
      PromptOptions.AddTrustedCertificate,
    ]

    if (this.resolvedCredentialOffer) promptOptions.unshift(PromptOptions.RequestCredential)
    if (this.resolvedPresentationRequest) promptOptions.unshift(PromptOptions.AcceptPresentationRequest)

    return this.pickOne(promptOptions)
  }

  public async processAnswer() {
    const choice = await this.getPromptChoice()

    switch (choice) {
      case PromptOptions.ResolveCredentialOffer:
        await this.resolveCredentialOffer()
        break
      case PromptOptions.DynamicCredentialRequest:
        await this.dynamicCredentialRequest()
        break
      case PromptOptions.RequestCredential:
        await this.requestCredential()
        break
      case PromptOptions.ResolveProofRequest:
        await this.resolveProofRequest()
        break
      case PromptOptions.AcceptPresentationRequest:
        await this.acceptPresentationRequest()
        break
      case PromptOptions.AddTrustedCertificate:
        await this.addTrustedCertificate()
        break
      case PromptOptions.Exit:
        await this.exit()
        break
      case PromptOptions.Restart:
        await this.restart()
        return
    }
    await this.processAnswer()
  }

  public async exitUseCase(title: string) {
    return await this.inquireConfirmation(title)
  }

  public async resolveCredentialOffer() {
    const credentialOffer = await this.inquireInput('Enter credential offer: ')
    const resolvedCredentialOffer = await this.holder.resolveCredentialOffer(credentialOffer)
    this.resolvedCredentialOffer = resolvedCredentialOffer

    console.log(greenText(`Received credential offer for the following credentials.`))
    console.log(greenText(Object.keys(resolvedCredentialOffer.offeredCredentialConfigurations).join('\n')))
  }

  public async dynamicCredentialRequest() {
    const credentialOffer = await this.inquireInput('Enter issuer url: ')
    const issuerMetadata = await this.holder.resolveIssuerMetadata(credentialOffer)
    const configurationsWithScope = Object.entries(
      issuerMetadata.credentialIssuer.credential_configurations_supported
    ).filter(([, configuration]) => configuration.scope)

    this.resolvedCredentialOffer = {
      credentialOfferPayload: {
        credential_configuration_ids: configurationsWithScope.map(([id]) => id),
        credential_issuer: issuerMetadata.credentialIssuer.credential_issuer,
        grants: {
          authorization_code: {
            authorization_server: issuerMetadata.authorizationServers.find((a) => a.authorization_endpoint)?.issuer,
          },
        },
      },
      metadata: issuerMetadata,
      offeredCredentialConfigurations: Object.fromEntries(
        configurationsWithScope
      ) as OpenId4VciCredentialConfigurationsSupportedWithFormats,
    }

    console.log(greenText(`We can request authorization for the following credentials.`))
    console.log(greenText(configurationsWithScope.map(([id]) => id).join('\n')))
  }

  public async addTrustedCertificate() {
    const trustedCertificate = await this.inquireInput('Enter trusted certificate: ')
    await this.holder.agent.x509.addTrustedCertificate(trustedCertificate)

    console.log(greenText(`Added trusted certificate`))
  }

  public async requestCredential() {
    if (!this.resolvedCredentialOffer) {
      throw new Error('No credential offer resolved yet.')
    }

    const credentialsThatCanBeRequested = Object.keys(this.resolvedCredentialOffer.offeredCredentialConfigurations)
    const credentialsToRequest = await this.pickMultiple(credentialsThatCanBeRequested)

    const resolvedAuthorization = await this.holder.initiateAuthorization(
      this.resolvedCredentialOffer,
      credentialsToRequest
    )
    let authorizationCode: string | undefined = undefined
    let codeVerifier: string | undefined = undefined
    let txCode: string | undefined = undefined

    if (resolvedAuthorization.authorizationFlow === 'Oauth2Redirect') {
      console.log(redText(`Authorization required for credential issuance`, true))
      console.log("Open the following url in your browser to authorize. Once you're done come back here")
      console.log(resolvedAuthorization.authorizationRequestUrl)

      const code = new Promise<string>((resolve, reject) => {
        this.holder.app.get('/redirect', (req, res) => {
          if (req.query.code) {
            resolve(req.query.code as string)
            // Store original routes
            const originalStack = this.holder.app._router.stack

            // Remove specific GET route by path
            this.holder.app._router.stack = originalStack.filter(
              (layer: { route?: { path: string; methods: { get?: unknown } } }) =>
                !(layer.route && layer.route.path === '/redirect' && layer.route.methods.get)
            )
            res.send('Success! You can now go back to the terminal')
          } else {
            console.log(redText(`Error during authorization`, true))
            console.log(JSON.stringify(req.query, null, 2))
            res.status(500).send('Error during authentication')
            reject()
          }
        })
      })

      console.log('\n\n')
      codeVerifier = resolvedAuthorization.codeVerifier
      authorizationCode = await code
      console.log(greenText('Authorization complete', true))
    } else if (resolvedAuthorization.authorizationFlow === 'PresentationDuringIssuance') {
      console.log(redText(`Presentation during issuance not supported yet`, true))
      return
    } else if (resolvedAuthorization.authorizationFlow === 'PreAuthorized') {
      if (this.resolvedCredentialOffer.credentialOfferPayload.grants?.[preAuthorizedCodeGrantIdentifier]?.tx_code) {
        txCode = await this.inquireInput('Enter PIN')
      }
    }

    console.log(greenText(`Requesting the following credential '${credentialsToRequest}'`))

    const credentials = await this.holder.requestAndStoreCredentials(this.resolvedCredentialOffer, {
      credentialsToRequest,
      clientId: authorizationCode ? this.holder.client.clientId : undefined,
      codeVerifier,
      code: authorizationCode,
      redirectUri: authorizationCode ? this.holder.client.redirectUri : undefined,
      txCode,
    })

    console.log(greenText(`Received and stored the following credentials.`, true))
    this.resolvedCredentialOffer = undefined

    credentials.forEach(this.printCredential)
  }

  public async resolveProofRequest() {
    const proofRequestUri = await this.inquireInput('Enter proof request: ')
    this.resolvedPresentationRequest = await this.holder.resolveProofRequest(proofRequestUri)

    if (this.resolvedPresentationRequest.presentationExchange) {
      const presentationDefinition = this.resolvedPresentationRequest.presentationExchange.definition
      console.log(
        greenText(`Received DIF Presentation Exchange request with purpose: '${presentationDefinition.purpose}'`)
      )

      if (this.resolvedPresentationRequest.presentationExchange.credentialsForRequest.areRequirementsSatisfied) {
        const selectedCredentials = Object.values(
          this.holder.agent.modules.openId4VcHolder.selectCredentialsForPresentationExchangeRequest(
            this.resolvedPresentationRequest.presentationExchange.credentialsForRequest
          )
        ).flatMap((e) => e)
        console.log(
          greenText(
            `All requirements for creating the presentation are satisfied. The following credentials will be shared`,
            true
          )
        )
        selectedCredentials.forEach(this.printCredential)
      } else {
        console.log(redText(`No credentials available that satisfy the proof request.`))
      }
    } else if (this.resolvedPresentationRequest.dcql) {
      console.log(greenText('Received DCQL request'))

      if (this.resolvedPresentationRequest.dcql.queryResult.canBeSatisfied) {
        const selectedCredentials = Object.values(
          this.holder.agent.modules.openId4VcHolder.selectCredentialsForDcqlRequest(
            this.resolvedPresentationRequest.dcql.queryResult
          )
        ).flatMap((e) => e.credentialRecord)
        console.log(
          greenText(
            `All requirements for creating the presentation are satisfied. The following credentials will be shared`,
            true
          )
        )
        selectedCredentials.forEach(this.printCredential)
      } else {
        console.log(redText(`No credentials available that satisfy the proof request.`))
      }
    }
  }

  public async acceptPresentationRequest() {
    if (!this.resolvedPresentationRequest) throw new Error('No presentation request resolved yet.')

    console.log(greenText(`Accepting the presentation request.`))

    const serverResponse = await this.holder.acceptPresentationRequest(this.resolvedPresentationRequest)

    if (serverResponse.status >= 200 && serverResponse.status < 300) {
      console.log(`received success status code '${serverResponse.status}'`)
    } else {
      console.log(`received error status code '${serverResponse.status}'. ${JSON.stringify(serverResponse.body)}`)
    }

    this.resolvedPresentationRequest = undefined
  }

  public async exit() {
    if (await this.inquireConfirmation(Title.ConfirmTitle)) {
      await this.holder.exit()
    }
  }

  public async restart() {
    const confirmed = await this.inquireConfirmation(Title.ConfirmTitle)
    if (confirmed) {
      await this.holder.restart()
      await runHolder()
    } else {
      await this.processAnswer()
    }
  }

  private printCredential = (credential: W3cCredentialRecord | SdJwtVcRecord | MdocRecord) => {
    if (credential.type === 'W3cCredentialRecord') {
      console.log(greenText(`W3cCredentialRecord with claim format ${credential.credential.claimFormat}`, true))
      console.log(JSON.stringify(credential.credential.jsonCredential, null, 2))
      console.log('')
    } else if (credential.type === 'MdocRecord') {
      console.log(greenText(`MdocRecord`, true))
      const namespaces = Mdoc.fromBase64Url(credential.base64Url).issuerSignedNamespaces
      console.log(JSON.stringify(namespaces, null, 2))
      console.log('')
    } else {
      console.log(greenText(`SdJwtVcRecord`, true))
      const prettyClaims = this.holder.agent.sdJwtVc.fromCompact(credential.compactSdJwtVc).prettyClaims
      console.log(JSON.stringify(prettyClaims, null, 2))
      console.log('')
    }
  }
}

void runHolder()
