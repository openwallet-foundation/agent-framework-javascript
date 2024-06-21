import type { SdJwtVcRecord, W3cCredentialRecord } from '@credo-ts/core'
import type { OpenId4VcSiopResolvedAuthorizationRequest, OpenId4VciResolvedCredentialOffer } from '@credo-ts/openid4vc'

import { DifPresentationExchangeService } from '@credo-ts/core'
import console, { clear } from 'console'
import { textSync } from 'figlet'
import { prompt } from 'inquirer'

import { BaseInquirer, ConfirmOptions } from './BaseInquirer'
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
  RequestCredential = 'Accept the credential offer.',
  ResolveProofRequest = 'Resolve a proof request.',
  AcceptPresentationRequest = 'Accept the presentation request.',
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
    const promptOptions = [PromptOptions.ResolveCredentialOffer, PromptOptions.ResolveProofRequest]

    if (this.resolvedCredentialOffer) promptOptions.push(PromptOptions.RequestCredential)
    if (this.resolvedPresentationRequest) promptOptions.push(PromptOptions.AcceptPresentationRequest)

    return prompt([this.inquireOptions(promptOptions.map((o) => o.valueOf()))])
  }

  public async processAnswer() {
    const choice = await this.getPromptChoice()

    switch (choice.options) {
      case PromptOptions.ResolveCredentialOffer:
        await this.resolveCredentialOffer()
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
    const confirm = await prompt([this.inquireConfirmation(title)])
    if (confirm.options === ConfirmOptions.No) {
      return false
    } else if (confirm.options === ConfirmOptions.Yes) {
      return true
    }
  }

  public async resolveCredentialOffer() {
    const credentialOffer = await prompt([this.inquireInput('Enter credential offer: ')])
    const resolvedCredentialOffer = await this.holder.resolveCredentialOffer(credentialOffer.input)
    this.resolvedCredentialOffer = resolvedCredentialOffer

    console.log(greenText(`Received credential offer for the following credentials.`))
    console.log(greenText(resolvedCredentialOffer.offeredCredentials.map((credential) => credential.id).join('\n')))
  }

  public async requestCredential() {
    if (!this.resolvedCredentialOffer) {
      throw new Error('No credential offer resolved yet.')
    }

    const credentialsThatCanBeRequested = this.resolvedCredentialOffer.offeredCredentials.map(
      (credential) => credential.id
    )

    const choice = await prompt([this.inquireOptions(credentialsThatCanBeRequested)])

    const credentialToRequest = this.resolvedCredentialOffer.offeredCredentials.find(
      (credential) => credential.id === choice.options
    )
    if (!credentialToRequest) throw new Error('Credential to request not found.')

    console.log(greenText(`Requesting the following credential '${credentialToRequest.id}'`))

    const credentials = await this.holder.requestAndStoreCredentials(
      this.resolvedCredentialOffer,
      this.resolvedCredentialOffer.offeredCredentials.map((o) => o.id)
    )

    console.log(greenText(`Received and stored the following credentials.`))
    console.log('')
    credentials.forEach(this.printCredential)
  }

  public async resolveProofRequest() {
    const proofRequestUri = await prompt([this.inquireInput('Enter proof request: ')])
    this.resolvedPresentationRequest = await this.holder.resolveProofRequest(proofRequestUri.input)

    const presentationDefinition = this.resolvedPresentationRequest?.presentationExchange?.definition
    console.log(greenText(`Presentation Purpose: '${presentationDefinition?.purpose}'`))

    if (this.resolvedPresentationRequest?.presentationExchange?.credentialsForRequest.areRequirementsSatisfied) {
      const selectedCredentials = Object.values(
        this.holder.agent.dependencyManager
          .resolve(DifPresentationExchangeService)
          .selectCredentialsForRequest(this.resolvedPresentationRequest.presentationExchange.credentialsForRequest)
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
  }

  public async exit() {
    const confirm = await prompt([this.inquireConfirmation(Title.ConfirmTitle)])
    if (confirm.options === ConfirmOptions.No) {
      return
    } else if (confirm.options === ConfirmOptions.Yes) {
      await this.holder.exit()
    }
  }

  public async restart() {
    const confirm = await prompt([this.inquireConfirmation(Title.ConfirmTitle)])
    if (confirm.options === ConfirmOptions.No) {
      await this.processAnswer()
      return
    } else if (confirm.options === ConfirmOptions.Yes) {
      await this.holder.restart()
      await runHolder()
    }
  }

  private printCredential = (credential: W3cCredentialRecord | SdJwtVcRecord) => {
    if (credential.type === 'W3cCredentialRecord') {
      console.log(greenText(`W3cCredentialRecord with claim format ${credential.credential.claimFormat}`, true))
      console.log(JSON.stringify(credential.credential.jsonCredential, null, 2))
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
