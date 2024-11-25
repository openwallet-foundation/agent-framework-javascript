import { clear } from 'console'
import { textSync } from 'figlet'

import { BaseInquirer } from './BaseInquirer'
import { Title, purpleText } from './OutputClass'
import { Verifier, dcqls, presentationDefinitions } from './Verifier'

export const runVerifier = async () => {
  clear()
  console.log(textSync('Verifier', { horizontalLayout: 'full' }))
  const verifier = await VerifierInquirer.build()
  await verifier.processAnswer()
}

enum PromptOptions {
  CreateProofOffer = 'Request the presentation of a credential.',
  Exit = 'Exit',
  Restart = 'Restart',
}

export class VerifierInquirer extends BaseInquirer {
  public verifier: Verifier

  public constructor(verifier: Verifier) {
    super()
    this.verifier = verifier
  }

  public static async build(): Promise<VerifierInquirer> {
    const verifier = await Verifier.build()
    return new VerifierInquirer(verifier)
  }

  public async processAnswer() {
    const choice = await this.pickOne(Object.values(PromptOptions))

    switch (choice) {
      case PromptOptions.CreateProofOffer:
        await this.createProofRequest()
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

  public async createProofRequest() {
    const presentationDefinitionId = await this.pickOne([
      ...presentationDefinitions.map((p) => p.id),
      ...dcqls.map((d) => d.id),
    ])
    const presentationDefinition = presentationDefinitions.find((p) => p.id === presentationDefinitionId)
    const dcql = dcqls.find((dcql) => dcql.id === presentationDefinitionId)?.dcql
    if (!presentationDefinition && !dcql) throw new Error('No presentation definition found')

    const proofRequest = await this.verifier.createProofRequest({ presentationDefinition, dcql })

    console.log(purpleText(`Proof request for the presentation of an ${presentationDefinitionId}.\n'${proofRequest}'`))
  }

  public async exit() {
    if (await this.inquireConfirmation(Title.ConfirmTitle)) {
      await this.verifier.exit()
    }
  }

  public async restart() {
    const confirmed = await this.inquireConfirmation(Title.ConfirmTitle)
    if (confirmed) {
      await this.verifier.restart()
      await runVerifier()
    } else {
      await this.processAnswer()
    }
  }
}

void runVerifier()
