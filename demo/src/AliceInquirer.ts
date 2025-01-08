import type { CredentialExchangeRecord, ProofExchangeRecord } from '@credo-ts/didcomm'

import { clear } from 'console'
import { textSync } from 'figlet'
import { prompt } from 'inquirer'

import { Alice } from './Alice'
import { BaseInquirer, ConfirmOptions } from './BaseInquirer'
import { Listener } from './Listener'
import { Title } from './OutputClass'

export const runAlice = async () => {
  clear()
  console.log(textSync('Alice', { horizontalLayout: 'full' }))
  const alice = await AliceInquirer.build()
  await alice.processAnswer()
}

enum PromptOptions {
  ReceiveConnectionUrl = 'Receive connection invitation',
  SendMessage = 'Send message',
  Exit = 'Exit',
  Restart = 'Restart',
}

export class AliceInquirer extends BaseInquirer {
  public alice: Alice
  public promptOptionsString: string[]
  public listener: Listener

  public constructor(alice: Alice) {
    super()
    this.alice = alice
    this.listener = new Listener()
    this.promptOptionsString = Object.values(PromptOptions)
    this.listener.messageListener(this.alice.agent, this.alice.name)
  }

  public static async build(): Promise<AliceInquirer> {
    const alice = await Alice.build()
    return new AliceInquirer(alice)
  }

  private async getPromptChoice() {
    if (this.alice.connectionRecordFaberId) return prompt([this.inquireOptions(this.promptOptionsString)])

    const reducedOption = [PromptOptions.ReceiveConnectionUrl, PromptOptions.Exit, PromptOptions.Restart]
    return prompt([this.inquireOptions(reducedOption)])
  }

  public async processAnswer() {
    const choice = await this.getPromptChoice()
    if (this.listener.on) return

    switch (choice.options) {
      case PromptOptions.ReceiveConnectionUrl:
        await this.connection()
        break
      case PromptOptions.SendMessage:
        await this.message()
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

  public async acceptCredentialOffer(credentialRecord: CredentialExchangeRecord) {
    const confirm = await prompt([this.inquireConfirmation(Title.CredentialOfferTitle)])
    if (confirm.options === ConfirmOptions.No) {
      await this.alice.agent.modules.credentials.declineOffer(credentialRecord.id)
    } else if (confirm.options === ConfirmOptions.Yes) {
      await this.alice.acceptCredentialOffer(credentialRecord)
    }
  }

  public async acceptProofRequest(proofRecord: ProofExchangeRecord) {
    const confirm = await prompt([this.inquireConfirmation(Title.ProofRequestTitle)])
    if (confirm.options === ConfirmOptions.No) {
      await this.alice.agent.modules.proofs.declineRequest({ proofRecordId: proofRecord.id })
    } else if (confirm.options === ConfirmOptions.Yes) {
      await this.alice.acceptProofRequest(proofRecord)
    }
  }

  public async connection() {
    const title = Title.InvitationTitle
    const getUrl = await prompt([this.inquireInput(title)])
    await this.alice.acceptConnection(getUrl.input)
    if (!this.alice.connected) return

    this.listener.credentialOfferListener(this.alice, this)
    this.listener.proofRequestListener(this.alice, this)
  }

  public async message() {
    const message = await this.inquireMessage()
    if (!message) return

    await this.alice.sendMessage(message)
  }

  public async exit() {
    const confirm = await prompt([this.inquireConfirmation(Title.ConfirmTitle)])
    if (confirm.options === ConfirmOptions.No) {
      return
    } else if (confirm.options === ConfirmOptions.Yes) {
      await this.alice.exit()
    }
  }

  public async restart() {
    const confirm = await prompt([this.inquireConfirmation(Title.ConfirmTitle)])
    if (confirm.options === ConfirmOptions.No) {
      await this.processAnswer()
      return
    } else if (confirm.options === ConfirmOptions.Yes) {
      await this.alice.restart()
      await runAlice()
    }
  }
}

void runAlice()
