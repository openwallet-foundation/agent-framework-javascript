/*eslint import/no-cycle: [2, { maxDepth: 1 }]*/
import type { CredentialRecord, ProofRecord } from '@aries-framework/core'

import { BaseAgent } from './BaseAgent'
import { greenText, Output, redText } from './OutputClass'

export class Alice extends BaseAgent {
  public connectionRecordFaberId?: string
  public connected: boolean

  public constructor(port: number, name: string) {
    super(port, name)
    this.connected = false
  }

  public static async build(): Promise<Alice> {
    const alice = new Alice(9000, 'alice')
    await alice.initializeAgent()
    return alice
  }

  private async getConnectionRecord() {
    if (!this.connectionRecordFaberId) {
      throw Error(redText(Output.missingConnectionRecord))
    }
    return await this.agent.connections.getById(this.connectionRecordFaberId)
  }

  private async printConnectionInvite() {
    const invite = await this.agent.connections.createConnection()
    this.connectionRecordFaberId = invite.connectionRecord.id

    console.log(Output.connectionLink, invite.invitation.toUrl({ domain: `http://localhost:${this.port}` }), '\n')
    return invite.connectionRecord
  }

  private async waitForConnection() {
    const connectionRecord = await this.getConnectionRecord()

    console.log('Waiting for Faber to finish connection...')
    try {
      await this.agent.connections.returnWhenIsConnected(connectionRecord.id)
    } catch (e) {
      console.log(redText(`\nTimeout of 20 seconds reached.. Returning to home screen.\n`))
      return
    }
    console.log(greenText(Output.connectionEstablished))
    this.connected = true
  }

  public async setupConnection() {
    await this.printConnectionInvite()
    await this.waitForConnection()
  }

  public async acceptCredentialOffer(credentialRecord: CredentialRecord) {
    await this.agent.credentials.acceptOffer(credentialRecord.id)
    console.log(greenText('\nCredential offer accepted!\n'))
  }

  public async acceptProofRequest(proofRecord: ProofRecord) {
    const retrievedCredentials = await this.agent.proofs.getRequestedCredentialsForProofRequest(proofRecord.id, {
      filterByPresentationPreview: true,
    })
    const requestedCredentials = this.agent.proofs.autoSelectCredentialsForProofRequest(retrievedCredentials)
    await this.agent.proofs.acceptRequest(proofRecord.id, requestedCredentials)
    console.log(greenText('\nProof request accepted!\n'))
  }

  public async sendMessage(message: string) {
    const connectionRecord = await this.getConnectionRecord()
    await this.agent.basicMessages.sendMessage(connectionRecord.id, message)
  }

  public async exit() {
    console.log(Output.exit)
    await this.agent.shutdown()
    process.exit()
  }

  public async restart() {
    await this.agent.shutdown()
  }
}
