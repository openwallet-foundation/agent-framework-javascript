/*eslint import/no-cycle: [2, { maxDepth: 1 }]*/
import type { CredentialExchangeRecord, ProofRecord } from '@aries-framework/core'

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
      throw Error(redText(Output.MissingConnectionRecord))
    }
    return await this.agent.connections.getById(this.connectionRecordFaberId)
  }

  private async printConnectionInvite() {
    const outOfBand = await this.agent.oob.createInvitation()
    // FIXME: this won't work as oob doesn't create a connection immediately
    const [connectionRecord] = await this.agent.connections.findAllByOutOfBandId(outOfBand.id)
    if (!connectionRecord) {
      throw new Error(redText(Output.NoConnectionRecordFromOutOfBand))
    }
    this.connectionRecordFaberId = connectionRecord.id

    console.log(
      Output.ConnectionLink,
      outOfBand.outOfBandInvitation.toUrl({ domain: `http://localhost:${this.port}` }),
      '\n'
    )
    return connectionRecord
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
    console.log(greenText(Output.ConnectionEstablished))
    this.connected = true
  }

  public async setupConnection() {
    await this.printConnectionInvite()
    await this.waitForConnection()
  }

  public async acceptCredentialOffer(credentialRecord: CredentialExchangeRecord) {
    await this.agent.credentials.acceptOffer({
      credentialRecordId: credentialRecord.id,
    })
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
    console.log(Output.Exit)
    await this.agent.shutdown()
    process.exit(0)
  }

  public async restart() {
    await this.agent.shutdown()
  }
}
