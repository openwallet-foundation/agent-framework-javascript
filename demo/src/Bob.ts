/*eslint import/no-cycle: [2, { maxDepth: 1 }]*/
import type { ValueTransferRecord } from '@aries-framework/core'

import { DidMarker, Transports, ValueTransferState } from '@aries-framework/core'

import { BaseAgent } from './BaseAgent'
import { greenText, Output, redText } from './OutputClass'

export class Bob extends BaseAgent {
  public valueTransferRecordId?: string

  public constructor(name: string, port?: number) {
    super({
      name,
      port,
      transports: [Transports.NFC, Transports.HTTP],
      mediatorConnectionsInvite: BaseAgent.defaultMediatorConnectionInvite,
      staticDids: [
        {
          seed: '6b8b882e2618fa5d45ee7229ca880081',
          transports: [Transports.NFC],
          marker: DidMarker.Offline,
        },
        {
          seed: '6b8b882e2618fa5d45ee7229ca880082',
          transports: [Transports.NFC, Transports.HTTP],
          marker: DidMarker.Online,
        },
      ],
      valueTransferConfig: {
        party: {
          witnessDid:
            'did:peer:2.Ez6LSmBWXTiZQVVx37zwoZK3MvEebphDwd81AmBryFxyYg2dS.Vz6MkhuEV8mevESoVDVVtnznFfc6MHGwSwhwqM9FSooVntCEu.SeyJzIjoiaHR0cDovLzE5Mi4xNjguMS4xNDU6MzAwMC9hcGkvdjEiLCJ0IjoiZG0iLCJyIjpbImRpZDpwZWVyOjIuRXo2TFNuSFM5ZjNock11THJOOXo2WmhvN1RjQlJ2U3lLN0hQalF0d0ttdTNvc1d3Ri5WejZNa3JhaEFvVkxRUzlTNUdGNXNVS3R1ZFhNZWRVU1pkZGVKaGpIdEFGYVY0aG9WLlNXM3NpY3lJNkltaDBkSEE2THk4eE9USXVNVFk0TGpFdU1UUTFPak13TURBdllYQnBMM1l4SWl3aWRDSTZJbVJ0SWl3aWNpSTZXMTBzSW1FaU9sc2laR2xrWTI5dGJTOTJNaUpkZlN4N0luTWlPaUozY3pvdkx6RTVNaTR4TmpndU1TNHhORFU2TXpBd01DOWhjR2t2ZGpFaUxDSjBJam9pWkcwaUxDSnlJanBiWFN3aVlTSTZXeUprYVdSamIyMXRMM1l5SWwxOVhRIl0sImEiOlsiZGlkY29tbS92MiJdfQ',
        },
      },
    })
  }

  public static async build(): Promise<Bob> {
    const getter = new Bob('bob', undefined)
    await getter.initializeAgent()
    const publicDid = await getter.agent.getOnlinePublicDid()
    console.log(`Bob Public DID: ${publicDid?.did}`)
    return getter
  }

  private async getValueTransferRecord() {
    if (!this.valueTransferRecordId) {
      throw Error(redText(Output.MissingValueTransferRecord))
    }
    return await this.agent.valueTransfer.getById(this.valueTransferRecordId)
  }

  public async requestPayment(giver: string) {
    const { record } = await this.agent.valueTransfer.requestPayment({
      amount: 1,
      giver,
      transport: Transports.NFC,
    })
    this.valueTransferRecordId = record.id
    console.log(greenText('\nRequest Sent!\n'))
    await this.waitForPayment()
  }

  public async acceptPaymentOffer(valueTransferRecord: ValueTransferRecord, witness: string) {
    const { record } = await this.agent.valueTransfer.acceptPaymentOffer({
      recordId: valueTransferRecord.id,
      witness,
    })
    this.valueTransferRecordId = record.id
    console.log(greenText('\nPayment offer accepted!\n'))
    await this.waitForPayment()
  }

  public async abortPaymentOffer(valueTransferRecord: ValueTransferRecord) {
    const { record } = await this.agent.valueTransfer.abortTransaction(valueTransferRecord.id)
    this.valueTransferRecordId = record.id
    console.log(redText('\nPayment request rejected!\n'))
    console.log(record.problemReportMessage)
  }

  private async waitForPayment() {
    const valueTransferRecord = await this.getValueTransferRecord()

    console.log('Waiting for Giver to pay...')
    try {
      const record = await this.agent.valueTransfer.returnWhenIsCompleted(valueTransferRecord.id)
      if (record.state === ValueTransferState.Completed) {
        console.log(greenText(Output.PaymentDone))
        console.log(greenText('Receipt:'))
        console.log(record.receipt)
        const balance = await this.agent.valueTransfer.getBalance()
        console.log(greenText('Balance: ' + balance))
      }
      if (record.state === ValueTransferState.Failed) {
        console.log(redText('Payment Failed:'))
        console.log(record.problemReportMessage)
      }
    } catch (e) {
      console.log(redText(`\nTimeout of 120 seconds reached.. Returning to home screen.\n`))
      return
    }
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
