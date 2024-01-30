import type { RegisterCredentialDefinitionReturnStateFinished } from '@aries-framework/anoncreds'
import type {
  ConnectionRecord,
  ConnectionStateChangedEvent,
  CredentialStateChangedEvent,
  ProofStateChangedEvent,
} from '@aries-framework/core'
import type {
  IndyVdrRegisterSchemaOptions,
  IndyVdrRegisterCredentialDefinitionOptions,
} from '@aries-framework/indy-vdr'
import type BottomBar from 'inquirer/lib/ui/bottom-bar'

import {
  CredentialState,
  ConnectionEventTypes,
  CredentialEventTypes,
  KeyType,
  TypedArrayEncoder,
  W3cCredential,
  W3cCredentialSubject,
  utils,
  ProofEventTypes,
  ProofState,
} from '@aries-framework/core'
import { randomInt } from 'crypto'
import { ui } from 'inquirer'

import { BaseAgent, indyNetworkConfig } from './BaseAgent'
import { Color, Output, greenText, purpleText, redText } from './OutputClass'

export enum RegistryOptions {
  indy = 'did:indy',
  cheqd = 'did:cheqd',
}

export class Faber extends BaseAgent {
  public outOfBandId?: string
  public credentialDefinition?: RegisterCredentialDefinitionReturnStateFinished
  public anonCredsIssuerId!: string
  public ui: BottomBar

  public constructor(port: number, name: string) {
    super({ port, name, useLegacyIndySdk: true })
    this.ui = new ui.BottomBar()
  }

  public static async build(): Promise<Faber> {
    const faber = new Faber(9001, 'faber' + randomInt(10000))
    await faber.initializeAgent()

    return faber
  }

  public async importDid(registry: string) {
    // NOTE: we assume the did is already registered on the ledger, we just store the private key in the wallet
    // and store the existing did in the wallet
    // indy did is based on private key (seed)
    const unqualifiedIndyDid = '2jEvRuKmfBJTRa7QowDpNN'
    const cheqdDid = 'did:cheqd:testnet:d37eba59-513d-42d3-8f9f-d1df0548b675'
    const indyDid = `did:indy:${indyNetworkConfig.indyNamespace}:${unqualifiedIndyDid}`

    const did = registry === RegistryOptions.indy ? indyDid : cheqdDid
    await this.agent.dids.import({
      did,
      overwrite: true,
      privateKeys: [
        {
          keyType: KeyType.Ed25519,
          privateKey: TypedArrayEncoder.fromString('afjdemoverysercure00000000000000'),
        },
      ],
    })
    this.anonCredsIssuerId = did
  }

  private async getConnectionRecord() {
    if (!this.outOfBandId) {
      throw Error(redText(Output.MissingConnectionRecord))
    }

    const [connection] = await this.agent.connections.findAllByOutOfBandId(this.outOfBandId)

    if (!connection) {
      throw Error(redText(Output.MissingConnectionRecord))
    }

    return connection
  }

  private async printConnectionInvite() {
    const outOfBand = await this.agent.oob.createInvitation()
    this.outOfBandId = outOfBand.id

    console.log(
      Output.ConnectionLink,
      outOfBand.outOfBandInvitation.toUrl({ domain: `http://localhost:${this.port}` }),
      '\n'
    )
  }

  private async waitForConnection() {
    if (!this.outOfBandId) {
      throw new Error(redText(Output.MissingConnectionRecord))
    }

    console.log('Waiting for Alice to finish connection...')

    const getConnectionRecord = (outOfBandId: string) =>
      new Promise<ConnectionRecord>((resolve, reject) => {
        // Timeout of 20 seconds
        const timeoutId = setTimeout(() => reject(new Error(redText(Output.MissingConnectionRecord))), 20000)

        // Start listener
        this.agent.events.on<ConnectionStateChangedEvent>(ConnectionEventTypes.ConnectionStateChanged, (e) => {
          if (e.payload.connectionRecord.outOfBandId !== outOfBandId) return

          clearTimeout(timeoutId)
          resolve(e.payload.connectionRecord)
        })

        // Also retrieve the connection record by invitation if the event has already fired
        void this.agent.connections.findAllByOutOfBandId(outOfBandId).then(([connectionRecord]) => {
          if (connectionRecord) {
            clearTimeout(timeoutId)
            resolve(connectionRecord)
          }
        })
      })

    const connectionRecord = await getConnectionRecord(this.outOfBandId)

    try {
      await this.agent.connections.returnWhenIsConnected(connectionRecord.id)
    } catch (e) {
      console.log(redText(`\nTimeout of 20 seconds reached.. Returning to home screen.\n`))
      return
    }
    console.log(greenText(Output.ConnectionEstablished))
  }

  public async setupConnection() {
    await this.printConnectionInvite()
    await this.waitForConnection()
  }

  private printSchema(name: string, version: string, attributes: string[]) {
    console.log(`\n\nThe credential definition will look like this:\n`)
    console.log(purpleText(`Name: ${Color.Reset}${name}`))
    console.log(purpleText(`Version: ${Color.Reset}${version}`))
    console.log(
      purpleText(`Attributes: ${Color.Reset}${attributes[0]}, ${attributes[1]}, ${attributes[2]}, ${attributes[3]}\n`)
    )
  }

  private async registerSchema() {
    if (!this.anonCredsIssuerId) {
      throw new Error(redText('Missing anoncreds issuerId'))
    }
    const schemaTemplate = {
      name: 'Faber College' + utils.uuid(),
      version: '1.0.0',
      attrNames: ['id', 'name', 'height', 'age'],
      issuerId: this.anonCredsIssuerId,
    }
    this.printSchema(schemaTemplate.name, schemaTemplate.version, schemaTemplate.attrNames)
    this.ui.updateBottomBar(greenText('\nRegistering schema...\n', false))

    const { schemaState } = await this.agent.modules.anoncreds.registerSchema<IndyVdrRegisterSchemaOptions>({
      schema: schemaTemplate,
      options: {
        endorserMode: 'internal',
        endorserDid: this.anonCredsIssuerId,
      },
    })

    if (schemaState.state !== 'finished') {
      throw new Error(
        `Error registering schema: ${schemaState.state === 'failed' ? schemaState.reason : 'Not Finished'}`
      )
    }
    this.ui.updateBottomBar('\nSchema registered!\n')
    return schemaState
  }

  private async registerCredentialDefinition(schemaId: string) {
    if (!this.anonCredsIssuerId) {
      throw new Error(redText('Missing anoncreds issuerId'))
    }

    this.ui.updateBottomBar('\nRegistering credential definition...\n')
    const { credentialDefinitionState } =
      await this.agent.modules.anoncreds.registerCredentialDefinition<IndyVdrRegisterCredentialDefinitionOptions>({
        credentialDefinition: {
          schemaId,
          issuerId: this.anonCredsIssuerId,
          tag: 'latest',
        },
        options: {
          supportRevocation: false,
          endorserMode: 'internal',
          endorserDid: this.anonCredsIssuerId,
        },
      })

    if (credentialDefinitionState.state !== 'finished') {
      throw new Error(
        `Error registering credential definition: ${
          credentialDefinitionState.state === 'failed' ? credentialDefinitionState.reason : 'Not Finished'
        }}`
      )
    }

    this.credentialDefinition = credentialDefinitionState
    this.ui.updateBottomBar('\nCredential definition registered!!\n')
    return this.credentialDefinition
  }

  public async issueCredential() {
    const schema = await this.registerSchema()
    const credentialDefinition = await this.registerCredentialDefinition(schema.schemaId)
    const connectionRecord = await this.getConnectionRecord()

    this.ui.updateBottomBar('\nSending credential offer...\n')

    await this.agent.credentials.offerCredential({
      connectionId: connectionRecord.id,
      protocolVersion: 'v2',
      credentialFormats: {
        dataIntegrity: {
          bindingRequired: true,
          anonCredsLinkSecretBindingMethodOptions: {
            credentialDefinitionId: credentialDefinition.credentialDefinitionId,
          },
          credential: new W3cCredential({
            type: ['VerifiableCredential'],
            issuanceDate: new Date().toISOString(),
            issuer: this.anonCredsIssuerId as string,
            credentialSubject: new W3cCredentialSubject({
              claims: {
                name: 'Alice Smith',
                age: 28,
                height: 173,
              },
            }),
          }),
        },
      },
    })
    this.ui.updateBottomBar(
      `\nCredential offer sent!\n\nGo to the Alice agent to accept the credential offer\n\n${Color.Reset}`
    )

    this.agent.events.on<CredentialStateChangedEvent>(CredentialEventTypes.CredentialStateChanged, async (afjEvent) => {
      const credentialRecord = afjEvent.payload.credentialRecord
      if (afjEvent.payload.credentialRecord.state !== CredentialState.RequestReceived) return

      console.log(`\nAccepting Credential Request. Sending Credential!\n\n`)

      await this.agent.credentials.acceptRequest({
        credentialRecordId: credentialRecord.id,
        credentialFormats: {
          dataIntegrity: {
            credentialSubjectId: 'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
            didCommSignedAttachmentAcceptRequestOptions: {
              kid: 'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9#z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
            },
          },
        },
      })
    })
  }

  private async printProofFlow(print: string) {
    this.ui.updateBottomBar(print)
    await new Promise((f) => setTimeout(f, 2000))
  }

  public async sendProofRequest() {
    const connectionRecord = await this.getConnectionRecord()
    await this.printProofFlow(greenText('\nRequesting proof...\n', false))

    await this.agent.proofs.requestProof({
      protocolVersion: 'v2',
      connectionId: connectionRecord.id,
      proofFormats: {
        presentationExchange: {
          presentationDefinition: {
            id: '1234567',
            name: 'Age Verification',
            purpose: 'We need to verify your age before entering a bar',
            input_descriptors: [
              {
                id: 'age-verification',
                name: 'A specific type of VC + Issuer',
                purpose: 'We want a VC of this type generated by this issuer',
                schema: [
                  {
                    uri: 'https://www.w3.org/2018/credentials/v1',
                  },
                ],
                constraints: {
                  limit_disclosure: 'required',
                  fields: [
                    {
                      path: ['$.issuer'],
                      filter: {
                        type: 'string',
                        const: 'did:cheqd:testnet:d37eba59-513d-42d3-8f9f-d1df0548b675',
                      },
                    },
                    {
                      path: ['$.credentialSubject.name'],
                    },
                    {
                      path: ['$.credentialSubject.height'],
                    },
                    {
                      path: ['$.credentialSubject.age'],
                      predicate: 'preferred',
                      filter: {
                        type: 'number',
                        minimum: 18,
                      },
                    },
                  ],
                },
              },
            ],
            format: {
              di_vc: {
                proof_type: ['DataIntegrityProof'],
                cryptosuite: ['anoncredsvc-2023', 'eddsa-rdfc-2022'],
              },
            },
          },
        },
      },
    })
    this.ui.updateBottomBar(
      `\nProof request sent!\n\nGo to the Alice agent to accept the proof request\n\n${Color.Reset}`
    )

    this.agent.events.on<ProofStateChangedEvent>(ProofEventTypes.ProofStateChanged, async (afjEvent) => {
      if (afjEvent.payload.proofRecord.state !== ProofState.PresentationReceived) return

      const proofRecord = afjEvent.payload.proofRecord

      console.log(`\nAccepting Presentation!\n\n${Color.Reset}`)
      await this.agent.proofs.acceptPresentation({
        proofRecordId: proofRecord.id,
      })
    })
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
