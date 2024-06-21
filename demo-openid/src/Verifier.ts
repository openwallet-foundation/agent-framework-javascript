import type { DifPresentationExchangeDefinitionV2 } from '@credo-ts/core'
import type { OpenId4VcVerifierRecord } from '@credo-ts/openid4vc'

import { AskarModule } from '@credo-ts/askar'
import { OpenId4VcVerifierModule } from '@credo-ts/openid4vc'
import { ariesAskar } from '@hyperledger/aries-askar-nodejs'
import { Router } from 'express'

import { BaseAgent } from './BaseAgent'
import { Output } from './OutputClass'

const universityDegreePresentationDefinition = {
  id: 'UniversityDegreeCredential',
  purpose: 'Present your UniversityDegreeCredential to verify your education level.',
  input_descriptors: [
    {
      id: 'UniversityDegreeCredentialDescriptor',
      constraints: {
        fields: [
          {
            // Works for JSON-LD, SD-JWT and JWT
            path: ['$.vc.type.*', '$.vct', '$.type'],
            filter: {
              type: 'string',
              pattern: 'UniversityDegree',
            },
          },
        ],
      },
    },
  ],
}

const openBadgeCredentialPresentationDefinition = {
  id: 'OpenBadgeCredential',
  purpose: 'Provide proof of employment to confirm your employment status.',
  input_descriptors: [
    {
      id: 'OpenBadgeCredentialDescriptor',
      constraints: {
        fields: [
          {
            // Works for JSON-LD, SD-JWT and JWT
            path: ['$.vc.type.*', '$.vct', '$.type'],
            filter: {
              type: 'string',
              pattern: 'OpenBadgeCredential',
            },
          },
        ],
      },
    },
  ],
}

export const presentationDefinitions = [
  universityDegreePresentationDefinition,
  openBadgeCredentialPresentationDefinition,
]

export class Verifier extends BaseAgent<{ askar: AskarModule; openId4VcVerifier: OpenId4VcVerifierModule }> {
  public verifierRecord!: OpenId4VcVerifierRecord

  public constructor(port: number, name: string) {
    const openId4VcSiopRouter = Router()

    super({
      port,
      name,
      modules: {
        askar: new AskarModule({ ariesAskar }),
        openId4VcVerifier: new OpenId4VcVerifierModule({
          baseUrl: 'http://localhost:4000/siop',
          router: openId4VcSiopRouter,
        }),
      },
    })

    this.app.use('/siop', openId4VcSiopRouter)
  }

  public static async build(): Promise<Verifier> {
    const verifier = new Verifier(4000, 'OpenId4VcVerifier ' + Math.random().toString())
    await verifier.initializeAgent('96213c3d7fc8d4d6754c7a0fd969598g')
    verifier.verifierRecord = await verifier.agent.modules.openId4VcVerifier.createVerifier()

    return verifier
  }

  // TODO: add method to show the received presentation submission
  public async createProofRequest(presentationDefinition: DifPresentationExchangeDefinitionV2) {
    const { authorizationRequest } = await this.agent.modules.openId4VcVerifier.createAuthorizationRequest({
      requestSigner: {
        method: 'did',
        didUrl: this.verificationMethod.id,
      },
      verifierId: this.verifierRecord.verifierId,
      presentationExchange: {
        definition: presentationDefinition,
      },
    })

    return authorizationRequest
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
