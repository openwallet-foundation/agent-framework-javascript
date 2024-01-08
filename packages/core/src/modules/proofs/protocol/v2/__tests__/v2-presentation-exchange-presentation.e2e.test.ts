import type { getJsonLdModules } from '../../../../../../tests'
import type { Agent } from '../../../../../agent/Agent'
import type { ProofExchangeRecord } from '../../../repository/ProofExchangeRecord'

import { waitForCredentialRecord, setupJsonLdTests, waitForProofExchangeRecord } from '../../../../../../tests'
import testLogger from '../../../../../../tests/logger'
import { KeyType } from '../../../../../crypto'
import { DidCommMessageRepository } from '../../../../../storage'
import { TypedArrayEncoder } from '../../../../../utils'
import { AutoAcceptCredential, CredentialState } from '../../../../credentials'
import { CREDENTIALS_CONTEXT_V1_URL } from '../../../../vc'
import { ProofState } from '../../../models/ProofState'
import { V2PresentationMessage, V2RequestPresentationMessage } from '../messages'
import { V2ProposePresentationMessage } from '../messages/V2ProposePresentationMessage'

import { TEST_INPUT_DESCRIPTORS_CITIZENSHIP } from './fixtures'

const jsonld = {
  credential: {
    '@context': [CREDENTIALS_CONTEXT_V1_URL, 'https://www.w3.org/2018/credentials/examples/v1'],
    type: ['VerifiableCredential', 'UniversityDegreeCredential'],
    issuer: 'did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL',
    issuanceDate: '2017-10-22T12:23:48Z',
    credentialSubject: {
      id: 'did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL',
      degree: {
        type: 'BachelorDegree',
        name: 'Bachelor of Science and Arts',
      },
    },
  },
  options: {
    proofType: 'Ed25519Signature2018',
    proofPurpose: 'assertionMethod',
  },
}

describe('Present Proof', () => {
  let proverAgent: Agent<ReturnType<typeof getJsonLdModules>>
  let issuerAgent: Agent<ReturnType<typeof getJsonLdModules>>
  let verifierAgent: Agent<ReturnType<typeof getJsonLdModules>>

  let issuerProverConnectionId: string
  let proverVerifierConnectionId: string

  let verifierProofExchangeRecord: ProofExchangeRecord
  let proverProofExchangeRecord: ProofExchangeRecord

  let didCommMessageRepository: DidCommMessageRepository

  beforeAll(async () => {
    testLogger.test('Initializing the agents')
    ;({
      holderAgent: proverAgent,
      issuerAgent,
      verifierAgent,
      issuerHolderConnectionId: issuerProverConnectionId,
      holderVerifierConnectionId: proverVerifierConnectionId,
    } = await setupJsonLdTests({
      holderName: 'presentation exchange prover agent',
      issuerName: 'presentation exchange issuer agent',
      verifierName: 'presentation exchange verifier agent',
      createConnections: true,
      autoAcceptCredentials: AutoAcceptCredential.Always,
    }))

    await issuerAgent.wallet.createKey({
      privateKey: TypedArrayEncoder.fromString('testseed000000000000000000000001'),
      keyType: KeyType.Ed25519,
    })

    await proverAgent.wallet.createKey({
      privateKey: TypedArrayEncoder.fromString('testseed000000000000000000000001'),
      keyType: KeyType.Ed25519,
    })

    await issuerAgent.credentials.offerCredential({
      connectionId: issuerProverConnectionId,
      protocolVersion: 'v2',
      credentialFormats: { jsonld },
    })

    await waitForCredentialRecord(proverAgent, { state: CredentialState.Done })
  })

  afterAll(async () => {
    testLogger.test('Shutting down both agents')
    await proverAgent.shutdown()
    await proverAgent.wallet.delete()
    await verifierAgent.shutdown()
    await verifierAgent.wallet.delete()
  })

  test(`Prover Creates and sends Proof Proposal to a Verifier`, async () => {
    testLogger.test('Prover sends proof proposal to a Verifier')

    const verifierPresentationRecordPromise = waitForProofExchangeRecord(verifierAgent, {
      state: ProofState.ProposalReceived,
    })

    proverProofExchangeRecord = await proverAgent.proofs.proposeProof({
      connectionId: proverVerifierConnectionId,
      protocolVersion: 'v2',
      proofFormats: {
        presentationExchange: {
          presentationDefinition: {
            id: 'e950bfe5-d7ec-4303-ad61-6983fb976ac9',
            input_descriptors: [TEST_INPUT_DESCRIPTORS_CITIZENSHIP],
          },
        },
      },
      comment: 'V2 Presentation Exchange propose proof test',
    })

    testLogger.test('Verifier waits for presentation from the Prover')
    verifierProofExchangeRecord = await verifierPresentationRecordPromise

    didCommMessageRepository = proverAgent.dependencyManager.resolve<DidCommMessageRepository>(DidCommMessageRepository)

    const proposal = await didCommMessageRepository.findAgentMessage(verifierAgent.context, {
      associatedRecordId: verifierProofExchangeRecord.id,
      messageClass: V2ProposePresentationMessage,
    })

    expect(proposal).toMatchObject({
      type: 'https://didcomm.org/present-proof/2.0/propose-presentation',
      formats: [
        {
          attachmentId: expect.any(String),
          format: 'dif/presentation-exchange/definitions@v1.0',
        },
      ],
      proposalAttachments: [
        {
          id: expect.any(String),
          mimeType: 'application/json',
          data: {
            json: {
              input_descriptors: expect.any(Array),
            },
          },
        },
      ],
      id: expect.any(String),
      comment: 'V2 Presentation Exchange propose proof test',
    })
    expect(verifierProofExchangeRecord.id).not.toBeNull()
    expect(verifierProofExchangeRecord).toMatchObject({
      threadId: verifierProofExchangeRecord.threadId,
      state: ProofState.ProposalReceived,
      protocolVersion: 'v2',
    })
  })

  test(`Verifier accepts the Proposal send by the Prover`, async () => {
    const proverPresentationRecordPromise = waitForProofExchangeRecord(proverAgent, {
      threadId: verifierProofExchangeRecord.threadId,
      state: ProofState.RequestReceived,
    })

    testLogger.test('Verifier accepts presentation proposal from the Prover')
    verifierProofExchangeRecord = await verifierAgent.proofs.acceptProposal({
      proofRecordId: verifierProofExchangeRecord.id,
    })

    testLogger.test('Prover waits for proof request from the Verifier')
    proverProofExchangeRecord = await proverPresentationRecordPromise

    didCommMessageRepository = proverAgent.dependencyManager.resolve<DidCommMessageRepository>(DidCommMessageRepository)

    const request = await didCommMessageRepository.findAgentMessage(proverAgent.context, {
      associatedRecordId: proverProofExchangeRecord.id,
      messageClass: V2RequestPresentationMessage,
    })

    expect(request).toMatchObject({
      type: 'https://didcomm.org/present-proof/2.0/request-presentation',
      id: expect.any(String),
      formats: [
        {
          attachmentId: expect.any(String),
          format: 'dif/presentation-exchange/definitions@v1.0',
        },
      ],
      requestAttachments: [
        {
          id: expect.any(String),
          mimeType: 'application/json',
          data: {
            json: {
              presentation_definition: {
                id: expect.any(String),
                input_descriptors: [
                  {
                    id: TEST_INPUT_DESCRIPTORS_CITIZENSHIP.id,
                    constraints: {
                      fields: TEST_INPUT_DESCRIPTORS_CITIZENSHIP.constraints.fields,
                    },
                  },
                ],
              },
            },
          },
        },
      ],
    })

    expect(proverProofExchangeRecord).toMatchObject({
      id: expect.any(String),
      threadId: verifierProofExchangeRecord.threadId,
      state: ProofState.RequestReceived,
      protocolVersion: 'v2',
    })
  })

  test(`Prover accepts presentation request from the Verifier`, async () => {
    // Prover retrieves the requested credentials and accepts the presentation request
    testLogger.test('Prover accepts presentation request from Verifier')

    const verifierPresentationRecordPromise = waitForProofExchangeRecord(verifierAgent, {
      threadId: verifierProofExchangeRecord.threadId,
      state: ProofState.PresentationReceived,
    })

    await proverAgent.proofs.acceptRequest({
      proofRecordId: proverProofExchangeRecord.id,
    })

    // Verifier waits for the presentation from the Prover
    testLogger.test('Verifier waits for presentation from the Prover')
    verifierProofExchangeRecord = await verifierPresentationRecordPromise

    const presentation = await didCommMessageRepository.findAgentMessage(verifierAgent.context, {
      associatedRecordId: verifierProofExchangeRecord.id,
      messageClass: V2PresentationMessage,
    })

    // {
    //    "@type":"https://didcomm.org/present-proof/2.0/presentation",
    //    "last_presentation":true,
    //    "formats":[
    //       {
    //          "attach_id":"97cf1dbf-2ce0-4641-9083-00f4aec99478",
    //          "format":"dif/presentation-exchange/submission@v1.0"
    //       }
    //    ],
    //    "presentations~attach":[
    //       {
    //          "@id":"97cf1dbf-2ce0-4641-9083-00f4aec99478",
    //          "mime-type":"application/json",
    //          "data":{
    //             "json":{
    //                "presentation_submission":{
    //                   "id":"dHOs_n7UF7QAbJvEovHeW",
    //                   "definition_id":"e950bfe5-d7ec-4303-ad61-6983fb976ac9",
    //                   "descriptor_map":[
    //                      {
    //                         "id":"citizenship_input_1",
    //                         "format":"ldp_vp",
    //                         "path":"$",
    //                         "path_nested":{
    //                            "id":"citizenship_input_1",
    //                            "format":"ldp_vc ",
    //                            "path":"$.verifiableCredential[0]"
    //                         }
    //                      }
    //                   ]
    //                },
    //                "context":[
    //                   "https://www.w3.org/2018/credentials/v1"
    //                ],
    //                "type":[
    //                   "VerifiableP resentation"
    //                ],
    //                "holder":"did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
    //                "verifiableCredential":[
    //                   {
    //                      "@context":[
    //                         "https://www.w3.org/2018/credentials/v1",
    //                         "https://www.w3.org/2018/credentials/examples/v1"
    //                      ],
    //                      "type":[
    //                         "Verifiab leCredential",
    //                         "UniversityDegreeCredential"
    //                      ],
    //                      "issuer":"did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
    //                      "issuanceDate":"2017-10-22T12:23:48Z",
    //                      "credentialSubject":{
    //                         "id":"did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38Eef XmgDL",
    //                         "degree":{
    //                            "type":"BachelorDegree",
    //                            "name":"Bachelor of Science and Arts"
    //                         }
    //                      },
    //                      "proof":{
    //                         "verificationMethod":"di d:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
    //                         "type":"E d25519Signature2018",
    //                         "created":"2023-12-19T12:38:36Z",
    //                         "proofPurpose":"assertionMethod",
    //                         "jws":"eyJhbGciOiJFZERTQSIs ImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..U3oPjRgz-fTd_kkUtNgWKh-FRWWkKdy0iSgOiGA1d7IyImuL1URQwJjd3UlJAkFf1kl7NeakiCtZ cFfxkPpECQ"
    //                      }
    //                   }
    //                ],
    //                "proof":{
    //                   "verificationMethod":"did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Yc puk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
    //                   "type":"Ed25519Signature2018",
    //                   "created":"2023-12-19T12:38:37Z",
    //                   "proofPurpos e":"authentication",
    //                   "challenge":"273899451763000636595367",
    //                   "jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsi YjY0Il19..X_pR5Evhj-byuMkhJfXfoj9HO03iLKtltq64A4cueuLAH-Ix5D-G9g7r4xec9ysyga8GS2tZQl0OK4W9LJcOAQ"
    //                }
    //             }
    //          }
    //       }
    //    ],
    //    "@id":"2cdf aa16-d132-4778-9d6f-622fc0e0fa84",
    //    "~thread":{
    //       "thid":"e03cfab3-7ab1-477f-9df7-dc7ede70b952"
    //    },
    //    "~please_ack":{
    //       "on":[
    //          " RECEIPT"
    //       ]
    //    }
    // }

    expect(presentation).toMatchObject({
      type: 'https://didcomm.org/present-proof/2.0/presentation',
      formats: [
        {
          attachmentId: expect.any(String),
          format: 'dif/presentation-exchange/submission@v1.0',
        },
      ],
      presentationAttachments: [
        {
          id: expect.any(String),
          mimeType: 'application/json',
          data: {
            json: {
              '@context': expect.any(Array),
              type: expect.any(Array),
              presentation_submission: {
                id: expect.any(String),
                definition_id: expect.any(String),
                descriptor_map: [
                  {
                    id: 'citizenship_input_1',
                    format: 'ldp_vc',
                    path: '$.verifiableCredential[0]',
                  },
                ],
              },
              verifiableCredential: [
                {
                  '@context': [
                    'https://www.w3.org/2018/credentials/v1',
                    'https://www.w3.org/2018/credentials/examples/v1',
                  ],
                  type: ['VerifiableCredential', 'UniversityDegreeCredential'],
                  issuer: expect.any(String),
                  issuanceDate: expect.any(String),
                  credentialSubject: {
                    id: expect.any(String),
                    degree: {
                      type: 'BachelorDegree',
                      name: 'Bachelor of Science and Arts',
                    },
                  },
                  proof: {
                    verificationMethod: expect.any(String),
                    type: 'Ed25519Signature2018',
                    created: expect.any(String),
                    proofPurpose: 'assertionMethod',
                    jws: expect.any(String),
                  },
                },
              ],
              proof: {
                verificationMethod: expect.any(String),
                type: 'Ed25519Signature2018',
                created: expect.any(String),
                proofPurpose: 'authentication',
                challenge: expect.any(String),
                jws: expect.any(String),
              },
            },
          },
        },
      ],
      id: expect.any(String),
      thread: {
        threadId: verifierProofExchangeRecord.threadId,
      },
    })

    expect(verifierProofExchangeRecord.id).not.toBeNull()
    expect(verifierProofExchangeRecord).toMatchObject({
      threadId: verifierProofExchangeRecord.threadId,
      state: ProofState.PresentationReceived,
      protocolVersion: 'v2',
    })
  })

  test(`Verifier accepts the presentation provided by the Prover`, async () => {
    const proverProofExchangeRecordPromise = waitForProofExchangeRecord(proverAgent, {
      threadId: proverProofExchangeRecord.threadId,
      state: ProofState.Done,
    })

    // Verifier accepts the presentation provided by by the Prover
    testLogger.test('Verifier accepts the presentation provided by the Prover')
    await verifierAgent.proofs.acceptPresentation({ proofRecordId: verifierProofExchangeRecord.id })

    // Prover waits until she received a presentation acknowledgement
    testLogger.test('Prover waits until she receives a presentation acknowledgement')
    proverProofExchangeRecord = await proverProofExchangeRecordPromise

    expect(verifierProofExchangeRecord).toMatchObject({
      id: expect.any(String),
      createdAt: expect.any(Date),
      threadId: proverProofExchangeRecord.threadId,
      connectionId: expect.any(String),
      isVerified: true,
      state: ProofState.PresentationReceived,
    })

    expect(proverProofExchangeRecord).toMatchObject({
      id: expect.any(String),
      createdAt: expect.any(Date),
      threadId: verifierProofExchangeRecord.threadId,
      connectionId: expect.any(String),
      state: ProofState.Done,
    })
  })
})
