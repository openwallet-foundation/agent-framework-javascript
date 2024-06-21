import type { AnonCredsTestsAgent } from './anoncredsSetup'
import type { EventReplaySubject } from '../../core/tests'
import type { AnonCredsRequestProofFormat } from '@credo-ts/anoncreds'
import type { CredentialExchangeRecord } from '@credo-ts/core'

import {
  Attachment,
  AttachmentData,
  LinkedAttachment,
  ProofState,
  ProofExchangeRecord,
  V2ProposePresentationMessage,
  V2RequestPresentationMessage,
  V2PresentationMessage,
} from '@credo-ts/core'

import { sleep } from '../../core/src/utils/sleep'
import { waitForProofExchangeRecord } from '../../core/tests'
import testLogger from '../../core/tests/logger'
import { dateToTimestamp } from '../src/utils/timestamp'

import { InMemoryAnonCredsRegistry } from './InMemoryAnonCredsRegistry'
import { issueAnonCredsCredential, setupAnonCredsTests } from './anoncredsSetup'

describe('PP V2 AnonCreds Proofs', () => {
  let faberAgent: AnonCredsTestsAgent
  let faberReplay: EventReplaySubject
  let aliceAgent: AnonCredsTestsAgent
  let aliceReplay: EventReplaySubject
  let credentialDefinitionId: string
  let revocationRegistryDefinitionId: string | null
  let aliceConnectionId: string
  let faberConnectionId: string
  let faberProofExchangeRecord: ProofExchangeRecord
  let aliceProofExchangeRecord: ProofExchangeRecord
  let faberCredentialExchangeRecord: CredentialExchangeRecord

  const inMemoryRegistry = new InMemoryAnonCredsRegistry()

  const issuerId = 'did:indy:local:LjgpST2rjsoxYegQDRm7EL'

  beforeAll(async () => {
    testLogger.test('Initializing the agents')
    ;({
      issuerAgent: faberAgent,
      issuerReplay: faberReplay,

      holderAgent: aliceAgent,
      holderReplay: aliceReplay,
      credentialDefinitionId,
      revocationRegistryDefinitionId,
      //revocationStatusListTimestamp,
      issuerHolderConnectionId: faberConnectionId,
      holderIssuerConnectionId: aliceConnectionId,
    } = await setupAnonCredsTests({
      issuerId,
      issuerName: 'Faber agent AnonCreds proofs',
      holderName: 'Alice agent AnonCreds proofs',
      attributeNames: ['name', 'age', 'image_0', 'image_1'],
      registries: [inMemoryRegistry],
      supportRevocation: true,
    }))
    ;({ issuerCredentialExchangeRecord: faberCredentialExchangeRecord } = await issueAnonCredsCredential({
      issuerAgent: faberAgent,
      holderAgent: aliceAgent,
      holderReplay: aliceReplay,
      issuerReplay: faberReplay,
      issuerHolderConnectionId: faberConnectionId,
      revocationRegistryDefinitionId,
      offer: {
        credentialDefinitionId,
        attributes: [
          {
            name: 'name',
            value: 'John',
          },
          {
            name: 'age',
            value: '99',
          },
        ],
        linkedAttachments: [
          new LinkedAttachment({
            name: 'image_0',
            attachment: new Attachment({
              filename: 'picture-of-a-cat.png',
              data: new AttachmentData({ base64: 'cGljdHVyZSBvZiBhIGNhdA==' }),
            }),
          }),
          new LinkedAttachment({
            name: 'image_1',
            attachment: new Attachment({
              filename: 'picture-of-a-dog.png',
              data: new AttachmentData({ base64: 'UGljdHVyZSBvZiBhIGRvZw==' }),
            }),
          }),
        ],
      },
    }))
  })

  afterAll(async () => {
    testLogger.test('Shutting down both agents')
    await faberAgent.shutdown()
    await faberAgent.wallet.delete()
    await aliceAgent.shutdown()
    await aliceAgent.wallet.delete()
  })

  test('Alice starts with proof proposal to Faber', async () => {
    // Alice sends a presentation proposal to Faber
    testLogger.test('Alice sends a presentation proposal to Faber')

    let faberProofExchangeRecordPromise = waitForProofExchangeRecord(faberAgent, {
      state: ProofState.ProposalReceived,
    })

    aliceProofExchangeRecord = await aliceAgent.proofs.proposeProof({
      connectionId: aliceConnectionId,
      protocolVersion: 'v2',
      proofFormats: {
        anoncreds: {
          name: 'abc',
          version: '1.0',
          attributes: [
            {
              name: 'name',
              value: 'Alice',
              credentialDefinitionId,
            },
          ],
          predicates: [
            {
              name: 'age',
              predicate: '>=',
              threshold: 50,
              credentialDefinitionId,
            },
          ],
        },
      },
    })

    // Faber waits for a presentation proposal from Alice
    testLogger.test('Faber waits for a presentation proposal from Alice')
    faberProofExchangeRecord = await faberProofExchangeRecordPromise

    const proposal = await faberAgent.proofs.findProposalMessage(faberProofExchangeRecord.id)
    expect(proposal).toMatchObject({
      type: 'https://didcomm.org/present-proof/2.0/propose-presentation',
      formats: [
        {
          attachmentId: expect.any(String),
          format: 'anoncreds/proof-request@v1.0',
        },
      ],
      proposalAttachments: [
        {
          id: expect.any(String),
          mimeType: 'application/json',
          data: {
            base64: expect.any(String),
          },
        },
      ],
      id: expect.any(String),
    })
    expect(faberProofExchangeRecord.id).not.toBeNull()
    expect(faberProofExchangeRecord).toMatchObject({
      threadId: faberProofExchangeRecord.threadId,
      state: ProofState.ProposalReceived,
      protocolVersion: 'v2',
    })

    let aliceProofExchangeRecordPromise = waitForProofExchangeRecord(aliceAgent, {
      state: ProofState.RequestReceived,
    })

    // Faber accepts the presentation proposal from Alice
    testLogger.test('Faber accepts presentation proposal from Alice')
    faberProofExchangeRecord = await faberAgent.proofs.acceptProposal({
      proofRecordId: faberProofExchangeRecord.id,
    })

    // Alice waits for presentation request from Faber
    testLogger.test('Alice waits for presentation request from Faber')
    aliceProofExchangeRecord = await aliceProofExchangeRecordPromise

    const request = await faberAgent.proofs.findRequestMessage(faberProofExchangeRecord.id)
    expect(request).toMatchObject({
      type: 'https://didcomm.org/present-proof/2.0/request-presentation',
      formats: [
        {
          attachmentId: expect.any(String),
          format: 'anoncreds/proof-request@v1.0',
        },
      ],
      requestAttachments: [
        {
          id: expect.any(String),
          mimeType: 'application/json',
          data: {
            base64: expect.any(String),
          },
        },
      ],
      id: expect.any(String),
      thread: {
        threadId: faberProofExchangeRecord.threadId,
      },
    })

    // Alice retrieves the requested credentials and accepts the presentation request
    testLogger.test('Alice accepts presentation request from Faber')

    const requestedCredentials = await aliceAgent.proofs.selectCredentialsForRequest({
      proofRecordId: aliceProofExchangeRecord.id,
    })

    faberProofExchangeRecordPromise = waitForProofExchangeRecord(faberAgent, {
      threadId: aliceProofExchangeRecord.threadId,
      state: ProofState.PresentationReceived,
    })

    await aliceAgent.proofs.acceptRequest({
      proofRecordId: aliceProofExchangeRecord.id,
      proofFormats: { anoncreds: requestedCredentials.proofFormats.anoncreds },
    })

    // Faber waits for the presentation from Alice
    testLogger.test('Faber waits for presentation from Alice')
    faberProofExchangeRecord = await faberProofExchangeRecordPromise

    const presentation = await faberAgent.proofs.findPresentationMessage(faberProofExchangeRecord.id)
    expect(presentation).toMatchObject({
      type: 'https://didcomm.org/present-proof/2.0/presentation',
      formats: [
        {
          attachmentId: expect.any(String),
          format: 'anoncreds/proof@v1.0',
        },
      ],
      presentationAttachments: [
        {
          id: expect.any(String),
          mimeType: 'application/json',
          data: {
            base64: expect.any(String),
          },
        },
      ],
      id: expect.any(String),
      thread: {
        threadId: faberProofExchangeRecord.threadId,
      },
    })
    expect(faberProofExchangeRecord.id).not.toBeNull()
    expect(faberProofExchangeRecord).toMatchObject({
      threadId: faberProofExchangeRecord.threadId,
      state: ProofState.PresentationReceived,
      protocolVersion: 'v2',
    })

    aliceProofExchangeRecordPromise = waitForProofExchangeRecord(aliceAgent, {
      threadId: aliceProofExchangeRecord.threadId,
      state: ProofState.Done,
    })

    // Faber accepts the presentation provided by Alice
    testLogger.test('Faber accepts the presentation provided by Alice')
    await faberAgent.proofs.acceptPresentation({ proofRecordId: faberProofExchangeRecord.id })

    // Alice waits until she received a presentation acknowledgement
    testLogger.test('Alice waits until she receives a presentation acknowledgement')
    aliceProofExchangeRecord = await aliceProofExchangeRecordPromise

    expect(faberProofExchangeRecord).toMatchObject({
      type: ProofExchangeRecord.type,
      id: expect.any(String),
      createdAt: expect.any(Date),
      threadId: aliceProofExchangeRecord.threadId,
      connectionId: expect.any(String),
      isVerified: true,
      state: ProofState.PresentationReceived,
    })

    expect(aliceProofExchangeRecord).toMatchObject({
      type: ProofExchangeRecord.type,
      id: expect.any(String),
      createdAt: expect.any(Date),
      threadId: faberProofExchangeRecord.threadId,
      connectionId: expect.any(String),
      state: ProofState.Done,
    })

    const proposalMessage = await aliceAgent.proofs.findProposalMessage(aliceProofExchangeRecord.id)
    const requestMessage = await aliceAgent.proofs.findRequestMessage(aliceProofExchangeRecord.id)
    const presentationMessage = await aliceAgent.proofs.findPresentationMessage(aliceProofExchangeRecord.id)

    expect(proposalMessage).toBeInstanceOf(V2ProposePresentationMessage)
    expect(requestMessage).toBeInstanceOf(V2RequestPresentationMessage)
    expect(presentationMessage).toBeInstanceOf(V2PresentationMessage)

    const formatData = await aliceAgent.proofs.getFormatData(aliceProofExchangeRecord.id)

    expect(formatData).toMatchObject({
      proposal: {
        anoncreds: {
          name: 'abc',
          version: '1.0',
          nonce: expect.any(String),
          requested_attributes: {
            [Object.keys(formatData.proposal?.anoncreds?.requested_attributes ?? {})[0]]: {
              name: 'name',
              restrictions: [
                {
                  cred_def_id: credentialDefinitionId,
                },
              ],
            },
          },
          requested_predicates: {
            [Object.keys(formatData.proposal?.anoncreds?.requested_predicates ?? {})[0]]: {
              name: 'age',
              p_type: '>=',
              p_value: 50,
              restrictions: [
                {
                  cred_def_id: credentialDefinitionId,
                },
              ],
            },
          },
        },
      },
      request: {
        anoncreds: {
          name: 'abc',
          version: '1.0',
          nonce: expect.any(String),
          requested_attributes: {
            [Object.keys(formatData.request?.anoncreds?.requested_attributes ?? {})[0]]: {
              name: 'name',
              restrictions: [
                {
                  cred_def_id: credentialDefinitionId,
                },
              ],
            },
          },
          requested_predicates: {
            [Object.keys(formatData.request?.anoncreds?.requested_predicates ?? {})[0]]: {
              name: 'age',
              p_type: '>=',
              p_value: 50,
              restrictions: [
                {
                  cred_def_id: credentialDefinitionId,
                },
              ],
            },
          },
        },
      },
      presentation: {
        anoncreds: {
          proof: {
            // Only one proof means the predicate and attribute was combined into one proof (and thus we can
            // know that it was the same cred)
            proofs: [
              {
                primary_proof: expect.any(Object),
                non_revoc_proof: null,
              },
            ],
            aggregated_proof: {
              c_hash: expect.any(String),
              c_list: expect.any(Array),
            },
          },
          requested_proof: expect.any(Object),
          identifiers: expect.any(Array),
        },
      },
    })
  })

  test('Faber starts with proof request to Alice', async () => {
    let aliceProofExchangeRecordPromise = waitForProofExchangeRecord(aliceAgent, {
      state: ProofState.RequestReceived,
    })

    // Faber sends a presentation request to Alice
    testLogger.test('Faber sends a presentation request to Alice')
    faberProofExchangeRecord = await faberAgent.proofs.requestProof({
      protocolVersion: 'v2',
      connectionId: faberConnectionId,
      proofFormats: {
        anoncreds: {
          name: 'Proof Request',
          version: '1.0.0',
          requested_attributes: {
            name: {
              name: 'name',
              restrictions: [
                {
                  cred_def_id: credentialDefinitionId,
                },
              ],
            },
            image_0: {
              name: 'image_0',
              restrictions: [
                {
                  cred_def_id: credentialDefinitionId,
                },
              ],
            },
          },
          requested_predicates: {
            age: {
              name: 'age',
              p_type: '>=',
              p_value: 50,
              restrictions: [
                {
                  cred_def_id: credentialDefinitionId,
                },
              ],
            },
          },
        },
      },
    })

    // Alice waits for presentation request from Faber
    testLogger.test('Alice waits for presentation request from Faber')
    aliceProofExchangeRecord = await aliceProofExchangeRecordPromise

    const request = await faberAgent.proofs.findRequestMessage(faberProofExchangeRecord.id)
    expect(request).toMatchObject({
      type: 'https://didcomm.org/present-proof/2.0/request-presentation',
      formats: [
        {
          attachmentId: expect.any(String),
          format: 'anoncreds/proof-request@v1.0',
        },
      ],
      requestAttachments: [
        {
          id: expect.any(String),
          mimeType: 'application/json',
          data: {
            base64: expect.any(String),
          },
        },
      ],
      id: expect.any(String),
    })

    expect(aliceProofExchangeRecord.id).not.toBeNull()
    expect(aliceProofExchangeRecord).toMatchObject({
      threadId: aliceProofExchangeRecord.threadId,
      state: ProofState.RequestReceived,
      protocolVersion: 'v2',
    })

    // Alice retrieves the requested credentials and accepts the presentation request
    testLogger.test('Alice accepts presentation request from Faber')

    const requestedCredentials = await aliceAgent.proofs.selectCredentialsForRequest({
      proofRecordId: aliceProofExchangeRecord.id,
    })

    const faberProofExchangeRecordPromise = waitForProofExchangeRecord(faberAgent, {
      threadId: aliceProofExchangeRecord.threadId,
      state: ProofState.PresentationReceived,
    })

    await aliceAgent.proofs.acceptRequest({
      proofRecordId: aliceProofExchangeRecord.id,
      proofFormats: { anoncreds: requestedCredentials.proofFormats.anoncreds },
    })

    // Faber waits until it receives a presentation from Alice
    testLogger.test('Faber waits for presentation from Alice')
    faberProofExchangeRecord = await faberProofExchangeRecordPromise

    const presentation = await faberAgent.proofs.findPresentationMessage(faberProofExchangeRecord.id)
    expect(presentation).toMatchObject({
      type: 'https://didcomm.org/present-proof/2.0/presentation',
      formats: [
        {
          attachmentId: expect.any(String),
          format: 'anoncreds/proof@v1.0',
        },
      ],
      presentationAttachments: [
        {
          id: expect.any(String),
          mimeType: 'application/json',
          data: {
            base64: expect.any(String),
          },
        },
      ],
      id: expect.any(String),
      thread: {
        threadId: faberProofExchangeRecord.threadId,
      },
    })
    expect(faberProofExchangeRecord.id).not.toBeNull()
    expect(faberProofExchangeRecord).toMatchObject({
      threadId: faberProofExchangeRecord.threadId,
      state: ProofState.PresentationReceived,
      protocolVersion: 'v2',
    })

    aliceProofExchangeRecordPromise = waitForProofExchangeRecord(aliceAgent, {
      threadId: aliceProofExchangeRecord.threadId,
      state: ProofState.Done,
    })

    // Faber accepts the presentation
    testLogger.test('Faber accept the presentation from Alice')
    await faberAgent.proofs.acceptPresentation({ proofRecordId: faberProofExchangeRecord.id })

    // Alice waits until she receives a presentation acknowledgement
    testLogger.test('Alice waits for acceptance by Faber')
    aliceProofExchangeRecord = await aliceProofExchangeRecordPromise

    expect(faberProofExchangeRecord).toMatchObject({
      type: ProofExchangeRecord.type,
      id: expect.any(String),
      createdAt: expect.any(Date),
      threadId: aliceProofExchangeRecord.threadId,
      connectionId: expect.any(String),
      isVerified: true,
      state: ProofState.PresentationReceived,
    })

    expect(aliceProofExchangeRecord).toMatchObject({
      type: ProofExchangeRecord.type,
      id: expect.any(String),
      createdAt: expect.any(Date),
      threadId: faberProofExchangeRecord.threadId,
      connectionId: expect.any(String),
      state: ProofState.Done,
    })
  })

  test('Alice provides credentials via call to getRequestedCredentials', async () => {
    const aliceProofExchangeRecordPromise = waitForProofExchangeRecord(aliceAgent, {
      state: ProofState.RequestReceived,
    })

    // Faber sends a presentation request to Alice
    testLogger.test('Faber sends a presentation request to Alice')
    faberProofExchangeRecord = await faberAgent.proofs.requestProof({
      protocolVersion: 'v2',
      connectionId: faberConnectionId,
      proofFormats: {
        anoncreds: {
          name: 'Proof Request',
          version: '1.0.0',
          requested_attributes: {
            name: {
              name: 'name',
              restrictions: [
                {
                  cred_def_id: credentialDefinitionId,
                },
              ],
            },
            image_0: {
              name: 'image_0',
              restrictions: [
                {
                  cred_def_id: credentialDefinitionId,
                },
              ],
            },
          },
          requested_predicates: {
            age: {
              name: 'age',
              p_type: '>=',
              p_value: 50,
              restrictions: [
                {
                  cred_def_id: credentialDefinitionId,
                },
              ],
            },
          },
        },
      },
    })

    // Alice waits for presentation request from Faber
    testLogger.test('Alice waits for presentation request from Faber')
    aliceProofExchangeRecord = await aliceProofExchangeRecordPromise

    const retrievedCredentials = await aliceAgent.proofs.getCredentialsForRequest({
      proofRecordId: aliceProofExchangeRecord.id,
    })

    expect(retrievedCredentials).toMatchObject({
      proofFormats: {
        anoncreds: {
          attributes: {
            name: [
              {
                credentialId: expect.any(String),
                revealed: true,
                credentialInfo: {
                  credentialId: expect.any(String),
                  attributes: {
                    image_0: 'hl:zQmfDXo7T3J43j3CTkEZaz7qdHuABhWktksZ7JEBueZ5zUS',
                    image_1: 'hl:zQmRHBT9rDs5QhsnYuPY3mNpXxgLcnNXkhjWJvTSAPMmcVd',
                    name: 'John',
                    age: 99,
                  },
                  schemaId: expect.any(String),
                  credentialDefinitionId: expect.any(String),
                  credentialRevocationId: '1',
                  revocationRegistryId: revocationRegistryDefinitionId,
                },
              },
            ],
            image_0: [
              {
                credentialId: expect.any(String),
                revealed: true,
                credentialInfo: {
                  credentialId: expect.any(String),
                  attributes: {
                    age: 99,
                    image_0: 'hl:zQmfDXo7T3J43j3CTkEZaz7qdHuABhWktksZ7JEBueZ5zUS',
                    image_1: 'hl:zQmRHBT9rDs5QhsnYuPY3mNpXxgLcnNXkhjWJvTSAPMmcVd',
                    name: 'John',
                  },
                  schemaId: expect.any(String),
                  credentialDefinitionId: expect.any(String),
                  credentialRevocationId: '1',
                  revocationRegistryId: revocationRegistryDefinitionId,
                },
              },
            ],
          },
          predicates: {
            age: [
              {
                credentialId: expect.any(String),
                credentialInfo: {
                  credentialId: expect.any(String),
                  attributes: {
                    image_1: 'hl:zQmRHBT9rDs5QhsnYuPY3mNpXxgLcnNXkhjWJvTSAPMmcVd',
                    image_0: 'hl:zQmfDXo7T3J43j3CTkEZaz7qdHuABhWktksZ7JEBueZ5zUS',
                    name: 'John',
                    age: 99,
                  },
                  schemaId: expect.any(String),
                  credentialDefinitionId: expect.any(String),
                  credentialRevocationId: '1',
                  revocationRegistryId: revocationRegistryDefinitionId,
                },
              },
            ],
          },
        },
      },
    })
  })

  test('Faber starts with proof request to Alice but gets Problem Reported', async () => {
    const aliceProofExchangeRecordPromise = waitForProofExchangeRecord(aliceAgent, {
      state: ProofState.RequestReceived,
    })

    // Faber sends a presentation request to Alice
    testLogger.test('Faber sends a presentation request to Alice')
    faberProofExchangeRecord = await faberAgent.proofs.requestProof({
      protocolVersion: 'v2',
      connectionId: faberConnectionId,
      proofFormats: {
        anoncreds: {
          name: 'proof-request',
          version: '1.0',
          requested_attributes: {
            name: {
              name: 'name',
              restrictions: [
                {
                  cred_def_id: credentialDefinitionId,
                },
              ],
            },
            image_0: {
              name: 'image_0',
              restrictions: [
                {
                  cred_def_id: credentialDefinitionId,
                },
              ],
            },
          },
          requested_predicates: {
            age: {
              name: 'age',
              p_type: '>=',
              p_value: 50,
              restrictions: [
                {
                  cred_def_id: credentialDefinitionId,
                },
              ],
            },
          },
        },
      },
    })

    // Alice waits for presentation request from Faber
    testLogger.test('Alice waits for presentation request from Faber')
    aliceProofExchangeRecord = await aliceProofExchangeRecordPromise

    const request = await faberAgent.proofs.findRequestMessage(faberProofExchangeRecord.id)

    expect(request).toMatchObject({
      type: 'https://didcomm.org/present-proof/2.0/request-presentation',
      formats: [
        {
          attachmentId: expect.any(String),
          format: 'anoncreds/proof-request@v1.0',
        },
      ],
      requestAttachments: [
        {
          id: expect.any(String),
          mimeType: 'application/json',
          data: {
            base64: expect.any(String),
          },
        },
      ],
      id: expect.any(String),
    })

    expect(aliceProofExchangeRecord.id).not.toBeNull()
    expect(aliceProofExchangeRecord).toMatchObject({
      threadId: aliceProofExchangeRecord.threadId,
      state: ProofState.RequestReceived,
      protocolVersion: 'v2',
    })

    const faberProofExchangeRecordPromise = waitForProofExchangeRecord(faberAgent, {
      threadId: aliceProofExchangeRecord.threadId,
      state: ProofState.Abandoned,
    })

    aliceProofExchangeRecord = await aliceAgent.proofs.sendProblemReport({
      description: 'Problem inside proof request',
      proofRecordId: aliceProofExchangeRecord.id,
    })

    faberProofExchangeRecord = await faberProofExchangeRecordPromise

    expect(faberProofExchangeRecord).toMatchObject({
      threadId: aliceProofExchangeRecord.threadId,
      state: ProofState.Abandoned,
      protocolVersion: 'v2',
    })
  })

  test('Credential is revoked after proof request and before presentation', async () => {
    let aliceProofExchangeRecordPromise = waitForProofExchangeRecord(aliceAgent, {
      state: ProofState.RequestReceived,
    })

    const nrpRequestedTime = dateToTimestamp(new Date()) + 1

    const requestProofFormat: AnonCredsRequestProofFormat = {
      non_revoked: { from: nrpRequestedTime, to: nrpRequestedTime },
      name: 'Proof Request',
      version: '1.0.0',
      requested_attributes: {
        name: {
          name: 'name',
          restrictions: [
            {
              cred_def_id: credentialDefinitionId,
            },
          ],
        },
        image_0: {
          name: 'image_0',
          restrictions: [
            {
              cred_def_id: credentialDefinitionId,
            },
          ],
        },
      },
      requested_predicates: {
        age: {
          name: 'age',
          p_type: '>=',
          p_value: 50,
          restrictions: [
            {
              cred_def_id: credentialDefinitionId,
            },
          ],
        },
      },
    }

    // Faber sends a presentation request to Alice
    testLogger.test('Faber sends a presentation request to Alice')
    faberProofExchangeRecord = await faberAgent.proofs.requestProof({
      protocolVersion: 'v2',
      connectionId: faberConnectionId,
      proofFormats: {
        anoncreds: requestProofFormat,
      },
    })

    // Alice waits for presentation request from Faber
    testLogger.test('Alice waits for presentation request from Faber')
    aliceProofExchangeRecord = await aliceProofExchangeRecordPromise

    // Alice retrieves the requested credentials and accepts the presentation request
    testLogger.test('Alice accepts presentation request from Faber')

    const requestedCredentials = await aliceAgent.proofs.selectCredentialsForRequest({
      proofRecordId: aliceProofExchangeRecord.id,
    })

    const faberProofExchangeRecordPromise = waitForProofExchangeRecord(faberAgent, {
      threadId: aliceProofExchangeRecord.threadId,
      state: ProofState.PresentationReceived,
    })

    // Revoke the credential
    const credentialRevocationRegistryDefinitionId = faberCredentialExchangeRecord.getTag(
      'anonCredsRevocationRegistryId'
    ) as string
    const credentialRevocationIndex = faberCredentialExchangeRecord.getTag('anonCredsCredentialRevocationId') as string

    expect(credentialRevocationRegistryDefinitionId).toBeDefined()
    expect(credentialRevocationIndex).toBeDefined()

    // FIXME: do not use delays. Maybe we can add the timestamp to parameters?
    // InMemoryAnonCredsRegistry would respect what we ask while actual VDRs will use their own
    await sleep(2000)
    await faberAgent.modules.anoncreds.updateRevocationStatusList({
      revocationStatusList: {
        revocationRegistryDefinitionId: credentialRevocationRegistryDefinitionId,
        revokedCredentialIndexes: [Number(credentialRevocationIndex)],
      },
      options: {},
    })

    await aliceAgent.proofs.acceptRequest({
      proofRecordId: aliceProofExchangeRecord.id,
      proofFormats: { anoncreds: requestedCredentials.proofFormats.anoncreds },
    })

    // Faber waits until it receives a presentation from Alice
    testLogger.test('Faber waits for presentation from Alice')
    faberProofExchangeRecord = await faberProofExchangeRecordPromise

    aliceProofExchangeRecordPromise = waitForProofExchangeRecord(aliceAgent, {
      threadId: aliceProofExchangeRecord.threadId,
      state: ProofState.Done,
    })

    // Faber accepts the presentation
    testLogger.test('Faber accept the presentation from Alice')
    await faberAgent.proofs.acceptPresentation({ proofRecordId: faberProofExchangeRecord.id })

    // Alice waits until she receives a presentation acknowledgement
    testLogger.test('Alice waits for acceptance by Faber')
    aliceProofExchangeRecord = await aliceProofExchangeRecordPromise

    expect(faberProofExchangeRecord).toMatchObject({
      threadId: aliceProofExchangeRecord.threadId,
      isVerified: true,
      state: ProofState.PresentationReceived,
    })

    expect(aliceProofExchangeRecord).toMatchObject({
      threadId: faberProofExchangeRecord.threadId,
      state: ProofState.Done,
    })
  })

  test('Credential is revoked before proof request', async () => {
    // Revoke the credential
    const credentialRevocationRegistryDefinitionId = faberCredentialExchangeRecord.getTag(
      'anonCredsRevocationRegistryId'
    ) as string
    const credentialRevocationIndex = faberCredentialExchangeRecord.getTag('anonCredsCredentialRevocationId') as string

    expect(credentialRevocationRegistryDefinitionId).toBeDefined()
    expect(credentialRevocationIndex).toBeDefined()

    const { revocationStatusListState } = await faberAgent.modules.anoncreds.updateRevocationStatusList({
      revocationStatusList: {
        revocationRegistryDefinitionId: credentialRevocationRegistryDefinitionId,
        revokedCredentialIndexes: [Number(credentialRevocationIndex)],
      },
      options: {},
    })

    expect(revocationStatusListState.revocationStatusList).toBeDefined()
    const revokedTimestamp = revocationStatusListState.revocationStatusList?.timestamp

    const aliceProofExchangeRecordPromise = waitForProofExchangeRecord(aliceAgent, {
      state: ProofState.RequestReceived,
    })

    const nrpRequestedTime = (revokedTimestamp ?? dateToTimestamp(new Date())) + 1

    const requestProofFormat: AnonCredsRequestProofFormat = {
      non_revoked: { from: nrpRequestedTime, to: nrpRequestedTime },
      name: 'Proof Request',
      version: '1.0.0',
      requested_attributes: {
        name: {
          name: 'name',
          restrictions: [
            {
              cred_def_id: credentialDefinitionId,
            },
          ],
        },
        image_0: {
          name: 'image_0',
          restrictions: [
            {
              cred_def_id: credentialDefinitionId,
            },
          ],
        },
      },
      requested_predicates: {
        age: {
          name: 'age',
          p_type: '>=',
          p_value: 50,
          restrictions: [
            {
              cred_def_id: credentialDefinitionId,
            },
          ],
        },
      },
    }

    // Faber sends a presentation request to Alice
    testLogger.test('Faber sends a presentation request to Alice')
    faberProofExchangeRecord = await faberAgent.proofs.requestProof({
      protocolVersion: 'v2',
      connectionId: faberConnectionId,
      proofFormats: {
        anoncreds: requestProofFormat,
      },
    })

    // Alice waits for presentation request from Faber
    testLogger.test('Alice waits for presentation request from Faber')
    aliceProofExchangeRecord = await aliceProofExchangeRecordPromise

    // Alice retrieves the requested credentials and accepts the presentation request
    testLogger.test('Alice accepts presentation request from Faber')

    const requestedCredentials = await aliceAgent.proofs.selectCredentialsForRequest({
      proofRecordId: aliceProofExchangeRecord.id,
      proofFormats: { anoncreds: { filterByNonRevocationRequirements: false } },
    })

    const faberProofExchangeRecordPromise = waitForProofExchangeRecord(faberAgent, {
      threadId: aliceProofExchangeRecord.threadId,
    })

    await aliceAgent.proofs.acceptRequest({
      proofRecordId: aliceProofExchangeRecord.id,
      proofFormats: { anoncreds: requestedCredentials.proofFormats.anoncreds },
    })

    // Faber waits until it receives a presentation from Alice
    testLogger.test('Faber waits for presentation from Alice')
    faberProofExchangeRecord = await faberProofExchangeRecordPromise

    // Faber receives presentation and checks that it is not valid
    expect(faberProofExchangeRecord).toMatchObject({
      threadId: aliceProofExchangeRecord.threadId,
      isVerified: false,
      state: ProofState.Abandoned,
    })

    // Faber will send a problem report, meaning for Alice that the proof state is abandoned
    // as well
    await waitForProofExchangeRecord(aliceAgent, {
      threadId: aliceProofExchangeRecord.threadId,
      state: ProofState.Abandoned,
    })
  })
})
