import type { AnonCredsTestsAgent } from '../../anoncreds/tests/anoncredsSetup'
import type { EventReplaySubject } from '../../core/tests'
import type { DifPresentationExchangeDefinitionV2 } from '@credo-ts/core'

import {
  AutoAcceptCredential,
  CredentialExchangeRecord,
  CredentialState,
  ProofState,
  W3cCredential,
  W3cCredentialSubject,
} from '@credo-ts/core'

import { InMemoryAnonCredsRegistry } from '../../anoncreds/tests/InMemoryAnonCredsRegistry'
import { setupAnonCredsTests } from '../../anoncreds/tests/anoncredsSetup'
import { presentationDefinition } from '../../anoncreds/tests/fixtures/presentation-definition'
import { createDidKidVerificationMethod } from '../../core/tests'
import { waitForCredentialRecordSubject, waitForProofExchangeRecord } from '../../core/tests/helpers'

import { cheqdPayerSeeds } from './setupCheqdModule'

describe('anoncreds w3c data integrity e2e tests', () => {
  let issuerId: string
  let issuerAgent: AnonCredsTestsAgent
  let holderAgent: AnonCredsTestsAgent
  let credentialDefinitionId: string
  let issuerHolderConnectionId: string
  let holderIssuerConnectionId: string

  let issuerReplay: EventReplaySubject
  let holderReplay: EventReplaySubject

  afterEach(async () => {
    await issuerAgent.shutdown()
    await issuerAgent.wallet.delete()
    await holderAgent.shutdown()
    await holderAgent.wallet.delete()
  })

  test('cheqd issuance and verification flow starting from offer without revocation', async () => {
    ;({
      issuerAgent,
      issuerReplay,
      holderAgent,
      holderReplay,
      credentialDefinitionId,
      issuerHolderConnectionId,
      holderIssuerConnectionId,
      issuerId,
    } = await setupAnonCredsTests({
      issuerName: 'Issuer Agent Credentials v2',
      holderName: 'Holder Agent Credentials v2',
      attributeNames: ['id', 'name', 'height', 'age'],
      registries: [new InMemoryAnonCredsRegistry()],
      cheqd: {
        seed: cheqdPayerSeeds[3],
      },
    }))

    const holderKdv = await createDidKidVerificationMethod(holderAgent.context, '96213c3d7fc8d4d6754c7a0fd969598f')
    const linkSecret = await holderAgent.modules.anoncreds.createLinkSecret({ linkSecretId: 'linkSecretId' })
    expect(linkSecret).toBe('linkSecretId')

    const credential = new W3cCredential({
      context: [
        'https://www.w3.org/2018/credentials/v1',
        'https://w3id.org/security/data-integrity/v2',
        {
          '@vocab': 'https://www.w3.org/ns/credentials/issuer-dependent#',
        },
      ],
      type: ['VerifiableCredential'],
      issuer: issuerId,
      issuanceDate: new Date().toISOString(),
      credentialSubject: new W3cCredentialSubject({
        id: holderKdv.did,
        claims: { name: 'John', age: '25', height: 173 },
      }),
    })

    // issuer offers credential
    let issuerRecord = await issuerAgent.credentials.offerCredential({
      protocolVersion: 'v2',
      autoAcceptCredential: AutoAcceptCredential.Never,
      connectionId: issuerHolderConnectionId,
      credentialFormats: {
        dataIntegrity: {
          bindingRequired: true,
          credential,
          anonCredsLinkSecretBinding: {
            credentialDefinitionId,
            revocationRegistryDefinitionId: undefined,
            revocationRegistryIndex: undefined,
          },
          didCommSignedAttachmentBinding: {},
        },
      },
    })

    // Holder processes and accepts offer
    let holderRecord = await waitForCredentialRecordSubject(holderReplay, {
      state: CredentialState.OfferReceived,
      threadId: issuerRecord.threadId,
    })
    holderRecord = await holderAgent.credentials.acceptOffer({
      credentialRecordId: holderRecord.id,
      autoAcceptCredential: AutoAcceptCredential.Never,
      credentialFormats: {
        dataIntegrity: {
          anonCredsLinkSecret: {
            linkSecretId: 'linkSecretId',
          },
        },
      },
    })

    // issuer receives request and accepts
    issuerRecord = await waitForCredentialRecordSubject(issuerReplay, {
      state: CredentialState.RequestReceived,
      threadId: holderRecord.threadId,
    })
    issuerRecord = await issuerAgent.credentials.acceptRequest({
      credentialRecordId: issuerRecord.id,
      autoAcceptCredential: AutoAcceptCredential.Never,
      credentialFormats: {
        dataIntegrity: {},
      },
    })

    holderRecord = await waitForCredentialRecordSubject(holderReplay, {
      state: CredentialState.CredentialReceived,
      threadId: issuerRecord.threadId,
    })
    holderRecord = await holderAgent.credentials.acceptCredential({
      credentialRecordId: holderRecord.id,
    })

    issuerRecord = await waitForCredentialRecordSubject(issuerReplay, {
      state: CredentialState.Done,
      threadId: holderRecord.threadId,
    })

    expect(holderRecord).toMatchObject({
      type: CredentialExchangeRecord.type,
      id: expect.any(String),
      createdAt: expect.any(Date),
      metadata: {
        data: {
          '_anoncreds/credential': {
            credentialDefinitionId,
            schemaId: expect.any(String),
          },
          '_anoncreds/credentialRequest': {
            link_secret_blinding_data: {
              v_prime: expect.any(String),
              vr_prime: null,
            },
            nonce: expect.any(String),
            link_secret_name: 'linkSecretId',
          },
        },
      },
      state: CredentialState.Done,
    })

    const tags = holderRecord.getTags()
    expect(tags.credentialIds).toHaveLength(1)

    let issuerProofExchangeRecordPromise = waitForProofExchangeRecord(issuerAgent, {
      state: ProofState.ProposalReceived,
    })

    const pdCopy = JSON.parse(JSON.stringify(presentationDefinition))
    pdCopy.input_descriptors.forEach((ide: DifPresentationExchangeDefinitionV2['input_descriptors'][number]) => {
      delete ide.constraints?.statuses
      if (ide.constraints.fields && ide.constraints.fields[0].filter?.const) {
        ide.constraints.fields[0].filter.const = issuerId
      }
    })

    let holderProofExchangeRecord = await holderAgent.proofs.proposeProof({
      protocolVersion: 'v2',
      connectionId: holderIssuerConnectionId,
      proofFormats: {
        presentationExchange: {
          presentationDefinition: pdCopy,
        },
      },
    })

    let issuerProofExchangeRecord = await issuerProofExchangeRecordPromise

    let holderProofExchangeRecordPromise = waitForProofExchangeRecord(holderAgent, {
      state: ProofState.RequestReceived,
    })

    issuerProofExchangeRecord = await issuerAgent.proofs.acceptProposal({
      proofRecordId: issuerProofExchangeRecord.id,
    })

    holderProofExchangeRecord = await holderProofExchangeRecordPromise

    const requestedCredentials = await holderAgent.proofs.selectCredentialsForRequest({
      proofRecordId: holderProofExchangeRecord.id,
    })

    const selectedCredentials = requestedCredentials.proofFormats.presentationExchange?.credentials
    if (!selectedCredentials) {
      throw new Error('No credentials found for presentation exchange')
    }

    issuerProofExchangeRecordPromise = waitForProofExchangeRecord(issuerAgent, {
      threadId: holderProofExchangeRecord.threadId,
      state: ProofState.PresentationReceived,
    })

    await holderAgent.proofs.acceptRequest({
      proofRecordId: holderProofExchangeRecord.id,
      proofFormats: {
        presentationExchange: {
          credentials: selectedCredentials,
        },
      },
    })
    issuerProofExchangeRecord = await issuerProofExchangeRecordPromise

    holderProofExchangeRecordPromise = waitForProofExchangeRecord(holderAgent, {
      threadId: holderProofExchangeRecord.threadId,
      state: ProofState.Done,
    })

    await issuerAgent.proofs.acceptPresentation({ proofRecordId: issuerProofExchangeRecord.id })

    holderProofExchangeRecord = await holderProofExchangeRecordPromise
  })
})
