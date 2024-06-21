import type { DataIntegrityCredentialRequest, DidRepository } from '@credo-ts/core'

import {
  ProofRole,
  CredentialRole,
  AgentContext,
  CredentialExchangeRecord,
  CredentialPreviewAttribute,
  CredentialState,
  DidResolverService,
  DidsModuleConfig,
  InjectionSymbols,
  KeyDidRegistrar,
  KeyDidResolver,
  ProofExchangeRecord,
  ProofState,
  SignatureSuiteToken,
  W3cCredential,
  W3cCredentialService,
  W3cCredentialSubject,
  W3cCredentialsModuleConfig,
} from '@credo-ts/core'
import { Subject } from 'rxjs'

import { InMemoryStorageService } from '../../../tests/InMemoryStorageService'
import { InMemoryWallet } from '../../../tests/InMemoryWallet'
import { DataIntegrityCredentialFormatService } from '../../anoncreds/src/formats/DataIntegrityCredentialFormatService'
import { AnonCredsRegistryService } from '../../anoncreds/src/services/registry/AnonCredsRegistryService'
import { dateToTimestamp } from '../../anoncreds/src/utils/timestamp'
import { InMemoryAnonCredsRegistry } from '../../anoncreds/tests/InMemoryAnonCredsRegistry'
import { agentDependencies, getAgentConfig, getAgentContext, testLogger } from '../../core/tests'
import { AnonCredsRsHolderService, AnonCredsRsIssuerService, AnonCredsRsVerifierService } from '../src/anoncreds-rs'

import { InMemoryTailsFileService } from './InMemoryTailsFileService'
import { anoncreds } from './helpers'

import {
  AnonCredsCredentialDefinitionPrivateRecord,
  AnonCredsCredentialDefinitionPrivateRepository,
  AnonCredsCredentialDefinitionRecord,
  AnonCredsCredentialDefinitionRepository,
  AnonCredsHolderServiceSymbol,
  AnonCredsIssuerServiceSymbol,
  AnonCredsKeyCorrectnessProofRecord,
  AnonCredsKeyCorrectnessProofRepository,
  AnonCredsLinkSecretRecord,
  AnonCredsLinkSecretRepository,
  AnonCredsModuleConfig,
  AnonCredsProofFormatService,
  AnonCredsRevocationRegistryDefinitionPrivateRecord,
  AnonCredsRevocationRegistryDefinitionPrivateRepository,
  AnonCredsRevocationRegistryDefinitionRecord,
  AnonCredsRevocationRegistryDefinitionRepository,
  AnonCredsRevocationRegistryState,
  AnonCredsSchemaRecord,
  AnonCredsSchemaRepository,
  AnonCredsVerifierServiceSymbol,
} from '@credo-ts/anoncreds'

const registry = new InMemoryAnonCredsRegistry()
const tailsFileService = new InMemoryTailsFileService()
const anonCredsModuleConfig = new AnonCredsModuleConfig({
  anoncreds,
  registries: [registry],
  tailsFileService,
})

const agentConfig = getAgentConfig('AnonCreds format services using anoncreds-rs')
const anonCredsVerifierService = new AnonCredsRsVerifierService()
const anonCredsHolderService = new AnonCredsRsHolderService()
const anonCredsIssuerService = new AnonCredsRsIssuerService()

const inMemoryStorageService = new InMemoryStorageService()

const didsModuleConfig = new DidsModuleConfig({
  registrars: [new KeyDidRegistrar()],
  resolvers: [new KeyDidResolver()],
})
const fileSystem = new agentDependencies.FileSystem()

const wallet = new InMemoryWallet()

const agentContext = getAgentContext({
  registerInstances: [
    [InjectionSymbols.Stop$, new Subject<boolean>()],
    [InjectionSymbols.AgentDependencies, agentDependencies],
    [InjectionSymbols.FileSystem, fileSystem],
    [InjectionSymbols.StorageService, inMemoryStorageService],
    [AnonCredsIssuerServiceSymbol, anonCredsIssuerService],
    [AnonCredsHolderServiceSymbol, anonCredsHolderService],
    [AnonCredsVerifierServiceSymbol, anonCredsVerifierService],
    [InjectionSymbols.Logger, testLogger],
    [DidsModuleConfig, didsModuleConfig],
    [DidResolverService, new DidResolverService(testLogger, didsModuleConfig, {} as unknown as DidRepository)],
    [AnonCredsRegistryService, new AnonCredsRegistryService()],
    [AnonCredsModuleConfig, anonCredsModuleConfig],
    [W3cCredentialsModuleConfig, new W3cCredentialsModuleConfig()],
    [SignatureSuiteToken, 'default'],
  ],
  agentConfig,
  wallet,
})

agentContext.dependencyManager.registerInstance(AgentContext, agentContext)

const dataIntegrityCredentialFormatService = new DataIntegrityCredentialFormatService()
const anoncredsProofFormatService = new AnonCredsProofFormatService()

const indyDid = 'did:indy:local:LjgpST2rjsoxYegQDRm7EL'

describe('data integrity format service (anoncreds)', () => {
  beforeAll(async () => {
    await wallet.createAndOpen(agentConfig.walletConfig)
  })

  afterEach(async () => {
    inMemoryStorageService.contextCorrelationIdToRecords = {}
  })

  test('issuance and verification flow anoncreds starting from offer without negotiation and without revocation', async () => {
    await anonCredsFlowTest({ issuerId: indyDid, revocable: false })
  })

  test('issuance and verification flow anoncreds starting from offer without negotiation and with revocation', async () => {
    await anonCredsFlowTest({ issuerId: indyDid, revocable: true })
  })
})

async function anonCredsFlowTest(options: { issuerId: string; revocable: boolean }) {
  const { issuerId, revocable } = options

  const schema = await anonCredsIssuerService.createSchema(agentContext, {
    attrNames: ['name', 'age'],
    issuerId,
    name: 'Employee Credential',
    version: '1.0.0',
  })

  const { schemaState } = await registry.registerSchema(agentContext, {
    schema,
    options: {},
  })

  if (!schemaState.schema || !schemaState.schemaId) {
    throw new Error('Failed to create schema')
  }

  await agentContext.dependencyManager.resolve(AnonCredsSchemaRepository).save(
    agentContext,
    new AnonCredsSchemaRecord({
      schema: schemaState.schema,
      schemaId: schemaState.schemaId,
      methodName: 'inMemory',
    })
  )

  const { credentialDefinition, credentialDefinitionPrivate, keyCorrectnessProof } =
    await anonCredsIssuerService.createCredentialDefinition(agentContext, {
      issuerId,
      schemaId: schemaState.schemaId as string,
      schema,
      tag: 'Employee Credential',
      supportRevocation: revocable,
    })

  const { credentialDefinitionState } = await registry.registerCredentialDefinition(agentContext, {
    credentialDefinition,
    options: {},
  })

  if (!credentialDefinitionState.credentialDefinition || !credentialDefinitionState.credentialDefinitionId) {
    throw new Error('Failed to create credential definition')
  }

  if (!credentialDefinitionPrivate || !keyCorrectnessProof) {
    throw new Error('Failed to get private part of credential definition')
  }

  await agentContext.dependencyManager.resolve(AnonCredsCredentialDefinitionRepository).save(
    agentContext,
    new AnonCredsCredentialDefinitionRecord({
      credentialDefinition: credentialDefinitionState.credentialDefinition,
      credentialDefinitionId: credentialDefinitionState.credentialDefinitionId,
      methodName: 'inMemory',
    })
  )

  await agentContext.dependencyManager.resolve(AnonCredsCredentialDefinitionPrivateRepository).save(
    agentContext,
    new AnonCredsCredentialDefinitionPrivateRecord({
      value: credentialDefinitionPrivate,
      credentialDefinitionId: credentialDefinitionState.credentialDefinitionId,
    })
  )

  await agentContext.dependencyManager.resolve(AnonCredsKeyCorrectnessProofRepository).save(
    agentContext,
    new AnonCredsKeyCorrectnessProofRecord({
      value: keyCorrectnessProof,
      credentialDefinitionId: credentialDefinitionState.credentialDefinitionId,
    })
  )

  let revocationRegistryDefinitionId: string | undefined
  if (revocable) {
    const { revocationRegistryDefinition, revocationRegistryDefinitionPrivate } =
      await anonCredsIssuerService.createRevocationRegistryDefinition(agentContext, {
        issuerId: issuerId,
        credentialDefinition,
        credentialDefinitionId: credentialDefinitionState.credentialDefinitionId,
        maximumCredentialNumber: 100,
        tailsDirectoryPath: await tailsFileService.getTailsBasePath(agentContext),
        tag: 'default',
      })

    // At this moment, tails file should be published and a valid public URL will be received
    const localTailsFilePath = revocationRegistryDefinition.value.tailsLocation

    const { revocationRegistryDefinitionState } = await registry.registerRevocationRegistryDefinition(agentContext, {
      revocationRegistryDefinition,
      options: {},
    })

    revocationRegistryDefinitionId = revocationRegistryDefinitionState.revocationRegistryDefinitionId

    if (
      !revocationRegistryDefinitionState.revocationRegistryDefinition ||
      !revocationRegistryDefinitionId ||
      !revocationRegistryDefinitionPrivate
    ) {
      throw new Error('Failed to create revocation registry')
    }

    await agentContext.dependencyManager.resolve(AnonCredsRevocationRegistryDefinitionRepository).save(
      agentContext,
      new AnonCredsRevocationRegistryDefinitionRecord({
        revocationRegistryDefinition: revocationRegistryDefinitionState.revocationRegistryDefinition,
        revocationRegistryDefinitionId,
      })
    )

    await agentContext.dependencyManager.resolve(AnonCredsRevocationRegistryDefinitionPrivateRepository).save(
      agentContext,
      new AnonCredsRevocationRegistryDefinitionPrivateRecord({
        state: AnonCredsRevocationRegistryState.Active,
        value: revocationRegistryDefinitionPrivate,
        credentialDefinitionId: revocationRegistryDefinitionState.revocationRegistryDefinition.credDefId,
        revocationRegistryDefinitionId,
      })
    )

    const createdRevocationStatusList = await anonCredsIssuerService.createRevocationStatusList(agentContext, {
      issuerId: issuerId,
      revocationRegistryDefinition,
      revocationRegistryDefinitionId,
      tailsFilePath: localTailsFilePath,
    })

    const { revocationStatusListState } = await registry.registerRevocationStatusList(agentContext, {
      revocationStatusList: createdRevocationStatusList,
      options: {},
    })

    if (!revocationStatusListState.revocationStatusList) {
      throw new Error('Failed to create revocation status list')
    }
  }

  const linkSecret = await anonCredsHolderService.createLinkSecret(agentContext, { linkSecretId: 'linkSecretId' })
  expect(linkSecret.linkSecretId).toBe('linkSecretId')

  await agentContext.dependencyManager.resolve(AnonCredsLinkSecretRepository).save(
    agentContext,
    new AnonCredsLinkSecretRecord({
      value: linkSecret.linkSecretValue,
      linkSecretId: linkSecret.linkSecretId,
    })
  )

  const holderCredentialRecord = new CredentialExchangeRecord({
    protocolVersion: 'v1',
    state: CredentialState.ProposalSent,
    threadId: 'f365c1a5-2baf-4873-9432-fa87c888a0aa',
    role: CredentialRole.Holder,
  })

  const issuerCredentialRecord = new CredentialExchangeRecord({
    protocolVersion: 'v1',
    state: CredentialState.ProposalReceived,
    threadId: 'f365c1a5-2baf-4873-9432-fa87c888a0aa',
    role: CredentialRole.Issuer,
  })

  const credentialAttributes = [
    new CredentialPreviewAttribute({ name: 'name', value: 'John' }),
    new CredentialPreviewAttribute({ name: 'age', value: '25' }),
  ]

  // Set attributes on the credential record, this is normally done by the protocol service
  holderCredentialRecord.credentialAttributes = credentialAttributes
  issuerCredentialRecord.credentialAttributes = credentialAttributes

  // --------------------------------------------------------------------------------------------------------

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
    credentialSubject: new W3cCredentialSubject({ claims: { name: 'John', age: '25' } }),
  })

  const { attachment: offerAttachment } = await dataIntegrityCredentialFormatService.createOffer(agentContext, {
    credentialRecord: issuerCredentialRecord,
    credentialFormats: {
      dataIntegrity: {
        bindingRequired: true,
        credential,
        anonCredsLinkSecretBinding: {
          credentialDefinitionId: credentialDefinitionState.credentialDefinitionId,
          revocationRegistryDefinitionId,
          revocationRegistryIndex: revocable ? 1 : undefined,
        },
        didCommSignedAttachmentBinding: {},
      },
    },
  })

  // Holder processes and accepts offer
  await dataIntegrityCredentialFormatService.processOffer(agentContext, {
    credentialRecord: holderCredentialRecord,
    attachment: offerAttachment,
  })
  const { attachment: requestAttachment, appendAttachments: requestAppendAttachments } =
    await dataIntegrityCredentialFormatService.acceptOffer(agentContext, {
      credentialRecord: holderCredentialRecord,
      offerAttachment,
      credentialFormats: {
        dataIntegrity: {
          dataModelVersion: '1.1',
          anonCredsLinkSecret: {
            linkSecretId: linkSecret.linkSecretId,
          },
        },
      },
    })

  // Make sure the request contains an entropy and does not contain a prover_did field
  expect(
    (requestAttachment.getDataAsJson() as DataIntegrityCredentialRequest).binding_proof?.anoncreds_link_secret?.entropy
  ).toBeDefined()
  expect((requestAttachment.getDataAsJson() as Record<string, unknown>).prover_did).toBeUndefined()

  // Issuer processes and accepts request
  await dataIntegrityCredentialFormatService.processRequest(agentContext, {
    credentialRecord: issuerCredentialRecord,
    attachment: requestAttachment,
  })
  const { attachment: credentialAttachment } = await dataIntegrityCredentialFormatService.acceptRequest(agentContext, {
    credentialRecord: issuerCredentialRecord,
    requestAttachment,
    offerAttachment,
    requestAppendAttachments,
    credentialFormats: { dataIntegrity: {} },
  })

  // Holder processes and accepts credential
  await dataIntegrityCredentialFormatService.processCredential(agentContext, {
    offerAttachment,
    credentialRecord: holderCredentialRecord,
    attachment: credentialAttachment,
    requestAttachment,
  })

  expect(holderCredentialRecord.credentials).toEqual([
    { credentialRecordType: 'w3c', credentialRecordId: expect.any(String) },
  ])

  const credentialRecordId = holderCredentialRecord.credentials[0].credentialRecordId
  const w3cCredentialService = agentContext.dependencyManager.resolve(W3cCredentialService)
  const credentialRecord = await w3cCredentialService.getCredentialRecordById(agentContext, credentialRecordId)
  const credentialId = credentialRecord.id

  const anonCredsCredential = await anonCredsHolderService.getCredential(agentContext, {
    id: credentialId,
  })

  expect(anonCredsCredential).toEqual({
    credentialId,
    attributes: {
      age: 25,
      name: 'John',
    },
    linkSecretId: 'linkSecretId',
    schemaId: schemaState.schemaId,
    credentialDefinitionId: credentialDefinitionState.credentialDefinitionId,
    revocationRegistryId: revocable ? revocationRegistryDefinitionId : null,
    credentialRevocationId: revocable ? '1' : null,
    methodName: 'inMemory',
    createdAt: expect.any(Date),
    updatedAt: expect.any(Date),
  })

  const expectedCredentialMetadata = revocable
    ? {
        schemaId: schemaState.schemaId,
        credentialDefinitionId: credentialDefinitionState.credentialDefinitionId,
        revocationRegistryId: revocationRegistryDefinitionId,
        credentialRevocationId: '1',
      }
    : {
        schemaId: schemaState.schemaId,
        credentialDefinitionId: credentialDefinitionState.credentialDefinitionId,
      }
  expect(holderCredentialRecord.metadata.data).toEqual({
    '_anoncreds/credential': expectedCredentialMetadata,
    '_anoncreds/credentialRequest': {
      link_secret_blinding_data: expect.any(Object),
      link_secret_name: expect.any(String),
      nonce: expect.any(String),
    },
  })

  expect(issuerCredentialRecord.metadata.data).toEqual({
    '_anoncreds/credential': expectedCredentialMetadata,
  })

  const holderProofRecord = new ProofExchangeRecord({
    protocolVersion: 'v1',
    state: ProofState.ProposalSent,
    role: ProofRole.Prover,
    threadId: '4f5659a4-1aea-4f42-8c22-9a9985b35e38',
  })
  const verifierProofRecord = new ProofExchangeRecord({
    protocolVersion: 'v1',
    role: ProofRole.Verifier,
    state: ProofState.ProposalReceived,
    threadId: '4f5659a4-1aea-4f42-8c22-9a9985b35e38',
  })

  const nrpRequestedTime = dateToTimestamp(new Date())

  const { attachment: proofProposalAttachment } = await anoncredsProofFormatService.createProposal(agentContext, {
    proofFormats: {
      anoncreds: {
        attributes: [
          {
            name: 'name',
            credentialDefinitionId: credentialDefinitionState.credentialDefinitionId,
            value: 'John',
            referent: '1',
          },
        ],
        predicates: [
          {
            credentialDefinitionId: credentialDefinitionState.credentialDefinitionId,
            name: 'age',
            predicate: '>=',
            threshold: 18,
          },
        ],
        name: 'Proof Request',
        version: '1.0',
        nonRevokedInterval: { from: nrpRequestedTime, to: nrpRequestedTime },
      },
    },
    proofRecord: holderProofRecord,
  })

  await anoncredsProofFormatService.processProposal(agentContext, {
    attachment: proofProposalAttachment,
    proofRecord: verifierProofRecord,
  })

  const { attachment: proofRequestAttachment } = await anoncredsProofFormatService.acceptProposal(agentContext, {
    proofRecord: verifierProofRecord,
    proposalAttachment: proofProposalAttachment,
  })

  await anoncredsProofFormatService.processRequest(agentContext, {
    attachment: proofRequestAttachment,
    proofRecord: holderProofRecord,
  })

  const { attachment: proofAttachment } = await anoncredsProofFormatService.acceptRequest(agentContext, {
    proofRecord: holderProofRecord,
    requestAttachment: proofRequestAttachment,
    proposalAttachment: proofProposalAttachment,
  })

  const isValid = await anoncredsProofFormatService.processPresentation(agentContext, {
    attachment: proofAttachment,
    proofRecord: verifierProofRecord,
    requestAttachment: proofRequestAttachment,
  })

  expect(isValid).toBe(true)
}
