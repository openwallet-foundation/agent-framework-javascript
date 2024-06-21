import type { AnonCredsCredentialRequest } from '../../models'
import type { DidRepository } from '@credo-ts/core'

import {
  CredentialState,
  CredentialExchangeRecord,
  KeyType,
  CredentialPreviewAttribute,
  ProofExchangeRecord,
  ProofState,
  EventEmitter,
  InjectionSymbols,
  SignatureSuiteToken,
  W3cCredentialsModuleConfig,
  DidResolverService,
  DidsModuleConfig,
  ProofRole,
  CredentialRole,
} from '@credo-ts/core'
import { Subject } from 'rxjs'

import { InMemoryStorageService } from '../../../../../tests/InMemoryStorageService'
import { InMemoryWallet } from '../../../../../tests/InMemoryWallet'
import { anoncreds } from '../../../../anoncreds/tests/helpers'
import { indyDidFromPublicKeyBase58 } from '../../../../core/src/utils/did'
import { testLogger } from '../../../../core/tests'
import { agentDependencies, getAgentConfig, getAgentContext } from '../../../../core/tests/helpers'
import { InMemoryAnonCredsRegistry } from '../../../tests/InMemoryAnonCredsRegistry'
import { AnonCredsModuleConfig } from '../../AnonCredsModuleConfig'
import { AnonCredsRsHolderService, AnonCredsRsIssuerService, AnonCredsRsVerifierService } from '../../anoncreds-rs'
import {
  AnonCredsCredentialDefinitionPrivateRecord,
  AnonCredsCredentialDefinitionPrivateRepository,
  AnonCredsCredentialDefinitionRecord,
  AnonCredsCredentialDefinitionRepository,
  AnonCredsCredentialRepository,
  AnonCredsKeyCorrectnessProofRecord,
  AnonCredsKeyCorrectnessProofRepository,
  AnonCredsLinkSecretRecord,
  AnonCredsLinkSecretRepository,
} from '../../repository'
import {
  AnonCredsHolderServiceSymbol,
  AnonCredsIssuerServiceSymbol,
  AnonCredsVerifierServiceSymbol,
} from '../../services'
import { AnonCredsRegistryService } from '../../services/registry/AnonCredsRegistryService'
import {
  getUnqualifiedCredentialDefinitionId,
  getUnqualifiedSchemaId,
  parseIndyCredentialDefinitionId,
  parseIndySchemaId,
} from '../../utils/indyIdentifiers'
import { LegacyIndyCredentialFormatService } from '../LegacyIndyCredentialFormatService'
import { LegacyIndyProofFormatService } from '../LegacyIndyProofFormatService'

const registry = new InMemoryAnonCredsRegistry()
const anonCredsModuleConfig = new AnonCredsModuleConfig({
  registries: [registry],
  anoncreds,
  autoCreateLinkSecret: false,
})

const agentConfig = getAgentConfig('LegacyIndyFormatServicesTest')
const anonCredsVerifierService = new AnonCredsRsVerifierService()
const anonCredsHolderService = new AnonCredsRsHolderService()
const anonCredsIssuerService = new AnonCredsRsIssuerService()
const wallet = new InMemoryWallet()
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const storageService = new InMemoryStorageService<any>()
const eventEmitter = new EventEmitter(agentDependencies, new Subject())
const anonCredsLinkSecretRepository = new AnonCredsLinkSecretRepository(storageService, eventEmitter)
const anonCredsCredentialDefinitionRepository = new AnonCredsCredentialDefinitionRepository(
  storageService,
  eventEmitter
)
const anonCredsCredentialDefinitionPrivateRepository = new AnonCredsCredentialDefinitionPrivateRepository(
  storageService,
  eventEmitter
)

const inMemoryStorageService = new InMemoryStorageService()
const anonCredsCredentialRepository = new AnonCredsCredentialRepository(storageService, eventEmitter)
const anonCredsKeyCorrectnessProofRepository = new AnonCredsKeyCorrectnessProofRepository(storageService, eventEmitter)
const agentContext = getAgentContext({
  registerInstances: [
    [InjectionSymbols.Stop$, new Subject<boolean>()],
    [InjectionSymbols.AgentDependencies, agentDependencies],
    [InjectionSymbols.FileSystem, new agentDependencies.FileSystem()],
    [InjectionSymbols.StorageService, inMemoryStorageService],
    [InjectionSymbols.Logger, testLogger],
    [AnonCredsIssuerServiceSymbol, anonCredsIssuerService],
    [AnonCredsHolderServiceSymbol, anonCredsHolderService],
    [AnonCredsVerifierServiceSymbol, anonCredsVerifierService],
    [DidResolverService, new DidResolverService(testLogger, new DidsModuleConfig(), {} as unknown as DidRepository)],
    [AnonCredsRegistryService, new AnonCredsRegistryService()],
    [AnonCredsModuleConfig, anonCredsModuleConfig],
    [AnonCredsLinkSecretRepository, anonCredsLinkSecretRepository],
    [AnonCredsCredentialDefinitionRepository, anonCredsCredentialDefinitionRepository],
    [AnonCredsCredentialDefinitionPrivateRepository, anonCredsCredentialDefinitionPrivateRepository],
    [AnonCredsCredentialRepository, anonCredsCredentialRepository],
    [AnonCredsKeyCorrectnessProofRepository, anonCredsKeyCorrectnessProofRepository],
    [W3cCredentialsModuleConfig, new W3cCredentialsModuleConfig()],
    [InjectionSymbols.StorageService, storageService],
    [SignatureSuiteToken, 'default'],
  ],
  agentConfig,
  wallet,
})

const indyCredentialFormatService = new LegacyIndyCredentialFormatService()
const indyProofFormatService = new LegacyIndyProofFormatService()

// We can split up these tests when we can use AnonCredsRS as a backend, but currently
// we need to have the link secrets etc in the wallet which is not so easy to do with Indy
describe('Legacy indy format services', () => {
  beforeEach(async () => {
    await wallet.createAndOpen(agentConfig.walletConfig)
  })

  afterEach(async () => {
    await wallet.delete()
  })

  test('issuance and verification flow starting from proposal without negotiation and without revocation', async () => {
    // This is just so we don't have to register an actual indy did (as we don't have the indy did registrar configured)
    const key = await wallet.createKey({ keyType: KeyType.Ed25519 })
    const unqualifiedIndyDid = indyDidFromPublicKeyBase58(key.publicKeyBase58)
    const indyDid = `did:indy:pool1:${unqualifiedIndyDid}`

    // Create link secret
    const { linkSecretValue } = await anonCredsHolderService.createLinkSecret(agentContext, {
      linkSecretId: 'link-secret-id',
    })
    const anonCredsLinkSecret = new AnonCredsLinkSecretRecord({
      linkSecretId: 'link-secret-id',
      value: linkSecretValue,
    })
    anonCredsLinkSecret.setTag('isDefault', true)
    await anonCredsLinkSecretRepository.save(agentContext, anonCredsLinkSecret)

    const schema = await anonCredsIssuerService.createSchema(agentContext, {
      attrNames: ['name', 'age'],
      issuerId: indyDid,
      name: 'Employee Credential',
      version: '1.0.0',
    })

    const { schemaState } = await registry.registerSchema(agentContext, {
      schema,
      options: {},
    })

    const { credentialDefinition, credentialDefinitionPrivate, keyCorrectnessProof } =
      await anonCredsIssuerService.createCredentialDefinition(agentContext, {
        issuerId: indyDid,
        schemaId: schemaState.schemaId as string,
        schema,
        tag: 'Employee Credential',
        supportRevocation: false,
      })

    const { credentialDefinitionState } = await registry.registerCredentialDefinition(agentContext, {
      credentialDefinition,
      options: {},
    })

    if (
      !credentialDefinitionState.credentialDefinition ||
      !credentialDefinitionState.credentialDefinitionId ||
      !schemaState.schema ||
      !schemaState.schemaId
    ) {
      throw new Error('Failed to create schema or credential definition')
    }

    await anonCredsCredentialDefinitionRepository.save(
      agentContext,
      new AnonCredsCredentialDefinitionRecord({
        credentialDefinition,
        credentialDefinitionId: credentialDefinitionState.credentialDefinitionId,
        methodName: 'indy',
      })
    )

    if (!keyCorrectnessProof || !credentialDefinitionPrivate) {
      throw new Error('Failed to create credential definition private or key correctness proof')
    }

    await anonCredsKeyCorrectnessProofRepository.save(
      agentContext,
      new AnonCredsKeyCorrectnessProofRecord({
        credentialDefinitionId: credentialDefinitionState.credentialDefinitionId,
        value: keyCorrectnessProof,
      })
    )

    await anonCredsCredentialDefinitionPrivateRepository.save(
      agentContext,
      new AnonCredsCredentialDefinitionPrivateRecord({
        credentialDefinitionId: credentialDefinitionState.credentialDefinitionId,
        value: credentialDefinitionPrivate,
      })
    )

    const holderCredentialRecord = new CredentialExchangeRecord({
      protocolVersion: 'v1',
      state: CredentialState.ProposalSent,
      role: CredentialRole.Holder,
      threadId: 'f365c1a5-2baf-4873-9432-fa87c888a0aa',
    })

    const issuerCredentialRecord = new CredentialExchangeRecord({
      protocolVersion: 'v1',
      state: CredentialState.ProposalReceived,
      role: CredentialRole.Issuer,
      threadId: 'f365c1a5-2baf-4873-9432-fa87c888a0aa',
    })

    const credentialAttributes = [
      new CredentialPreviewAttribute({
        name: 'name',
        value: 'John',
      }),
      new CredentialPreviewAttribute({
        name: 'age',
        value: '25',
      }),
    ]

    const cd = parseIndyCredentialDefinitionId(credentialDefinitionState.credentialDefinitionId)
    const legacyCredentialDefinitionId = getUnqualifiedCredentialDefinitionId(
      cd.namespaceIdentifier,
      cd.schemaSeqNo,
      cd.tag
    )

    const s = parseIndySchemaId(schemaState.schemaId)
    const legacySchemaId = getUnqualifiedSchemaId(s.namespaceIdentifier, s.schemaName, s.schemaVersion)

    // Holder creates proposal
    holderCredentialRecord.credentialAttributes = credentialAttributes
    const { attachment: proposalAttachment } = await indyCredentialFormatService.createProposal(agentContext, {
      credentialRecord: holderCredentialRecord,
      credentialFormats: {
        indy: {
          attributes: credentialAttributes,
          credentialDefinitionId: legacyCredentialDefinitionId,
        },
      },
    })

    // Issuer processes and accepts proposal
    await indyCredentialFormatService.processProposal(agentContext, {
      credentialRecord: issuerCredentialRecord,
      attachment: proposalAttachment,
    })
    // Set attributes on the credential record, this is normally done by the protocol service
    issuerCredentialRecord.credentialAttributes = credentialAttributes
    const { attachment: offerAttachment } = await indyCredentialFormatService.acceptProposal(agentContext, {
      credentialRecord: issuerCredentialRecord,
      proposalAttachment: proposalAttachment,
    })

    // Holder processes and accepts offer
    await indyCredentialFormatService.processOffer(agentContext, {
      credentialRecord: holderCredentialRecord,
      attachment: offerAttachment,
    })
    const { attachment: requestAttachment } = await indyCredentialFormatService.acceptOffer(agentContext, {
      credentialRecord: holderCredentialRecord,
      offerAttachment,
    })

    // Make sure the request contains a prover_did field
    expect((requestAttachment.getDataAsJson() as AnonCredsCredentialRequest).prover_did).toBeDefined()

    // Issuer processes and accepts request
    await indyCredentialFormatService.processRequest(agentContext, {
      credentialRecord: issuerCredentialRecord,
      attachment: requestAttachment,
    })
    const { attachment: credentialAttachment } = await indyCredentialFormatService.acceptRequest(agentContext, {
      credentialRecord: issuerCredentialRecord,
      requestAttachment,
      offerAttachment,
    })

    // Holder processes and accepts credential
    await indyCredentialFormatService.processCredential(agentContext, {
      offerAttachment,
      credentialRecord: holderCredentialRecord,
      attachment: credentialAttachment,
      requestAttachment,
    })

    expect(holderCredentialRecord.credentials).toEqual([
      { credentialRecordType: 'w3c', credentialRecordId: expect.any(String) },
    ])

    const credentialId = holderCredentialRecord.credentials[0].credentialRecordId
    const anonCredsCredential = await anonCredsHolderService.getCredential(agentContext, {
      id: credentialId,
    })

    expect(anonCredsCredential).toEqual({
      credentialId,
      attributes: {
        age: 25,
        name: 'John',
      },
      schemaId: schemaState.schemaId,
      linkSecretId: 'link-secret-id',
      credentialDefinitionId: credentialDefinitionState.credentialDefinitionId,
      revocationRegistryId: null,
      credentialRevocationId: null,
      methodName: 'inMemory',
      createdAt: expect.any(Date),
      updatedAt: expect.any(Date),
    })

    expect(holderCredentialRecord.metadata.data).toEqual({
      '_anoncreds/credential': {
        schemaId: legacySchemaId,
        credentialDefinitionId: legacyCredentialDefinitionId,
      },
      '_anoncreds/credentialRequest': {
        link_secret_blinding_data: expect.any(Object),
        link_secret_name: expect.any(String),
        nonce: expect.any(String),
      },
    })

    expect(issuerCredentialRecord.metadata.data).toEqual({
      '_anoncreds/credential': {
        schemaId: legacySchemaId,
        credentialDefinitionId: legacyCredentialDefinitionId,
      },
    })

    const holderProofRecord = new ProofExchangeRecord({
      protocolVersion: 'v1',
      state: ProofState.ProposalSent,
      role: ProofRole.Prover,
      threadId: '4f5659a4-1aea-4f42-8c22-9a9985b35e38',
    })
    const verifierProofRecord = new ProofExchangeRecord({
      protocolVersion: 'v1',
      state: ProofState.ProposalReceived,
      role: ProofRole.Verifier,
      threadId: '4f5659a4-1aea-4f42-8c22-9a9985b35e38',
    })

    const { attachment: proofProposalAttachment } = await indyProofFormatService.createProposal(agentContext, {
      proofFormats: {
        indy: {
          attributes: [
            {
              name: 'name',
              credentialDefinitionId: legacyCredentialDefinitionId,
              value: 'John',
              referent: '1',
            },
          ],
          predicates: [
            {
              credentialDefinitionId: legacyCredentialDefinitionId,
              name: 'age',
              predicate: '>=',
              threshold: 18,
            },
          ],
          name: 'Proof Request',
          version: '1.0',
        },
      },
      proofRecord: holderProofRecord,
    })

    await indyProofFormatService.processProposal(agentContext, {
      attachment: proofProposalAttachment,
      proofRecord: verifierProofRecord,
    })

    const { attachment: proofRequestAttachment } = await indyProofFormatService.acceptProposal(agentContext, {
      proofRecord: verifierProofRecord,
      proposalAttachment: proofProposalAttachment,
    })

    await indyProofFormatService.processRequest(agentContext, {
      attachment: proofRequestAttachment,
      proofRecord: holderProofRecord,
    })

    const { attachment: proofAttachment } = await indyProofFormatService.acceptRequest(agentContext, {
      proofRecord: holderProofRecord,
      requestAttachment: proofRequestAttachment,
      proposalAttachment: proofProposalAttachment,
    })

    const isValid = await indyProofFormatService.processPresentation(agentContext, {
      attachment: proofAttachment,
      proofRecord: verifierProofRecord,
      requestAttachment: proofRequestAttachment,
    })

    expect(isValid).toBe(true)
  })
})
