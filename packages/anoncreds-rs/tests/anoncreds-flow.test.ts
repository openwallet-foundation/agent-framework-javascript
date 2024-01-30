import type { AnonCredsCredentialRequest } from '@credo-ts/anoncreds'
import type { Wallet } from '@credo-ts/core'

import {
  AnonCredsRevocationRegistryDefinitionPrivateRecord,
  AnonCredsRevocationRegistryDefinitionPrivateRepository,
  AnonCredsRevocationRegistryDefinitionRecord,
  AnonCredsRevocationRegistryDefinitionRepository,
  AnonCredsRevocationRegistryState,
  AnonCredsModuleConfig,
  AnonCredsHolderServiceSymbol,
  AnonCredsIssuerServiceSymbol,
  AnonCredsVerifierServiceSymbol,
  AnonCredsSchemaRecord,
  AnonCredsSchemaRepository,
  AnonCredsCredentialDefinitionRepository,
  AnonCredsCredentialDefinitionRecord,
  AnonCredsCredentialDefinitionPrivateRepository,
  AnonCredsCredentialDefinitionPrivateRecord,
  AnonCredsKeyCorrectnessProofRepository,
  AnonCredsKeyCorrectnessProofRecord,
  AnonCredsLinkSecretRepository,
  AnonCredsLinkSecretRecord,
  AnonCredsProofFormatService,
  AnonCredsCredentialFormatService,
} from '@credo-ts/anoncreds'
import {
  CredentialState,
  CredentialExchangeRecord,
  CredentialPreviewAttribute,
  InjectionSymbols,
  ProofState,
  ProofExchangeRecord,
} from '@credo-ts/core'
import { Subject } from 'rxjs'

import { InMemoryStorageService } from '../../../tests/InMemoryStorageService'
import { AnonCredsRegistryService } from '../../anoncreds/src/services/registry/AnonCredsRegistryService'
import { dateToTimestamp } from '../../anoncreds/src/utils/timestamp'
import { InMemoryAnonCredsRegistry } from '../../anoncreds/tests/InMemoryAnonCredsRegistry'
import { agentDependencies, getAgentConfig, getAgentContext } from '../../core/tests/helpers'
import { AnonCredsRsHolderService } from '../src/services/AnonCredsRsHolderService'
import { AnonCredsRsIssuerService } from '../src/services/AnonCredsRsIssuerService'
import { AnonCredsRsVerifierService } from '../src/services/AnonCredsRsVerifierService'

import { InMemoryTailsFileService } from './InMemoryTailsFileService'

const registry = new InMemoryAnonCredsRegistry()
const tailsFileService = new InMemoryTailsFileService()
const anonCredsModuleConfig = new AnonCredsModuleConfig({
  registries: [registry],
  tailsFileService,
})

const agentConfig = getAgentConfig('AnonCreds format services using anoncreds-rs')
const anonCredsVerifierService = new AnonCredsRsVerifierService()
const anonCredsHolderService = new AnonCredsRsHolderService()
const anonCredsIssuerService = new AnonCredsRsIssuerService()

const wallet = { generateNonce: () => Promise.resolve('947121108704767252195123') } as Wallet

const inMemoryStorageService = new InMemoryStorageService()
const agentContext = getAgentContext({
  registerInstances: [
    [InjectionSymbols.Stop$, new Subject<boolean>()],
    [InjectionSymbols.AgentDependencies, agentDependencies],
    [InjectionSymbols.FileSystem, new agentDependencies.FileSystem()],
    [InjectionSymbols.StorageService, inMemoryStorageService],
    [AnonCredsIssuerServiceSymbol, anonCredsIssuerService],
    [AnonCredsHolderServiceSymbol, anonCredsHolderService],
    [AnonCredsVerifierServiceSymbol, anonCredsVerifierService],
    [AnonCredsRegistryService, new AnonCredsRegistryService()],
    [AnonCredsModuleConfig, anonCredsModuleConfig],
  ],
  agentConfig,
  wallet,
})

const anoncredsCredentialFormatService = new AnonCredsCredentialFormatService()
const anoncredsProofFormatService = new AnonCredsProofFormatService()

const indyDid = 'did:indy:local:LjgpST2rjsoxYegQDRm7EL'

describe('AnonCreds format services using anoncreds-rs', () => {
  afterEach(() => {
    inMemoryStorageService.records = {}
  })

  test('issuance and verification flow starting from proposal without negotiation and without revocation', async () => {
    await anonCredsFlowTest({ issuerId: indyDid, revocable: false })
  })

  test('issuance and verification flow starting from proposal without negotiation and with revocation', async () => {
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
      issuerId: indyDid,
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
        issuerId: indyDid,
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
      issuerId: indyDid,
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
  })

  const issuerCredentialRecord = new CredentialExchangeRecord({
    protocolVersion: 'v1',
    state: CredentialState.ProposalReceived,
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

  // Holder creates proposal
  holderCredentialRecord.credentialAttributes = credentialAttributes
  const { attachment: proposalAttachment } = await anoncredsCredentialFormatService.createProposal(agentContext, {
    credentialRecord: holderCredentialRecord,
    credentialFormats: {
      anoncreds: {
        attributes: credentialAttributes,
        credentialDefinitionId: credentialDefinitionState.credentialDefinitionId,
      },
    },
  })

  // Issuer processes and accepts proposal
  await anoncredsCredentialFormatService.processProposal(agentContext, {
    credentialRecord: issuerCredentialRecord,
    attachment: proposalAttachment,
  })
  // Set attributes on the credential record, this is normally done by the protocol service
  issuerCredentialRecord.credentialAttributes = credentialAttributes

  // If revocable, specify revocation registry definition id and index
  const credentialFormats = revocable
    ? { anoncreds: { revocationRegistryDefinitionId, revocationRegistryIndex: 1 } }
    : undefined

  const { attachment: offerAttachment } = await anoncredsCredentialFormatService.acceptProposal(agentContext, {
    credentialRecord: issuerCredentialRecord,
    proposalAttachment: proposalAttachment,
    credentialFormats,
  })

  // Holder processes and accepts offer
  await anoncredsCredentialFormatService.processOffer(agentContext, {
    credentialRecord: holderCredentialRecord,
    attachment: offerAttachment,
  })
  const { attachment: requestAttachment } = await anoncredsCredentialFormatService.acceptOffer(agentContext, {
    credentialRecord: holderCredentialRecord,
    offerAttachment,
    credentialFormats: {
      anoncreds: {
        linkSecretId: linkSecret.linkSecretId,
      },
    },
  })

  // Make sure the request contains an entropy and does not contain a prover_did field
  expect((requestAttachment.getDataAsJson() as AnonCredsCredentialRequest).entropy).toBeDefined()
  expect((requestAttachment.getDataAsJson() as AnonCredsCredentialRequest).prover_did).toBeUndefined()

  // Issuer processes and accepts request
  await anoncredsCredentialFormatService.processRequest(agentContext, {
    credentialRecord: issuerCredentialRecord,
    attachment: requestAttachment,
  })
  const { attachment: credentialAttachment } = await anoncredsCredentialFormatService.acceptRequest(agentContext, {
    credentialRecord: issuerCredentialRecord,
    requestAttachment,
    offerAttachment,
  })

  // Holder processes and accepts credential
  await anoncredsCredentialFormatService.processCredential(agentContext, {
    credentialRecord: holderCredentialRecord,
    attachment: credentialAttachment,
    requestAttachment,
  })

  expect(holderCredentialRecord.credentials).toEqual([
    { credentialRecordType: 'anoncreds', credentialRecordId: expect.any(String) },
  ])

  const credentialId = holderCredentialRecord.credentials[0].credentialRecordId
  const anonCredsCredential = await anonCredsHolderService.getCredential(agentContext, {
    credentialId,
  })

  expect(anonCredsCredential).toEqual({
    credentialId,
    attributes: {
      age: '25',
      name: 'John',
    },
    schemaId: schemaState.schemaId,
    credentialDefinitionId: credentialDefinitionState.credentialDefinitionId,
    revocationRegistryId: revocable ? revocationRegistryDefinitionId : null,
    credentialRevocationId: revocable ? '1' : null,
    methodName: 'inMemory',
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
    threadId: '4f5659a4-1aea-4f42-8c22-9a9985b35e38',
  })
  const verifierProofRecord = new ProofExchangeRecord({
    protocolVersion: 'v1',
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
