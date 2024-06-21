import type { AnonCredsProofRequest } from '@credo-ts/anoncreds'
import type { DidRepository } from '@credo-ts/core'

import {
  DidResolverService,
  DidsModuleConfig,
  InjectionSymbols,
  SignatureSuiteToken,
  W3cCredentialsModuleConfig,
} from '@credo-ts/core'
import { anoncreds } from '@hyperledger/anoncreds-nodejs'
import { Subject } from 'rxjs'

import { InMemoryStorageService } from '../../../../../tests/InMemoryStorageService'
import { InMemoryWallet } from '../../../../../tests/InMemoryWallet'
import { InMemoryAnonCredsRegistry } from '../../../../anoncreds/tests/InMemoryAnonCredsRegistry'
import { testLogger } from '../../../../core/tests'
import { agentDependencies, getAgentConfig, getAgentContext } from '../../../../core/tests/helpers'
import { encodeCredentialValue } from '../../utils/credential'
import { AnonCredsRsHolderService } from '../AnonCredsRsHolderService'
import { AnonCredsRsIssuerService } from '../AnonCredsRsIssuerService'
import { AnonCredsRsVerifierService } from '../AnonCredsRsVerifierService'

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
  AnonCredsSchemaRecord,
  AnonCredsSchemaRepository,
  AnonCredsVerifierServiceSymbol,
  getUnqualifiedCredentialDefinitionId,
  getUnqualifiedSchemaId,
  parseIndyCredentialDefinitionId,
  parseIndySchemaId,
} from '@credo-ts/anoncreds'

const agentConfig = getAgentConfig('AnonCredsCredentialFormatServiceTest')
const anonCredsVerifierService = new AnonCredsRsVerifierService()
const anonCredsHolderService = new AnonCredsRsHolderService()
const anonCredsIssuerService = new AnonCredsRsIssuerService()
const storageService = new InMemoryStorageService()
const wallet = new InMemoryWallet()
const registry = new InMemoryAnonCredsRegistry()

const agentContext = getAgentContext({
  wallet,
  registerInstances: [
    [InjectionSymbols.Stop$, new Subject<boolean>()],
    [InjectionSymbols.AgentDependencies, agentDependencies],
    [InjectionSymbols.StorageService, storageService],
    [AnonCredsIssuerServiceSymbol, anonCredsIssuerService],
    [AnonCredsHolderServiceSymbol, anonCredsHolderService],
    [AnonCredsVerifierServiceSymbol, anonCredsVerifierService],
    [
      AnonCredsModuleConfig,
      new AnonCredsModuleConfig({
        registries: [registry],
        anoncreds,
      }),
    ],

    [InjectionSymbols.Logger, testLogger],
    [DidResolverService, new DidResolverService(testLogger, new DidsModuleConfig(), {} as unknown as DidRepository)],
    [W3cCredentialsModuleConfig, new W3cCredentialsModuleConfig()],
    [SignatureSuiteToken, 'default'],
  ],
  agentConfig,
})

describe('AnonCredsRsServices', () => {
  test('issuance flow without revocation', async () => {
    const issuerId = 'did:indy:pool:localtest:TL1EaPFCZ8Si5aUrqScBDt'

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

    const { credentialDefinition, credentialDefinitionPrivate, keyCorrectnessProof } =
      await anonCredsIssuerService.createCredentialDefinition(agentContext, {
        issuerId,
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

    if (!credentialDefinitionPrivate || !keyCorrectnessProof) {
      throw new Error('Failed to get private part of credential definition')
    }

    await agentContext.dependencyManager.resolve(AnonCredsSchemaRepository).save(
      agentContext,
      new AnonCredsSchemaRecord({
        schema: schemaState.schema,
        schemaId: schemaState.schemaId,
        methodName: 'inMemory',
      })
    )

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

    const credentialOffer = await anonCredsIssuerService.createCredentialOffer(agentContext, {
      credentialDefinitionId: credentialDefinitionState.credentialDefinitionId,
    })

    const linkSecret = await anonCredsHolderService.createLinkSecret(agentContext, { linkSecretId: 'linkSecretId' })
    expect(linkSecret.linkSecretId).toBe('linkSecretId')

    await agentContext.dependencyManager.resolve(AnonCredsLinkSecretRepository).save(
      agentContext,
      new AnonCredsLinkSecretRecord({
        value: linkSecret.linkSecretValue,
        linkSecretId: linkSecret.linkSecretId,
      })
    )

    const credentialRequestState = await anonCredsHolderService.createCredentialRequest(agentContext, {
      credentialDefinition: credentialDefinitionState.credentialDefinition,
      credentialOffer,
      linkSecretId: linkSecret.linkSecretId,
    })

    const { credential } = await anonCredsIssuerService.createCredential(agentContext, {
      credentialOffer,
      credentialRequest: credentialRequestState.credentialRequest,
      credentialValues: {
        name: { raw: 'John', encoded: encodeCredentialValue('John') },
        age: { raw: '25', encoded: encodeCredentialValue('25') },
      },
    })

    const credentialId = await anonCredsHolderService.storeCredential(agentContext, {
      credential,
      credentialDefinition,
      schema,
      credentialDefinitionId: credentialDefinitionState.credentialDefinitionId,
      credentialRequestMetadata: credentialRequestState.credentialRequestMetadata,
    })

    const credentialInfo = await anonCredsHolderService.getCredential(agentContext, {
      id: credentialId,
    })

    expect(credentialInfo).toEqual({
      credentialId,
      attributes: {
        age: 25,
        name: 'John',
      },
      linkSecretId: 'linkSecretId',
      schemaId: schemaState.schemaId,
      credentialDefinitionId: credentialDefinitionState.credentialDefinitionId,
      revocationRegistryId: null,
      credentialRevocationId: null,
      methodName: 'inMemory',
      createdAt: expect.any(Date),
      updatedAt: expect.any(Date),
    })

    const proofRequest: AnonCredsProofRequest = {
      nonce: anoncreds.generateNonce(),
      name: 'pres_req_1',
      version: '0.1',
      requested_attributes: {
        attr1_referent: {
          name: 'name',
        },
      },
      requested_predicates: {
        predicate1_referent: { name: 'age', p_type: '>=' as const, p_value: 18 },
      },
    }

    const proof = await anonCredsHolderService.createProof(agentContext, {
      credentialDefinitions: { [credentialDefinitionState.credentialDefinitionId]: credentialDefinition },
      proofRequest,
      selectedCredentials: {
        attributes: {
          attr1_referent: { credentialId, credentialInfo, revealed: true },
        },
        predicates: {
          predicate1_referent: { credentialId, credentialInfo },
        },
        selfAttestedAttributes: {},
      },
      schemas: { [schemaState.schemaId]: schema },
      revocationRegistries: {},
    })

    const verifiedProof = await anonCredsVerifierService.verifyProof(agentContext, {
      credentialDefinitions: { [credentialDefinitionState.credentialDefinitionId]: credentialDefinition },
      proof,
      proofRequest,
      schemas: { [schemaState.schemaId]: schema },
      revocationRegistries: {},
    })

    expect(verifiedProof).toBeTruthy()
  })

  test('issuance flow with unqualified identifiers', async () => {
    // Use qualified identifiers to create schema and credential definition (we only support qualified identifiers for these)
    const issuerId = 'did:indy:pool:localtest:A4CYPASJYRZRt98YWrac3H'

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

    const { credentialDefinition, credentialDefinitionPrivate, keyCorrectnessProof } =
      await anonCredsIssuerService.createCredentialDefinition(agentContext, {
        issuerId,
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

    if (!credentialDefinitionPrivate || !keyCorrectnessProof) {
      throw new Error('Failed to get private part of credential definition')
    }

    await agentContext.dependencyManager.resolve(AnonCredsSchemaRepository).save(
      agentContext,
      new AnonCredsSchemaRecord({
        schema: schemaState.schema,
        schemaId: schemaState.schemaId,
        methodName: 'inMemory',
      })
    )

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

    const { namespaceIdentifier, schemaSeqNo, tag } = parseIndyCredentialDefinitionId(
      credentialDefinitionState.credentialDefinitionId
    )
    const unqualifiedCredentialDefinitionId = getUnqualifiedCredentialDefinitionId(
      namespaceIdentifier,
      schemaSeqNo,
      tag
    )

    const parsedSchema = parseIndySchemaId(schemaState.schemaId)
    const unqualifiedSchemaId = getUnqualifiedSchemaId(
      parsedSchema.namespaceIdentifier,
      parsedSchema.schemaName,
      parsedSchema.schemaVersion
    )

    // Create offer with unqualified credential definition id
    const credentialOffer = await anonCredsIssuerService.createCredentialOffer(agentContext, {
      credentialDefinitionId: unqualifiedCredentialDefinitionId,
    })

    const linkSecret = await anonCredsHolderService.createLinkSecret(agentContext, { linkSecretId: 'someLinkSecretId' })
    expect(linkSecret.linkSecretId).toBe('someLinkSecretId')

    await agentContext.dependencyManager.resolve(AnonCredsLinkSecretRepository).save(
      agentContext,
      new AnonCredsLinkSecretRecord({
        value: linkSecret.linkSecretValue,
        linkSecretId: linkSecret.linkSecretId,
      })
    )

    const unqualifiedCredentialDefinition = await registry.getCredentialDefinition(
      agentContext,
      credentialOffer.cred_def_id
    )
    const unqualifiedSchema = await registry.getSchema(agentContext, credentialOffer.schema_id)
    if (!unqualifiedCredentialDefinition.credentialDefinition || !unqualifiedSchema.schema) {
      throw new Error('unable to fetch credential definition or schema')
    }

    const credentialRequestState = await anonCredsHolderService.createCredentialRequest(agentContext, {
      credentialDefinition: unqualifiedCredentialDefinition.credentialDefinition,
      credentialOffer,
      linkSecretId: linkSecret.linkSecretId,
    })

    const { credential } = await anonCredsIssuerService.createCredential(agentContext, {
      credentialOffer,
      credentialRequest: credentialRequestState.credentialRequest,
      credentialValues: {
        name: { raw: 'John', encoded: encodeCredentialValue('John') },
        age: { raw: '25', encoded: encodeCredentialValue('25') },
      },
    })

    // store credential now requires qualified identifiers
    const credentialId = await anonCredsHolderService.storeCredential(agentContext, {
      credential,
      credentialDefinition,
      schema,
      credentialDefinitionId: credentialDefinitionState.credentialDefinitionId,
      credentialRequestMetadata: credentialRequestState.credentialRequestMetadata,
    })

    const credentialInfo = await anonCredsHolderService.getCredential(agentContext, {
      id: credentialId,
    })

    expect(credentialInfo).toEqual({
      credentialId,
      attributes: {
        age: 25,
        name: 'John',
      },
      linkSecretId: 'someLinkSecretId',
      schemaId: schemaState.schemaId,
      credentialDefinitionId: credentialDefinitionState.credentialDefinitionId,
      revocationRegistryId: null,
      credentialRevocationId: null,
      methodName: 'inMemory',
      createdAt: expect.any(Date),
      updatedAt: expect.any(Date),
    })

    const proofRequest: AnonCredsProofRequest = {
      nonce: anoncreds.generateNonce(),
      name: 'pres_req_1',
      version: '0.1',
      requested_attributes: {
        attr1_referent: {
          name: 'name',
        },
      },
      requested_predicates: {
        predicate1_referent: { name: 'age', p_type: '>=' as const, p_value: 18 },
      },
    }

    const proof = await anonCredsHolderService.createProof(agentContext, {
      credentialDefinitions: { [unqualifiedCredentialDefinitionId]: credentialDefinition },
      proofRequest,
      selectedCredentials: {
        attributes: {
          attr1_referent: { credentialId, credentialInfo, revealed: true },
        },
        predicates: {
          predicate1_referent: { credentialId, credentialInfo },
        },
        selfAttestedAttributes: {},
      },
      schemas: { [unqualifiedSchemaId]: schema },
      revocationRegistries: {},
    })

    const verifiedProof = await anonCredsVerifierService.verifyProof(agentContext, {
      credentialDefinitions: { [unqualifiedCredentialDefinitionId]: credentialDefinition },
      proof,
      proofRequest,
      schemas: { [unqualifiedSchemaId]: schema },
      revocationRegistries: {},
    })

    expect(verifiedProof).toBeTruthy()
  })
})
