import type { W3cAnonCredsCredentialMetadata } from '../../utils/metadata'
import type { AnonCredsCredentialTags } from '../../utils/w3cAnonCredsUtils'
import type {
  AnonCredsCredentialDefinition,
  AnonCredsProofRequest,
  AnonCredsRevocationStatusList,
  AnonCredsSchema,
  AnonCredsSelectedCredentials,
} from '@credo-ts/anoncreds'
import type { DidRepository } from '@credo-ts/core'
import type { JsonObject } from '@hyperledger/anoncreds-shared'

import {
  DidResolverService,
  DidsModuleConfig,
  InjectionSymbols,
  SignatureSuiteToken,
  W3cCredentialRecord,
  W3cCredentialRepository,
  W3cCredentialSubject,
  W3cCredentialsModuleConfig,
  W3cJsonLdVerifiableCredential,
} from '@credo-ts/core'
import { anoncreds } from '@hyperledger/anoncreds-nodejs'
import { Subject } from 'rxjs'

import { InMemoryStorageService } from '../../../../../tests/InMemoryStorageService'
import { AnonCredsCredentialDefinitionRepository } from '../../../../anoncreds/src/repository/AnonCredsCredentialDefinitionRepository'
import { AnonCredsLinkSecretRepository } from '../../../../anoncreds/src/repository/AnonCredsLinkSecretRepository'
import { InMemoryAnonCredsRegistry } from '../../../../anoncreds/tests/InMemoryAnonCredsRegistry'
import { testLogger } from '../../../../core/tests'
import { agentDependencies, getAgentConfig, getAgentContext, mockFunction } from '../../../../core/tests/helpers'
import { W3cAnonCredsCredentialMetadataKey } from '../../utils/metadata'
import { AnonCredsRsHolderService } from '../AnonCredsRsHolderService'

import { InMemoryWallet } from './../../../../../tests/InMemoryWallet'
import {
  createCredentialDefinition,
  createCredentialForHolder,
  createCredentialOffer,
  createLinkSecret,
  storeCredential,
} from './helpers'

import {
  AnonCredsCredentialRepository,
  AnonCredsModuleConfig,
  AnonCredsHolderServiceSymbol,
  AnonCredsLinkSecretRecord,
} from '@credo-ts/anoncreds'

const agentConfig = getAgentConfig('AnonCredsRsHolderServiceTest')
const anonCredsHolderService = new AnonCredsRsHolderService()

jest.mock('../../../../anoncreds/src/repository/AnonCredsCredentialDefinitionRepository')
const CredentialDefinitionRepositoryMock =
  AnonCredsCredentialDefinitionRepository as jest.Mock<AnonCredsCredentialDefinitionRepository>
const credentialDefinitionRepositoryMock = new CredentialDefinitionRepositoryMock()

jest.mock('../../../../anoncreds/src/repository/AnonCredsLinkSecretRepository')
const AnonCredsLinkSecretRepositoryMock = AnonCredsLinkSecretRepository as jest.Mock<AnonCredsLinkSecretRepository>
const anoncredsLinkSecretRepositoryMock = new AnonCredsLinkSecretRepositoryMock()

jest.mock('../../../../core/src/modules/vc/repository/W3cCredentialRepository')
const W3cCredentialRepositoryMock = W3cCredentialRepository as jest.Mock<W3cCredentialRepository>
const w3cCredentialRepositoryMock = new W3cCredentialRepositoryMock()

jest.mock('../../../../anoncreds/src/repository/AnonCredsCredentialRepository')
const AnonCredsCredentialRepositoryMock = AnonCredsCredentialRepository as jest.Mock<AnonCredsCredentialRepository>
const anoncredsCredentialRepositoryMock = new AnonCredsCredentialRepositoryMock()

const inMemoryStorageService = new InMemoryStorageService()

const wallet = new InMemoryWallet()

const agentContext = getAgentContext({
  registerInstances: [
    [InjectionSymbols.AgentDependencies, agentDependencies],
    [InjectionSymbols.StorageService, inMemoryStorageService],
    [InjectionSymbols.Stop$, new Subject<boolean>()],
    [AnonCredsCredentialDefinitionRepository, credentialDefinitionRepositoryMock],
    [AnonCredsLinkSecretRepository, anoncredsLinkSecretRepositoryMock],
    [W3cCredentialRepository, w3cCredentialRepositoryMock],
    [AnonCredsCredentialRepository, anoncredsCredentialRepositoryMock],
    [AnonCredsHolderServiceSymbol, anonCredsHolderService],
    [
      AnonCredsModuleConfig,
      new AnonCredsModuleConfig({
        registries: [new InMemoryAnonCredsRegistry({})],
        anoncreds,
      }),
    ],
    [InjectionSymbols.Logger, testLogger],
    [DidResolverService, new DidResolverService(testLogger, new DidsModuleConfig(), {} as unknown as DidRepository)],
    [W3cCredentialsModuleConfig, new W3cCredentialsModuleConfig()],
    [SignatureSuiteToken, 'default'],
  ],
  agentConfig,
  wallet,
})

describe('AnonCredsRsHolderService', () => {
  const getByCredentialIdMock = jest.spyOn(anoncredsCredentialRepositoryMock, 'getByCredentialId')
  const findByIdMock = jest.spyOn(w3cCredentialRepositoryMock, 'findById')
  const findByQueryMock = jest.spyOn(w3cCredentialRepositoryMock, 'findByQuery')

  beforeEach(() => {
    findByIdMock.mockClear()
    getByCredentialIdMock.mockClear()
    findByQueryMock.mockClear()
  })

  test('createCredentialRequest', async () => {
    mockFunction(anoncredsLinkSecretRepositoryMock.getByLinkSecretId).mockResolvedValue(
      new AnonCredsLinkSecretRecord({ linkSecretId: 'linkSecretId', value: createLinkSecret() })
    )

    const { credentialDefinition, keyCorrectnessProof } = createCredentialDefinition({
      attributeNames: ['phoneNumber'],
      issuerId: 'issuer:uri',
    })
    const credentialOffer = createCredentialOffer(keyCorrectnessProof)

    const { credentialRequest } = await anonCredsHolderService.createCredentialRequest(agentContext, {
      credentialDefinition,
      credentialOffer,
      linkSecretId: 'linkSecretId',
    })

    expect(credentialRequest.cred_def_id).toBe('creddef:uri')
    expect(credentialRequest.prover_did).toBeUndefined()
  })

  test('createLinkSecret', async () => {
    let linkSecret = await anonCredsHolderService.createLinkSecret(agentContext, {
      linkSecretId: 'linkSecretId',
    })

    expect(linkSecret.linkSecretId).toBe('linkSecretId')
    expect(linkSecret.linkSecretValue).toBeDefined()

    linkSecret = await anonCredsHolderService.createLinkSecret(agentContext)

    expect(linkSecret.linkSecretId).toBeDefined()
    expect(linkSecret.linkSecretValue).toBeDefined()
  })

  test('createProof', async () => {
    const proofRequest: AnonCredsProofRequest = {
      nonce: anoncreds.generateNonce(),
      name: 'pres_req_1',
      version: '0.1',
      requested_attributes: {
        attr1_referent: {
          name: 'name',
          restrictions: [{ issuer_did: 'issuer:uri' }],
        },
        attr2_referent: {
          name: 'phoneNumber',
        },
        attr4_referent: {
          names: ['name', 'height'],
        },
        attr5_referent: {
          name: 'favouriteSport',
        },
      },
      requested_predicates: {
        predicate1_referent: { name: 'age', p_type: '>=' as const, p_value: 18 },
      },
      //non_revoked: { from: 10, to: 200 },
    }

    const {
      schema: personSchema,
      credentialDefinition: personCredentialDefinition,
      credentialDefinitionPrivate: personCredentialDefinitionPrivate,
      keyCorrectnessProof: personKeyCorrectnessProof,
    } = createCredentialDefinition({
      attributeNames: ['name', 'age', 'sex', 'height'],
      issuerId: 'issuer:uri',
    })

    const {
      schema: phoneSchema,
      credentialDefinition: phoneCredentialDefinition,
      credentialDefinitionPrivate: phoneCredentialDefinitionPrivate,
      keyCorrectnessProof: phoneKeyCorrectnessProof,
    } = createCredentialDefinition({
      attributeNames: ['phoneNumber'],
      issuerId: 'issuer:uri',
    })

    const linkSecret = createLinkSecret()

    mockFunction(anoncredsLinkSecretRepositoryMock.getByLinkSecretId).mockResolvedValue(
      new AnonCredsLinkSecretRecord({ linkSecretId: 'linkSecretId', value: linkSecret })
    )

    const {
      credential: personCredential,
      credentialInfo: personCredentialInfo,
      revocationRegistryDefinition: personRevRegDef,
      tailsPath: personTailsPath,
    } = await createCredentialForHolder({
      agentContext,
      attributes: {
        name: 'John',
        sex: 'M',
        height: '179',
        age: '19',
      },
      credentialDefinition: personCredentialDefinition as unknown as JsonObject,
      schemaId: 'personschema:uri',
      credentialDefinitionId: 'personcreddef:uri',
      credentialDefinitionPrivate: personCredentialDefinitionPrivate,
      keyCorrectnessProof: personKeyCorrectnessProof,
      linkSecret,
      linkSecretId: 'linkSecretId',
      revocationRegistryDefinitionId: 'personrevregid:uri',
    })
    const personRecord = await storeCredential(agentContext, personCredential, {
      credentialDefinitionId: 'personcreddef:uri',
      schemaId: 'personschema:uri',
      schema: personSchema as unknown as AnonCredsSchema,
      linkSecretId: 'linkSecretId',
    })

    const {
      credential: phoneCredential,
      credentialInfo: phoneCredentialInfo,
      revocationRegistryDefinition: phoneRevRegDef,
      tailsPath: phoneTailsPath,
    } = await createCredentialForHolder({
      agentContext,
      attributes: {
        phoneNumber: 'linkSecretId56',
      },
      credentialDefinition: phoneCredentialDefinition as unknown as JsonObject,
      schemaId: 'phoneschema:uri',
      credentialDefinitionId: 'phonecreddef:uri',
      credentialDefinitionPrivate: phoneCredentialDefinitionPrivate,
      keyCorrectnessProof: phoneKeyCorrectnessProof,
      linkSecret,
      linkSecretId: 'linkSecretId',
      revocationRegistryDefinitionId: 'phonerevregid:uri',
    })

    const phoneRecord = await storeCredential(agentContext, phoneCredential, {
      credentialDefinitionId: 'phonecreddef:uri',
      schemaId: 'phoneschema:uri',
      schema: phoneSchema as unknown as AnonCredsSchema,
      linkSecretId: 'linkSecretId',
    })

    const selectedCredentials: AnonCredsSelectedCredentials = {
      selfAttestedAttributes: { attr5_referent: 'football' },
      attributes: {
        attr1_referent: {
          credentialId: personRecord.id,
          credentialInfo: { ...personCredentialInfo, credentialId: personRecord.id },
          revealed: true,
        },
        attr2_referent: {
          credentialId: phoneRecord.id,
          credentialInfo: { ...phoneCredentialInfo, credentialId: phoneRecord.id },
          revealed: true,
        },
        attr4_referent: {
          credentialId: personRecord.id,
          credentialInfo: { ...personCredentialInfo, credentialId: personRecord.id },
          revealed: true,
        },
      },
      predicates: {
        predicate1_referent: {
          credentialId: personRecord.id,
          credentialInfo: { ...personCredentialInfo, credentialId: personRecord.id },
        },
      },
    }

    findByIdMock.mockResolvedValueOnce(personRecord)
    findByIdMock.mockResolvedValueOnce(phoneRecord)

    const revocationRegistries = {
      'personrevregid:uri': {
        tailsFilePath: personTailsPath,
        definition: JSON.parse(anoncreds.getJson({ objectHandle: personRevRegDef })),
        revocationStatusLists: { '1': {} as AnonCredsRevocationStatusList },
      },
      'phonerevregid:uri': {
        tailsFilePath: phoneTailsPath,
        definition: JSON.parse(anoncreds.getJson({ objectHandle: phoneRevRegDef })),
        revocationStatusLists: { '1': {} as AnonCredsRevocationStatusList },
      },
    }

    await anonCredsHolderService.createProof(agentContext, {
      credentialDefinitions: {
        'personcreddef:uri': personCredentialDefinition as AnonCredsCredentialDefinition,
        'phonecreddef:uri': phoneCredentialDefinition as AnonCredsCredentialDefinition,
      },
      proofRequest,
      selectedCredentials,
      schemas: {
        'phoneschema:uri': { attrNames: ['phoneNumber'], issuerId: 'issuer:uri', name: 'phoneschema', version: '1' },
        'personschema:uri': {
          attrNames: ['name', 'sex', 'height', 'age'],
          issuerId: 'issuer:uri',
          name: 'personschema',
          version: '1',
        },
      },
      revocationRegistries,
    })

    expect(findByIdMock).toHaveBeenCalledTimes(2)
    // TODO: check proof object
  })

  describe('getCredentialsForProofRequest', () => {
    const findByQueryMock = jest.spyOn(w3cCredentialRepositoryMock, 'findByQuery')
    const anonCredsFindByQueryMock = jest.spyOn(anoncredsCredentialRepositoryMock, 'findByQuery')

    const proofRequest: AnonCredsProofRequest = {
      nonce: anoncreds.generateNonce(),
      name: 'pres_req_1',
      version: '0.1',
      requested_attributes: {
        attr1_referent: {
          name: 'name',
          restrictions: [{ issuer_did: 'issuer:uri' }],
        },
        attr2_referent: {
          name: 'phoneNumber',
        },
        attr4_referent: {
          names: ['name', 'height'],
          restrictions: [{ cred_def_id: 'crededefid:uri', issuer_id: 'issuerid:uri' }, { schema_version: '1.0' }],
        },
        attr5_referent: {
          name: 'name',
          restrictions: [{ 'attr::name::value': 'Alice', 'attr::name::marker': '1' }],
        },
      },
      requested_predicates: {
        predicate1_referent: { name: 'age', p_type: '>=' as const, p_value: 18 },
      },
    }

    beforeEach(() => {
      findByQueryMock.mockResolvedValue([])
      anonCredsFindByQueryMock.mockResolvedValue([])
    })

    afterEach(() => {
      findByQueryMock.mockClear()
      anonCredsFindByQueryMock.mockClear()
    })

    test('invalid referent', async () => {
      await expect(
        anonCredsHolderService.getCredentialsForProofRequest(agentContext, {
          proofRequest,
          attributeReferent: 'name',
        })
      ).rejects.toThrowError()
    })

    test('referent with single restriction', async () => {
      await anonCredsHolderService.getCredentialsForProofRequest(agentContext, {
        proofRequest,
        attributeReferent: 'attr1_referent',
      })

      expect(findByQueryMock).toHaveBeenCalledWith(agentContext, {
        $and: [
          {
            'anonCredsAttr::name::marker': true,
          },
          {
            issuerId: 'issuer:uri',
          },
        ],
      })
    })

    test('referent without restrictions', async () => {
      await anonCredsHolderService.getCredentialsForProofRequest(agentContext, {
        proofRequest,
        attributeReferent: 'attr2_referent',
      })

      expect(findByQueryMock).toHaveBeenCalledWith(agentContext, {
        $and: [
          {
            'anonCredsAttr::phoneNumber::marker': true,
          },
        ],
      })
    })

    test('referent with multiple names and restrictions', async () => {
      await anonCredsHolderService.getCredentialsForProofRequest(agentContext, {
        proofRequest,
        attributeReferent: 'attr4_referent',
      })

      expect(findByQueryMock).toHaveBeenCalledWith(agentContext, {
        $and: [
          {
            'anonCredsAttr::name::marker': true,
            'anonCredsAttr::height::marker': true,
          },
          {
            $or: [
              {
                anonCredsCredentialDefinitionId: 'crededefid:uri',
                issuerId: 'issuerid:uri',
              },
              {
                anonCredsSchemaVersion: '1.0',
              },
            ],
          },
        ],
      })
    })

    test('referent with attribute values and marker restriction', async () => {
      await anonCredsHolderService.getCredentialsForProofRequest(agentContext, {
        proofRequest,
        attributeReferent: 'attr5_referent',
      })

      expect(findByQueryMock).toHaveBeenCalledWith(agentContext, {
        $and: [
          {
            'anonCredsAttr::name::marker': true,
          },
          {
            'anonCredsAttr::name::value': 'Alice',
            'anonCredsAttr::name::marker': true,
          },
        ],
      })
    })

    test('predicate referent', async () => {
      await anonCredsHolderService.getCredentialsForProofRequest(agentContext, {
        proofRequest,
        attributeReferent: 'predicate1_referent',
      })

      expect(findByQueryMock).toHaveBeenCalledWith(agentContext, {
        $and: [
          {
            'anonCredsAttr::age::marker': true,
          },
        ],
      })
    })
  })

  test('deleteCredential', async () => {
    const record = new W3cCredentialRecord({
      credential: {} as W3cJsonLdVerifiableCredential,
      tags: {},
    })
    findByIdMock.mockResolvedValueOnce(null).mockResolvedValueOnce(record)
    getByCredentialIdMock.mockRejectedValueOnce(new Error())

    await expect(anonCredsHolderService.deleteCredential(agentContext, 'credentialId')).rejects.toThrow()
    await anonCredsHolderService.deleteCredential(agentContext, 'credentialId')
    expect(findByIdMock).toHaveBeenCalledWith(agentContext, 'credentialId')
  })

  test('get single Credential', async () => {
    const record = new W3cCredentialRecord({
      credential: new W3cJsonLdVerifiableCredential({
        credentialSubject: new W3cCredentialSubject({ claims: { attr1: 'value1', attr2: 'value2' } }),
        issuer: 'test',
        issuanceDate: Date.now().toString(),
        type: ['VerifiableCredential'],
        proof: {
          created: Date.now().toString(),
          type: 'test',
          proofPurpose: 'test',
          verificationMethod: 'test',
        },
      }),
      tags: {},
    })

    const tags: AnonCredsCredentialTags = {
      anonCredsLinkSecretId: 'linkSecretId',
      anonCredsCredentialDefinitionId: 'credDefId',
      anonCredsSchemaId: 'schemaId',
      anonCredsSchemaName: 'schemaName',
      anonCredsSchemaIssuerId: 'schemaIssuerId',
      anonCredsSchemaVersion: 'schemaVersion',
      anonCredsMethodName: 'methodName',
      anonCredsCredentialRevocationId: 'credentialRevocationId',
      anonCredsRevocationRegistryId: 'revRegId',
    }

    const anonCredsCredentialMetadata: W3cAnonCredsCredentialMetadata = {
      credentialRevocationId: tags.anonCredsCredentialRevocationId,
      linkSecretId: tags.anonCredsLinkSecretId,
      methodName: tags.anonCredsMethodName,
    }

    record.setTags(tags)
    record.metadata.set(W3cAnonCredsCredentialMetadataKey, anonCredsCredentialMetadata)

    findByIdMock.mockResolvedValueOnce(null).mockResolvedValueOnce(record)
    getByCredentialIdMock.mockRejectedValueOnce(new Error())

    await expect(anonCredsHolderService.getCredential(agentContext, { id: 'myCredentialId' })).rejects.toThrowError()

    const credentialInfo = await anonCredsHolderService.getCredential(agentContext, { id: 'myCredentialId' })

    expect(credentialInfo).toMatchObject({
      attributes: { attr1: 'value1', attr2: 'value2' },
      credentialDefinitionId: 'credDefId',
      credentialId: record.id,
      revocationRegistryId: 'revRegId',
      schemaId: 'schemaId',
      credentialRevocationId: 'credentialRevocationId',
    })
  })

  test('getCredentials', async () => {
    const record = new W3cCredentialRecord({
      credential: new W3cJsonLdVerifiableCredential({
        credentialSubject: new W3cCredentialSubject({ claims: { attr1: 'value1', attr2: 'value2' } }),
        issuer: 'test',
        issuanceDate: Date.now().toString(),
        type: ['VerifiableCredential'],
        proof: {
          created: Date.now().toString(),
          type: 'test',
          proofPurpose: 'test',
          verificationMethod: 'test',
        },
      }),
      tags: {},
    })
    const records = [record]

    const tags: AnonCredsCredentialTags = {
      anonCredsLinkSecretId: 'linkSecretId',
      anonCredsCredentialDefinitionId: 'credDefId',
      anonCredsSchemaId: 'schemaId',
      anonCredsSchemaName: 'schemaName',
      anonCredsSchemaIssuerId: 'schemaIssuerId',
      anonCredsSchemaVersion: 'schemaVersion',
      anonCredsMethodName: 'methodName',
      anonCredsCredentialRevocationId: 'credentialRevocationId',
      anonCredsRevocationRegistryId: 'revRegId',
    }

    const anonCredsCredentialMetadata: W3cAnonCredsCredentialMetadata = {
      credentialRevocationId: tags.anonCredsCredentialRevocationId,
      linkSecretId: tags.anonCredsLinkSecretId,
      methodName: tags.anonCredsMethodName,
    }

    record.setTags(tags)
    record.metadata.set(W3cAnonCredsCredentialMetadataKey, anonCredsCredentialMetadata)

    findByQueryMock.mockResolvedValueOnce(records)

    const credentialInfo = await anonCredsHolderService.getCredentials(agentContext, {
      credentialDefinitionId: 'credDefId',
      schemaId: 'schemaId',
      schemaIssuerId: 'schemaIssuerDid',
      schemaName: 'schemaName',
      schemaVersion: 'schemaVersion',
      issuerId: 'issuerDid',
      methodName: 'inMemory',
    })

    expect(findByQueryMock).toHaveBeenCalledWith(agentContext, {
      anonCredsCredentialDefinitionId: 'credDefId',
      anonCredsSchemaId: 'schemaId',
      anonCredsSchemaIssuerId: 'schemaIssuerDid',
      issuerId: 'issuerDid',
      anonCredsSchemaName: 'schemaName',
      anonCredsSchemaVersion: 'schemaVersion',
      anonCredsMethodName: 'inMemory',
    })
    expect(credentialInfo).toMatchObject([
      {
        attributes: { attr1: 'value1', attr2: 'value2' },
        credentialDefinitionId: 'credDefId',
        credentialId: record.id,
        revocationRegistryId: 'revRegId',
        schemaId: 'schemaId',
        credentialRevocationId: 'credentialRevocationId',
      },
    ])
  })

  test('storeCredential', async () => {
    const { credentialDefinition, credentialDefinitionPrivate, keyCorrectnessProof } = createCredentialDefinition({
      attributeNames: ['name', 'age', 'sex', 'height'],
      issuerId: 'issuer:uri',
    })

    const linkSecret = createLinkSecret()

    mockFunction(anoncredsLinkSecretRepositoryMock.getByLinkSecretId).mockResolvedValue(
      new AnonCredsLinkSecretRecord({ linkSecretId: 'linkSecretId', value: linkSecret })
    )

    const saveCredentialMock = jest.spyOn(w3cCredentialRepositoryMock, 'save')

    const { credential } = await createCredentialForHolder({
      agentContext,
      attributes: {
        name: 'John',
        sex: 'M',
        height: '179',
        age: '19',
      },
      credentialDefinition: credentialDefinition as unknown as JsonObject,
      schemaId: 'did:indy:bcovrin:test:SDqTzbVuCowusqGBNbNDjH/anoncreds/v0/SCHEMA/credentialDefinition-name/1.0',
      credentialDefinitionId: 'did:indy:bcovrin:test:SDqTzbVuCowusqGBNbNDjH/anoncreds/v0/CLAIM_DEF/104/default',
      credentialDefinitionPrivate,
      keyCorrectnessProof,
      linkSecret,
      linkSecretId: 'linkSecretId',
      revocationRegistryDefinitionId: 'did:indy:sovrin:test:12345/anoncreds/v0/REV_REG_DEF/420/someTag/anotherTag',
    })

    await storeCredential(agentContext, credential, {
      schema: {
        name: 'schemaname',
        attrNames: ['name', 'age', 'height', 'sex'],
        issuerId: 'did:indy:bcovrin:test:SDqTzbVuCowusqGBNbNDjH',
        version: '1.0',
      },

      linkSecretId: 'linkSecretId',
      schemaId: 'did:indy:bcovrin:test:SDqTzbVuCowusqGBNbNDjH/anoncreds/v0/SCHEMA/credentialDefinition-name/1.0',
      credentialDefinitionId: 'did:indy:bcovrin:test:SDqTzbVuCowusqGBNbNDjH/anoncreds/v0/CLAIM_DEF/104/default',
    })

    expect(saveCredentialMock).toHaveBeenCalledWith(agentContext, expect.objectContaining({ credential }))
  })
})
