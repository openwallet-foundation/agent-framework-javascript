import type { CreateDidKidVerificationMethodReturn } from '../../core/tests'
import type { DidRepository } from '@credo-ts/core'

import {
  AgentContext,
  CredentialExchangeRecord,
  CredentialPreviewAttribute,
  CredentialState,
  DidResolverService,
  DidsModuleConfig,
  Ed25519Signature2018,
  InjectionSymbols,
  KeyDidRegistrar,
  KeyDidResolver,
  KeyType,
  SignatureSuiteToken,
  VERIFICATION_METHOD_TYPE_ED25519_VERIFICATION_KEY_2018,
  VERIFICATION_METHOD_TYPE_ED25519_VERIFICATION_KEY_2020,
  W3cCredential,
  W3cCredentialService,
  W3cCredentialSubject,
  W3cCredentialsModuleConfig,
  CredentialRole,
} from '@credo-ts/core'
import { Subject } from 'rxjs'

import { InMemoryStorageService } from '../../../tests/InMemoryStorageService'
import { InMemoryWallet } from '../../../tests/InMemoryWallet'
import { DataIntegrityCredentialFormatService } from '../../anoncreds/src/formats/DataIntegrityCredentialFormatService'
import { AnonCredsRegistryService } from '../../anoncreds/src/services/registry/AnonCredsRegistryService'
import { InMemoryAnonCredsRegistry } from '../../anoncreds/tests/InMemoryAnonCredsRegistry'
import {
  agentDependencies,
  getAgentConfig,
  getAgentContext,
  testLogger,
  createDidKidVerificationMethod,
} from '../../core/tests'
import {
  AnonCredsHolderServiceSymbol,
  AnonCredsIssuerServiceSymbol,
  AnonCredsModuleConfig,
  AnonCredsVerifierServiceSymbol,
} from '../src'
import { AnonCredsRsHolderService, AnonCredsRsIssuerService, AnonCredsRsVerifierService } from '../src/anoncreds-rs'

import { InMemoryTailsFileService } from './InMemoryTailsFileService'
import { anoncreds } from './helpers'

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
    [
      SignatureSuiteToken,
      {
        suiteClass: Ed25519Signature2018,
        proofType: 'Ed25519Signature2018',
        verificationMethodTypes: [
          VERIFICATION_METHOD_TYPE_ED25519_VERIFICATION_KEY_2018,
          VERIFICATION_METHOD_TYPE_ED25519_VERIFICATION_KEY_2020,
        ],
        keyTypes: [KeyType.Ed25519],
      },
    ],
  ],
  agentConfig,
  wallet,
})

agentContext.dependencyManager.registerInstance(AgentContext, agentContext)

const dataIntegrityCredentialFormatService = new DataIntegrityCredentialFormatService()

describe('data integrity format service (w3c)', () => {
  let issuerKdv: CreateDidKidVerificationMethodReturn
  let holderKdv: CreateDidKidVerificationMethodReturn

  beforeAll(async () => {
    await wallet.createAndOpen(agentConfig.walletConfig)

    issuerKdv = await createDidKidVerificationMethod(agentContext, '96213c3d7fc8d4d6754c7a0fd969598g')
    holderKdv = await createDidKidVerificationMethod(agentContext, '96213c3d7fc8d4d6754c7a0fd969598f')
  })

  afterEach(async () => {
    inMemoryStorageService.contextCorrelationIdToRecords = {}
  })

  test('issuance and verification flow w3c starting from offer without negotiation and without revocation', async () => {
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
      issuer: issuerKdv.did,
      issuanceDate: new Date().toISOString(),
      credentialSubject: new W3cCredentialSubject({ claims: { name: 'John', age: 25 } }),
    })

    const { attachment: offerAttachment } = await dataIntegrityCredentialFormatService.createOffer(agentContext, {
      credentialRecord: issuerCredentialRecord,
      credentialFormats: {
        dataIntegrity: {
          bindingRequired: true,
          credential,
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
            didCommSignedAttachment: {
              kid: holderKdv.kid,
            },
          },
        },
      })

    // Issuer processes and accepts request
    await dataIntegrityCredentialFormatService.processRequest(agentContext, {
      credentialRecord: issuerCredentialRecord,
      attachment: requestAttachment,
    })
    const { attachment: credentialAttachment } = await dataIntegrityCredentialFormatService.acceptRequest(
      agentContext,
      {
        credentialRecord: issuerCredentialRecord,
        requestAttachment,
        offerAttachment,
        requestAppendAttachments,
        credentialFormats: {
          dataIntegrity: {
            credentialSubjectId: issuerKdv.did,
            issuerVerificationMethod: issuerKdv.kid,
          },
        },
      }
    )

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

    await expect(
      anonCredsHolderService.getCredential(agentContext, {
        id: holderCredentialRecord.id,
      })
    ).rejects.toThrow()

    expect(holderCredentialRecord.metadata.data).toEqual({})
    expect(issuerCredentialRecord.metadata.data).toEqual({})

    const credentialRecordId = holderCredentialRecord.credentials[0].credentialRecordId
    const w3cCredentialService = agentContext.dependencyManager.resolve(W3cCredentialService)
    const credentialRecord = await w3cCredentialService.getCredentialRecordById(agentContext, credentialRecordId)

    expect(credentialRecord.credential).toEqual({
      ...{
        ...credential,
        credentialSubject: new W3cCredentialSubject({
          id: issuerKdv.did,
          claims: (credential.credentialSubject as W3cCredentialSubject).claims,
        }),
      },
      proof: expect.any(Object),
    })
  })
})
