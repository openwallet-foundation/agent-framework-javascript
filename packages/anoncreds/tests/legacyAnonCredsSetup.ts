import type { PreCreatedAnonCredsDefinition } from './preCreatedAnonCredsDefinition'
import type { EventReplaySubject } from '../../core/tests'
import type {
  AnonCredsRegisterCredentialDefinitionOptions,
  AnonCredsRequestedAttribute,
  AnonCredsRequestedPredicate,
  AnonCredsOfferCredentialFormat,
  AnonCredsSchema,
  RegisterCredentialDefinitionReturnStateFinished,
  RegisterSchemaReturnStateFinished,
} from '../src'
import type { AutoAcceptProof, ConnectionRecord } from '@credo-ts/didcomm'

import { TypedArrayEncoder, CacheModule, InMemoryLruCache, Agent, CredoError, DidsModule } from '@credo-ts/core'
import {
  AgentEventTypes,
  AutoAcceptCredential,
  CredentialEventTypes,
  CredentialsModule,
  CredentialState,
  ProofEventTypes,
  ProofsModule,
  ProofState,
  V2CredentialProtocol,
  V2ProofProtocol,
} from '@credo-ts/didcomm'
import { randomUUID } from 'crypto'

import { sleep } from '../../core/src/utils/sleep'
import { setupSubjectTransports, setupEventReplaySubjects } from '../../core/tests'
import {
  getInMemoryAgentOptions,
  importExistingIndyDidFromPrivateKey,
  makeConnection,
  publicDidSeed,
  waitForCredentialRecordSubject,
  waitForProofExchangeRecordSubject,
} from '../../core/tests/helpers'
import testLogger from '../../core/tests/logger'
import { getDefaultDidcommModules } from '../../didcomm/src/util/modules'
import {
  IndyVdrAnonCredsRegistry,
  IndyVdrSovDidResolver,
  IndyVdrModule,
  IndyVdrIndyDidResolver,
  IndyVdrIndyDidRegistrar,
} from '../../indy-vdr/src'
import { indyVdrModuleConfig } from '../../indy-vdr/tests/helpers'
import {
  AnonCredsCredentialFormatService,
  AnonCredsProofFormatService,
  getUnqualifiedCredentialDefinitionId,
  getUnqualifiedSchemaId,
  parseIndyCredentialDefinitionId,
  parseIndySchemaId,
  V1CredentialProtocol,
  V1ProofProtocol,
  AnonCredsModule,
  LegacyIndyCredentialFormatService,
  LegacyIndyProofFormatService,
} from '../src'

import { InMemoryAnonCredsRegistry } from './InMemoryAnonCredsRegistry'
import { anoncreds } from './helpers'
import {
  anoncredsDefinitionFourAttributesNoRevocation,
  storePreCreatedAnonCredsDefinition,
} from './preCreatedAnonCredsDefinition'

// Helper type to get the type of the agents (with the custom modules) for the credential tests
export type AnonCredsTestsAgent = Agent<
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ReturnType<typeof getAnonCredsIndyModules> & { didcomm?: any; mediationRecipient?: any; mediator?: any }
>

export const getAnonCredsIndyModules = ({
  autoAcceptCredentials,
  autoAcceptProofs,
}: {
  autoAcceptCredentials?: AutoAcceptCredential
  autoAcceptProofs?: AutoAcceptProof
} = {}) => {
  // Add support for resolving pre-created credential definitions and schemas
  const inMemoryAnonCredsRegistry = new InMemoryAnonCredsRegistry({
    existingCredentialDefinitions: {
      [anoncredsDefinitionFourAttributesNoRevocation.credentialDefinitionId]:
        anoncredsDefinitionFourAttributesNoRevocation.credentialDefinition,
    },
    existingSchemas: {
      [anoncredsDefinitionFourAttributesNoRevocation.schemaId]: anoncredsDefinitionFourAttributesNoRevocation.schema,
    },
  })

  const legacyIndyCredentialFormatService = new LegacyIndyCredentialFormatService()
  const legacyIndyProofFormatService = new LegacyIndyProofFormatService()

  const modules = {
    ...getDefaultDidcommModules(),
    credentials: new CredentialsModule({
      autoAcceptCredentials,
      credentialProtocols: [
        new V1CredentialProtocol({
          indyCredentialFormat: legacyIndyCredentialFormatService,
        }),
        new V2CredentialProtocol({
          credentialFormats: [legacyIndyCredentialFormatService, new AnonCredsCredentialFormatService()],
        }),
      ],
    }),
    proofs: new ProofsModule({
      autoAcceptProofs,
      proofProtocols: [
        new V1ProofProtocol({
          indyProofFormat: legacyIndyProofFormatService,
        }),
        new V2ProofProtocol({
          proofFormats: [legacyIndyProofFormatService, new AnonCredsProofFormatService()],
        }),
      ],
    }),
    anoncreds: new AnonCredsModule({
      registries: [new IndyVdrAnonCredsRegistry(), inMemoryAnonCredsRegistry],
      anoncreds,
    }),
    indyVdr: new IndyVdrModule(indyVdrModuleConfig),
    dids: new DidsModule({
      resolvers: [new IndyVdrSovDidResolver(), new IndyVdrIndyDidResolver()],
      registrars: [new IndyVdrIndyDidRegistrar()],
    }),
    cache: new CacheModule({
      cache: new InMemoryLruCache({ limit: 100 }),
    }),
  } as const

  return modules
}

export async function presentLegacyAnonCredsProof({
  verifierAgent,
  verifierReplay,

  holderAgent,
  holderReplay,

  verifierHolderConnectionId,

  request: { attributes, predicates },
}: {
  holderAgent: AnonCredsTestsAgent
  holderReplay: EventReplaySubject

  verifierAgent: AnonCredsTestsAgent
  verifierReplay: EventReplaySubject

  verifierHolderConnectionId: string
  request: {
    attributes?: Record<string, AnonCredsRequestedAttribute>
    predicates?: Record<string, AnonCredsRequestedPredicate>
  }
}) {
  let holderProofExchangeRecordPromise = waitForProofExchangeRecordSubject(holderReplay, {
    state: ProofState.RequestReceived,
  })

  let verifierProofExchangeRecord = await verifierAgent.modules.proofs.requestProof({
    connectionId: verifierHolderConnectionId,
    proofFormats: {
      indy: {
        name: 'Test Proof Request',
        requested_attributes: attributes,
        requested_predicates: predicates,
        version: '1.0',
      },
    },
    protocolVersion: 'v2',
  })

  let holderProofExchangeRecord = await holderProofExchangeRecordPromise

  const selectedCredentials = await holderAgent.modules.proofs.selectCredentialsForRequest({
    proofRecordId: holderProofExchangeRecord.id,
  })

  const verifierProofExchangeRecordPromise = waitForProofExchangeRecordSubject(verifierReplay, {
    threadId: holderProofExchangeRecord.threadId,
    state: ProofState.PresentationReceived,
  })

  await holderAgent.modules.proofs.acceptRequest({
    proofRecordId: holderProofExchangeRecord.id,
    proofFormats: { indy: selectedCredentials.proofFormats.indy },
  })

  verifierProofExchangeRecord = await verifierProofExchangeRecordPromise

  // assert presentation is valid
  expect(verifierProofExchangeRecord.isVerified).toBe(true)

  holderProofExchangeRecordPromise = waitForProofExchangeRecordSubject(holderReplay, {
    threadId: holderProofExchangeRecord.threadId,
    state: ProofState.Done,
  })

  verifierProofExchangeRecord = await verifierAgent.modules.proofs.acceptPresentation({
    proofRecordId: verifierProofExchangeRecord.id,
  })
  holderProofExchangeRecord = await holderProofExchangeRecordPromise

  return {
    verifierProofExchangeRecord,
    holderProofExchangeRecord,
  }
}

export async function issueLegacyAnonCredsCredential({
  issuerAgent,
  issuerReplay,

  holderAgent,
  holderReplay,

  issuerHolderConnectionId,
  offer,
}: {
  issuerAgent: AnonCredsTestsAgent
  issuerReplay: EventReplaySubject

  holderAgent: AnonCredsTestsAgent
  holderReplay: EventReplaySubject

  issuerHolderConnectionId: string
  offer: AnonCredsOfferCredentialFormat
}) {
  let issuerCredentialExchangeRecord = await issuerAgent.modules.credentials.offerCredential({
    comment: 'some comment about credential',
    connectionId: issuerHolderConnectionId,
    protocolVersion: 'v1',
    credentialFormats: {
      indy: offer,
    },
    autoAcceptCredential: AutoAcceptCredential.ContentApproved,
  })

  let holderCredentialExchangeRecord = await waitForCredentialRecordSubject(holderReplay, {
    threadId: issuerCredentialExchangeRecord.threadId,
    state: CredentialState.OfferReceived,
  })

  await holderAgent.modules.credentials.acceptOffer({
    credentialRecordId: holderCredentialExchangeRecord.id,
    autoAcceptCredential: AutoAcceptCredential.ContentApproved,
  })

  // Because we use auto-accept it can take a while to have the whole credential flow finished
  // Both parties need to interact with the ledger and sign/verify the credential
  holderCredentialExchangeRecord = await waitForCredentialRecordSubject(holderReplay, {
    threadId: issuerCredentialExchangeRecord.threadId,
    state: CredentialState.Done,
  })
  issuerCredentialExchangeRecord = await waitForCredentialRecordSubject(issuerReplay, {
    threadId: issuerCredentialExchangeRecord.threadId,
    state: CredentialState.Done,
  })

  return {
    issuerCredentialExchangeRecord,
    holderCredentialExchangeRecord,
  }
}

interface SetupAnonCredsTestsReturn<VerifierName extends string | undefined, CreateConnections extends boolean> {
  issuerAgent: AnonCredsTestsAgent
  issuerReplay: EventReplaySubject

  holderAgent: AnonCredsTestsAgent
  holderReplay: EventReplaySubject

  issuerHolderConnectionId: CreateConnections extends true ? string : undefined
  holderIssuerConnectionId: CreateConnections extends true ? string : undefined

  verifierHolderConnectionId: CreateConnections extends true
    ? VerifierName extends string
      ? string
      : undefined
    : undefined
  holderVerifierConnectionId: CreateConnections extends true
    ? VerifierName extends string
      ? string
      : undefined
    : undefined

  verifierAgent: VerifierName extends string ? AnonCredsTestsAgent : undefined
  verifierReplay: VerifierName extends string ? EventReplaySubject : undefined

  schemaId: string
  credentialDefinitionId: string
}

export async function setupAnonCredsTests<
  VerifierName extends string | undefined = undefined,
  CreateConnections extends boolean = true
>({
  issuerName,
  holderName,
  verifierName,
  autoAcceptCredentials,
  autoAcceptProofs,
  attributeNames,
  preCreatedDefinition,
  createConnections,
}: {
  issuerName: string
  holderName: string
  verifierName?: VerifierName
  autoAcceptCredentials?: AutoAcceptCredential
  autoAcceptProofs?: AutoAcceptProof
  attributeNames?: string[]
  preCreatedDefinition?: PreCreatedAnonCredsDefinition
  createConnections?: CreateConnections
}): Promise<SetupAnonCredsTestsReturn<VerifierName, CreateConnections>> {
  const issuerAgent = new Agent(
    getInMemoryAgentOptions(
      issuerName,
      {
        endpoints: ['rxjs:issuer'],
      },
      {
        logger: testLogger,
      },
      getAnonCredsIndyModules({
        autoAcceptCredentials,
        autoAcceptProofs,
      })
    )
  )

  const holderAgent = new Agent(
    getInMemoryAgentOptions(
      holderName,
      {
        endpoints: ['rxjs:holder'],
      },
      {},
      getAnonCredsIndyModules({
        autoAcceptCredentials,
        autoAcceptProofs,
      })
    )
  )

  const verifierAgent = verifierName
    ? new Agent(
        getInMemoryAgentOptions(
          verifierName,
          {
            endpoints: ['rxjs:verifier'],
          },
          {},
          getAnonCredsIndyModules({
            autoAcceptCredentials,
            autoAcceptProofs,
          })
        )
      )
    : undefined

  setupSubjectTransports(verifierAgent ? [issuerAgent, holderAgent, verifierAgent] : [issuerAgent, holderAgent])
  const [issuerReplay, holderReplay, verifierReplay] = setupEventReplaySubjects(
    verifierAgent ? [issuerAgent, holderAgent, verifierAgent] : [issuerAgent, holderAgent],
    [
      CredentialEventTypes.CredentialStateChanged,
      ProofEventTypes.ProofStateChanged,
      AgentEventTypes.AgentMessageProcessed,
    ]
  )

  await issuerAgent.initialize()
  await holderAgent.initialize()
  if (verifierAgent) await verifierAgent.initialize()

  let credentialDefinitionId: string
  let schemaId: string

  if (attributeNames) {
    const result = await prepareForAnonCredsIssuance(issuerAgent, {
      attributeNames,
    })
    schemaId = result.schema.schemaId
    credentialDefinitionId = result.credentialDefinition.credentialDefinitionId
  } else if (preCreatedDefinition) {
    const result = await storePreCreatedAnonCredsDefinition(issuerAgent, preCreatedDefinition)
    schemaId = result.schemaId
    credentialDefinitionId = result.credentialDefinitionId
  } else {
    throw new CredoError('Either attributeNames or preCreatedDefinition must be provided')
  }

  let issuerHolderConnection: ConnectionRecord | undefined
  let holderIssuerConnection: ConnectionRecord | undefined
  let verifierHolderConnection: ConnectionRecord | undefined
  let holderVerifierConnection: ConnectionRecord | undefined

  if (createConnections ?? true) {
    ;[issuerHolderConnection, holderIssuerConnection] = await makeConnection(issuerAgent, holderAgent)

    if (verifierAgent) {
      ;[holderVerifierConnection, verifierHolderConnection] = await makeConnection(holderAgent, verifierAgent)
    }
  }

  return {
    issuerAgent,
    issuerReplay,

    holderAgent,
    holderReplay,

    verifierAgent: verifierName ? verifierAgent : undefined,
    verifierReplay: verifierName ? verifierReplay : undefined,

    credentialDefinitionId,
    schemaId,

    issuerHolderConnectionId: issuerHolderConnection?.id,
    holderIssuerConnectionId: holderIssuerConnection?.id,
    holderVerifierConnectionId: holderVerifierConnection?.id,
    verifierHolderConnectionId: verifierHolderConnection?.id,
  } as unknown as SetupAnonCredsTestsReturn<VerifierName, CreateConnections>
}

export async function prepareForAnonCredsIssuance(agent: Agent, { attributeNames }: { attributeNames: string[] }) {
  // Add existing endorser did to the wallet
  const unqualifiedDid = await importExistingIndyDidFromPrivateKey(agent, TypedArrayEncoder.fromString(publicDidSeed))
  const didIndyDid = `did:indy:pool:localtest:${unqualifiedDid}`

  const schema = await registerSchema(agent, {
    // TODO: update attrNames to attributeNames
    attrNames: attributeNames,
    name: `Schema ${randomUUID()}`,
    version: '1.0',
    issuerId: didIndyDid,
  })

  // Wait some time pass to let ledger settle the object
  await sleep(1000)

  const credentialDefinition = await registerCredentialDefinition(agent, {
    schemaId: schema.schemaId,
    issuerId: didIndyDid,
    tag: 'default',
  })

  const s = parseIndySchemaId(schema.schemaId)
  const cd = parseIndyCredentialDefinitionId(credentialDefinition.credentialDefinitionId)

  const legacySchemaId = getUnqualifiedSchemaId(s.namespaceIdentifier, s.schemaName, s.schemaVersion)
  const legacyCredentialDefinitionId = getUnqualifiedCredentialDefinitionId(
    cd.namespaceIdentifier,
    cd.schemaSeqNo,
    cd.tag
  )

  // Wait some time pass to let ledger settle the object
  await sleep(1000)

  // NOTE: we return the legacy schema and credential definition ids here because that's what currently expected
  // in all tests. If we also support did:indy in tests we probably want to return the qualified identifiers here
  // and transform them to the legacy variant in the specific tests that need it.
  return {
    schema: {
      ...schema,
      schemaId: legacySchemaId,
    },
    credentialDefinition: {
      ...credentialDefinition,
      credentialDefinitionId: legacyCredentialDefinitionId,
    },
  }
}

async function registerSchema(
  agent: AnonCredsTestsAgent,
  schema: AnonCredsSchema
): Promise<RegisterSchemaReturnStateFinished> {
  const { schemaState } = await agent.modules.anoncreds.registerSchema({
    schema,
    options: {},
  })

  testLogger.test(`created schema with id ${schemaState.schemaId}`, schema)

  if (schemaState.state !== 'finished') {
    throw new CredoError(`Schema not created: ${schemaState.state === 'failed' ? schemaState.reason : 'Not finished'}`)
  }

  return schemaState
}

async function registerCredentialDefinition(
  agent: AnonCredsTestsAgent,
  credentialDefinition: AnonCredsRegisterCredentialDefinitionOptions,
  supportRevocation?: boolean
): Promise<RegisterCredentialDefinitionReturnStateFinished> {
  const { credentialDefinitionState } = await agent.modules.anoncreds.registerCredentialDefinition({
    credentialDefinition,
    options: {
      supportRevocation: supportRevocation ?? false,
    },
  })

  if (credentialDefinitionState.state !== 'finished') {
    throw new CredoError(
      `Credential definition not created: ${
        credentialDefinitionState.state === 'failed' ? credentialDefinitionState.reason : 'Not finished'
      }`
    )
  }

  return credentialDefinitionState
}
