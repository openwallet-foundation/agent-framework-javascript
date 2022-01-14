import type { SubjectMessage } from '../../../tests/transport/SubjectInboundTransport'
import type {
  AutoAcceptProof,
  BasicMessage,
  BasicMessageStateChangedEvent,
  ConnectionRecordProps,
  CredentialDefinitionTemplate,
  CredentialOfferTemplate,
  CredentialStateChangedEvent,
  InitConfig,
  ProofAttributeInfo,
  ProofPredicateInfo,
  ProofStateChangedEvent,
  SchemaTemplate,
} from '../src'
import type { Schema, CredDef } from 'indy-sdk'
import type { Observable } from 'rxjs'

import path from 'path'
import { firstValueFrom, Subject, ReplaySubject } from 'rxjs'
import { catchError, filter, map, timeout } from 'rxjs/operators'

import { SubjectInboundTransport } from '../../../tests/transport/SubjectInboundTransport'
import { SubjectOutboundTransport } from '../../../tests/transport/SubjectOutboundTransport'
import { agentDependencies } from '../../node/src'
import {
  LogLevel,
  AgentConfig,
  AriesFrameworkError,
  BasicMessageEventTypes,
  ConnectionInvitationMessage,
  ConnectionRecord,
  ConnectionRole,
  ConnectionState,
  CredentialEventTypes,
  CredentialPreview,
  CredentialState,
  DidCommService,
  DidDoc,
  PredicateType,
  PresentationPreview,
  PresentationPreviewAttribute,
  PresentationPreviewPredicate,
  ProofEventTypes,
  ProofState,
  Agent,
} from '../src'
import { Attachment, AttachmentData } from '../src/decorators/attachment/Attachment'
import { AutoAcceptCredential } from '../src/modules/credentials/CredentialAutoAcceptType'
import { LinkedAttachment } from '../src/utils/LinkedAttachment'
import { uuid } from '../src/utils/uuid'

import testLogger, { TestLogger } from './logger'

export const genesisPath = process.env.GENESIS_TXN_PATH
  ? path.resolve(process.env.GENESIS_TXN_PATH)
  : path.join(__dirname, '../../../network/genesis/local-genesis.txn')

export const publicDidSeed = process.env.TEST_AGENT_PUBLIC_DID_SEED ?? '000000000000000000000000Trustee9'

export function getBaseConfig(name: string, extraConfig: Partial<InitConfig> = {}) {
  const config: InitConfig = {
    label: `Agent: ${name}`,
    walletConfig: {
      id: `Wallet: ${name}`,
      key: `Key: ${name}`,
    },
    publicDidSeed,
    autoAcceptConnections: true,
    indyLedgers: [
      {
        id: `pool-${name}`,
        isProduction: false,
        genesisPath,
      },
    ],
    logger: new TestLogger(LogLevel.error, name),
    ...extraConfig,
  }

  return { config, agentDependencies } as const
}

export function getAgentConfig(name: string, extraConfig: Partial<InitConfig> = {}) {
  const { config, agentDependencies } = getBaseConfig(name, extraConfig)
  return new AgentConfig(config, agentDependencies)
}

export async function waitForProofRecord(
  agent: Agent,
  options: {
    threadId?: string
    state?: ProofState
    previousState?: ProofState | null
    timeoutMs?: number
  }
) {
  const observable = agent.events.observable<ProofStateChangedEvent>(ProofEventTypes.ProofStateChanged)

  return waitForProofRecordSubject(observable, options)
}

export function waitForProofRecordSubject(
  subject: ReplaySubject<ProofStateChangedEvent> | Observable<ProofStateChangedEvent>,
  {
    threadId,
    state,
    previousState,
    timeoutMs = 10000,
  }: {
    threadId?: string
    state?: ProofState
    previousState?: ProofState | null
    timeoutMs?: number
  }
) {
  const observable = subject instanceof ReplaySubject ? subject.asObservable() : subject
  return firstValueFrom(
    observable.pipe(
      filter((e) => previousState === undefined || e.payload.previousState === previousState),
      filter((e) => threadId === undefined || e.payload.proofRecord.threadId === threadId),
      filter((e) => state === undefined || e.payload.proofRecord.state === state),
      timeout(timeoutMs),
      catchError(() => {
        throw new Error(
          `ProofStateChangedEvent event not emitted within specified timeout: {
  previousState: ${previousState},
  threadId: ${threadId},
  state: ${state}
}`
        )
      }),
      map((e) => e.payload.proofRecord)
    )
  )
}

export function waitForCredentialRecordSubject(
  subject: ReplaySubject<CredentialStateChangedEvent> | Observable<CredentialStateChangedEvent>,
  {
    threadId,
    state,
    previousState,
    timeoutMs = 10000,
  }: {
    threadId?: string
    state?: CredentialState
    previousState?: CredentialState | null
    timeoutMs?: number
  }
) {
  const observable = subject instanceof ReplaySubject ? subject.asObservable() : subject
  return firstValueFrom(
    observable.pipe(
      filter((e) => previousState === undefined || e.payload.previousState === previousState),
      filter((e) => threadId === undefined || e.payload.credentialRecord.threadId === threadId),
      filter((e) => state === undefined || e.payload.credentialRecord.state === state),
      timeout(timeoutMs),
      catchError(() => {
        throw new Error(`CredentialStateChanged event not emitted within specified timeout: {
  previousState: ${previousState},
  threadId: ${threadId},
  state: ${state}
}`)
      }),
      map((e) => e.payload.credentialRecord)
    )
  )
}

export async function waitForCredentialRecord(
  agent: Agent,
  options: {
    threadId?: string
    state?: CredentialState
    previousState?: CredentialState | null
    timeoutMs?: number
  }
) {
  const observable = agent.events.observable<CredentialStateChangedEvent>(CredentialEventTypes.CredentialStateChanged)

  return waitForCredentialRecordSubject(observable, options)
}

export async function waitForBasicMessage(agent: Agent, { content }: { content?: string }): Promise<BasicMessage> {
  return new Promise((resolve) => {
    const listener = (event: BasicMessageStateChangedEvent) => {
      const contentMatches = content === undefined || event.payload.message.content === content

      if (contentMatches) {
        agent.events.off<BasicMessageStateChangedEvent>(BasicMessageEventTypes.BasicMessageStateChanged, listener)

        resolve(event.payload.message)
      }
    }

    agent.events.on<BasicMessageStateChangedEvent>(BasicMessageEventTypes.BasicMessageStateChanged, listener)
  })
}

export function getMockConnection({
  state = ConnectionState.Invited,
  role = ConnectionRole.Invitee,
  id = 'test',
  did = 'test-did',
  threadId = 'threadId',
  verkey = 'key-1',
  didDoc = new DidDoc({
    id: did,
    publicKey: [],
    authentication: [],
    service: [
      new DidCommService({
        id: `${did};indy`,
        serviceEndpoint: 'https://endpoint.com',
        recipientKeys: [verkey],
      }),
    ],
  }),
  tags = {},
  theirLabel,
  invitation = new ConnectionInvitationMessage({
    label: 'test',
    recipientKeys: [verkey],
    serviceEndpoint: 'https:endpoint.com/msg',
  }),
  theirDid = 'their-did',
  theirDidDoc = new DidDoc({
    id: theirDid,
    publicKey: [],
    authentication: [],
    service: [
      new DidCommService({
        id: `${did};indy`,
        serviceEndpoint: 'https://endpoint.com',
        recipientKeys: [verkey],
      }),
    ],
  }),
  multiUseInvitation = false,
}: Partial<ConnectionRecordProps> = {}) {
  return new ConnectionRecord({
    did,
    didDoc,
    threadId,
    theirDid,
    theirDidDoc,
    id,
    role,
    state,
    tags,
    verkey,
    invitation,
    theirLabel,
    multiUseInvitation,
  })
}

export async function makeConnection(
  agentA: Agent,
  agentB: Agent,
  config?: {
    autoAcceptConnection?: boolean
    alias?: string
    mediatorId?: string
  }
) {
  // eslint-disable-next-line prefer-const
  let { invitation, connectionRecord: agentAConnection } = await agentA.connections.createConnection(config)
  let agentBConnection = await agentB.connections.receiveInvitation(invitation)

  agentAConnection = await agentA.connections.returnWhenIsConnected(agentAConnection.id)
  agentBConnection = await agentB.connections.returnWhenIsConnected(agentBConnection.id)

  return [agentAConnection, agentBConnection]
}

export async function registerSchema(agent: Agent, schemaTemplate: SchemaTemplate): Promise<Schema> {
  const schema = await agent.ledger.registerSchema(schemaTemplate)
  testLogger.test(`created schema with id ${schema.id}`, schema)
  return schema
}

export async function registerDefinition(
  agent: Agent,
  definitionTemplate: CredentialDefinitionTemplate
): Promise<CredDef> {
  const credentialDefinition = await agent.ledger.registerCredentialDefinition(definitionTemplate)
  testLogger.test(`created credential definition with id ${credentialDefinition.id}`, credentialDefinition)
  return credentialDefinition
}

export async function prepareForIssuance(agent: Agent, attributes: string[]) {
  const publicDid = agent.publicDid?.did

  if (!publicDid) {
    throw new AriesFrameworkError('No public did')
  }

  await ensurePublicDidIsOnLedger(agent, publicDid)

  const schema = await registerSchema(agent, {
    attributes,
    name: `schema-${uuid()}`,
    version: '1.0',
  })

  const definition = await registerDefinition(agent, {
    schema,
    signatureType: 'CL',
    supportRevocation: false,
    tag: 'default',
  })

  return {
    schema,
    definition,
    publicDid,
  }
}

export async function ensurePublicDidIsOnLedger(agent: Agent, publicDid: string) {
  try {
    testLogger.test(`Ensure test DID ${publicDid} is written to ledger`)
    await agent.ledger.getPublicDid(publicDid)
  } catch (error) {
    // Unfortunately, this won't prevent from the test suite running because of Jest runner runs all tests
    // regardless of thrown errors. We're more explicit about the problem with this error handling.
    throw new Error(`Test DID ${publicDid} is not written on ledger or ledger is not available: ${error.message}`)
  }
}

/**
 * Assumes that the autoAcceptCredential is set to {@link AutoAcceptCredential.ContentApproved}
 */
export async function issueCredential({
  issuerAgent,
  issuerConnectionId,
  holderAgent,
  credentialTemplate,
}: {
  issuerAgent: Agent
  issuerConnectionId: string
  holderAgent: Agent
  credentialTemplate: Omit<CredentialOfferTemplate, 'autoAcceptCredential'>
}) {
  const issuerReplay = new ReplaySubject<CredentialStateChangedEvent>()
  const holderReplay = new ReplaySubject<CredentialStateChangedEvent>()

  issuerAgent.events
    .observable<CredentialStateChangedEvent>(CredentialEventTypes.CredentialStateChanged)
    .subscribe(issuerReplay)
  holderAgent.events
    .observable<CredentialStateChangedEvent>(CredentialEventTypes.CredentialStateChanged)
    .subscribe(holderReplay)

  let issuerCredentialRecord = await issuerAgent.credentials.offerCredential(issuerConnectionId, {
    ...credentialTemplate,
    autoAcceptCredential: AutoAcceptCredential.ContentApproved,
  })

  let holderCredentialRecord = await waitForCredentialRecordSubject(holderReplay, {
    threadId: issuerCredentialRecord.threadId,
    state: CredentialState.OfferReceived,
  })

  await holderAgent.credentials.acceptOffer(holderCredentialRecord.id, {
    autoAcceptCredential: AutoAcceptCredential.ContentApproved,
  })

  // Because we use auto-accept it can take a while to have the whole credential flow finished
  // Both parties need to interact with the ledger and sign/verify the credential
  holderCredentialRecord = await waitForCredentialRecordSubject(holderReplay, {
    threadId: issuerCredentialRecord.threadId,
    state: CredentialState.Done,
  })

  issuerCredentialRecord = await waitForCredentialRecordSubject(issuerReplay, {
    threadId: issuerCredentialRecord.threadId,
    state: CredentialState.Done,
  })

  return {
    issuerCredential: issuerCredentialRecord,
    holderCredential: holderCredentialRecord,
  }
}

export async function issueConnectionLessCredential({
  issuerAgent,
  holderAgent,
  credentialTemplate,
}: {
  issuerAgent: Agent
  holderAgent: Agent
  credentialTemplate: Omit<CredentialOfferTemplate, 'autoAcceptCredential'>
}) {
  const issuerReplay = new ReplaySubject<CredentialStateChangedEvent>()
  const holderReplay = new ReplaySubject<CredentialStateChangedEvent>()

  issuerAgent.events
    .observable<CredentialStateChangedEvent>(CredentialEventTypes.CredentialStateChanged)
    .subscribe(issuerReplay)
  holderAgent.events
    .observable<CredentialStateChangedEvent>(CredentialEventTypes.CredentialStateChanged)
    .subscribe(holderReplay)

  // eslint-disable-next-line prefer-const
  let { credentialRecord: issuerCredentialRecord, offerMessage } = await issuerAgent.credentials.createOutOfBandOffer({
    ...credentialTemplate,
    autoAcceptCredential: AutoAcceptCredential.ContentApproved,
  })

  await holderAgent.receiveMessage(offerMessage.toJSON())

  let holderCredentialRecord = await waitForCredentialRecordSubject(holderReplay, {
    threadId: issuerCredentialRecord.threadId,
    state: CredentialState.OfferReceived,
  })

  holderCredentialRecord = await holderAgent.credentials.acceptOffer(holderCredentialRecord.id, {
    autoAcceptCredential: AutoAcceptCredential.ContentApproved,
  })

  holderCredentialRecord = await waitForCredentialRecordSubject(holderReplay, {
    threadId: issuerCredentialRecord.threadId,
    state: CredentialState.Done,
  })

  issuerCredentialRecord = await waitForCredentialRecordSubject(issuerReplay, {
    threadId: issuerCredentialRecord.threadId,
    state: CredentialState.Done,
  })

  return {
    issuerCredential: issuerCredentialRecord,
    holderCredential: holderCredentialRecord,
  }
}

export async function presentProof({
  verifierAgent,
  verifierConnectionId,
  holderAgent,
  presentationTemplate: { attributes, predicates },
}: {
  verifierAgent: Agent
  verifierConnectionId: string
  holderAgent: Agent
  presentationTemplate: {
    attributes?: Record<string, ProofAttributeInfo>
    predicates?: Record<string, ProofPredicateInfo>
  }
}) {
  const verifierReplay = new ReplaySubject<ProofStateChangedEvent>()
  const holderReplay = new ReplaySubject<ProofStateChangedEvent>()

  verifierAgent.events.observable<ProofStateChangedEvent>(ProofEventTypes.ProofStateChanged).subscribe(verifierReplay)
  holderAgent.events.observable<ProofStateChangedEvent>(ProofEventTypes.ProofStateChanged).subscribe(holderReplay)

  let verifierRecord = await verifierAgent.proofs.requestProof(verifierConnectionId, {
    name: 'test-proof-request',
    requestedAttributes: attributes,
    requestedPredicates: predicates,
  })

  let holderRecord = await waitForProofRecordSubject(holderReplay, {
    threadId: verifierRecord.threadId,
    state: ProofState.RequestReceived,
  })

  const retrievedCredentials = await holderAgent.proofs.getRequestedCredentialsForProofRequest(holderRecord.id)
  const requestedCredentials = holderAgent.proofs.autoSelectCredentialsForProofRequest(retrievedCredentials)
  await holderAgent.proofs.acceptRequest(holderRecord.id, requestedCredentials)

  verifierRecord = await waitForProofRecordSubject(verifierReplay, {
    threadId: holderRecord.threadId,
    state: ProofState.PresentationReceived,
  })

  // assert presentation is valid
  expect(verifierRecord.isVerified).toBe(true)

  verifierRecord = await verifierAgent.proofs.acceptPresentation(verifierRecord.id)
  holderRecord = await waitForProofRecordSubject(holderReplay, {
    threadId: holderRecord.threadId,
    state: ProofState.Done,
  })

  return {
    verifierProof: verifierRecord,
    holderProof: holderRecord,
  }
}

/**
 * Returns mock of function with correct type annotations according to original function `fn`.
 * It can be used also for class methods.
 *
 * @param fn function you want to mock
 * @returns mock function with type annotations
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function mockFunction<T extends (...args: any[]) => any>(fn: T): jest.MockedFunction<T> {
  return fn as jest.MockedFunction<T>
}

/**
 * Set a property using a getter value on a mocked oject.
 */
// eslint-disable-next-line @typescript-eslint/ban-types
export function mockProperty<T extends {}, K extends keyof T>(object: T, property: K, value: T[K]) {
  Object.defineProperty(object, property, { get: () => value })
}

export async function setupCredentialTests(
  faberName: string,
  aliceName: string,
  autoAcceptCredentials?: AutoAcceptCredential
) {
  const faberMessages = new Subject<SubjectMessage>()
  const aliceMessages = new Subject<SubjectMessage>()
  const subjectMap = {
    'rxjs:faber': faberMessages,
    'rxjs:alice': aliceMessages,
  }
  const faberConfig = getBaseConfig(faberName, {
    endpoints: ['rxjs:faber'],
    autoAcceptCredentials,
  })

  const aliceConfig = getBaseConfig(aliceName, {
    endpoints: ['rxjs:alice'],
    autoAcceptCredentials,
  })
  const faberAgent = new Agent(faberConfig.config, faberConfig.agentDependencies)
  faberAgent.registerInboundTransport(new SubjectInboundTransport(faberMessages))
  faberAgent.registerOutboundTransport(new SubjectOutboundTransport(aliceMessages, subjectMap))
  await faberAgent.initialize()

  const aliceAgent = new Agent(aliceConfig.config, aliceConfig.agentDependencies)
  aliceAgent.registerInboundTransport(new SubjectInboundTransport(aliceMessages))
  aliceAgent.registerOutboundTransport(new SubjectOutboundTransport(faberMessages, subjectMap))
  await aliceAgent.initialize()

  const {
    schema: { id: schemaId },
    definition: { id: credDefId },
  } = await prepareForIssuance(faberAgent, ['name', 'age', 'profile_picture', 'x-ray'])

  const [faberConnection, aliceConnection] = await makeConnection(faberAgent, aliceAgent)

  return { faberAgent, aliceAgent, credDefId, schemaId, faberConnection, aliceConnection }
}

export async function setupProofsTest(faberName: string, aliceName: string, autoAcceptProofs?: AutoAcceptProof) {
  const credentialPreview = CredentialPreview.fromRecord({
    name: 'John',
    age: '99',
  })

  const unique = uuid().substring(0, 4)

  const faberConfig = getBaseConfig(`${faberName}-${unique}`, {
    autoAcceptProofs,
    endpoints: ['rxjs:faber'],
  })

  const aliceConfig = getBaseConfig(`${aliceName}-${unique}`, {
    autoAcceptProofs,
    endpoints: ['rxjs:alice'],
  })

  const faberMessages = new Subject<SubjectMessage>()
  const aliceMessages = new Subject<SubjectMessage>()

  const subjectMap = {
    'rxjs:faber': faberMessages,
    'rxjs:alice': aliceMessages,
  }
  const faberAgent = new Agent(faberConfig.config, faberConfig.agentDependencies)
  faberAgent.registerInboundTransport(new SubjectInboundTransport(faberMessages))
  faberAgent.registerOutboundTransport(new SubjectOutboundTransport(aliceMessages, subjectMap))
  await faberAgent.initialize()

  const aliceAgent = new Agent(aliceConfig.config, aliceConfig.agentDependencies)
  aliceAgent.registerInboundTransport(new SubjectInboundTransport(aliceMessages))
  aliceAgent.registerOutboundTransport(new SubjectOutboundTransport(faberMessages, subjectMap))
  await aliceAgent.initialize()

  const { definition } = await prepareForIssuance(faberAgent, ['name', 'age', 'image_0', 'image_1'])

  const [agentAConnection, agentBConnection] = await makeConnection(faberAgent, aliceAgent)
  expect(agentAConnection.isReady).toBe(true)
  expect(agentBConnection.isReady).toBe(true)

  const faberConnection = agentAConnection
  const aliceConnection = agentBConnection

  const presentationPreview = new PresentationPreview({
    attributes: [
      new PresentationPreviewAttribute({
        name: 'name',
        credentialDefinitionId: definition.id,
        referent: '0',
        value: 'John',
      }),
      new PresentationPreviewAttribute({
        name: 'image_0',
        credentialDefinitionId: definition.id,
      }),
    ],
    predicates: [
      new PresentationPreviewPredicate({
        name: 'age',
        credentialDefinitionId: definition.id,
        predicate: PredicateType.GreaterThanOrEqualTo,
        threshold: 50,
      }),
    ],
  })

  await issueCredential({
    issuerAgent: faberAgent,
    issuerConnectionId: faberConnection.id,
    holderAgent: aliceAgent,
    credentialTemplate: {
      credentialDefinitionId: definition.id,
      comment: 'some comment about credential',
      preview: credentialPreview,
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
  })

  const faberReplay = new ReplaySubject<ProofStateChangedEvent>()
  const aliceReplay = new ReplaySubject<ProofStateChangedEvent>()

  faberAgent.events.observable<ProofStateChangedEvent>(ProofEventTypes.ProofStateChanged).subscribe(faberReplay)
  aliceAgent.events.observable<ProofStateChangedEvent>(ProofEventTypes.ProofStateChanged).subscribe(aliceReplay)

  return {
    faberAgent,
    aliceAgent,
    credDefId: definition.id,
    faberConnection,
    aliceConnection,
    presentationPreview,
    faberReplay,
    aliceReplay,
  }
}
