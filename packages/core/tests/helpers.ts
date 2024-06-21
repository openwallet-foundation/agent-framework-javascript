/* eslint-disable @typescript-eslint/no-non-null-assertion */
import type { AskarWalletSqliteStorageConfig } from '../../askar/src/wallet'
import type {
  AgentDependencies,
  BaseEvent,
  BasicMessage,
  BasicMessageStateChangedEvent,
  ConnectionRecordProps,
  CredentialStateChangedEvent,
  InitConfig,
  InjectionToken,
  ProofStateChangedEvent,
  Wallet,
  Agent,
  CredentialState,
  ConnectionStateChangedEvent,
  Buffer,
  AgentMessageProcessedEvent,
  RevocationNotificationReceivedEvent,
  KeyDidCreateOptions,
  ConnectionDidRotatedEvent,
} from '../src'
import type { AgentModulesInput, EmptyModuleMap } from '../src/agent/AgentModules'
import type { TrustPingReceivedEvent, TrustPingResponseReceivedEvent } from '../src/modules/connections/TrustPingEvents'
import type { ProofState } from '../src/modules/proofs/models/ProofState'
import type { WalletConfig } from '../src/types'
import type { Observable } from 'rxjs'

import { readFileSync } from 'fs'
import path from 'path'
import { lastValueFrom, firstValueFrom, ReplaySubject } from 'rxjs'
import { catchError, filter, map, take, timeout } from 'rxjs/operators'

import { InMemoryWalletModule } from '../../../tests/InMemoryWalletModule'
import { agentDependencies } from '../../node/src'
import {
  AgentEventTypes,
  OutOfBandDidCommService,
  ConnectionsModule,
  ConnectionEventTypes,
  TypedArrayEncoder,
  AgentConfig,
  AgentContext,
  BasicMessageEventTypes,
  ConnectionRecord,
  CredentialEventTypes,
  DependencyManager,
  DidExchangeRole,
  DidExchangeState,
  HandshakeProtocol,
  InjectionSymbols,
  ProofEventTypes,
  TrustPingEventTypes,
  DidsApi,
} from '../src'
import { Key, KeyType } from '../src/crypto'
import { DidKey } from '../src/modules/dids/methods/key'
import { OutOfBandRole } from '../src/modules/oob/domain/OutOfBandRole'
import { OutOfBandState } from '../src/modules/oob/domain/OutOfBandState'
import { OutOfBandInvitation } from '../src/modules/oob/messages'
import { OutOfBandRecord } from '../src/modules/oob/repository'
import { KeyDerivationMethod } from '../src/types'
import { sleep } from '../src/utils/sleep'
import { uuid } from '../src/utils/uuid'

import testLogger, { TestLogger } from './logger'

export const genesisPath = process.env.GENESIS_TXN_PATH
  ? path.resolve(process.env.GENESIS_TXN_PATH)
  : path.join(__dirname, '../../../network/genesis/local-genesis.txn')

export const genesisTransactions = readFileSync(genesisPath).toString('utf-8')

export const publicDidSeed = process.env.TEST_AGENT_PUBLIC_DID_SEED ?? '000000000000000000000000Trustee9'
export const taaVersion = (process.env.TEST_AGENT_TAA_VERSION ?? '1') as `${number}.${number}` | `${number}`
export const taaAcceptanceMechanism = process.env.TEST_AGENT_TAA_ACCEPTANCE_MECHANISM ?? 'accept'
export { agentDependencies }

export function getAskarWalletConfig(
  name: string,
  {
    inMemory = true,
    random = uuid().slice(0, 4),
    maxConnections,
  }: { inMemory?: boolean; random?: string; maxConnections?: number } = {}
) {
  return {
    id: `Wallet: ${name} - ${random}`,
    key: 'DZ9hPqFWTPxemcGea72C1X1nusqk5wFNLq6QPjwXGqAa', // generated using indy.generateWalletKey
    keyDerivationMethod: KeyDerivationMethod.Raw,
    // Use in memory by default
    storage: {
      type: 'sqlite',
      config: {
        inMemory,
        maxConnections,
      },
    } satisfies AskarWalletSqliteStorageConfig,
  } satisfies WalletConfig
}

export function getAgentOptions<AgentModules extends AgentModulesInput | EmptyModuleMap>(
  name: string,
  extraConfig: Partial<InitConfig> = {},
  inputModules?: AgentModules,
  inMemoryWallet = true
): { config: InitConfig; modules: AgentModules; dependencies: AgentDependencies; inMemory?: boolean } {
  const random = uuid().slice(0, 4)
  const config: InitConfig = {
    label: `Agent: ${name} - ${random}`,
    walletConfig: getAskarWalletConfig(name, { inMemory: inMemoryWallet, random }),
    // TODO: determine the log level based on an environment variable. This will make it
    // possible to run e.g. failed github actions in debug mode for extra logs
    logger: TestLogger.fromLogger(testLogger, name),
    ...extraConfig,
  }

  const m = (inputModules ?? {}) as AgentModulesInput
  const modules = {
    ...m,
    // Make sure connections module is always defined so we can set autoAcceptConnections
    connections:
      m.connections ??
      new ConnectionsModule({
        autoAcceptConnections: true,
      }),
  }

  return { config, modules: modules as AgentModules, dependencies: agentDependencies } as const
}

export function getInMemoryAgentOptions<AgentModules extends AgentModulesInput | EmptyModuleMap>(
  name: string,
  extraConfig: Partial<InitConfig> = {},
  inputModules?: AgentModules
): { config: InitConfig; modules: AgentModules; dependencies: AgentDependencies } {
  const random = uuid().slice(0, 4)
  const config: InitConfig = {
    label: `Agent: ${name} - ${random}`,
    walletConfig: {
      id: `Wallet: ${name} - ${random}`,
      key: `Wallet: ${name}`,
    },
    // TODO: determine the log level based on an environment variable. This will make it
    // possible to run e.g. failed github actions in debug mode for extra logs
    logger: TestLogger.fromLogger(testLogger, name),
    ...extraConfig,
  }

  const m = (inputModules ?? {}) as AgentModulesInput
  const modules = {
    ...m,
    inMemory: new InMemoryWalletModule(),
    // Make sure connections module is always defined so we can set autoAcceptConnections
    connections:
      m.connections ??
      new ConnectionsModule({
        autoAcceptConnections: true,
      }),
  }

  return { config, modules: modules as unknown as AgentModules, dependencies: agentDependencies } as const
}

export async function importExistingIndyDidFromPrivateKey(agent: Agent, privateKey: Buffer) {
  const key = await agent.wallet.createKey({
    keyType: KeyType.Ed25519,
    privateKey,
  })

  // did is first 16 bytes of public key encoded as base58
  const unqualifiedIndyDid = TypedArrayEncoder.toBase58(key.publicKey.slice(0, 16))

  // import the did in the wallet so it can be used
  await agent.dids.import({ did: `did:indy:pool:localtest:${unqualifiedIndyDid}` })

  return unqualifiedIndyDid
}

export function getAgentConfig(
  name: string,
  extraConfig: Partial<InitConfig> = {}
): AgentConfig & { walletConfig: WalletConfig } {
  const { config, dependencies } = getAgentOptions(name, extraConfig)
  return new AgentConfig(config, dependencies) as AgentConfig & { walletConfig: WalletConfig }
}

export function getAgentContext({
  dependencyManager = new DependencyManager(),
  wallet,
  agentConfig,
  contextCorrelationId = 'mock',
  registerInstances = [],
}: {
  dependencyManager?: DependencyManager
  wallet?: Wallet
  agentConfig?: AgentConfig
  contextCorrelationId?: string
  // Must be an array of arrays as objects can't have injection tokens
  // as keys (it must be number, string or symbol)
  registerInstances?: Array<[InjectionToken, unknown]>
} = {}) {
  if (wallet) dependencyManager.registerInstance(InjectionSymbols.Wallet, wallet)
  if (agentConfig) dependencyManager.registerInstance(AgentConfig, agentConfig)

  // Register custom instances on the dependency manager
  for (const [token, instance] of registerInstances.values()) {
    dependencyManager.registerInstance(token, instance)
  }

  return new AgentContext({ dependencyManager, contextCorrelationId })
}

export async function waitForProofExchangeRecord(
  agent: Agent,
  options: {
    threadId?: string
    parentThreadId?: string
    state?: ProofState
    previousState?: ProofState | null
    timeoutMs?: number
  }
) {
  const observable = agent.events.observable<ProofStateChangedEvent>(ProofEventTypes.ProofStateChanged)

  return waitForProofExchangeRecordSubject(observable, options)
}

const isProofStateChangedEvent = (e: BaseEvent): e is ProofStateChangedEvent =>
  e.type === ProofEventTypes.ProofStateChanged
const isCredentialStateChangedEvent = (e: BaseEvent): e is CredentialStateChangedEvent =>
  e.type === CredentialEventTypes.CredentialStateChanged
const isConnectionStateChangedEvent = (e: BaseEvent): e is ConnectionStateChangedEvent =>
  e.type === ConnectionEventTypes.ConnectionStateChanged
const isConnectionDidRotatedEvent = (e: BaseEvent): e is ConnectionDidRotatedEvent =>
  e.type === ConnectionEventTypes.ConnectionDidRotated
const isTrustPingReceivedEvent = (e: BaseEvent): e is TrustPingReceivedEvent =>
  e.type === TrustPingEventTypes.TrustPingReceivedEvent
const isTrustPingResponseReceivedEvent = (e: BaseEvent): e is TrustPingResponseReceivedEvent =>
  e.type === TrustPingEventTypes.TrustPingResponseReceivedEvent
const isAgentMessageProcessedEvent = (e: BaseEvent): e is AgentMessageProcessedEvent =>
  e.type === AgentEventTypes.AgentMessageProcessed

export function waitForProofExchangeRecordSubject(
  subject: ReplaySubject<BaseEvent> | Observable<BaseEvent>,
  {
    threadId,
    parentThreadId,
    state,
    previousState,
    timeoutMs = 10000,
    count = 1,
  }: {
    threadId?: string
    parentThreadId?: string
    state?: ProofState
    previousState?: ProofState | null
    timeoutMs?: number
    count?: number
  }
) {
  const observable: Observable<BaseEvent> = subject instanceof ReplaySubject ? subject.asObservable() : subject
  return lastValueFrom(
    observable.pipe(
      filter(isProofStateChangedEvent),
      filter((e) => previousState === undefined || e.payload.previousState === previousState),
      filter((e) => threadId === undefined || e.payload.proofRecord.threadId === threadId),
      filter((e) => parentThreadId === undefined || e.payload.proofRecord.parentThreadId === parentThreadId),
      filter((e) => state === undefined || e.payload.proofRecord.state === state),
      timeout(timeoutMs),
      catchError(() => {
        throw new Error(
          `ProofStateChangedEvent event not emitted within specified timeout: ${timeoutMs}
          previousState: ${previousState},
          threadId: ${threadId},
          parentThreadId: ${parentThreadId},
          state: ${state}
        }`
        )
      }),
      take(count),
      map((e) => e.payload.proofRecord)
    )
  )
}

export async function waitForTrustPingReceivedEvent(
  agent: Agent,
  options: {
    threadId?: string
    timeoutMs?: number
  }
) {
  const observable = agent.events.observable<TrustPingReceivedEvent>(TrustPingEventTypes.TrustPingReceivedEvent)

  return waitForTrustPingReceivedEventSubject(observable, options)
}

export function waitForTrustPingReceivedEventSubject(
  subject: ReplaySubject<BaseEvent> | Observable<BaseEvent>,
  {
    threadId,
    timeoutMs = 10000,
  }: {
    threadId?: string
    timeoutMs?: number
  }
) {
  const observable = subject instanceof ReplaySubject ? subject.asObservable() : subject
  return firstValueFrom(
    observable.pipe(
      filter(isTrustPingReceivedEvent),
      filter((e) => threadId === undefined || e.payload.message.threadId === threadId),
      timeout(timeoutMs),
      catchError(() => {
        throw new Error(
          `TrustPingReceivedEvent event not emitted within specified timeout: ${timeoutMs}
  threadId: ${threadId},
}`
        )
      }),
      map((e) => e.payload.message)
    )
  )
}

export async function waitForTrustPingResponseReceivedEvent(
  agent: Agent,
  options: {
    threadId?: string
    timeoutMs?: number
  }
) {
  const observable = agent.events.observable<TrustPingResponseReceivedEvent>(
    TrustPingEventTypes.TrustPingResponseReceivedEvent
  )

  return waitForTrustPingResponseReceivedEventSubject(observable, options)
}

export function waitForTrustPingResponseReceivedEventSubject(
  subject: ReplaySubject<BaseEvent> | Observable<BaseEvent>,
  {
    threadId,
    timeoutMs = 10000,
  }: {
    threadId?: string
    timeoutMs?: number
  }
) {
  const observable = subject instanceof ReplaySubject ? subject.asObservable() : subject
  return firstValueFrom(
    observable.pipe(
      filter(isTrustPingResponseReceivedEvent),
      filter((e) => threadId === undefined || e.payload.message.threadId === threadId),
      timeout(timeoutMs),
      catchError(() => {
        throw new Error(
          `TrustPingResponseReceivedEvent event not emitted within specified timeout: ${timeoutMs}
  threadId: ${threadId},
}`
        )
      }),
      map((e) => e.payload.message)
    )
  )
}

export async function waitForAgentMessageProcessedEvent(
  agent: Agent,
  options: {
    threadId?: string
    messageType?: string
    timeoutMs?: number
  }
) {
  const observable = agent.events.observable<AgentMessageProcessedEvent>(AgentEventTypes.AgentMessageProcessed)

  return waitForAgentMessageProcessedEventSubject(observable, options)
}

export function waitForAgentMessageProcessedEventSubject(
  subject: ReplaySubject<BaseEvent> | Observable<BaseEvent>,
  {
    threadId,
    timeoutMs = 10000,
    messageType,
  }: {
    threadId?: string
    messageType?: string
    timeoutMs?: number
  }
) {
  const observable = subject instanceof ReplaySubject ? subject.asObservable() : subject
  return firstValueFrom(
    observable.pipe(
      filter(isAgentMessageProcessedEvent),
      filter((e) => threadId === undefined || e.payload.message.threadId === threadId),
      filter((e) => messageType === undefined || e.payload.message.type === messageType),
      timeout(timeoutMs),
      catchError(() => {
        throw new Error(
          `AgentMessageProcessedEvent event not emitted within specified timeout: ${timeoutMs}
  threadId: ${threadId}, messageType: ${messageType}
}`
        )
      }),
      map((e) => e.payload.message)
    )
  )
}

export function waitForCredentialRecordSubject(
  subject: ReplaySubject<BaseEvent> | Observable<BaseEvent>,
  {
    threadId,
    state,
    previousState,
    timeoutMs = 15000, // sign and store credential in W3c credential protocols take several seconds
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
      filter(isCredentialStateChangedEvent),
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

export function waitForDidRotateSubject(
  subject: ReplaySubject<BaseEvent> | Observable<BaseEvent>,
  {
    threadId,
    state,
    timeoutMs = 15000, // sign and store credential in W3c credential protocols take several seconds
  }: {
    threadId?: string
    state?: DidExchangeState
    previousState?: DidExchangeState | null
    timeoutMs?: number
  }
) {
  const observable = subject instanceof ReplaySubject ? subject.asObservable() : subject

  return firstValueFrom(
    observable.pipe(
      filter(isConnectionDidRotatedEvent),
      filter((e) => threadId === undefined || e.payload.connectionRecord.threadId === threadId),
      filter((e) => state === undefined || e.payload.connectionRecord.state === state),
      timeout(timeoutMs),
      catchError(() => {
        throw new Error(`ConnectionDidRotated event not emitted within specified timeout: {
  threadId: ${threadId},
  state: ${state}
}`)
      }),
      map((e) => e.payload)
    )
  )
}

export function waitForConnectionRecordSubject(
  subject: ReplaySubject<BaseEvent> | Observable<BaseEvent>,
  {
    threadId,
    state,
    previousState,
    timeoutMs = 15000, // sign and store credential in W3c credential protocols take several seconds
  }: {
    threadId?: string
    state?: DidExchangeState
    previousState?: DidExchangeState | null
    timeoutMs?: number
  }
) {
  const observable = subject instanceof ReplaySubject ? subject.asObservable() : subject

  return firstValueFrom(
    observable.pipe(
      filter(isConnectionStateChangedEvent),
      filter((e) => previousState === undefined || e.payload.previousState === previousState),
      filter((e) => threadId === undefined || e.payload.connectionRecord.threadId === threadId),
      filter((e) => state === undefined || e.payload.connectionRecord.state === state),
      timeout(timeoutMs),
      catchError(() => {
        throw new Error(`ConnectionStateChanged event not emitted within specified timeout: {
  previousState: ${previousState},
  threadId: ${threadId},
  state: ${state}
}`)
      }),
      map((e) => e.payload.connectionRecord)
    )
  )
}

export async function waitForConnectionRecord(
  agent: Agent,
  options: {
    threadId?: string
    state?: DidExchangeState
    previousState?: DidExchangeState | null
    timeoutMs?: number
  }
) {
  const observable = agent.events.observable<ConnectionStateChangedEvent>(ConnectionEventTypes.ConnectionStateChanged)
  return waitForConnectionRecordSubject(observable, options)
}

export async function waitForDidRotate(
  agent: Agent,
  options: {
    threadId?: string
    state?: DidExchangeState
    timeoutMs?: number
  }
) {
  const observable = agent.events.observable<ConnectionDidRotatedEvent>(ConnectionEventTypes.ConnectionDidRotated)
  return waitForDidRotateSubject(observable, options)
}

export async function waitForBasicMessage(
  agent: Agent,
  { content, connectionId }: { content?: string; connectionId?: string }
): Promise<BasicMessage> {
  return new Promise((resolve) => {
    const listener = (event: BasicMessageStateChangedEvent) => {
      const contentMatches = content === undefined || event.payload.message.content === content
      const connectionIdMatches =
        connectionId === undefined || event.payload.basicMessageRecord.connectionId === connectionId

      if (contentMatches && connectionIdMatches) {
        agent.events.off<BasicMessageStateChangedEvent>(BasicMessageEventTypes.BasicMessageStateChanged, listener)

        resolve(event.payload.message)
      }
    }

    agent.events.on<BasicMessageStateChangedEvent>(BasicMessageEventTypes.BasicMessageStateChanged, listener)
  })
}

export async function waitForRevocationNotification(
  agent: Agent,
  options: {
    threadId?: string
    timeoutMs?: number
  }
) {
  const observable = agent.events.observable<RevocationNotificationReceivedEvent>(
    CredentialEventTypes.RevocationNotificationReceived
  )

  return waitForRevocationNotificationSubject(observable, options)
}

export function waitForRevocationNotificationSubject(
  subject: ReplaySubject<RevocationNotificationReceivedEvent> | Observable<RevocationNotificationReceivedEvent>,
  {
    threadId,
    timeoutMs = 10000,
  }: {
    threadId?: string
    timeoutMs?: number
  }
) {
  const observable = subject instanceof ReplaySubject ? subject.asObservable() : subject
  return firstValueFrom(
    observable.pipe(
      filter((e) => threadId === undefined || e.payload.credentialRecord.threadId === threadId),
      timeout(timeoutMs),
      catchError(() => {
        throw new Error(
          `RevocationNotificationReceivedEvent event not emitted within specified timeout: {
    threadId: ${threadId},
  }`
        )
      }),
      map((e) => e.payload.credentialRecord)
    )
  )
}

export function getMockConnection({
  state = DidExchangeState.InvitationReceived,
  role = DidExchangeRole.Requester,
  id = 'test',
  did = 'test-did',
  threadId = 'threadId',
  tags = {},
  theirLabel,
  theirDid = 'their-did',
}: Partial<ConnectionRecordProps> = {}) {
  return new ConnectionRecord({
    did,
    threadId,
    theirDid,
    id,
    role,
    state,
    tags,
    theirLabel,
  })
}

export function getMockOutOfBand({
  label,
  serviceEndpoint,
  recipientKeys = [
    new DidKey(Key.fromPublicKeyBase58('ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7', KeyType.Ed25519)).did,
  ],
  mediatorId,
  role,
  state,
  reusable,
  reuseConnectionId,
  imageUrl,
}: {
  label?: string
  serviceEndpoint?: string
  mediatorId?: string
  recipientKeys?: string[]
  role?: OutOfBandRole
  state?: OutOfBandState
  reusable?: boolean
  reuseConnectionId?: string
  imageUrl?: string
} = {}) {
  const options = {
    label: label ?? 'label',
    imageUrl: imageUrl ?? undefined,
    accept: ['didcomm/aip1', 'didcomm/aip2;env=rfc19'],
    handshakeProtocols: [HandshakeProtocol.DidExchange],
    services: [
      new OutOfBandDidCommService({
        id: `#inline-0`,
        serviceEndpoint: serviceEndpoint ?? 'http://example.com',
        recipientKeys,
        routingKeys: [],
      }),
    ],
  }
  const outOfBandInvitation = new OutOfBandInvitation(options)
  const outOfBandRecord = new OutOfBandRecord({
    mediatorId,
    role: role || OutOfBandRole.Receiver,
    state: state || OutOfBandState.Initial,
    outOfBandInvitation: outOfBandInvitation,
    reusable,
    reuseConnectionId,
    tags: {
      recipientKeyFingerprints: recipientKeys.map((didKey) => DidKey.fromDid(didKey).key.fingerprint),
    },
  })
  return outOfBandRecord
}

export async function makeConnection(agentA: Agent, agentB: Agent) {
  const agentAOutOfBand = await agentA.oob.createInvitation({
    handshakeProtocols: [HandshakeProtocol.Connections],
  })

  let { connectionRecord: agentBConnection } = await agentB.oob.receiveInvitation(agentAOutOfBand.outOfBandInvitation)

  agentBConnection = await agentB.connections.returnWhenIsConnected(agentBConnection!.id)
  let [agentAConnection] = await agentA.connections.findAllByOutOfBandId(agentAOutOfBand.id)
  agentAConnection = await agentA.connections.returnWhenIsConnected(agentAConnection!.id)

  return [agentAConnection, agentBConnection]
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

export async function retryUntilResult<T, M extends () => Promise<T | null>>(
  method: M,
  {
    intervalMs = 500,
    delay = 1000,
    maxAttempts = 5,
  }: {
    intervalMs?: number
    delay?: number
    maxAttempts?: number
  } = {}
): Promise<T> {
  await sleep(delay)

  for (let i = 0; i < maxAttempts; i++) {
    const result = await method()
    if (result) return result
    await sleep(intervalMs)
  }

  throw new Error(`Unable to get result from method in ${maxAttempts} attempts`)
}

export type CreateDidKidVerificationMethodReturn = Awaited<ReturnType<typeof createDidKidVerificationMethod>>
export async function createDidKidVerificationMethod(agentContext: AgentContext, secretKey?: string) {
  const dids = agentContext.dependencyManager.resolve(DidsApi)
  const didCreateResult = await dids.create<KeyDidCreateOptions>({
    method: 'key',
    options: { keyType: KeyType.Ed25519 },
    secret: { privateKey: secretKey ? TypedArrayEncoder.fromString(secretKey) : undefined },
  })

  const did = didCreateResult.didState.did as string
  const didKey = DidKey.fromDid(did)
  const kid = `${did}#${didKey.key.fingerprint}`

  const verificationMethod = didCreateResult.didState.didDocument?.dereferenceKey(kid, ['authentication'])
  if (!verificationMethod) throw new Error('No verification method found')

  return { did, kid, verificationMethod }
}
