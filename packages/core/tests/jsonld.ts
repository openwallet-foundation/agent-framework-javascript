import type { EventReplaySubject } from './events'
import type { AutoAcceptCredential, AutoAcceptProof, ConnectionRecord } from '../../didcomm/src'

import { InMemoryWalletModule } from '../../../tests/InMemoryWalletModule'
import { askarModule } from '../../askar/tests/helpers'
import { BbsModule } from '../../bbs-signatures/src/BbsModule'
import {
  DifPresentationExchangeProofFormatService,
  V2ProofProtocol,
  CredentialEventTypes,
  ProofEventTypes,
  ProofsModule,
  CredentialsModule,
  JsonLdCredentialFormatService,
  V2CredentialProtocol,
} from '../../didcomm/src'
import { getDefaultDidcommModules } from '../../didcomm/src/util/modules'
import { CacheModule, InMemoryLruCache, Agent, W3cCredentialsModule } from '../src'
import { customDocumentLoader } from '../src/modules/vc/data-integrity/__tests__/documentLoader'

import { setupEventReplaySubjects } from './events'
import { getAgentOptions, makeConnection } from './helpers'
import { setupSubjectTransports } from './transport'

export type JsonLdTestsAgent = Agent<ReturnType<typeof getJsonLdModules>>

export const getJsonLdModules = ({
  autoAcceptCredentials,
  autoAcceptProofs,
  useBbs = false,
}: { autoAcceptCredentials?: AutoAcceptCredential; autoAcceptProofs?: AutoAcceptProof; useBbs?: boolean } = {}) =>
  ({
    ...getDefaultDidcommModules(),
    credentials: new CredentialsModule({
      credentialProtocols: [new V2CredentialProtocol({ credentialFormats: [new JsonLdCredentialFormatService()] })],
      autoAcceptCredentials,
    }),
    w3cCredentials: new W3cCredentialsModule({
      documentLoader: customDocumentLoader,
    }),
    proofs: new ProofsModule({
      autoAcceptProofs,
      proofProtocols: [new V2ProofProtocol({ proofFormats: [new DifPresentationExchangeProofFormatService()] })],
    }),
    cache: new CacheModule({
      cache: new InMemoryLruCache({ limit: 100 }),
    }),
    // We don't support signing provider in in memory wallet yet, so if BBS is used we need to use Askar
    ...(useBbs
      ? {
          askar: askarModule,
          bbs: new BbsModule(),
        }
      : {
          inMemory: new InMemoryWalletModule(),
        }),
  } as const)

interface SetupJsonLdTestsReturn<VerifierName extends string | undefined, CreateConnections extends boolean> {
  issuerAgent: JsonLdTestsAgent
  issuerReplay: EventReplaySubject

  holderAgent: JsonLdTestsAgent
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

  verifierAgent: VerifierName extends string ? JsonLdTestsAgent : undefined
  verifierReplay: VerifierName extends string ? EventReplaySubject : undefined

  credentialDefinitionId: string
}

export async function setupJsonLdTests<
  VerifierName extends string | undefined = undefined,
  CreateConnections extends boolean = true
>({
  issuerName,
  holderName,
  verifierName,
  autoAcceptCredentials,
  autoAcceptProofs,
  createConnections,
  useBbs = false,
}: {
  issuerName: string
  holderName: string
  verifierName?: VerifierName
  autoAcceptCredentials?: AutoAcceptCredential
  autoAcceptProofs?: AutoAcceptProof
  createConnections?: CreateConnections
  useBbs?: boolean
}): Promise<SetupJsonLdTestsReturn<VerifierName, CreateConnections>> {
  const modules = getJsonLdModules({
    autoAcceptCredentials,
    autoAcceptProofs,
    useBbs,
  })

  const issuerAgent = new Agent(
    getAgentOptions(
      issuerName,
      {
        endpoints: ['rxjs:issuer'],
      },
      {},
      modules
    )
  )

  const holderAgent = new Agent(
    getAgentOptions(
      holderName,
      {
        endpoints: ['rxjs:holder'],
      },
      {},
      modules
    )
  )

  const verifierAgent = verifierName
    ? new Agent(
        getAgentOptions(
          verifierName,
          {
            endpoints: ['rxjs:verifier'],
          },
          {},
          modules
        )
      )
    : undefined

  setupSubjectTransports(verifierAgent ? [issuerAgent, holderAgent, verifierAgent] : [issuerAgent, holderAgent])
  const [issuerReplay, holderReplay, verifierReplay] = setupEventReplaySubjects(
    verifierAgent ? [issuerAgent, holderAgent, verifierAgent] : [issuerAgent, holderAgent],
    [CredentialEventTypes.CredentialStateChanged, ProofEventTypes.ProofStateChanged]
  )

  await issuerAgent.initialize()
  await holderAgent.initialize()
  if (verifierAgent) await verifierAgent.initialize()

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

    issuerHolderConnectionId: issuerHolderConnection?.id,
    holderIssuerConnectionId: holderIssuerConnection?.id,
    holderVerifierConnectionId: holderVerifierConnection?.id,
    verifierHolderConnectionId: verifierHolderConnection?.id,
  } as unknown as SetupJsonLdTestsReturn<VerifierName, CreateConnections>
}
