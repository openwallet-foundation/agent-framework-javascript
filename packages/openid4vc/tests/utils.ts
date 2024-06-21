import type {
  OpenId4VcIssuanceSessionState,
  OpenId4VcIssuanceSessionStateChangedEvent,
  OpenId4VcVerificationSessionState,
  OpenId4VcVerificationSessionStateChangedEvent,
} from '../src'
import type { BaseEvent, ModulesMap } from '@credo-ts/core'
import type { TenantsModule } from '@credo-ts/tenants'
import type { Observable } from 'rxjs'

import { Agent, LogLevel, utils } from '@credo-ts/core'
import { ReplaySubject, lastValueFrom, filter, timeout, catchError, take, map } from 'rxjs'

import {
  TestLogger,
  agentDependencies,
  createDidKidVerificationMethod,
  setupEventReplaySubjects,
} from '../../core/tests'
import { OpenId4VcVerifierEvents, OpenId4VcIssuerEvents } from '../src'

export async function createAgentFromModules<MM extends ModulesMap>(label: string, modulesMap: MM, secretKey: string) {
  const agent = new Agent<MM>({
    config: { label, walletConfig: { id: utils.uuid(), key: utils.uuid() }, logger: new TestLogger(LogLevel.off) },
    dependencies: agentDependencies,
    modules: modulesMap,
  })

  await agent.initialize()
  const data = await createDidKidVerificationMethod(agent.context, secretKey)

  const [replaySubject] = setupEventReplaySubjects(
    [agent],
    [OpenId4VcIssuerEvents.IssuanceSessionStateChanged, OpenId4VcVerifierEvents.VerificationSessionStateChanged]
  )

  return {
    ...data,
    agent,
    replaySubject,
  }
}

export type AgentType<MM extends ModulesMap> = Awaited<ReturnType<typeof createAgentFromModules<MM>>>

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AgentWithTenantsModule = Agent<{ tenants: TenantsModule<any> }>

export async function createTenantForAgent(
  // FIXME: we need to make some improvements on the agent typing. It'a quite hard
  // to get it right at the moment
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  agent: AgentWithTenantsModule & any,
  label: string
) {
  const tenantRecord = await agent.modules.tenants.createTenant({
    config: {
      label,
    },
  })

  const tenant = await agent.modules.tenants.getTenantAgent({ tenantId: tenantRecord.id })
  const data = await createDidKidVerificationMethod(tenant)
  await tenant.endSession()

  return {
    ...data,
    tenantId: tenantRecord.id,
  }
}

export type TenantType = Awaited<ReturnType<typeof createTenantForAgent>>

export function waitForCredentialIssuanceSessionRecordSubject(
  subject: ReplaySubject<BaseEvent> | Observable<BaseEvent>,
  {
    state,
    previousState,
    timeoutMs = 10000,
    count = 1,
    contextCorrelationId,
    issuanceSessionId,
  }: {
    state?: OpenId4VcIssuanceSessionState
    previousState?: OpenId4VcIssuanceSessionState | null
    timeoutMs?: number
    count?: number
    contextCorrelationId?: string
    issuanceSessionId?: string
  }
) {
  const observable: Observable<BaseEvent> = subject instanceof ReplaySubject ? subject.asObservable() : subject
  return lastValueFrom(
    observable.pipe(
      filter((e) => contextCorrelationId === undefined || e.metadata.contextCorrelationId === contextCorrelationId),
      filter(
        (event): event is OpenId4VcIssuanceSessionStateChangedEvent =>
          event.type === OpenId4VcIssuerEvents.IssuanceSessionStateChanged
      ),
      filter((e) => previousState === undefined || e.payload.previousState === previousState),
      filter((e) => state === undefined || e.payload.issuanceSession.state === state),
      filter((e) => issuanceSessionId === undefined || e.payload.issuanceSession.id === issuanceSessionId),
      timeout(timeoutMs),
      catchError(() => {
        throw new Error(
          `OpenId4VcIssuanceSessionStateChangedEvent event not emitted within specified timeout: ${timeoutMs}
          contextCorrelationId: ${contextCorrelationId},
          issuanceSessionId: ${issuanceSessionId}
          previousState: ${previousState},
          state: ${state}
        }`
        )
      }),
      take(count),
      map((e) => e.payload.issuanceSession)
    )
  )
}

export function waitForVerificationSessionRecordSubject(
  subject: ReplaySubject<BaseEvent> | Observable<BaseEvent>,
  {
    state,
    previousState,
    timeoutMs = 10000,
    count = 1,
    contextCorrelationId,
    verificationSessionId,
  }: {
    state?: OpenId4VcVerificationSessionState
    previousState?: OpenId4VcVerificationSessionState | null
    timeoutMs?: number
    count?: number
    contextCorrelationId?: string
    verificationSessionId?: string
  }
) {
  const observable: Observable<BaseEvent> = subject instanceof ReplaySubject ? subject.asObservable() : subject
  return lastValueFrom(
    observable.pipe(
      filter((e) => contextCorrelationId === undefined || e.metadata.contextCorrelationId === contextCorrelationId),
      filter(
        (event): event is OpenId4VcVerificationSessionStateChangedEvent =>
          event.type === OpenId4VcVerifierEvents.VerificationSessionStateChanged
      ),
      filter((e) => previousState === undefined || e.payload.previousState === previousState),
      filter((e) => state === undefined || e.payload.verificationSession.state === state),
      filter((e) => verificationSessionId === undefined || e.payload.verificationSession.id === verificationSessionId),
      timeout(timeoutMs),
      catchError(() => {
        throw new Error(
          `OpenId4VcVerificationSessionStateChangedEvent event not emitted within specified timeout: ${timeoutMs}
          contextCorrelationId: ${contextCorrelationId},
          verificationSessionId: ${verificationSessionId}
          previousState: ${previousState},
          state: ${state}
        }`
        )
      }),
      take(count),
      map((e) => e.payload.verificationSession)
    )
  )
}
