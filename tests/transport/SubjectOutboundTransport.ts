import type { SubjectMessage } from './SubjectInboundTransport'
import type { Logger, AgentContext } from '@credo-ts/core'
import type { OutboundPackage, OutboundTransport } from '@credo-ts/didcomm'

import { takeUntil, Subject, take } from 'rxjs'

import { InjectionSymbols, CredoError } from '@credo-ts/core'
import { MessageReceiver } from '@credo-ts/didcomm'

export class SubjectOutboundTransport implements OutboundTransport {
  private logger!: Logger
  private subjectMap: { [key: string]: Subject<SubjectMessage> | undefined }
  private agentContext!: AgentContext
  private stop$!: Subject<boolean>

  public supportedSchemes = ['rxjs', 'wss']

  public constructor(subjectMap: { [key: string]: Subject<SubjectMessage> | undefined }) {
    this.subjectMap = subjectMap
  }

  public async start(agentContext: AgentContext): Promise<void> {
    this.agentContext = agentContext

    this.logger = agentContext.dependencyManager.resolve(InjectionSymbols.Logger)
    this.stop$ = agentContext.dependencyManager.resolve(InjectionSymbols.Stop$)
  }

  public async stop(): Promise<void> {
    // No logic needed
  }

  public async sendMessage(outboundPackage: OutboundPackage) {
    const messageReceiver = this.agentContext.dependencyManager.resolve(MessageReceiver)
    this.logger.debug(`Sending outbound message to endpoint ${outboundPackage.endpoint}`, {
      endpoint: outboundPackage.endpoint,
    })
    const { payload, endpoint } = outboundPackage

    if (!endpoint) {
      throw new CredoError('Cannot send message to subject without endpoint')
    }

    const subject = this.subjectMap[endpoint]

    if (!subject) {
      throw new CredoError(`No subject found for endpoint ${endpoint}`)
    }

    // Create a replySubject just for this session. Both ends will be able to close it,
    // mimicking a transport like http or websocket. Close session automatically when agent stops
    const replySubject = new Subject<SubjectMessage>()
    this.stop$.pipe(take(1)).subscribe(() => !replySubject.closed && replySubject.complete())

    replySubject.pipe(takeUntil(this.stop$)).subscribe({
      next: async ({ message }: SubjectMessage) => {
        this.logger.test('Received message')

        await messageReceiver.receiveMessage(message)
      },
    })

    subject.next({ message: payload, replySubject })
  }
}
