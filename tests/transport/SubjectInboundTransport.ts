import type { AgentContext } from '../../packages/core/src'
import type { InboundTransport, EncryptedMessage, TransportSession } from '../../packages/didcomm/src'
import type { Subscription } from 'rxjs'

import { Subject } from 'rxjs'

import { EventEmitter } from '../../packages/core/src'
import { uuid } from '../../packages/core/src/utils/uuid'
import { MessageReceiver, TransportService } from '../../packages/didcomm/src'

export type SubjectMessage = { message: EncryptedMessage; replySubject?: Subject<SubjectMessage> }

export class SubjectInboundTransport implements InboundTransport {
  public readonly ourSubject: Subject<SubjectMessage>
  private subscription?: Subscription

  public constructor(ourSubject = new Subject<SubjectMessage>()) {
    this.ourSubject = ourSubject
  }

  public async start(agent: AgentContext) {
    this.subscribe(agent)
  }

  public async stop() {
    this.subscription?.unsubscribe()
  }

  private subscribe(agentContext: AgentContext) {
    const logger = agentContext.config.logger
    const transportService = agentContext.dependencyManager.resolve(TransportService)
    const messageReceiver = agentContext.dependencyManager.resolve(MessageReceiver)
    const eventEmitter = agentContext.dependencyManager.resolve(EventEmitter)

    this.subscription = this.ourSubject.subscribe({
      next: async ({ message, replySubject }: SubjectMessage) => {
        logger.test('Received message')

        let session: SubjectTransportSession | undefined
        if (replySubject) {
          session = new SubjectTransportSession(`subject-session-${uuid()}`, replySubject)

          // When the subject is completed (e.g. when the session is closed), we need to
          // remove the session from the transport service so it won't be used for sending messages
          // in the future.
          replySubject.subscribe({
            complete: () => session && transportService.removeSession(session),
          })
        }

        // This emits a custom error in order to easily catch in E2E tests when a message
        // reception throws an error. TODO: Remove as soon as agent throws errors automatically
        try {
          await messageReceiver.receiveMessage(message, { session })
        } catch (error) {
          eventEmitter.emit(agentContext, {
            type: 'AgentReceiveMessageError',
            payload: error,
          })
        }
      },
    })
  }
}

export class SubjectTransportSession implements TransportSession {
  public id: string
  public readonly type = 'subject'
  private replySubject: Subject<SubjectMessage>

  public constructor(id: string, replySubject: Subject<SubjectMessage>) {
    this.id = id
    this.replySubject = replySubject
  }

  public async send(agentContext: AgentContext, encryptedMessage: EncryptedMessage): Promise<void> {
    this.replySubject.next({ message: encryptedMessage })
  }

  public async close(): Promise<void> {
    this.replySubject.complete()
  }
}
