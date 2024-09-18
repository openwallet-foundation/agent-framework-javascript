import type {
  InboundTransport,
  Agent,
  TransportSession,
  EncryptedMessage,
  AgentContext,
  AgentMessageReceivedEvent,
  AgentMessageProcessedEvent,
} from '@credo-ts/core'
import type { Express, Request, Response } from 'express'
import type { Server } from 'http'

import { DidCommMimeType, CredoError, TransportService, utils, AgentEventTypes, deepEquality } from '@credo-ts/core'
import express, { text } from 'express'
import { filter, firstValueFrom, ReplaySubject, timeout } from 'rxjs'

const supportedContentTypes: string[] = [DidCommMimeType.V0, DidCommMimeType.V1]

export class HttpInboundTransport implements InboundTransport {
  public readonly app: Express
  private port: number
  private path: string
  private _server?: Server

  public get server() {
    return this._server
  }

  public constructor({ app, path, port }: { app?: Express; path?: string; port: number }) {
    this.port = port

    // Create Express App
    this.app = app ?? express()
    this.path = path ?? '/'

    this.app.use(text({ type: supportedContentTypes, limit: '5mb' }))
  }

  public async start(agent: Agent) {
    const transportService = agent.dependencyManager.resolve(TransportService)

    agent.config.logger.debug(`Starting HTTP inbound transport`, {
      port: this.port,
    })

    this.app.post(this.path, async (req, res) => {
      const contentType = req.headers['content-type']

      if (!contentType || !supportedContentTypes.includes(contentType)) {
        return res
          .status(415)
          .send('Unsupported content-type. Supported content-types are: ' + supportedContentTypes.join(', '))
      }

      const session = new HttpTransportSession(utils.uuid(), req, res)
      // We want to make sure the session is removed if the connection is closed, as it
      // can't be used anymore then. This could happen if the client abruptly closes the connection.
      req.once('close', () => transportService.removeSession(session))

      try {
        const message = req.body
        const encryptedMessage = JSON.parse(message) as EncryptedMessage

        const observable = agent.events.observable<AgentMessageProcessedEvent>(AgentEventTypes.AgentMessageProcessed)
        const subject = new ReplaySubject(1)

        observable
          .pipe(
            filter((e) => e.type === AgentEventTypes.AgentMessageProcessed),
            filter((e) => deepEquality(e.payload.encryptedMessage, encryptedMessage)),
            timeout({
              first: 10000, // timeout after 10 seconds
              meta: 'HttpInboundTransport.start',
            })
          )
          .subscribe(subject)

        agent.events.emit<AgentMessageReceivedEvent>(agent.context, {
          type: AgentEventTypes.AgentMessageReceived,
          payload: {
            message: encryptedMessage,
            session: session,
          },
        })

        // Wait for message to be processed
        await firstValueFrom(subject)

        // If agent did not use session when processing message we need to send response here.
        if (!res.headersSent) {
          res.status(200).end()
        }
      } catch (error) {
        agent.config.logger.error(`Error processing inbound message: ${error.message}`, error)

        if (!res.headersSent) {
          res.status(500).send('Error processing message')
        }
      } finally {
        transportService.removeSession(session)
      }
    })

    this._server = this.app.listen(this.port)
  }

  public async stop(): Promise<void> {
    return new Promise((resolve, reject) => this._server?.close((err) => (err ? reject(err) : resolve())))
  }
}

export class HttpTransportSession implements TransportSession {
  public id: string
  public readonly type = 'http'
  public req: Request
  public res: Response

  public constructor(id: string, req: Request, res: Response) {
    this.id = id
    this.req = req
    this.res = res
  }

  public async close(): Promise<void> {
    if (!this.res.headersSent) {
      this.res.status(200).end()
    }
  }

  public async send(agentContext: AgentContext, encryptedMessage: EncryptedMessage): Promise<void> {
    if (this.res.headersSent) {
      throw new CredoError(`${this.type} transport session has been closed.`)
    }

    // By default we take the agent config's default DIDComm content-type
    let responseMimeType = agentContext.config.didCommMimeType as string

    // However, if the request mime-type is a mime-type that is supported by us, we use that
    // to minimize the chance of interoperability issues
    const requestMimeType = this.req.headers['content-type']
    if (requestMimeType && supportedContentTypes.includes(requestMimeType)) {
      responseMimeType = requestMimeType
    }

    this.res.status(200).contentType(responseMimeType).json(encryptedMessage).end()
  }
}
