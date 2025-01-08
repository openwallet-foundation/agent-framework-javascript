import type { DummyStateChangedEvent } from './dummy'
import type { Socket } from 'net'

import { Agent, ConnectionsModule, ConsoleLogger, DidCommModule, LogLevel } from '@credo-ts/core'
import { agentDependencies, HttpInboundTransport, WsInboundTransport } from '@credo-ts/node'
import express from 'express'
import { Server } from 'ws'

import { DummyModule, DummyEventTypes, DummyState } from './dummy'

const run = async () => {
  // Create transports
  const port = process.env.RESPONDER_PORT ? Number(process.env.RESPONDER_PORT) : 3002
  const autoAcceptRequests = true
  const app = express()
  const socketServer = new Server({ noServer: true })

  const httpInboundTransport = new HttpInboundTransport({ app, port })
  const wsInboundTransport = new WsInboundTransport({ server: socketServer })

  // Setup the agent
  const agent = new Agent({
    config: {
      label: 'Dummy-powered agent - responder',
      walletConfig: {
        id: 'responder',
        key: 'responder',
      },
      logger: new ConsoleLogger(LogLevel.debug),
    },
    modules: {
      didcomm: new DidCommModule({ endpoints: [`http://localhost:${port}`] }),
      dummy: new DummyModule({ autoAcceptRequests }),
      connections: new ConnectionsModule({
        autoAcceptConnections: true,
      }),
    },
    dependencies: agentDependencies,
  })

  // Register transports
  agent.didcomm.registerInboundTransport(httpInboundTransport)
  agent.didcomm.registerInboundTransport(wsInboundTransport)

  // Allow to create invitation, no other way to ask for invitation yet
  app.get('/invitation', async (req, res) => {
    const { outOfBandInvitation } = await agent.oob.createInvitation()
    res.send(outOfBandInvitation.toUrl({ domain: `http://localhost:${port}/invitation` }))
  })

  // Now agent will handle messages and events from Dummy protocol

  //Initialize the agent
  await agent.initialize()

  httpInboundTransport.server?.on('upgrade', (request, socket, head) => {
    socketServer.handleUpgrade(request, socket as Socket, head, (socket) => {
      socketServer.emit('connection', socket, request)
    })
  })

  // If autoAcceptRequests is enabled, the handler will automatically respond
  // (no need to subscribe to event and manually accept)
  if (!autoAcceptRequests) {
    agent.events.on(DummyEventTypes.StateChanged, async (event: DummyStateChangedEvent) => {
      if (event.payload.dummyRecord.state === DummyState.RequestReceived) {
        await agent.modules.dummy.respond(event.payload.dummyRecord.id)
      }
    })
  }

  agent.config.logger.info(`Responder listening to port ${port}`)
}

void run()
