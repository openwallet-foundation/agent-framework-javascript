import type { OutboundTransport } from './OutboundTransport'
import type { AgentMessageReceivedEvent } from '../Events'
import type { OutboundPackage } from '../types'
import type { AgentContext, Logger } from '@credo-ts/core'

import { EventEmitter, CredoError, JsonEncoder } from '@credo-ts/core'
import { Subject } from 'rxjs'

import { DidCommModuleConfig } from '../DidCommModuleConfig'
import { AgentEventTypes } from '../Events'
import { isValidJweStructure } from '../util/JWE'

export class HttpOutboundTransport implements OutboundTransport {
  private agentContext!: AgentContext
  private logger!: Logger
  private fetch!: typeof fetch
  private isActive = false

  private outboundSessionCount = 0
  private outboundSessionsObservable = new Subject()

  public supportedSchemes = ['http', 'https']

  public async start(agentContext: AgentContext): Promise<void> {
    this.agentContext = agentContext
    this.logger = this.agentContext.config.logger
    this.fetch = this.agentContext.config.agentDependencies.fetch
    this.isActive = true
    this.outboundSessionCount = 0

    this.logger.debug('Starting HTTP outbound transport')
  }

  public async stop(): Promise<void> {
    this.logger.debug('Stopping HTTP outbound transport')
    this.isActive = false

    if (this.outboundSessionCount === 0) {
      this.agentContext.config.logger.debug(
        'No open outbound HTTP sessions. Immediately stopping HttpOutboundTransport'
      )
      return
    }

    this.agentContext.config.logger.debug(
      `Still ${this.outboundSessionCount} open outbound HTTP sessions. Waiting for sessions to close before stopping HttpOutboundTransport`
    )
    // Track all 'closed' sessions
    // TODO: add timeout? -> we have a timeout on the request
    return new Promise((resolve) =>
      this.outboundSessionsObservable.subscribe(() => {
        this.agentContext.config.logger.debug(
          `${this.outboundSessionCount} HttpOutboundTransport sessions still active`
        )
        if (this.outboundSessionCount === 0) resolve()
      })
    )
  }

  public async sendMessage(outboundPackage: OutboundPackage) {
    const { payload, endpoint } = outboundPackage
    const didCommMimeType = this.agentContext.dependencyManager.resolve(DidCommModuleConfig).didCommMimeType

    if (!this.isActive) {
      throw new CredoError('Outbound transport is not active. Not sending message.')
    }

    if (!endpoint) {
      throw new CredoError(`Missing endpoint. I don't know how and where to send the message.`)
    }

    this.logger.debug(`Sending outbound message to endpoint '${outboundPackage.endpoint}'`, {
      payload: outboundPackage.payload,
    })

    try {
      const abortController = new AbortController()
      const id = setTimeout(() => abortController.abort(), 15000)
      this.outboundSessionCount++

      let response
      let responseMessage
      try {
        response = await this.fetch(endpoint, {
          method: 'POST',
          body: JSON.stringify(payload),
          headers: { 'Content-Type': didCommMimeType },
          signal: abortController.signal as NonNullable<RequestInit['signal']>,
        })
        clearTimeout(id)
        responseMessage = await response.text()
      } catch (error) {
        // Request is aborted after 15 seconds, but that doesn't necessarily mean the request
        // went wrong. ACA-Py keeps the socket alive until it has a response message. So we assume
        // that if the error was aborted and we had return routing enabled, we should ignore the error.
        if (error.name == 'AbortError' && outboundPackage.responseRequested) {
          this.logger.debug(
            'Request was aborted due to timeout. Not throwing error due to return routing on sent message'
          )
        } else {
          throw error
        }
      }

      // TODO: do we just want to ignore messages that were returned if we didn't request it?
      // TODO: check response header type (and also update inbound transports to use the correct headers types)
      if (response && responseMessage) {
        this.logger.debug(`Response received`, { responseMessage, status: response.status })

        // This should not happen
        if (!this.isActive) {
          this.logger.error('Received response message over HttpOutboundTransport while transport was not active.')
        }

        try {
          const encryptedMessage = JsonEncoder.fromString(responseMessage)
          if (!isValidJweStructure(encryptedMessage)) {
            this.logger.error(
              `Received a response from the other agent but the structure of the incoming message is not a DIDComm message: ${responseMessage}`
            )
            return
          }
          // Emit event with the received agent message.
          const eventEmitter = this.agentContext.dependencyManager.resolve(EventEmitter)
          eventEmitter.emit<AgentMessageReceivedEvent>(this.agentContext, {
            type: AgentEventTypes.AgentMessageReceived,
            payload: {
              message: encryptedMessage,
            },
          })
        } catch (error) {
          this.logger.debug('Unable to parse response message')
        }
      } else {
        this.logger.debug(`No response received.`)
      }
    } catch (error) {
      this.logger.error(`Error sending message to ${endpoint}: ${error.message}`, {
        error,
        message: error.message,
        body: payload,
        didCommMimeType,
      })
      throw new CredoError(`Error sending message to ${endpoint}: ${error.message}`, { cause: error })
    } finally {
      this.outboundSessionCount--
      this.outboundSessionsObservable.next(undefined)
    }
  }
}
