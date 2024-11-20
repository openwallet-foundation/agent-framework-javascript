import type { OpenId4VcIssuerModuleConfigOptions } from './OpenId4VcIssuerModuleConfig'
import type { OpenId4VcIssuanceRequest } from './router'
import type { AgentContext, DependencyManager, Module } from '@credo-ts/core'
import type { NextFunction, Response } from 'express'

import { setGlobalConfig } from '@animo-id/oauth2'
import { AgentConfig } from '@credo-ts/core'

import { getAgentContextForActorId, getRequestContext, importExpress } from '../shared/router'

import { OpenId4VcIssuerApi } from './OpenId4VcIssuerApi'
import { OpenId4VcIssuerModuleConfig } from './OpenId4VcIssuerModuleConfig'
import { OpenId4VcIssuerService } from './OpenId4VcIssuerService'
import { OpenId4VcIssuanceSessionRepository } from './repository'
import { OpenId4VcIssuerRepository } from './repository/OpenId4VcIssuerRepository'
import {
  configureCredentialOfferEndpoint,
  configureAccessTokenEndpoint,
  configureCredentialEndpoint,
  configureIssuerMetadataEndpoint,
  configureOAuthAuthorizationServerMetadataEndpoint,
  configureJwksEndpoint,
  configureNonceEndpoint,
  configureAuthorizationChallengeEndpoint,
} from './router'
import { configureFederationEndpoint } from './router/federationEndpoint'

/**
 * @public
 */
export class OpenId4VcIssuerModule implements Module {
  public readonly api = OpenId4VcIssuerApi
  public readonly config: OpenId4VcIssuerModuleConfig

  public constructor(options: OpenId4VcIssuerModuleConfigOptions) {
    this.config = new OpenId4VcIssuerModuleConfig(options)
  }

  /**
   * Registers the dependencies of the openid4vc issuer module on the dependency manager.
   */
  public register(dependencyManager: DependencyManager) {
    const agentConfig = dependencyManager.resolve(AgentConfig)

    // Warn about experimental module
    agentConfig.logger.warn(
      "The '@credo-ts/openid4vc' Issuer module is experimental and could have unexpected breaking changes. When using this module, make sure to use strict versions for all @credo-ts packages."
    )

    if (agentConfig.allowInsecureHttpUrls) {
      setGlobalConfig({
        allowInsecureUrls: true,
      })
    }
    // Register config
    dependencyManager.registerInstance(OpenId4VcIssuerModuleConfig, this.config)

    // Services
    dependencyManager.registerSingleton(OpenId4VcIssuerService)

    // Repository
    dependencyManager.registerSingleton(OpenId4VcIssuerRepository)
    dependencyManager.registerSingleton(OpenId4VcIssuanceSessionRepository)
  }

  public async initialize(rootAgentContext: AgentContext): Promise<void> {
    this.configureRouter(rootAgentContext)
  }

  /**
   * Registers the endpoints on the router passed to this module.
   */
  private configureRouter(rootAgentContext: AgentContext) {
    const { Router, json, urlencoded } = importExpress()

    // TODO: it is currently not possible to initialize an agent
    // shut it down, and then start it again, as the
    // express router is configured with a specific `AgentContext` instance
    // and dependency manager. One option is to always create a new router
    // but then users cannot pass their own router implementation.
    // We need to find a proper way to fix this.

    // We use separate context router and endpoint router. Context router handles the linking of the request
    // to a specific agent context. Endpoint router only knows about a single context
    const endpointRouter = Router()
    const contextRouter = this.config.router

    // parse application/x-www-form-urlencoded
    contextRouter.use(urlencoded({ extended: false }))
    // parse application/json
    contextRouter.use(json())

    contextRouter.param('issuerId', async (req: OpenId4VcIssuanceRequest, _res, next, issuerId: string) => {
      if (!issuerId) {
        rootAgentContext.config.logger.debug('No issuerId provided for incoming oid4vci request, returning 404')
        _res.status(404).send('Not found')
      }

      let agentContext: AgentContext | undefined = undefined

      try {
        // FIXME: should we create combined openId actor record?
        agentContext = await getAgentContextForActorId(rootAgentContext, issuerId)
        const issuerApi = agentContext.dependencyManager.resolve(OpenId4VcIssuerApi)
        const issuer = await issuerApi.getIssuerByIssuerId(issuerId)

        req.requestContext = {
          agentContext,
          issuer,
        }
      } catch (error) {
        agentContext?.config.logger.error(
          'Failed to correlate incoming oid4vci request to existing tenant and issuer',
          {
            error,
          }
        )
        // If the opening failed
        await agentContext?.endSession()

        return _res.status(404).send('Not found')
      }

      next()
    })

    contextRouter.use('/:issuerId', endpointRouter)

    // Configure endpoints
    configureIssuerMetadataEndpoint(endpointRouter)
    configureJwksEndpoint(endpointRouter, this.config)
    configureNonceEndpoint(endpointRouter, this.config)
    configureOAuthAuthorizationServerMetadataEndpoint(endpointRouter)
    configureCredentialOfferEndpoint(endpointRouter, this.config)
    configureAccessTokenEndpoint(endpointRouter, this.config)
    configureAuthorizationChallengeEndpoint(endpointRouter, this.config)
    configureCredentialEndpoint(endpointRouter, this.config)
    configureFederationEndpoint(endpointRouter)

    // First one will be called for all requests (when next is called)
    contextRouter.use(async (req: OpenId4VcIssuanceRequest, _res: unknown, next) => {
      const { agentContext } = getRequestContext(req)
      await agentContext.endSession()

      next()
    })

    // This one will be called for all errors that are thrown
    contextRouter.use(async (_error: unknown, req: OpenId4VcIssuanceRequest, res: Response, next: NextFunction) => {
      const { agentContext } = getRequestContext(req)

      if (!res.headersSent) {
        agentContext.config.logger.warn(
          'Error was thrown but openid4vci endpoint did not send a response. Sending generic server_error.'
        )

        res.status(500).json({
          error: 'server_error',
          error_description: 'An unexpected error occurred on the server.',
        })
      }

      await agentContext.endSession()
      next()
    })
  }
}
