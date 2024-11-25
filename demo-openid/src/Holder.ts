import type { OpenId4VciResolvedCredentialOffer, OpenId4VcSiopResolvedAuthorizationRequest } from '@credo-ts/openid4vc'

import { AskarModule } from '@credo-ts/askar'
import {
  W3cJwtVerifiableCredential,
  W3cJsonLdVerifiableCredential,
  Mdoc,
  DidKey,
  DidJwk,
  getJwkFromKey,
} from '@credo-ts/core'
import {
  authorizationCodeGrantIdentifier,
  OpenId4VcHolderModule,
  OpenId4VciAuthorizationFlow,
  preAuthorizedCodeGrantIdentifier,
} from '@credo-ts/openid4vc'
import { ariesAskar } from '@hyperledger/aries-askar-nodejs'

import { BaseAgent } from './BaseAgent'
import { Output } from './OutputClass'

function getOpenIdHolderModules() {
  return {
    askar: new AskarModule({ ariesAskar }),
    openId4VcHolder: new OpenId4VcHolderModule(),
  } as const
}

export class Holder extends BaseAgent<ReturnType<typeof getOpenIdHolderModules>> {
  public client = {
    clientId: 'wallet',
    redirectUri: 'http://localhost:3000/redirect',
  }

  public constructor(port: number, name: string) {
    super({ port, name, modules: getOpenIdHolderModules() })
  }

  public static async build(): Promise<Holder> {
    const holder = new Holder(3000, 'OpenId4VcHolder ' + Math.random().toString())
    await holder.initializeAgent('96213c3d7fc8d4d6754c7a0fd969598e')
    await holder.agent.x509.addTrustedCertificate(
      'MIH7MIGioAMCAQICEFvUcSkwWUaPlEWnrOmu_EYwCgYIKoZIzj0EAwIwDTELMAkGA1UEBhMCREUwIBcNMDAwMTAxMDAwMDAwWhgPMjA1MDAxMDEwMDAwMDBaMA0xCzAJBgNVBAYTAkRFMDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgAC3A9V8ynqRcVjADqlfpZ9X8mwbew0TuQldH_QOpkadsWjAjAAMAoGCCqGSM49BAMCA0gAMEUCIQDXGNookSkHqRXiOP_0fVUdNIScY13h3DWkqSopFIYB2QIgUzNFnZ-SEdm-7UMzggaPiFgtznVzmHw2h4vVtuLzWlA'
    )

    return holder
  }

  public async resolveCredentialOffer(credentialOffer: string) {
    return await this.agent.modules.openId4VcHolder.resolveCredentialOffer(credentialOffer)
  }

  public async resolveIssuerMetadata(credentialIssuer: string) {
    return await this.agent.modules.openId4VcHolder.resolveIssuerMetadata(credentialIssuer)
  }

  public async initiateAuthorization(
    resolvedCredentialOffer: OpenId4VciResolvedCredentialOffer,
    credentialsToRequest: string[]
  ) {
    const grants = resolvedCredentialOffer.credentialOfferPayload.grants
    // TODO: extend iniateAuthorization in oid4vci lib? Or not?
    if (grants?.[preAuthorizedCodeGrantIdentifier]) {
      return {
        authorizationFlow: 'PreAuthorized',
        preAuthorizedCode: grants[preAuthorizedCodeGrantIdentifier]['pre-authorized_code'],
      } as const
    } else if (resolvedCredentialOffer.credentialOfferPayload.grants?.[authorizationCodeGrantIdentifier]) {
      const resolvedAuthorizationRequest = await this.agent.modules.openId4VcHolder.resolveIssuanceAuthorizationRequest(
        resolvedCredentialOffer,
        {
          clientId: this.client.clientId,
          redirectUri: this.client.redirectUri,
          scope: Object.entries(resolvedCredentialOffer.offeredCredentialConfigurations)
            .map(([id, value]) => (credentialsToRequest.includes(id) ? value.scope : undefined))
            .filter((v): v is string => Boolean(v)),
        }
      )

      if (resolvedAuthorizationRequest.authorizationFlow === OpenId4VciAuthorizationFlow.PresentationDuringIssuance) {
        return {
          ...resolvedAuthorizationRequest,
          authorizationFlow: `${OpenId4VciAuthorizationFlow.PresentationDuringIssuance}`,
        } as const
      } else {
        return {
          ...resolvedAuthorizationRequest,
          authorizationFlow: `${OpenId4VciAuthorizationFlow.Oauth2Redirect}`,
        } as const
      }
    }

    throw new Error('Unsupported grant type')
  }

  public async requestAndStoreCredentials(
    resolvedCredentialOffer: OpenId4VciResolvedCredentialOffer,
    options: {
      clientId?: string
      codeVerifier?: string
      credentialsToRequest: string[]
      code?: string
      redirectUri?: string
      txCode?: string
    }
  ) {
    const tokenResponse = await this.agent.modules.openId4VcHolder.requestToken(
      options.code && options.clientId
        ? {
            resolvedCredentialOffer,
            clientId: options.clientId,
            codeVerifier: options.codeVerifier,
            code: options.code,
            redirectUri: options.redirectUri,
          }
        : {
            resolvedCredentialOffer,
            txCode: options.txCode,
          }
    )

    const credentialResponse = await this.agent.modules.openId4VcHolder.requestCredentials({
      resolvedCredentialOffer,
      clientId: options.clientId,
      credentialConfigurationIds: options.credentialsToRequest,
      credentialBindingResolver: async ({ keyTypes, supportedDidMethods, supportsAllDidMethods }) => {
        const key = await this.agent.wallet.createKey({
          keyType: keyTypes[0],
        })

        if (supportsAllDidMethods || supportedDidMethods?.includes('did:key')) {
          const didKey = new DidKey(key)

          return {
            method: 'did',
            didUrl: `${didKey.did}#${didKey.key.fingerprint}`,
          }
        }
        if (supportedDidMethods?.includes('did:jwk')) {
          const didJwk = DidJwk.fromJwk(getJwkFromKey(key))

          return {
            method: 'did',
            didUrl: `${didJwk.did}#0`,
          }
        }

        // We fall back on jwk binding
        return {
          method: 'jwk',
          jwk: getJwkFromKey(key),
        }
      },
      ...tokenResponse,
    })

    const storedCredentials = await Promise.all(
      credentialResponse.credentials.map((response) => {
        // TODO: handle batch issuance
        const credential = response.credentials[0]
        if (credential instanceof W3cJwtVerifiableCredential || credential instanceof W3cJsonLdVerifiableCredential) {
          return this.agent.w3cCredentials.storeCredential({ credential })
        } else if (credential instanceof Mdoc) {
          return this.agent.mdoc.store(credential)
        } else {
          return this.agent.sdJwtVc.store(credential.compact)
        }
      })
    )

    return storedCredentials
  }

  public async resolveProofRequest(proofRequest: string) {
    const resolvedProofRequest = await this.agent.modules.openId4VcHolder.resolveSiopAuthorizationRequest(proofRequest)

    return resolvedProofRequest
  }

  public async acceptPresentationRequest(resolvedPresentationRequest: OpenId4VcSiopResolvedAuthorizationRequest) {
    if (!resolvedPresentationRequest.presentationExchange && !resolvedPresentationRequest.dcql) {
      throw new Error('Missing presentation exchange or dcql on resolved authorization request')
    }

    const submissionResult = await this.agent.modules.openId4VcHolder.acceptSiopAuthorizationRequest({
      authorizationRequest: resolvedPresentationRequest.authorizationRequest,
      presentationExchange: resolvedPresentationRequest.presentationExchange
        ? {
            credentials: this.agent.modules.openId4VcHolder.selectCredentialsForPresentationExchangeRequest(
              resolvedPresentationRequest.presentationExchange.credentialsForRequest
            ),
          }
        : undefined,
      dcql: resolvedPresentationRequest.dcql
        ? {
            credentials: this.agent.modules.openId4VcHolder.selectCredentialsForDcqlRequest(
              resolvedPresentationRequest.dcql.queryResult
            ),
          }
        : undefined,
    })

    return submissionResult.serverResponse
  }

  public async exit() {
    console.log(Output.Exit)
    await this.agent.shutdown()
    process.exit(0)
  }

  public async restart() {
    await this.agent.shutdown()
  }
}
