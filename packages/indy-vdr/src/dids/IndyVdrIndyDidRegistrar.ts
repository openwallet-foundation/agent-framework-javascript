import type { CommEndpointType, IndyEndpointAttrib } from './didSovUtil'
import type { IndyVdrPool } from '../pool'
import type {
  AgentContext,
  DidRegistrar,
  DidCreateOptions,
  DidCreateResult,
  DidDeactivateResult,
  DidUpdateResult,
  DidDocumentService,
} from '@aries-framework/core'

import {
  Hasher,
  TypedArrayEncoder,
  Key,
  KeyType,
  DidDocumentRole,
  DidRecord,
  DidRepository,
} from '@aries-framework/core'
import { AttribRequest, NymRequest } from '@hyperledger/indy-vdr-shared'

import { IndyVdrError } from '../error'
import { IndyVdrPoolService } from '../pool/IndyVdrPoolService'
import { isSelfCertifiedDid } from '../utils/did'

import { createKeyAgreementKey, deepObjectDiff, indyDidDocumentFromDid, parseIndyDid } from './didIndyUtil'
import { endpointsAttribFromServices } from './didSovUtil'

export class IndyVdrIndyDidRegistrar implements DidRegistrar {
  public readonly supportedMethods = ['indy']

  public async create(agentContext: AgentContext, options: IndyVdrDidCreateOptions): Promise<DidCreateResult> {
    const seed = options.secret?.seed
    if (seed && (typeof seed !== 'string' || seed.length !== 32)) {
      return {
        didDocumentMetadata: {},
        didRegistrationMetadata: {},
        didState: {
          state: 'failed',
          reason: 'Invalid seed provided',
        },
      }
    }

    const { alias, role, submitterDid, submitterVerkey, services, useEndpointAttrib } = options.options
    let verkey = options.options.verkey
    let did = options.did
    let id

    if (seed && did) {
      return {
        didDocumentMetadata: {},
        didRegistrationMetadata: {},
        didState: {
          state: 'failed',
          reason: `Only one of 'seed' and 'did' must be provided`,
        },
      }
    }

    try {
      const { namespace, id: submitterId } = parseIndyDid(submitterDid)

      if (did) {
        id = parseIndyDid(did).id
        if (!verkey) {
          return {
            didDocumentMetadata: {},
            didRegistrationMetadata: {},
            didState: {
              state: 'failed',
              reason: 'If a did is defined, a matching verkey must be provided',
            },
          }
        }
        if (!isSelfCertifiedDid) {
          throw new Error(`Initial verkey ${verkey} does not match did ˇ${did}`)
        }
      } else {
        // Create a new key and calculate did according to the rules for indy did method
        const key = await agentContext.wallet.createKey({ seed, keyType: KeyType.Ed25519 })
        const buffer = Hasher.hash(key.publicKey, 'sha2-256')

        id = TypedArrayEncoder.toBase58(buffer.slice(0, 16))
        verkey = key.publicKeyBase58
        did = `did:indy:${namespace}:${id}`
      }

      // Create base did document
      const didDocumentBuilder = indyDidDocumentFromDid(did, verkey)
      let diddocContent

      // Add services if object was passed
      if (services) {
        services.forEach((item) => didDocumentBuilder.addService(item))

        const commTypes: CommEndpointType[] = ['endpoint', 'did-communication', 'DIDComm']
        const serviceTypes = new Set(services.map((item) => item.type))

        const keyAgreementId = `${did}#key-agreement-1`

        // If there is at least a communication service, add the key agreement key
        if (commTypes.some((type) => serviceTypes.has(type))) {
          didDocumentBuilder
            .addVerificationMethod({
              controller: did,
              id: keyAgreementId,
              publicKeyBase58: createKeyAgreementKey(verkey),
              type: 'X25519KeyAgreementKey2019',
            })
            .addKeyAgreement(keyAgreementId)
        }

        if (!useEndpointAttrib) {
          // create diddocContent parameter based on the diff between the base and the resulting DID Document
          diddocContent = deepObjectDiff(
            didDocumentBuilder.build().toJSON(),
            indyDidDocumentFromDid(did, verkey).build().toJSON()
          )
        }
      }

      // Build did document
      const didDocument = didDocumentBuilder.build()

      // If there are services and we are using legacy indy endpoint attrib, make sure they are suitable before registering the DID
      if (services && useEndpointAttrib) {
        endpointsAttribFromServices(services)
      }

      const pool = agentContext.dependencyManager.resolve(IndyVdrPoolService).getPoolForNamespace(namespace)
      await this.registerPublicDid(
        agentContext,
        pool,
        submitterId,
        submitterVerkey,
        id,
        verkey,
        alias,
        role,
        diddocContent
      )

      if (services && useEndpointAttrib) {
        await this.setEndpointsForDid(agentContext, pool, verkey, id, endpointsAttribFromServices(services))
      }

      // Save the did so we know we created it and can issue with it
      const didRecord = new DidRecord({
        id: did,
        did,
        role: DidDocumentRole.Created,
        tags: {
          recipientKeyFingerprints: didDocument.recipientKeys.map((key: Key) => key.fingerprint),
        },
      })

      const didRepository = agentContext.dependencyManager.resolve(DidRepository)
      await didRepository.save(agentContext, didRecord)

      return {
        didDocumentMetadata: {
          did,
        },
        didRegistrationMetadata: {
          namespace,
        },
        didState: {
          state: 'finished',
          did,
          didDocument,
          secret: {
            // FIXME: the uni-registrar creates the seed in the registrar method
            // if it doesn't exist so the seed can always be returned. Currently
            // we can only return it if the seed was passed in by the user. Once
            // we have a secure method for generating seeds we should use the same
            // approach
            seed: options.secret?.seed,
          },
        },
      }
    } catch (error) {
      return {
        didDocumentMetadata: {},
        didRegistrationMetadata: {},
        didState: {
          state: 'failed',
          reason: `unknownError: ${error.message}`,
        },
      }
    }
  }

  public async update(): Promise<DidUpdateResult> {
    return {
      didDocumentMetadata: {},
      didRegistrationMetadata: {},
      didState: {
        state: 'failed',
        reason: `notImplemented: updating did:indy not implemented yet`,
      },
    }
  }

  public async deactivate(): Promise<DidDeactivateResult> {
    return {
      didDocumentMetadata: {},
      didRegistrationMetadata: {},
      didState: {
        state: 'failed',
        reason: `notImplemented: deactivating did:indy not implemented yet`,
      },
    }
  }

  private async registerPublicDid(
    agentContext: AgentContext,
    pool: IndyVdrPool,
    submitterDid: string,
    submitterVerkey: string,
    targetDid: string,
    verkey: string,
    alias?: string,
    role?: string,
    diddocContent?: Record<string, unknown>
  ) {
    try {
      agentContext.config.logger.debug(`Register public did '${targetDid}' on ledger '${pool}'`)

      // FIXME: Add diddocContent when supported by indy-vdr
      if (diddocContent) {
        throw new IndyVdrError('diddocContent is not yet supported')
      }

      const request = new NymRequest({ submitterDid, dest: targetDid, verkey, alias })

      const signingKey = Key.fromPublicKeyBase58(submitterVerkey, KeyType.Ed25519)

      const response = await pool.submitWriteRequest(agentContext, request, signingKey)

      agentContext.config.logger.debug(`Registered public did '${targetDid}' on ledger '${pool.indyNamespace}'`, {
        response,
      })

      return targetDid
    } catch (error) {
      agentContext.config.logger.error(
        `Error registering public did '${targetDid}' on ledger '${pool.indyNamespace}'`,
        {
          error,
          submitterDid,
          targetDid,
          verkey,
          alias,
          role,
          pool: pool.indyNamespace,
        }
      )

      throw error
    }
  }

  private async setEndpointsForDid(
    agentContext: AgentContext,
    pool: IndyVdrPool,
    submitterVerkey: string,
    did: string,
    endpoints: IndyEndpointAttrib
  ): Promise<void> {
    try {
      agentContext.config.logger.debug(`Set endpoints for did '${did}' on ledger '${pool.indyNamespace}'`, endpoints)

      const request = new AttribRequest({
        submitterDid: did,
        targetDid: did,
        raw: JSON.stringify({ endpoint: endpoints }),
      })

      const signingKey = Key.fromPublicKeyBase58(submitterVerkey, KeyType.Ed25519)

      const response = await pool.submitWriteRequest(agentContext, request, signingKey)
      agentContext.config.logger.debug(
        `Successfully set endpoints for did '${did}' on ledger '${pool.indyNamespace}'`,
        {
          response,
          endpoints,
        }
      )
    } catch (error) {
      agentContext.config.logger.error(`Error setting endpoints for did '${did}' on ledger '${pool.indyNamespace}'`, {
        error,
        did,
        endpoints,
      })

      throw new IndyVdrError(error)
    }
  }
}

export interface IndyVdrDidCreateOptions extends DidCreateOptions {
  method: 'indy'
  did?: string
  didDocument?: never // Not yet supported
  options: {
    alias?: string
    role?: string
    services?: DidDocumentService[]
    useEndpointAttrib?: boolean
    submitterDid: string
    submitterVerkey: string
    verkey?: string
  }
  secret?: {
    seed?: string
  }
}

// TODO: Add Update and Deactivate
export type IndyVdrIndyDidUpdateOptions = never
export type IndyVdrIndyDidDeactivateOptions = never
