import type { IndyEndpointAttrib } from './didSovUtil'
import type { IndyVdrPool } from '../pool'
import type {
  AgentContext,
  Buffer,
  DidCreateOptions,
  DidCreateResult,
  DidDeactivateResult,
  DidDocument,
  DidDocumentService,
  DidOperationStateActionBase,
  DidRegistrar,
  DidUpdateResult,
} from '@credo-ts/core'
import type { IndyVdrRequest } from '@hyperledger/indy-vdr-shared'

import { parseIndyDid } from '@credo-ts/anoncreds'
import {
  DidCommV1Service,
  DidCommV2Service,
  DidDocumentRole,
  DidRecord,
  DidRepository,
  Hasher,
  IndyAgentService,
  Key,
  KeyType,
  TypedArrayEncoder,
} from '@credo-ts/core'
import { AttribRequest, CustomRequest, NymRequest } from '@hyperledger/indy-vdr-shared'

import { IndyVdrError } from '../error'
import { IndyVdrPoolService } from '../pool/IndyVdrPoolService'

import {
  buildDidDocument,
  createKeyAgreementKey,
  didDocDiff,
  indyDidDocumentFromDid,
  isSelfCertifiedIndyDid,
  verificationKeyForIndyDid,
} from './didIndyUtil'
import { endpointsAttribFromServices } from './didSovUtil'

export class IndyVdrIndyDidRegistrar implements DidRegistrar {
  public readonly supportedMethods = ['indy']

  private didCreateActionResult({
    namespace,
    didAction,
    did,
  }: {
    namespace: string
    didAction: EndorseDidTxAction
    did: string
  }): IndyVdrDidCreateResult {
    return {
      jobId: did,
      didDocumentMetadata: {},
      didRegistrationMetadata: {
        didIndyNamespace: namespace,
      },
      didState: didAction,
    }
  }

  private didCreateFailedResult({ reason }: { reason: string }): IndyVdrDidCreateResult {
    return {
      didDocumentMetadata: {},
      didRegistrationMetadata: {},
      didState: {
        state: 'failed',
        reason: reason,
      },
    }
  }

  private didCreateFinishedResult({
    seed,
    privateKey,
    did,
    didDocument,
    namespace,
  }: {
    seed: Buffer | undefined
    privateKey: Buffer | undefined
    did: string
    didDocument: DidDocument
    namespace: string
  }): IndyVdrDidCreateResult {
    return {
      didDocumentMetadata: {},
      didRegistrationMetadata: {
        didIndyNamespace: namespace,
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
          seed: seed,
          privateKey: privateKey,
        },
      },
    }
  }

  public async parseInput(agentContext: AgentContext, options: IndyVdrDidCreateOptions): Promise<ParseInputResult> {
    let did = options.did
    let namespaceIdentifier: string
    let verificationKey: Key
    const seed = options.secret?.seed
    const privateKey = options.secret?.privateKey

    if (options.options.endorsedTransaction) {
      const _did = did as string
      const { namespace } = parseIndyDid(_did)
      // endorser did from the transaction
      const endorserNamespaceIdentifier = JSON.parse(options.options.endorsedTransaction.nymRequest).identifier

      return {
        status: 'ok',
        did: _did,
        namespace: namespace,
        namespaceIdentifier: parseIndyDid(_did).namespaceIdentifier,
        endorserNamespaceIdentifier,
        seed,
        privateKey,
      }
    }

    const endorserDid = options.options.endorserDid
    const { namespace: endorserNamespace, namespaceIdentifier: endorserNamespaceIdentifier } = parseIndyDid(endorserDid)

    const allowOne = [privateKey, seed, did].filter((e) => e !== undefined)
    if (allowOne.length > 1) {
      return {
        status: 'error',
        reason: `Only one of 'seed', 'privateKey' and 'did' must be provided`,
      }
    }

    if (did) {
      if (!options.options.verkey) {
        return {
          status: 'error',
          reason: 'If a did is defined, a matching verkey must be provided',
        }
      }

      const { namespace: didNamespace, namespaceIdentifier: didNamespaceIdentifier } = parseIndyDid(did)
      namespaceIdentifier = didNamespaceIdentifier
      verificationKey = Key.fromPublicKeyBase58(options.options.verkey, KeyType.Ed25519)

      if (!isSelfCertifiedIndyDid(did, options.options.verkey)) {
        return {
          status: 'error',
          reason: `Initial verkey ${options.options.verkey} does not match did ${did}`,
        }
      }

      if (didNamespace !== endorserNamespace) {
        return {
          status: 'error',
          reason: `The endorser did uses namespace: '${endorserNamespace}' and the did to register uses namespace: '${didNamespace}'. Namespaces must match.`,
        }
      }
    } else {
      // Create a new key and calculate did according to the rules for indy did method
      verificationKey = await agentContext.wallet.createKey({ privateKey, seed, keyType: KeyType.Ed25519 })
      const buffer = Hasher.hash(verificationKey.publicKey, 'sha-256')

      namespaceIdentifier = TypedArrayEncoder.toBase58(buffer.slice(0, 16))
      did = `did:indy:${endorserNamespace}:${namespaceIdentifier}`
    }

    return {
      status: 'ok',
      did,
      verificationKey,
      namespaceIdentifier,
      namespace: endorserNamespace,
      endorserNamespaceIdentifier,
      seed,
      privateKey,
    }
  }

  public async saveDidRecord(agentContext: AgentContext, did: string, didDocument: DidDocument): Promise<void> {
    // Save the did so we know we created it and can issue with it
    const didRecord = new DidRecord({
      did,
      role: DidDocumentRole.Created,
      didDocument,
    })

    const didRepository = agentContext.dependencyManager.resolve(DidRepository)
    await didRepository.save(agentContext, didRecord)
  }

  private createDidDocument(
    did: string,
    verificationKey: Key,
    services: DidDocumentService[] | undefined,
    useEndpointAttrib: boolean | undefined
  ) {
    // Create base did document
    const didDocumentBuilder = indyDidDocumentFromDid(did, verificationKey.publicKeyBase58)
    let diddocContent

    // Add services if object was passed
    if (services) {
      services.forEach((item) => {
        const prependDidIfNotPresent = (id: string) => {
          return id.startsWith('#') ? `${did}${id}` : id
        }

        // Prepend the did to the service id if it is not already there
        item.id = prependDidIfNotPresent(item.id)

        // TODO: should we also prepend the did to routingKeys?
        if (item instanceof DidCommV1Service) {
          item.recipientKeys = item.recipientKeys.map(prependDidIfNotPresent)
        }

        didDocumentBuilder.addService(item)
      })

      const commTypes = [IndyAgentService.type, DidCommV1Service.type, DidCommV2Service.type]
      const serviceTypes = new Set(services.map((item) => item.type))

      const keyAgreementId = `${did}#key-agreement-1`

      // If there is at least a communication service, add the key agreement key
      if (commTypes.some((type) => serviceTypes.has(type))) {
        didDocumentBuilder
          .addContext('https://w3id.org/security/suites/x25519-2019/v1')
          .addVerificationMethod({
            controller: did,
            id: keyAgreementId,
            publicKeyBase58: createKeyAgreementKey(verificationKey.publicKeyBase58),
            type: 'X25519KeyAgreementKey2019',
          })
          .addKeyAgreement(keyAgreementId)
      }

      // If there is a DIDComm V2 service, add context
      if (serviceTypes.has(DidCommV2Service.type)) {
        didDocumentBuilder.addContext('https://didcomm.org/messaging/contexts/v2')
      }

      if (!useEndpointAttrib) {
        // create diddocContent parameter based on the diff between the base and the resulting DID Document
        diddocContent = didDocDiff(
          didDocumentBuilder.build().toJSON(),
          indyDidDocumentFromDid(did, verificationKey.publicKeyBase58).build().toJSON()
        )
      }
    }

    // Build did document
    const didDocument = didDocumentBuilder.build()

    return {
      diddocContent,
      didDocument,
    }
  }

  public async create(agentContext: AgentContext, options: IndyVdrDidCreateOptions): Promise<IndyVdrDidCreateResult> {
    try {
      const res = await this.parseInput(agentContext, options)
      if (res.status === 'error') return this.didCreateFailedResult({ reason: res.reason })

      const { did, namespaceIdentifier, endorserNamespaceIdentifier, verificationKey, namespace, seed, privateKey } =
        res

      const pool = agentContext.dependencyManager.resolve(IndyVdrPoolService).getPoolForNamespace(namespace)

      let nymRequest: NymRequest | CustomRequest
      let didDocument: DidDocument | undefined
      let attribRequest: AttribRequest | CustomRequest | undefined
      let alias: string | undefined

      if (options.options.endorsedTransaction) {
        const { nymRequest: _nymRequest, attribRequest: _attribRequest } = options.options.endorsedTransaction
        nymRequest = new CustomRequest({ customRequest: _nymRequest })
        attribRequest = _attribRequest ? new CustomRequest({ customRequest: _attribRequest }) : undefined
      } else {
        const { services, useEndpointAttrib } = options.options
        alias = options.options.alias
        if (!verificationKey) throw new Error('VerificationKey not defined')

        const { didDocument: _didDocument, diddocContent } = this.createDidDocument(
          did,
          verificationKey,
          services,
          useEndpointAttrib
        )
        didDocument = _didDocument

        let didRegisterSigningKey: Key | undefined = undefined
        if (options.options.endorserMode === 'internal')
          didRegisterSigningKey = await verificationKeyForIndyDid(agentContext, options.options.endorserDid)

        nymRequest = await this.createRegisterDidWriteRequest({
          agentContext,
          pool,
          signingKey: didRegisterSigningKey,
          submitterNamespaceIdentifier: endorserNamespaceIdentifier,
          namespaceIdentifier,
          verificationKey,
          alias,
          diddocContent,
          role: options.options.role,
        })

        if (services && useEndpointAttrib) {
          const endpoints = endpointsAttribFromServices(services)
          attribRequest = await this.createSetDidEndpointsRequest({
            agentContext,
            pool,
            signingKey: verificationKey,
            endorserDid: options.options.endorserMode === 'external' ? options.options.endorserDid : undefined,
            unqualifiedDid: namespaceIdentifier,
            endpoints,
          })
        }

        if (options.options.endorserMode === 'external') {
          const didAction: EndorseDidTxAction = {
            state: 'action',
            action: 'endorseIndyTransaction',
            endorserDid: options.options.endorserDid,
            nymRequest: nymRequest.body,
            attribRequest: attribRequest?.body,
            did: did,
            secret: { seed, privateKey },
          }

          return this.didCreateActionResult({ namespace, didAction, did })
        }
      }
      await this.registerPublicDid(agentContext, pool, nymRequest)
      if (attribRequest) await this.setEndpointsForDid(agentContext, pool, attribRequest)
      didDocument = didDocument ?? (await buildDidDocument(agentContext, pool, did))
      await this.saveDidRecord(agentContext, did, didDocument)
      return this.didCreateFinishedResult({ did, didDocument, namespace, seed, privateKey })
    } catch (error) {
      return this.didCreateFailedResult({ reason: `unknownError: ${error.message}` })
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

  private async createRegisterDidWriteRequest(options: {
    agentContext: AgentContext
    pool: IndyVdrPool
    submitterNamespaceIdentifier: string
    namespaceIdentifier: string
    verificationKey: Key
    signingKey?: Key
    alias: string | undefined
    diddocContent?: Record<string, unknown>
    role?: NymRequestRole
  }) {
    const {
      agentContext,
      pool,
      submitterNamespaceIdentifier,
      namespaceIdentifier,
      verificationKey,
      alias,
      signingKey,
      role,
    } = options

    // FIXME: Add diddocContent when supported by indy-vdr
    if (options.diddocContent) {
      throw new IndyVdrError('diddocContent is not yet supported')
    }

    const request = new NymRequest({
      submitterDid: submitterNamespaceIdentifier,
      dest: namespaceIdentifier,
      verkey: verificationKey.publicKeyBase58,
      alias,
      role,
    })

    if (!signingKey) return request
    const writeRequest = await pool.prepareWriteRequest(agentContext, request, signingKey, undefined)
    return writeRequest
  }

  private async registerPublicDid<Request extends IndyVdrRequest>(
    agentContext: AgentContext,
    pool: IndyVdrPool,
    writeRequest: Request
  ) {
    const body = writeRequest.body
    try {
      const response = await pool.submitRequest(writeRequest)

      agentContext.config.logger.debug(`Register public did on ledger '${pool.indyNamespace}'\nRequest: ${body}}`, {
        response,
      })

      return
    } catch (error) {
      agentContext.config.logger.error(
        `Error Registering public did on ledger '${pool.indyNamespace}'\nRequest: ${body}}`
      )

      throw error
    }
  }

  private async createSetDidEndpointsRequest(options: {
    agentContext: AgentContext
    pool: IndyVdrPool
    signingKey: Key
    endorserDid?: string
    unqualifiedDid: string
    endpoints: IndyEndpointAttrib
  }): Promise<AttribRequest> {
    const { agentContext, pool, endpoints, unqualifiedDid, signingKey, endorserDid } = options
    const request = new AttribRequest({
      submitterDid: unqualifiedDid,
      targetDid: unqualifiedDid,
      raw: JSON.stringify({ endpoint: endpoints }),
    })

    const writeRequest = await pool.prepareWriteRequest(agentContext, request, signingKey, endorserDid)
    return writeRequest
  }

  private async setEndpointsForDid<Request extends IndyVdrRequest>(
    agentContext: AgentContext,
    pool: IndyVdrPool,
    writeRequest: Request
  ): Promise<void> {
    const body = writeRequest.body
    try {
      const response = await pool.submitRequest(writeRequest)

      agentContext.config.logger.debug(
        `Successfully set endpoints for did on ledger '${pool.indyNamespace}'.\nRequest: ${body}}`,
        {
          response,
        }
      )
    } catch (error) {
      agentContext.config.logger.error(
        `Error setting endpoints for did on ledger '${pool.indyNamespace}'.\nRequest: ${body}}`
      )

      throw new IndyVdrError(error)
    }
  }
}

interface IndyVdrDidCreateOptionsBase extends DidCreateOptions {
  didDocument?: never // Not yet supported
  options: {
    alias?: string
    role?: NymRequestRole
    services?: DidDocumentService[]
    useEndpointAttrib?: boolean
    verkey?: string

    // endorserDid is always required. We just have internal or external mode
    endorserDid: string
    // if endorserMode is 'internal', the endorserDid MUST be present in the wallet
    // if endorserMode is 'external', the endorserDid doesn't have to be present in the wallet
    endorserMode: 'internal' | 'external'
    endorsedTransaction?: never
  }
  secret?: {
    seed?: Buffer
    privateKey?: Buffer
  }
}

interface IndyVdrDidCreateOptionsWithDid extends IndyVdrDidCreateOptionsBase {
  method?: never
  did: string
}

interface IndyVdrDidCreateOptionsWithoutDid extends IndyVdrDidCreateOptionsBase {
  method: 'indy'
  did?: never
}

// When transactions have been endorsed. Only supported for external mode
// this is a separate interface so we can remove all the properties we don't need anymore.
interface IndyVdrDidCreateOptionsForSubmission extends DidCreateOptions {
  didDocument?: never
  did: string // for submission MUST always have a did, so we know which did we're submitting the transaction for. We MUST check whether the did passed here, matches with the
  method?: never
  options: {
    endorserMode: 'external'

    // provide the endorsed transactions. If these are provided
    // we will submit the transactions to the ledger
    endorsedTransaction: {
      nymRequest: string
      attribRequest?: string
    }
  }
  secret?: {
    seed?: Buffer
    privateKey?: Buffer
  }
}

export type IndyVdrDidCreateOptions =
  | IndyVdrDidCreateOptionsWithDid
  | IndyVdrDidCreateOptionsWithoutDid
  | IndyVdrDidCreateOptionsForSubmission

type ParseInputOk = {
  status: 'ok'
  did: string
  verificationKey?: Key
  namespaceIdentifier: string
  namespace: string
  endorserNamespaceIdentifier: string
  seed: Buffer | undefined
  privateKey: Buffer | undefined
}

type parseInputError = { status: 'error'; reason: string }

type ParseInputResult = ParseInputOk | parseInputError

export interface EndorseDidTxAction extends DidOperationStateActionBase {
  action: 'endorseIndyTransaction'
  endorserDid: string
  nymRequest: string
  attribRequest?: string
  did: string
}

export type IndyVdrDidCreateResult = DidCreateResult<EndorseDidTxAction>

export type NymRequestRole = 'STEWARD' | 'TRUSTEE' | 'ENDORSER' | 'NETWORK_MONITOR'
